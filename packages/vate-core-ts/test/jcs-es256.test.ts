import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { canonicalizeJcsJson } from "../src/jcs.js";
import { JcsEs256Verifier, JCS_ES256_PROFILE, JcsEs256ConfigurationError } from "../src/jcs-es256.js";

vi.mock("node:crypto", async importOriginal => {
  const original = await importOriginal<typeof import("node:crypto")>();
  return { ...original, verify: vi.fn(original.verify) };
});

const bytes = (text: string) => new TextEncoder().encode(text);
const sha = (raw: Uint8Array) => createHash("sha256").update(raw).digest("hex");
const url = (raw: Uint8Array) => Buffer.from(raw).toString("base64url");
// Intentionally public test scalars, not credentials.
const privateKeys = [1, 2, 3].map(n => createPrivateKey({ format: "der", type: "sec1", key: Buffer.from(
  "30310201010420" + n.toString(16).padStart(64, "0") + "a00a06082a8648ce3d030107", "hex") }));
const entries = privateKeys.map(privateKey => {
  const der = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return { key_sha256: sha(der), spki_der_base64: der.toString("base64") };
});
const typ = "urn:vate:local:jcs-es256:admission:v1";
const source = bytes('{ "z": 1, "a": "日本語" }');
const verifier = () => new JcsEs256Verifier({ expectedProfile: JCS_ES256_PROFILE, verificationKeys: entries.slice(0, 2) });
const header = (key = 0) => ({ alg: "ES256", kid: entries[key].key_sha256, typ });
function proof(raw = source, protectedJson = JSON.stringify(header()), key = 0, canonical = true) {
  const segment = url(bytes(protectedJson));
  const input = bytes(segment + "." + url(canonical ? canonicalizeJcsJson(raw) : raw));
  return bytes(segment + ".." + url(sign("sha256", input, { key: privateKeys[key], dsaEncoding: "ieee-p1363" })));
}
const assess = (raw = source, signature = proof()) => verifier().verify({ source: raw, proof: signature, expectedType: typ });
function rewrite(signature: Uint8Array, change: (parts: string[]) => void) {
  const parts = new TextDecoder().decode(signature).split(".");
  change(parts);
  return bytes(parts.join("."));
}

describe("explicit JCS detached JWS ES256 profile", () => {
  it("verifies a signature and preserves raw, canonical and proof identities", () => {
    const signature = proof();
    const result = assess(source, signature);
    expect(result).toMatchObject({ profile: JCS_ES256_PROFILE, status: "verified", reason: "SIGNATURE_VERIFIED",
      source_sha256: sha(source), proof_sha256: sha(signature), canonical_sha256: sha(canonicalizeJcsJson(source)), key_sha256: entries[0].key_sha256 });
    expect(result.signing_input_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(result).not.toHaveProperty("authorized");
  });
  it("accepts equivalent whitespace, escapes and key order", () => {
    expect(assess(bytes('{"a":"\\u65e5本語","z":1.0}\n')).status).toBe("verified");
  });
  it("signs the original protected header segment without rewriting it", () => {
    expect(assess(source, proof(source, JSON.stringify(header(), null, 2))).status).toBe("verified");
    const rewritten = rewrite(proof(), p => { p[0] = url(bytes(JSON.stringify(header(), null, 2))); });
    expect(assess(source, rewritten).reason).toBe("SIGNATURE_MISMATCH");
  });
  it("does not try a raw-byte or legacy VATE signing basis", () => {
    expect(assess(source, proof(source, undefined, 0, false)).reason).toBe("SIGNATURE_MISMATCH");
    expect(assess(source, bytes('{"contract":"vate-local-detached-p256-sha256-trial-v1"}')).reason).toBe("INVALID_DETACHED_JWS");
  });
  it("rejects changed content and a different registered signing key", () => {
    expect(assess(bytes('{"a":"日本語","z":2}')).reason).toBe("SIGNATURE_MISMATCH");
    expect(assess(source, proof(source, JSON.stringify(header()), 1)).reason).toBe("SIGNATURE_MISMATCH");
  });
  it("does not fetch an unknown key", () => {
    expect(assess(source, proof(source, JSON.stringify(header(2)), 2))).toMatchObject({ status: "not_assessed", reason: "UNKNOWN_KEY" });
  });
  it("binds the receiver-selected record type", () => {
    expect(verifier().verify({ source, proof: proof(), expectedType: "urn:vate:local:jcs-es256:post_execution:v1" }))
      .toMatchObject({ status: "invalid", reason: "RECEIPT_TYPE_MISMATCH" });
  });
  it("rejects invalid receiver type configuration", () => {
    for (const expectedType of ["", typ + "\n", "has space", "a".repeat(129), "日本語"]) {
      expect(() => verifier().verify({ source, proof: proof(), expectedType })).toThrow(JcsEs256ConfigurationError);
    }
  });
  it.each(["none", "HS256", "ES384", "EdDSA", "urn:example:algorithm"])("does not accept algorithm %s", alg => {
    expect(assess(source, proof(source, JSON.stringify({ ...header(), alg })))).toMatchObject({ status: "not_assessed", reason: "UNSUPPORTED_ALGORITHM" });
  });
  it.each(["crit", "b64", "jwk", "jku", "x5u", "x5c", "extra"])("does not accept header extension %s", name => {
    expect(assess(source, proof(source, JSON.stringify({ ...header(), [name]: false })))).toMatchObject({ status: "not_assessed", reason: "UNSUPPORTED_PROTECTED_HEADER" });
  });
  it.each([
    '{"alg":"ES256","alg":"ES256","kid":"x","typ":"x"}',
    '{"alg":"ES256","\\u0061lg":"ES256","kid":"x","typ":"x"}',
    '["ES256"]', '"ES256"', 'null', 'true', '256',
    JSON.stringify({ kid: entries[0].key_sha256, typ }),
    JSON.stringify({ alg: "ES256", typ }),
    JSON.stringify({ alg: "ES256", kid: entries[0].key_sha256 }),
    ...[null, 256, false, [], {}, "", "ES256 ", "ES256\n", "日本語"].map(alg => JSON.stringify({ ...header(), alg })),
    ...[null, 4, false, [], {}].map(typ => JSON.stringify({ ...header(), typ })),
    JSON.stringify({ ...header(), kid: 4 }),
    JSON.stringify({ ...header(), alg: null, extra: true }),
    JSON.stringify({ ...header(), kid: "bad", crit: [] }),
    JSON.stringify({ alg: "ES256", kid: entries[0].key_sha256, extra: true }),
  ])("rejects malformed or duplicate protected header %s", protectedJson => {
    vi.mocked(verify).mockClear();
    expect(assess(source, proof(source, protectedJson))).toMatchObject({
      status: "invalid", reason: "INVALID_DETACHED_JWS", key_sha256: null,
      canonical_sha256: null, signing_input_sha256: null,
    });
    expect(verify).not.toHaveBeenCalled();
  });
  it.each([
    (p: string[]) => { p[1] = url(source); },
    (p: string[]) => { p[0] += "="; },
    (p: string[]) => { p[2] += "="; },
    (p: string[]) => { p[2] = url(new Uint8Array(63)); },
    (p: string[]) => { p[2] += "\n"; },
    (p: string[]) => { p.push("extra"); },
  ])("rejects an unsupported compact encoding", change => {
    expect(assess(source, rewrite(proof(), change)).reason).toBe("INVALID_DETACHED_JWS");
  });
  it("rejects DER signatures instead of accepting another encoding", () => {
    const segment = url(bytes(JSON.stringify(header())));
    const signature = sign("sha256", bytes(segment + "." + url(canonicalizeJcsJson(source))), privateKeys[0]);
    expect(assess(source, bytes(segment + ".." + url(signature))).reason).toBe("INVALID_DETACHED_JWS");
  });
  it.each(['{"a":1,"a":2}', '{"x":"\\ud800"}', '{"n":1e400}', '\ufeff{}', 'x'])
    ("rejects invalid JCS input even if bytes were signed: %s", raw => {
      const input = bytes(raw);
      expect(assess(input, proof(input, undefined, 0, false))).toMatchObject({ status: "invalid" });
    });
  it.each([0xfdd0, 0xfdef, 0xfffe, 0xffff, 0x1fffe, 0x10ffff])
    ("rejects signed noncharacter %i before accepting a canonical digest", point => {
      const character = String.fromCodePoint(point);
      const canonical = bytes(JSON.stringify({ note: character }));
      // Sign fixed bytes without using the canonicalizer under test.
      const signature = proof(canonical, undefined, 0, false);
      const escaped = character.split("").map(unit => "\\u" + unit.charCodeAt(0).toString(16).padStart(4, "0")).join("");
      for (const input of [canonical, bytes('{"note":"' + escaped + '"}')]) {
        expect(assess(input, signature)).toMatchObject({ status: "invalid", reason: "JCS_INVALID_UNICODE",
          canonical_sha256: null, signing_input_sha256: null });
      }
    });
  it("rejects invalid UTF-8 payload and header", () => {
    expect(assess(Uint8Array.of(0xff)).reason).toBe("JCS_INVALID_UTF8");
    expect(assess(source, rewrite(proof(), p => { p[0] = url(Uint8Array.of(0xff)); })).reason).toBe("INVALID_DETACHED_JWS");
  });
  it("keeps missing bytes distinct from an invalid signature", () => {
    expect(verifier().verify({ source: null, proof: proof(), expectedType: typ })).toMatchObject({ status: "not_assessed", reason: "MISSING_RECEIPT" });
    expect(verifier().verify({ source, proof: null, expectedType: typ })).toMatchObject({ status: "not_assessed", reason: "MISSING_PROOF" });
    expect(assess(source, new Uint8Array()).status).toBe("invalid");
  });
  it("enforces input bounds", () => {
    expect(assess(new Uint8Array(1048577)).reason).toBe("INPUT_TOO_LARGE");
    expect(assess(source, new Uint8Array(4097)).reason).toBe("INPUT_TOO_LARGE");
  });
  it("reports a crypto backend failure separately", () => {
    vi.mocked(verify).mockImplementationOnce(() => { throw new Error("backend failure"); });
    expect(assess()).toMatchObject({ status: "error", reason: "CRYPTO_BACKEND_ERROR" });
    expect(assess().status).toBe("verified");
  });
});

describe("receiver key configuration", () => {
  const make = (keys = entries, profile = JCS_ES256_PROFILE) => new JcsEs256Verifier({ verificationKeys: keys, expectedProfile: profile });
  it("requires an explicit profile and bounded, nonduplicate key list", () => {
    for (const keys of [[], [...entries, entries[0]], Array(17).fill(entries[0])]) expect(() => make(keys)).toThrow(JcsEs256ConfigurationError);
    expect(() => make(entries, "other")).toThrow(JcsEs256ConfigurationError);
  });
  it("rejects mismatched fingerprints, extra key fields and malformed base64", () => {
    for (const change of [{ key_sha256: "0".repeat(64) }, { spki_der_base64: entries[0].spki_der_base64 + "\n" }, { extra: 1 }]) {
      expect(() => make([{ ...entries[0], ...change }])).toThrow(JcsEs256ConfigurationError);
    }
  });
  it.each(["secp384r1", "secp256k1"])("rejects wrong curve %s", namedCurve => {
    const der = generateKeyPairSync("ec", { namedCurve }).publicKey.export({ format: "der", type: "spki" });
    expect(() => make([{ key_sha256: sha(der), spki_der_base64: der.toString("base64") }])).toThrow(JcsEs256ConfigurationError);
  });
  it("rejects off-curve P-256 points including unused registered keys", () => {
    const der = Buffer.from(entries[0].spki_der_base64, "base64");
    der.fill(0, der.length - 64);
    expect(() => make([entries[0], { key_sha256: sha(der), spki_der_base64: der.toString("base64") }])).toThrow(JcsEs256ConfigurationError);
  });
  it("captures keys and does not depend on later metadata mutation", () => {
    const copied = entries.map(e => ({ ...e }));
    const instance = make(copied);
    copied[0].spki_der_base64 = "bad";
    expect(instance.verify({ source, proof: proof(), expectedType: typ }).status).toBe("verified");
  });
});
