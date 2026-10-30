import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import {
  assessExternalJsonDigest,
  canonicalizeJcsJson,
  digestDescriptorForJson,
  JCS_DIGEST_BASIS,
  JCS_INPUT_LIMITS,
  sha256Hex,
  type ExternalJsonDigestReference,
} from "../src/index.js";

const encode = (text: string) => new TextEncoder().encode(text);
const fixture = (name: string) => new URL(`./fixtures/aps-jcs/${name}`, import.meta.url);
const vectors = JSON.parse(readFileSync(fixture("jcs-test-vectors.json"), "utf8")).vectors;
const manifest = JSON.parse(readFileSync(fixture("SOURCES.json"), "utf8"));
const reference: ExternalJsonDigestReference = {
  basis: JCS_DIGEST_BASIS,
  digest: { alg: "sha-256", value: manifest.example.expected_sha256 },
};

describe("explicit external JCS digest assessment", () => {
  it("retains the pinned APS source, license, notice and extracted preimage bytes", () => {
    for (const file of manifest.files) {
      const bytes = readFileSync(fixture(file.path));
      expect(bytes.byteLength).toBe(file.bytes);
      expect(sha256Hex(bytes)).toBe(file.sha256);
    }
    expect(JSON.parse(readFileSync(fixture("action-ref-preimage.json"), "utf8")))
      .toEqual(vectors.find((v: { id: string }) => v.id === "v09-action-ref-tuple").input);
  });

  it.each(vectors)("matches pinned APS canonical bytes and digest: $id", (vector) => {
    const input = encode(JSON.stringify(vector.input));
    expect(new TextDecoder().decode(canonicalizeJcsJson(input))).toBe(vector.expected_canonical_bytes);
    const result = assessExternalJsonDigest(input, {
      basis: JCS_DIGEST_BASIS, digest: { alg: "sha-256", value: vector.expected_sha256 },
    });
    expect(result).toMatchObject({ status: "matched", computed_digest: { alg: "sha-256", value: vector.expected_sha256 } });
  });

  it("compares the selected action-ref preimage and retains its raw file identity", () => {
    const source = readFileSync(fixture("action-ref-preimage.json"));
    const result = assessExternalJsonDigest(source, reference);
    expect(result).toEqual({
      status: "matched", basis: JCS_DIGEST_BASIS,
      expected_digest: reference.digest, computed_digest: reference.digest,
      source_digest: { alg: "sha-256", value: "bd8446898160f79b7e5e27eda5f132fe3d7df9e6deab66545d38287b3c284311" },
    });
    const wrongPreimage = encode(JSON.stringify({ action: JSON.parse(source.toString()) }));
    expect(assessExternalJsonDigest(wrongPreimage, reference).status).toBe("mismatched");
    const mutated = encode(source.toString().replace("code_execution", "file_read"));
    expect(assessExternalJsonDigest(mutated, reference).status).toBe("mismatched");
  });

  it("does not fall back to the VATE fixture basis when a JCS digest mismatches", () => {
    const value = { summary: "許可しました" };
    const fixtureDigest = digestDescriptorForJson(value);
    const input = encode(JSON.stringify(value));
    expect(assessExternalJsonDigest(input, { basis: JCS_DIGEST_BASIS, digest: fixtureDigest }).status).toBe("mismatched");
    expect(assessExternalJsonDigest(input, { basis: "json-sorted-no-whitespace", digest: fixtureDigest }))
      .toEqual({ status: "not_assessed", reason: "unsupported_basis" });
  });

  it.each(["", "JCS", "RFC8785", "rfc8785-jcs-v2", " rfc8785-jcs", "rfc8785-jcs\n"])
    ("does not guess an unknown basis %s, even for matching bytes", (basis) => {
      expect(assessExternalJsonDigest(readFileSync(fixture("action-ref-preimage.json")), { ...reference, basis }))
        .toEqual({ status: "not_assessed", reason: "unsupported_basis" });
    });

  it.each(["sha256", "sha-512", "SHA-256", ""])("does not substitute an unsupported algorithm %s", (alg) => {
    expect(assessExternalJsonDigest(encode("null"), { ...reference, digest: { ...reference.digest, alg } }))
      .toEqual({ status: "not_assessed", reason: "unsupported_algorithm" });
  });

  it.each(["", "f".repeat(63), "f".repeat(65), "F".repeat(64), "sha256:" + "f".repeat(64), "f".repeat(64) + "\n"])
    ("requires exactly 64 lowercase hex characters: %s", (value) => {
      expect(assessExternalJsonDigest(encode("null"), { ...reference, digest: { alg: "sha-256", value } }))
        .toEqual({ status: "invalid_input", reason: "invalid_digest" });
    });

  it.each([null, undefined, {}, { basis: JCS_DIGEST_BASIS }, { basis: JCS_DIGEST_BASIS, digest: null }])
    ("handles invalid reference metadata without a digest: %s", (badReference) => {
      expect(assessExternalJsonDigest(encode("null"), badReference as never))
        .toEqual({ status: "invalid_input", reason: "invalid_reference" });
    });

  it.each([
    ['{"a":1,"\\u0061":2}', "duplicate_key"], ['"\\ud800"', "invalid_unicode"],
    ['{"note":"\\uffff"}', "invalid_unicode"], ['{"\\ud83f\\udffe":0}', "invalid_unicode"],
    ['{"note":"\ufdd0"}', "invalid_unicode"], ['{"\u{10ffff}":0}', "invalid_unicode"],
    ["1e400", "non_finite_number"], ["{} trailing", "invalid_json"],
  ])("returns input rejection without emitting a canonical digest: %s", (source, reason) => {
    expect(assessExternalJsonDigest(encode(source), reference)).toEqual({ status: "invalid_input", reason });
  });

  it("rejects malformed UTF-8 without a computed digest", () => {
    expect(assessExternalJsonDigest(new Uint8Array([0xff]), reference))
      .toEqual({ status: "invalid_input", reason: "invalid_utf8" });
  });

  it("enforces input types and limits before capturing the source", () => {
    expect(assessExternalJsonDigest(null as never, reference))
      .toEqual({ status: "invalid_input", reason: "invalid_bytes" });
    expect(assessExternalJsonDigest(new Uint8Array(JCS_INPUT_LIMITS.maxBytes + 1), reference))
      .toEqual({ status: "invalid_input", reason: "input_too_large" });
  });

  it("keeps both digests on one capture if shared source memory changes after decoding", () => {
    const bytes = readFileSync(fixture("action-ref-preimage.json"));
    const shared = new Uint8Array(new SharedArrayBuffer(bytes.length));
    shared.set(bytes);
    const decode = TextDecoder.prototype.decode;
    const spy = vi.spyOn(TextDecoder.prototype, "decode").mockImplementation(function (...args) {
      const text = decode.apply(this, args);
      // Deterministic stand-in for another worker modifying shared memory
      // between canonical decoding and the original-byte hash.
      shared.fill(0);
      return text;
    });
    try {
      const result = assessExternalJsonDigest(shared, reference);
      expect(result).toMatchObject({ status: "matched", source_digest: { value: sha256Hex(bytes) } });
      expect(sha256Hex(shared)).not.toBe(sha256Hex(bytes));
    } finally {
      spy.mockRestore();
    }
  });

  it("distinguishes raw input bytes from canonical identity", () => {
    const input = readFileSync(fixture("action-ref-preimage.json"));
    const compact = encode(JSON.stringify(JSON.parse(input.toString())));
    const first = assessExternalJsonDigest(input, reference);
    const second = assessExternalJsonDigest(compact, reference);
    expect(first.status).toBe("matched");
    expect(second.status).toBe("matched");
    if (first.status === "matched" && second.status === "matched") {
      expect(first.computed_digest).toEqual(second.computed_digest);
      expect(first.source_digest).not.toEqual(second.source_digest);
    }
  });

  // The normal verification sequence builds the package before running tests.
  it.each([
    [JCS_DIGEST_BASIS, "sha-256", reference.digest.value, 0, "matched"],
    [JCS_DIGEST_BASIS, "sha-256", "0".repeat(64), 1, "mismatched"],
    [JCS_DIGEST_BASIS, "sha-256", "invalid", 2, "invalid_input"],
    ["unknown", "sha-256", reference.digest.value, 3, "not_assessed"],
  ])("reports CLI outcome and exit status for %s / %s / %s", (basis, alg, digest, status, outcome) => {
    const result = spawnSync(process.execPath, [
      fileURLToPath(new URL("../examples/assess-external-json.mjs", import.meta.url)),
      fileURLToPath(fixture("action-ref-preimage.json")), basis, alg, digest,
    ], { encoding: "utf8" });
    expect(result.status).toBe(status);
    expect(JSON.parse(result.stdout).status).toBe(outcome);
  });

  it("does not report a digest mismatch when the verifier cannot load", () => {
    const directory = mkdtempSync(join(tmpdir(), "vate-jcs-cli-startup-"));
    const script = join(directory, "examples", "assess-external-json.mjs");
    try {
      mkdirSync(join(directory, "examples"));
      writeFileSync(script, readFileSync(new URL("../examples/assess-external-json.mjs", import.meta.url)));
      writeFileSync(join(directory, "package.json"), '{"type":"module"}');
      for (const failure of ["missing", "initialization"]) {
        if (failure === "initialization") {
          mkdirSync(join(directory, "dist"));
          writeFileSync(join(directory, "dist", "index.js"), 'throw new Error("test initialization failure");');
        }
        const result = spawnSync(process.execPath, [
          script, fileURLToPath(fixture("action-ref-preimage.json")),
          reference.basis, "sha-256", reference.digest.value,
        ], { encoding: "utf8" });
        expect(result.status).toBe(64);
        expect(result.stdout).toBe("");
        expect(result.stderr).toContain("Unable to load the verifier");
      }
    } finally {
      rmSync(directory, { recursive: true });
    }
  });

  it("rejects oversized and ambiguous files through the bounded CLI", () => {
    const directory = mkdtempSync(join(tmpdir(), "vate-jcs-cli-"));
    const script = fileURLToPath(new URL("../examples/assess-external-json.mjs", import.meta.url));
    try {
      for (const [name, text, reason] of [
        ["large.json", " ".repeat(JCS_INPUT_LIMITS.maxBytes * 2), "input_too_large"],
        ["duplicate.json", '{"a":1,"a":2}', "duplicate_key"],
      ]) {
        const path = join(directory, name);
        writeFileSync(path, text);
        const result = spawnSync(process.execPath, [script, path, reference.basis, "sha-256", reference.digest.value], { encoding: "utf8" });
        expect(result.status).toBe(2);
        expect(JSON.parse(result.stdout)).toEqual({ status: "invalid_input", reason });
      }
      for (const path of [directory, join(directory, "missing.json")]) {
        const result = spawnSync(process.execPath, [script, path, reference.basis, "sha-256", reference.digest.value], { encoding: "utf8" });
        expect(result.status).toBe(64);
        expect(result.stdout).toBe("");
      }
    } finally {
      rmSync(directory, { recursive: true });
    }
  });
});
