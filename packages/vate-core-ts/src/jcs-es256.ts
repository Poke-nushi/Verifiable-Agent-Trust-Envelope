import { Buffer } from "node:buffer";
import { createHash, createPublicKey, verify, type KeyObject } from "node:crypto";
import { canonicalizeJcsJson, JCS_INPUT_LIMITS, JcsInputError } from "./jcs.js";

/** Experimental, explicitly selected contract; not a normative VATE profile. */
export const JCS_ES256_PROFILE = "vate-local-jcs-es256-detached-v1" as const;
export const JCS_ES256_PROOF_LIMIT = 4096;
const SPKI_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d03010703420004";
const HEX = /^[0-9a-f]{64}$/;
const sha = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");

export interface JcsEs256VerificationKey {
  key_sha256: string;
  spki_der_base64: string;
}

export interface JcsEs256SignatureResult {
  profile: typeof JCS_ES256_PROFILE;
  status: "verified" | "invalid" | "not_assessed" | "error";
  reason: string;
  key_sha256: string | null;
  source_sha256: string | null;
  proof_sha256: string | null;
  canonical_sha256: string | null;
  signing_input_sha256: string | null;
}

export class JcsEs256ConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JcsEs256ConfigurationError";
  }
}

function exactObject(value: unknown, fields: string[]): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value, key));
}

function decodeUrl(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("invalid base64url");
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) throw new Error("noncanonical base64url");
  return decoded;
}

/**
 * Receiver-selected P-256 keys. Registration permits cryptographic checking,
 * not issuer authority. No keys or algorithms are selected from a remote URI.
 */
export class JcsEs256Verifier {
  readonly #keys = new Map<string, KeyObject>();

  constructor(options: { expectedProfile: string; verificationKeys: readonly JcsEs256VerificationKey[] }) {
    if (options?.expectedProfile !== JCS_ES256_PROFILE) {
      throw new JcsEs256ConfigurationError("explicit JCS ES256 profile required");
    }
    if (!Array.isArray(options.verificationKeys) || options.verificationKeys.length < 1 || options.verificationKeys.length > 16) {
      throw new JcsEs256ConfigurationError("supply 1..16 receiver-selected public keys");
    }
    for (const entry of options.verificationKeys) {
      try {
        if (!exactObject(entry, ["key_sha256", "spki_der_base64"]) ||
            typeof entry.key_sha256 !== "string" || entry.key_sha256.length !== 64 || !HEX.test(entry.key_sha256) ||
            typeof entry.spki_der_base64 !== "string" || entry.spki_der_base64.length !== 124) throw new Error();
        const der = Buffer.from(entry.spki_der_base64, "base64");
        if (der.length !== 91 || der.toString("base64") !== entry.spki_der_base64 ||
            !der.toString("hex").startsWith(SPKI_PREFIX) || sha(der) !== entry.key_sha256 || this.#keys.has(entry.key_sha256)) {
          throw new Error();
        }
        // OpenSSL-backed import rejects invalid/off-curve points. Fixed DER
        // encoding also excludes explicit parameters and compressed points.
        const key = createPublicKey({ key: der, format: "der", type: "spki" });
        if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw new Error();
        this.#keys.set(entry.key_sha256, key);
      } catch {
        throw new JcsEs256ConfigurationError("invalid, duplicate, or unsupported receiver P-256 public key");
      }
    }
  }

  verify(options: { source: Uint8Array | null; proof: Uint8Array | null; expectedType: string }): JcsEs256SignatureResult {
    if (typeof options.expectedType !== "string" || options.expectedType.length < 1 || options.expectedType.length > 128 ||
        /[^\x21-\x7e]/.test(options.expectedType)) {
      throw new JcsEs256ConfigurationError("receiver-selected expected type must be 1..128 printable ASCII characters");
    }
    const result: JcsEs256SignatureResult = {
      profile: JCS_ES256_PROFILE, status: "not_assessed", reason: "MISSING_RECEIPT", key_sha256: null,
      source_sha256: null, proof_sha256: null, canonical_sha256: null, signing_input_sha256: null,
    };
    const fail = (status: JcsEs256SignatureResult["status"], reason: string): JcsEs256SignatureResult => ({ ...result, status, reason });
    for (const [raw, limit] of [[options.source, JCS_INPUT_LIMITS.maxBytes], [options.proof, JCS_ES256_PROOF_LIMIT]] as const) {
      if (raw !== null && !(raw instanceof Uint8Array)) return fail("invalid", "INVALID_BYTES");
      if (raw !== null && raw.byteLength > limit) return fail("invalid", "INPUT_TOO_LARGE");
    }
    // Capture once: digests, canonicalization and verification use these bytes.
    const source = options.source === null ? null : new Uint8Array(options.source);
    const proof = options.proof === null ? null : new Uint8Array(options.proof);
    result.source_sha256 = source === null ? null : sha(source);
    result.proof_sha256 = proof === null ? null : sha(proof);
    if (source === null) return result;
    if (proof === null) return fail("not_assessed", "MISSING_PROOF");

    let protectedPart: string;
    let signature: Uint8Array;
    let header: Record<string, unknown>;
    try {
      // Compact serialization is ASCII with no whitespace, BOM or newline.
      const compact = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(proof);
      const segments = compact.split(".");
      if (segments.length !== 3 || segments[1] !== "") throw new Error();
      protectedPart = segments[0]!;
      signature = decodeUrl(segments[2]!);
      if (signature.byteLength !== 64) throw new Error();
      const parsed: unknown = JSON.parse(new TextDecoder().decode(canonicalizeJcsJson(decodeUrl(protectedPart))));
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
      header = parsed as Record<string, unknown>;
      // Malformed required members stay invalid even beside an unsupported extension.
      if (!["alg", "kid", "typ"].every(key => Object.hasOwn(header, key)) ||
          typeof header.alg !== "string" || header.alg.length === 0 || /[^\x21-\x7e]/.test(header.alg) ||
          typeof header.kid !== "string" || header.kid.length !== 64 || !HEX.test(header.kid) ||
          typeof header.typ !== "string") throw new Error();
      if (!exactObject(header, ["alg", "kid", "typ"])) return fail("not_assessed", "UNSUPPORTED_PROTECTED_HEADER");
    } catch {
      return fail("invalid", "INVALID_DETACHED_JWS");
    }
    if (header.alg !== "ES256") return fail("not_assessed", "UNSUPPORTED_ALGORITHM");
    if (header.typ !== options.expectedType) return fail("invalid", "RECEIPT_TYPE_MISMATCH");
    const keyId = header.kid as string;
    result.key_sha256 = keyId;
    const key = this.#keys.get(keyId);
    if (key === undefined) return fail("not_assessed", "UNKNOWN_KEY");
    let canonical: Uint8Array;
    try {
      canonical = canonicalizeJcsJson(source);
    } catch (error) {
      if (error instanceof JcsInputError) return fail("invalid", "JCS_" + error.code.toUpperCase());
      return fail("error", "CANONICALIZATION_ERROR");
    }
    result.canonical_sha256 = sha(canonical);
    // RFC 7515 detached JWS restores the encoded payload. Preserve the exact
    // protected header segment; only the payload uses JCS in this local profile.
    const signingInput = new TextEncoder().encode(protectedPart + "." + Buffer.from(canonical).toString("base64url"));
    result.signing_input_sha256 = sha(signingInput);
    try {
      return verify("sha256", signingInput, { key, dsaEncoding: "ieee-p1363" }, signature)
        ? fail("verified", "SIGNATURE_VERIFIED") : fail("invalid", "SIGNATURE_MISMATCH");
    } catch {
      return fail("error", "CRYPTO_BACKEND_ERROR");
    }
  }
}
