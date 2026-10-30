import { digestDescriptorForBytes, isSha256HexDigest } from "./digest.js";
import { canonicalizeJcsJson, JCS_DIGEST_BASIS, JCS_INPUT_LIMITS, JcsInputError, type JcsInputErrorCode } from "./jcs.js";
import type { DigestDescriptor } from "./types.js";

export interface ExternalJsonDigestReference {
  basis: string;
  digest: { alg: string; value: string };
}

export type ExternalJsonDigestAssessment =
  | {
      status: "matched" | "mismatched";
      basis: typeof JCS_DIGEST_BASIS;
      expected_digest: DigestDescriptor;
      computed_digest: DigestDescriptor;
      source_digest: DigestDescriptor;
    }
  | { status: "not_assessed"; reason: "unsupported_basis" | "unsupported_algorithm" }
  | { status: "invalid_input"; reason: JcsInputErrorCode | "invalid_reference" | "invalid_digest" };

/**
 * Compare one caller-selected external JSON preimage with an explicit digest
 * reference. Never tries an alternate basis. A match is only digest equality;
 * schema, preimage selection, signatures and admission policy remain separate.
 */
export function assessExternalJsonDigest(
  source: Uint8Array,
  reference: ExternalJsonDigestReference
): ExternalJsonDigestAssessment {
  if (reference === null || typeof reference !== "object" ||
      typeof reference.basis !== "string" ||
      reference.digest === null || typeof reference.digest !== "object" ||
      typeof reference.digest.alg !== "string" || typeof reference.digest.value !== "string") {
    return { status: "invalid_input", reason: "invalid_reference" };
  }
  if (reference.basis !== JCS_DIGEST_BASIS) {
    return { status: "not_assessed", reason: "unsupported_basis" };
  }
  if (reference.digest.alg !== "sha-256") {
    return { status: "not_assessed", reason: "unsupported_algorithm" };
  }
  if (reference.digest.value.length !== 64 || !isSha256HexDigest(reference.digest.value)) {
    return { status: "invalid_input", reason: "invalid_digest" };
  }
  if (!(source instanceof Uint8Array)) return { status: "invalid_input", reason: "invalid_bytes" };
  if (source.byteLength > JCS_INPUT_LIMITS.maxBytes) return { status: "invalid_input", reason: "input_too_large" };
  // Both identities must describe the same captured bytes, including when the
  // caller supplies memory shared with another worker.
  const captured = new Uint8Array(source);
  let canonical: Uint8Array;
  try {
    canonical = canonicalizeJcsJson(captured);
  } catch (error) {
    if (error instanceof JcsInputError) return { status: "invalid_input", reason: error.code };
    throw error;
  }
  const computed = digestDescriptorForBytes(canonical);
  return {
    status: computed.value === reference.digest.value ? "matched" : "mismatched",
    basis: JCS_DIGEST_BASIS,
    expected_digest: { alg: "sha-256", value: reference.digest.value },
    computed_digest: computed,
    source_digest: digestDescriptorForBytes(captured),
  };
}
