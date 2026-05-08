import { digestDescriptorForBytes, isSha256HexDigest } from "./digest.js";
import type { DigestBoundReference, DigestDescriptor } from "./types.js";

export function validateDigestDescriptor(digest: DigestDescriptor): string[] {
  const errors: string[] = [];
  if (digest.alg !== "sha-256") {
    errors.push("digest.alg must be sha-256");
  }
  if (!isSha256HexDigest(digest.value)) {
    errors.push("digest.value must be lowercase 64-character sha-256 hex");
  }
  return errors;
}

export function artifactReferenceMatchesBytes(
  reference: DigestBoundReference,
  bytes: Uint8Array
): string[] {
  const errors = validateDigestDescriptor(reference.digest);
  if (errors.length > 0) {
    return errors;
  }

  const actual = digestDescriptorForBytes(bytes);
  if (actual.value !== reference.digest.value) {
    return ["artifact digest mismatch"];
  }
  return [];
}
