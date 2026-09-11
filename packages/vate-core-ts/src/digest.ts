import { createHash } from "node:crypto";
import { stableJsonBytes } from "./json.js";
import type { DigestDescriptor, JsonValue } from "./types.js";

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function digestDescriptorForBytes(bytes: Uint8Array): DigestDescriptor {
  return {
    alg: "sha-256",
    value: sha256Hex(bytes),
  };
}

/**
 * Hash an object under stableJsonBytes's limited Python fixture input contract.
 * Numbers must be known Python integers in JavaScript's safe range; fractional
 * numbers, unsafe integers, and negative zero throw TypeError. Parsed 1.0/1e0
 * cannot be distinguished from 1. See docs/conformance/digest-basis.md.
 */
export function digestDescriptorForJson(value: JsonValue): DigestDescriptor {
  return digestDescriptorForBytes(stableJsonBytes(value));
}

export function isSha256HexDigest(value: string): boolean {
  return /^[a-f0-9]{64}$/.test(value);
}

export function digestDescriptorsEqual(
  a: DigestDescriptor,
  b: DigestDescriptor
): boolean {
  return a.alg === b.alg && a.value === b.value;
}
