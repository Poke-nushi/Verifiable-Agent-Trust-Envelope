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
