declare module "node:crypto" {
  export interface KeyObject {
    readonly asymmetricKeyType?: string;
    readonly asymmetricKeyDetails?: { namedCurve?: string };
  }
  export function createPublicKey(options: { key: Uint8Array; format: "der"; type: "spki" }): KeyObject;
  export function verify(algorithm: "sha256", data: Uint8Array,
    key: { key: KeyObject; dsaEncoding: "ieee-p1363" }, signature: Uint8Array): boolean;
  export function createHash(algorithm: "sha256"): {
    update(bytes: Uint8Array): {
      digest(encoding: "hex"): string;
    };
  };
}

declare module "node:buffer" {
  interface ByteBuffer extends Uint8Array {
    toString(encoding?: "hex" | "base64" | "base64url" | "utf8"): string;
  }
  export const Buffer: {
    from(value: string, encoding: "base64" | "base64url"): ByteBuffer;
    from(value: Uint8Array): ByteBuffer;
  };
}

declare module "node:fs" {
  export function readFileSync(path: string | URL, encoding: "utf8"): string;
}

declare module "node:path" {
  export function resolve(...paths: string[]): string;
}

declare const process: {
  cwd(): string;
};
