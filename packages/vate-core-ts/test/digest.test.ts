import { describe, expect, it } from "vitest";
import {
  digestDescriptorForJson,
  sha256Hex,
  stableJsonBytes,
} from "../src/index.js";

describe("digest helpers", () => {
  it("computes lowercase sha-256 hex for bytes", () => {
    expect(sha256Hex(new TextEncoder().encode("vate"))).toBe(
      "e62cdef847d6879987b208728946991b85a6ca97911678188686320f02f09f05"
    );
  });

  it("uses sorted-key compact JSON for the v0.3 fixture byte basis", () => {
    const bytes = stableJsonBytes({ b: 2, a: 1 });
    expect(new TextDecoder().decode(bytes)).toBe("{\"a\":1,\"b\":2}");
  });

  it("creates sha-256 digest descriptors for JSON", () => {
    const descriptor = digestDescriptorForJson({ b: 2, a: 1 });
    expect(descriptor.alg).toBe("sha-256");
    expect(descriptor.value).toMatch(/^[a-f0-9]{64}$/);
  });

  it("rejects values that JSON.stringify would silently rewrite", () => {
    expect(() =>
      stableJsonBytes({ omitted: undefined } as never)
    ).toThrow("unsupported JSON value");
    expect(() => stableJsonBytes(Number.NaN as never)).toThrow(
      "unsupported JSON number"
    );
    expect(() => stableJsonBytes([undefined] as never)).toThrow(
      "unsupported JSON value"
    );
  });
});
