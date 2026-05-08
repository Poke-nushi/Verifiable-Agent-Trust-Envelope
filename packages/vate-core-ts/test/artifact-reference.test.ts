import { describe, expect, it } from "vitest";
import {
  artifactReferenceMatchesBytes,
  validateDigestDescriptor,
  type ArtifactReference,
} from "../src/index.js";

describe("artifact references", () => {
  const goodRef: ArtifactReference = {
    type: "admission_request",
    uri: "examples/admission-request.example.json",
    media_type: "application/vate-admission-request+json",
    digest: {
      alg: "sha-256",
      value: "e62cdef847d6879987b208728946991b85a6ca97911678188686320f02f09f05",
    },
  };

  it("validates sha-256 hex digest descriptors", () => {
    expect(validateDigestDescriptor(goodRef.digest)).toEqual([]);
    expect(validateDigestDescriptor({ alg: "sha-256", value: "NOT_HEX" })).toEqual([
      "digest.value must be lowercase 64-character sha-256 hex",
    ]);
  });

  it("checks digest against bytes", () => {
    expect(artifactReferenceMatchesBytes(goodRef, new TextEncoder().encode("vate"))).toEqual([]);
    expect(artifactReferenceMatchesBytes(goodRef, new TextEncoder().encode("other"))).toEqual([
      "artifact digest mismatch",
    ]);
  });
});
