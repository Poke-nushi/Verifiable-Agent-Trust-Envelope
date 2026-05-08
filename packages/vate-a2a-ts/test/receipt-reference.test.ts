import { describe, expect, it } from "vitest";
import {
  buildAdmissionIssuedMetadata,
  validateVateA2aMetadata,
} from "../src/index.js";

describe("receipt reference helpers", () => {
  it("builds admission_issued metadata", () => {
    const metadata = buildAdmissionIssuedMetadata({
      transactionId: "txn-1",
      decision: "allow",
      issuer: "did:web:verifier.example",
      issuedAt: "2026-05-09T00:00:00Z",
      admissionReceipt: {
        type: "admission_receipt",
        uri: "https://verifier.example/receipts/1",
        media_type: "application/vate-admission-receipt+json",
        digest: {
          alg: "sha-256",
          value: "0".repeat(64),
        },
      },
    });

    expect(metadata.phase).toBe("admission_issued");
    expect(metadata.assurance_level).toBe("AL2");
    expect(metadata.decision).toBe("allow");
    expect(validateVateA2aMetadata(metadata)).toEqual([]);
  });
});
