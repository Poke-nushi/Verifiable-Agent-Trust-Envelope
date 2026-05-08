import { describe, expect, it } from "vitest";
import { createSutResultEntry } from "../src/index.js";

describe("SUT result helpers", () => {
  it("emits schema-shaped result entries and keeps proof verification out of scope", () => {
    const entry = createSutResultEntry({
      caseId: "allow-a2a-signed-agent-card-evidence",
      outcome: "allow",
      shouldExecute: true,
      reasonCodes: ["EVIDENCE_VERIFIED", "POLICY_MATCH"],
      checks: [{ name: "decision.outcome", pass: true }],
      proofArtifacts: [
        {
          kind: "jose_proof_package",
          case_artifact: "jose_proof",
          uri: "examples/jose/jose-detached-a2a-agent-card.example.json",
          media_type: "application/vate-jose-proof-fixture+json",
          digest: { alg: "sha-256", value: "0".repeat(64) },
        },
      ],
    });

    expect(entry).toMatchObject({
      case_id: "allow-a2a-signed-agent-card-evidence",
      status: "completed",
      outcome: "allow",
      should_execute: true,
      reason_codes: ["EVIDENCE_VERIFIED", "POLICY_MATCH"],
    });
    expect(entry).not.toHaveProperty("actual");
    expect(entry.artifacts?.proof_artifacts).toHaveLength(1);
    expect(entry.checks).toEqual([{ name: "decision.outcome", pass: true }]);
    expect(entry.limitations).toEqual([
      "JOSE proof artifact references are recorded only; production signature verification is outside this helper.",
    ]);
  });
});
