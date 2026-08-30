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

  it("emits post-execution linkage outcomes", () => {
    const entry = createSutResultEntry({
      caseId: "post-execution-after-deny",
      outcome: "failed",
      shouldExecute: false,
      reasonCodes: ["POST_EXEC_ADMISSION_DENIED"],
    });

    expect(entry).toMatchObject({
      case_id: "post-execution-after-deny",
      status: "completed",
      outcome: "failed",
      should_execute: false,
      reason_codes: ["POST_EXEC_ADMISSION_DENIED"],
    });
  });

  it("keeps evaluated corpus artifacts separate from generated receipts", () => {
    const generatedReceipt = {
      uri: "https://implementation.example/vate/admission/receipt-1.json",
      local_path: "artifacts/receipt-1.json",
      media_type: "application/vate-admission-receipt+json",
      digest: { alg: "sha-256" as const, value: "1".repeat(64) },
    };
    const entry = createSutResultEntry({
      caseId: "allow-valid-admission",
      artifactMode: "generated-receipts",
      outcome: "allow",
      shouldExecute: true,
      reasonCodes: ["EVIDENCE_VERIFIED", "POLICY_MATCH"],
      generatedArtifacts: { admission_receipt: generatedReceipt },
    });

    expect(entry.artifact_mode).toBe("generated-receipts");
    expect(entry.generated_artifacts?.admission_receipt).toEqual(generatedReceipt);
    expect(entry.artifacts).toBeUndefined();
  });

  it("records explicit SUT input artifacts separately from expected receipts", () => {
    const entry = createSutResultEntry({
      caseId: "deny-status-revoked",
      outcome: "deny",
      shouldExecute: false,
      reasonCodes: ["STATUS_REVOKED", "FAIL_CLOSED"],
      artifacts: {
        input_artifacts: [
          {
            case_artifact: "status_context",
            role: "status_evidence",
            uri: "conformance/al2-vate-v0.3/fixtures/status-revoked-context.json",
            media_type: "application/json",
            digest: { alg: "sha-256", value: "2".repeat(64) },
          },
        ],
      },
    });

    expect(entry.artifacts?.input_artifacts).toHaveLength(1);
    expect(entry.artifacts).not.toHaveProperty("admission_receipt");
  });

  it("rejects explicit SUT input artifacts combined with legacy siblings", () => {
    expect(() =>
      createSutResultEntry({
        caseId: "deny-status-revoked",
        outcome: "deny",
        shouldExecute: false,
        reasonCodes: ["STATUS_REVOKED", "FAIL_CLOSED"],
        artifacts: {
          input_artifacts: [
            {
              case_artifact: "status_context",
              role: "status_evidence",
              uri: "conformance/al2-vate-v0.3/fixtures/status-revoked-context.json",
              media_type: "application/json",
              digest: { alg: "sha-256", value: "2".repeat(64) },
            },
          ],
          admission_receipt: {
            uri: "expected-receipt.json",
            media_type: "application/vate-admission-receipt+json",
            digest: { alg: "sha-256", value: "3".repeat(64) },
          },
        } as never,
      })
    ).toThrow(/cannot be combined/);
  });

  it("rejects an empty explicit SUT input artifact list at runtime", () => {
    expect(() =>
      createSutResultEntry({
        caseId: "deny-status-revoked",
        outcome: "deny",
        shouldExecute: false,
        reasonCodes: ["STATUS_REVOKED", "FAIL_CLOSED"],
        artifacts: {
          input_artifacts: [],
        },
      } as never)
    ).toThrow(/must be a non-empty array/);
  });

  it("rejects malformed runtime artifact containers and explicit input lists", () => {
    const base = {
      caseId: "deny-status-revoked",
      outcome: "deny" as const,
      shouldExecute: false,
      reasonCodes: ["STATUS_REVOKED", "FAIL_CLOSED"],
    };

    for (const artifacts of [null, [], "invalid", 7, false]) {
      expect(() =>
        createSutResultEntry({
          ...base,
          artifacts,
        } as never)
      ).toThrow(/artifacts must be an object/);
    }

    for (const inputArtifacts of [null, {}, "invalid", 7, false]) {
      expect(() =>
        createSutResultEntry({
          ...base,
          artifacts: { input_artifacts: inputArtifacts },
        } as never)
      ).toThrow(/must be a non-empty array/);
    }
  });

  it("rejects duplicate explicit SUT input logical keys", () => {
    const reference = {
      case_artifact: "status_context",
      role: "status_evidence",
      uri: "conformance/al2-vate-v0.3/fixtures/status-revoked-context.json",
      media_type: "application/json",
      digest: { alg: "sha-256" as const, value: "2".repeat(64) },
    };

    expect(() =>
      createSutResultEntry({
        caseId: "deny-status-revoked",
        outcome: "deny",
        shouldExecute: false,
        reasonCodes: ["STATUS_REVOKED", "FAIL_CLOSED"],
        artifacts: {
          input_artifacts: [reference, { ...reference }],
        },
      })
    ).toThrow(/duplicates case_artifact=status_context role=status_evidence/);
  });

  it("rejects schema-invalid fields inside explicit SUT input references", () => {
    expect(() =>
      createSutResultEntry({
        caseId: "deny-status-revoked",
        outcome: "deny",
        shouldExecute: false,
        reasonCodes: ["STATUS_REVOKED", "FAIL_CLOSED"],
        artifacts: {
          input_artifacts: [
            {
              case_artifact: "status_context",
              role: "status_evidence",
              uri: "conformance/al2-vate-v0.3/fixtures/status-revoked-context.json",
              local_path: "expected-receipt.json",
              media_type: "application/json",
              digest: { alg: "sha-256", value: "2".repeat(64) },
            },
          ],
        },
      } as never)
    ).toThrow(/unsupported fields: local_path/);

    expect(() =>
      createSutResultEntry({
        caseId: "deny-status-revoked",
        outcome: "deny",
        shouldExecute: false,
        reasonCodes: ["STATUS_REVOKED", "FAIL_CLOSED"],
        artifacts: {
          input_artifacts: [
            {
              case_artifact: "status_context",
              role: "status_evidence",
              uri: "conformance/al2-vate-v0.3/fixtures/status-revoked-context.json",
              media_type: "application/json",
              digest: {
                alg: "sha-256",
                value: "2".repeat(64),
                expected_receipt: "must-not-be-an-input",
              },
            },
          ],
        },
      } as never)
    ).toThrow(/digest contains unsupported fields/);
  });
});
