import type {
  ProofArtifactReference,
  SutResultArtifacts,
  SutResultEntry,
  SutCaseStatus,
  SutOutcome,
} from "./types.js";

export interface CreateSutResultEntryInput {
  caseId: string;
  status?: SutCaseStatus;
  outcome: SutOutcome;
  shouldExecute: boolean;
  reasonCodes: string[];
  artifacts?: SutResultArtifacts;
  checks?: SutResultEntry["checks"];
  proofArtifacts?: ProofArtifactReference[];
  limitations?: string[];
}

export function createSutResultEntry(
  input: CreateSutResultEntryInput
): SutResultEntry {
  const artifacts: SutResultArtifacts | undefined =
    input.artifacts || input.proofArtifacts
      ? {
          ...(input.artifacts ?? {}),
          ...(input.proofArtifacts
            ? { proof_artifacts: input.proofArtifacts }
            : {}),
        }
      : undefined;
  const limitations = [...(input.limitations ?? [])];
  if (input.proofArtifacts && input.proofArtifacts.length > 0) {
    limitations.push(
      "JOSE proof artifact references are recorded only; production signature verification is outside this helper."
    );
  }

  return {
    case_id: input.caseId,
    status: input.status ?? "completed",
    outcome: input.outcome,
    should_execute: input.shouldExecute,
    reason_codes: input.reasonCodes,
    ...(input.checks && input.checks.length > 0 ? { checks: input.checks } : {}),
    ...(artifacts ? { artifacts } : {}),
    ...(limitations.length > 0 ? { limitations } : {}),
  };
}
