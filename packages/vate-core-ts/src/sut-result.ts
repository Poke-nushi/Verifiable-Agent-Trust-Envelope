import type {
  ProofArtifactReference,
  SutArtifactMode,
  SutExplicitInputArtifacts,
  SutGeneratedArtifacts,
  SutLegacyResultArtifacts,
  SutResultArtifacts,
  SutResultEntry,
  SutCaseStatus,
  SutOutcome,
} from "./types.js";

interface CreateSutResultEntryBase {
  caseId: string;
  status?: SutCaseStatus;
  outcome: SutOutcome;
  shouldExecute: boolean;
  reasonCodes: string[];
  artifactMode?: SutArtifactMode;
  generatedArtifacts?: SutGeneratedArtifacts;
  checks?: SutResultEntry["checks"];
  limitations?: string[];
}

export type CreateSutResultEntryInput = CreateSutResultEntryBase &
  (
    | {
        artifacts: SutExplicitInputArtifacts;
        proofArtifacts?: never;
      }
    | {
        artifacts?: SutLegacyResultArtifacts;
        proofArtifacts?: ProofArtifactReference[];
      }
  );

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExplicitInputArtifacts(
  artifacts: SutResultArtifacts | undefined
): artifacts is SutExplicitInputArtifacts {
  if (artifacts === undefined) {
    return false;
  }
  if (!isRecord(artifacts)) {
    throw new Error("SUT result artifacts must be an object");
  }
  if (!Object.prototype.hasOwnProperty.call(artifacts, "input_artifacts")) {
    return false;
  }
  if (!Array.isArray(artifacts.input_artifacts)) {
    throw new Error("explicit SUT input artifacts must be a non-empty array");
  }
  return true;
}

function validateExplicitInputArtifacts(
  artifacts: SutExplicitInputArtifacts
): void {
  if (artifacts.input_artifacts.length === 0) {
    throw new Error("explicit SUT input artifacts must be a non-empty array");
  }

  const allowedReferenceFields = new Set([
    "case_artifact",
    "role",
    "uri",
    "media_type",
    "digest",
  ]);
  const seenLogicalKeys = new Map<string, number>();
  for (const [index, reference] of artifacts.input_artifacts.entries()) {
    if (typeof reference !== "object" || reference === null) {
      throw new Error(`explicit SUT input artifact ${index} must be an object`);
    }
    const extraFields = Object.keys(reference).filter(
      (field) => !allowedReferenceFields.has(field)
    );
    if (extraFields.length > 0) {
      throw new Error(
        `explicit SUT input artifact ${index} contains unsupported fields: ${extraFields.join(", ")}`
      );
    }
    for (const field of ["case_artifact", "role", "uri", "media_type"] as const) {
      if (typeof reference[field] !== "string" || reference[field].length === 0) {
        throw new Error(
          `explicit SUT input artifact ${index}.${field} must be a non-empty string`
        );
      }
    }
    const logicalKey = JSON.stringify([reference.case_artifact, reference.role]);
    const firstIndex = seenLogicalKeys.get(logicalKey);
    if (firstIndex !== undefined) {
      throw new Error(
        `explicit SUT input artifact ${index} duplicates case_artifact=${reference.case_artifact} role=${reference.role} first used at index ${firstIndex}`
      );
    }
    seenLogicalKeys.set(logicalKey, index);
    const digest = reference.digest;
    if (typeof digest !== "object" || digest === null) {
      throw new Error(`explicit SUT input artifact ${index}.digest must be an object`);
    }
    const extraDigestFields = Object.keys(digest).filter(
      (field) => field !== "alg" && field !== "value"
    );
    if (extraDigestFields.length > 0) {
      throw new Error(
        `explicit SUT input artifact ${index}.digest contains unsupported fields: ${extraDigestFields.join(", ")}`
      );
    }
    if (
      digest.alg !== "sha-256" ||
      typeof digest.value !== "string" ||
      !/^[0-9a-f]{64}$/.test(digest.value)
    ) {
      throw new Error(
        `explicit SUT input artifact ${index}.digest must be a lowercase sha-256 descriptor`
      );
    }
  }
}

export function createSutResultEntry(
  input: CreateSutResultEntryInput
): SutResultEntry {
  const suppliedArtifacts = input.artifacts;
  const suppliedProofArtifacts = input.proofArtifacts;
  const explicitInputMode = hasExplicitInputArtifacts(suppliedArtifacts);
  if (explicitInputMode) {
    const siblingFields = Object.keys(suppliedArtifacts).filter(
      (field) => field !== "input_artifacts"
    );
    if (siblingFields.length > 0 || suppliedProofArtifacts !== undefined) {
      throw new Error(
        "explicit SUT input artifacts cannot be combined with receipt, context, proof, or extension siblings"
      );
    }
    validateExplicitInputArtifacts(suppliedArtifacts);
  }
  const artifacts: SutResultArtifacts | undefined = explicitInputMode
    ? suppliedArtifacts
    : suppliedArtifacts || suppliedProofArtifacts
      ? ({
          ...(suppliedArtifacts ?? {}),
          ...(suppliedProofArtifacts
            ? { proof_artifacts: suppliedProofArtifacts }
            : {}),
        } as SutLegacyResultArtifacts)
      : undefined;
  const limitations = [...(input.limitations ?? [])];
  if (input.proofArtifacts && input.proofArtifacts.length > 0) {
    limitations.push(
      "JOSE proof artifact references are recorded only; production signature verification is outside this helper."
    );
  }

  return {
    case_id: input.caseId,
    ...(input.artifactMode ? { artifact_mode: input.artifactMode } : {}),
    status: input.status ?? "completed",
    outcome: input.outcome,
    should_execute: input.shouldExecute,
    reason_codes: input.reasonCodes,
    ...(input.checks && input.checks.length > 0 ? { checks: input.checks } : {}),
    ...(artifacts ? { artifacts } : {}),
    ...(input.generatedArtifacts
      ? { generated_artifacts: input.generatedArtifacts }
      : {}),
    ...(limitations.length > 0 ? { limitations } : {}),
  };
}
