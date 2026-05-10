import type { AdmissionDecision, ArtifactReference } from "@vate/reference-core";

export interface BuildAdmissionIssuedMetadataInput {
  transactionId: string;
  decision: AdmissionDecision;
  issuer: string;
  issuedAt: string;
  expiresAt?: string;
  admissionReceipt: ArtifactReference;
  policySnapshot?: ArtifactReference;
}

export function buildAdmissionIssuedMetadata(
  input: BuildAdmissionIssuedMetadataInput
) {
  return {
    profile: "VATE-AL2-Verifier-Admission-v0.3" as const,
    phase: "admission_issued" as const,
    transaction_id: input.transactionId,
    assurance_level: "AL2" as const,
    decision: input.decision,
    admission_receipt: input.admissionReceipt,
    ...(input.policySnapshot ? { policy_snapshot: input.policySnapshot } : {}),
    issuer: input.issuer,
    issued_at: input.issuedAt,
    ...(input.expiresAt ? { expires_at: input.expiresAt } : {}),
  };
}
