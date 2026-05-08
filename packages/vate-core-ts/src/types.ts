export interface DigestDescriptor {
  alg: "sha-256";
  value: string;
}

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue =
  | JsonPrimitive
  | JsonValue[]
  | { [key: string]: JsonValue };

export interface DigestBoundReference {
  uri: string;
  media_type: string;
  digest: DigestDescriptor;
}

export interface ArtifactReference extends DigestBoundReference {
  type: string;
}

export type AdmissionDecision = "allow" | "attenuate" | "deny";

export type SutCaseStatus = "completed" | "skipped" | "error";

export type ProofArtifactKind =
  | "jose_proof_package"
  | "jose_detached_payload"
  | "jose_trust_bundle";

export interface ProofArtifactReference extends DigestBoundReference {
  kind: ProofArtifactKind;
  case_artifact: string;
}

export interface SutResultArtifacts {
  admission_receipt?: DigestBoundReference;
  post_execution_receipt?: DigestBoundReference;
  verification_context?: unknown[];
  proof_artifacts?: ProofArtifactReference[];
  [key: string]: unknown;
}

export interface SutResultEntry {
  case_id: string;
  status: SutCaseStatus;
  outcome: AdmissionDecision;
  should_execute: boolean;
  reason_codes: string[];
  artifacts?: SutResultArtifacts;
  checks?: Array<{
    name: string;
    pass: boolean;
    details?: string;
  }>;
  limitations?: string[];
}
