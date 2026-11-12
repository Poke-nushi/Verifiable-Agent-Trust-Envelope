import { digestDescriptorForBytes } from "./digest.js";
import { bindingCanonicalBytes, bindingNeed as need, parseRequestBindingJson, RequestBindingError, REQUEST_BINDING_LIMITS } from "./request-binding-json.js";
import type { DigestDescriptor, JsonValue } from "./types.js";

export { parseRequestBindingJson, RequestBindingError, REQUEST_BINDING_LIMITS } from "./request-binding-json.js";
export const REQUEST_BINDING_CONTRACT = "vate-request-binding-v1";
export const REQUEST_BINDING_PREIMAGE_PROFILE = "vate-purchase-cap-request-v1";
export const REQUEST_BINDING_TRANSFORMATION_PROFILE = "vate-max-amount-only-v1";
export const REQUEST_BINDING_CANONICALIZATION = "vate-v0.3-fixture-json";

export interface RequestBindingReference {
  uri: string;
  media_type: "application/json";
  digest: DigestDescriptor;
}
export interface RequestBindingOptions {
  requiredContract?: string;
  expectedAdmissionRequestRef?: RequestBindingReference | null;
}
export interface RequestBindingCheck {
  name: string;
  status: "checked" | "not_checked";
  pass: boolean | null;
  cause?: string;
}
export interface RequestBindingAssessment {
  contract: "vate-request-binding-assessment-v1";
  required_contract: string;
  receipt_digest: DigestDescriptor;
  status: "checked" | "not_checked";
  pass: boolean | null;
  binding_requirement_met: boolean;
  decision_allows_immediate_execution: boolean;
  checks: RequestBindingCheck[];
}

// Values below have crossed the strict JSON parser. Every accessed structure
// is validated before use; public entry points accept bytes, not JS objects.
type ObjectValue = { [key: string]: any };
const isObject = (value: unknown): value is ObjectValue => value !== null && typeof value === "object" && !Array.isArray(value);
const nonempty = (value: unknown): value is string => typeof value === "string" && value.length > 0;
const hex = (value: unknown): value is string => typeof value === "string" && /^[0-9a-f]{64}(?![\s\S])/.test(value);
const same = (a: unknown, b: unknown): boolean => {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((item, i) => same(item, b[i]));
  if (isObject(a) && isObject(b)) {
    const keys = Object.keys(a);
    return keys.length === Object.keys(b).length && keys.every(key => Object.hasOwn(b, key) && same(a[key], b[key]));
  }
  return false;
};
function exact(value: unknown, required: string[], optional: string[] = []): asserts value is ObjectValue {
  need(isObject(value) && required.every(key => Object.hasOwn(value, key))
    && Object.keys(value).every(key => required.includes(key) || optional.includes(key)), "SCHEMA_INVALID");
}
function text(value: unknown): asserts value is string { need(nonempty(value), "SCHEMA_INVALID"); }
function validateReference(value: unknown): asserts value is RequestBindingReference {
  exact(value, ["uri", "media_type", "digest"]);
  exact(value.digest, ["alg", "value"]);
  need(value.digest.alg === "sha-256" && hex(value.digest.value), "SCHEMA_INVALID");
  need(value.media_type === "application/json" && value.uri === "urn:sha256:" + value.digest.value, "SCHEMA_INVALID");
}

/** Reference exact bytes, independently of their JSON whitespace or key order. */
export function requestBindingReference(bytes: Uint8Array): RequestBindingReference {
  need(bytes instanceof Uint8Array, "SCHEMA_INVALID");
  const digest = digestDescriptorForBytes(bytes);
  return { uri: "urn:sha256:" + digest.value, media_type: "application/json", digest };
}
/** Hash strict original JSON under the existing Python fixture basis. */
export function requestBindingObjectHash(bytes: Uint8Array): string {
  return objectHash(parseRequestBindingJson(bytes));
}
function objectHash(value: JsonValue): string {
  return "sha-256:" + digestDescriptorForBytes(bindingCanonicalBytes(value)).value;
}
class Unavailable extends RequestBindingError {}
function resolve(ref: RequestBindingReference, artifacts: ReadonlyMap<string, Uint8Array>): ObjectValue {
  validateReference(ref);
  if (!artifacts.has(ref.uri)) throw new Unavailable("ARTIFACT_NOT_SUPPLIED");
  const supplied = artifacts.get(ref.uri);
  need(supplied instanceof Uint8Array, "SCHEMA_INVALID");
  need(supplied.byteLength <= REQUEST_BINDING_LIMITS.maxBytes, "ARTIFACT_TOO_LARGE");
  const raw = Uint8Array.from(supplied);
  need(same(digestDescriptorForBytes(raw), ref.digest), "DIGEST_MISMATCH");
  const result = parseRequestBindingJson(raw);
  need(isObject(result), "SCHEMA_INVALID");
  return result;
}
function amount(value: unknown): bigint {
  need(typeof value === "string" && /^(?:0|[1-9][0-9]{0,17})(?:\.[0-9]{1,8})?(?![\s\S])/.test(value), "INVALID_DECIMAL_AMOUNT");
  const [integer, fraction = ""] = value.split(".");
  return BigInt(integer!) * 100000000n + BigInt(fraction.padEnd(8, "0"));
}
function money(value: unknown): asserts value is ObjectValue {
  exact(value, ["currency", "value"]);
  need(typeof value.currency === "string" && /^[A-Z]{3}(?![\s\S])/.test(value.currency), "SCHEMA_INVALID");
  amount(value.value);
}
function constraints(value: unknown): asserts value is ObjectValue {
  exact(value, ["max_amount", "tool_allowlist"]);
  money(value.max_amount);
  const allowed = value.tool_allowlist;
  need(Array.isArray(allowed) && allowed.length > 0 && allowed.length <= 32 && allowed.every(nonempty), "SCHEMA_INVALID");
  need(new Set(allowed).size === allowed.length, "SCHEMA_INVALID");
}
function validateOperation(value: unknown): asserts value is ObjectValue {
  exact(value, ["preimage_profile", "operation_id", "action", "target", "payload", "constraints"]);
  need(value.preimage_profile === REQUEST_BINDING_PREIMAGE_PROFILE && value.action === "commerce.purchase", "UNSUPPORTED_OPERATION_PROFILE");
  text(value.operation_id);
  exact(value.target, ["resource", "audience"]);
  Object.values(value.target).forEach(text);
  exact(value.payload, ["tool", "order_id", "amount"]);
  text(value.payload.tool);
  text(value.payload.order_id);
  money(value.payload.amount);
  constraints(value.constraints);
}
function payloadWithin(operation: ObjectValue): boolean {
  const payload = operation.payload, cap = operation.constraints.max_amount;
  return payload.amount.currency === cap.currency && amount(payload.amount.value) <= amount(cap.value)
    && operation.constraints.tool_allowlist.includes(payload.tool);
}

// Match the core's supported RFC3339 subset, including calendar validity and
// all six fractional digits. Millisecond-only Date comparisons lose bindings.
function timestamp(value: unknown): bigint | null {
  if (typeof value !== "string") return null;
  const match = /^(\d{4})-(\d{2})-(\d{2})[Tt]([01]\d|2[0-3]):([0-5]\d):([0-5]\d)(?:\.(\d{1,6}))?([Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)(?![\s\S])/.exec(value);
  if (!match) return null;
  const year = Number(match[1]), month = Number(match[2]), day = Number(match[3]);
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > 31) return null;
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(Number(match[4]), Number(match[5]), Number(match[6]), 0);
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return null;
  const zone = match[8]!;
  const offset = zone.length === 1 ? 0 : (zone[0] === "-" ? -1 : 1) * (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(4)));
  return BigInt(date.getTime()) * 1000n + BigInt((match[7] ?? "").padEnd(6, "0")) - BigInt(offset) * 60000000n;
}

// The parity vectors cover every type and hint in evidence-vocabulary.v0.3.json.
const REQUEST_BINDING_EVIDENCE_HINTS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  admission_receipt: [], admission_request: [], agent_card: [], attenuation_candidate: [],
  delegated_payment_token: ["stripe_spt"], did_document: [], http_message_signature: [], local_policy: [], mission_permit: [],
  oap_decision: ["oap_aport"], oauth_access_token: ["mcp-oauth"], oauth_transaction_token: ["mcp-oauth"],
  oid4vp_presentation: [], openid_subject: ["openid-connect"], payment_authority: ["x402"],
  payment_mandate: ["ap2", "ap2_human_not_present"], payment_required_state: ["x402"], policy_snapshot: [],
  post_execution_receipt: [], runtime_attestation: ["spiffe"], runtime_disclosure: [], signed_agent_card: [],
  status_bundle: [], ucp_checkout_session: ["ucp"], vc_status: [], verifiable_credential: ["oap_aport"], web_bot_auth_signature: [],
});
function validEvidence(ref: unknown): boolean {
  if (!isObject(ref) || typeof ref.type !== "string" || !Object.hasOwn(REQUEST_BINDING_EVIDENCE_HINTS, ref.type)) return false;
  if (!nonempty(ref.uri) || !nonempty(ref.media_type) || !isObject(ref.digest)
    || ref.digest.alg !== "sha-256" || !hex(ref.digest.value)) return false;
  return !Object.hasOwn(ref, "protocol_hint") || (typeof ref.protocol_hint === "string" && REQUEST_BINDING_EVIDENCE_HINTS[ref.type]!.includes(ref.protocol_hint));
}
function validateAdmission(request: ObjectValue, original: ObjectValue): void {
  exact(request, ["version", "profile", "request_id", "transaction_id", "issued_at", "expires_at", "action", "target", "actor", "principal", "runtime", "audience", "input_hash", "constraints", "evidence_refs"]);
  need(request.version === "vate-0.3" && request.profile === "VATE-AL2-Verifier-Admission-v0.3", "SCHEMA_INVALID");
  for (const key of ["request_id", "transaction_id", "actor", "principal", "runtime", "audience"]) text(request[key]);
  const issued = timestamp(request.issued_at), expires = timestamp(request.expires_at);
  need(issued !== null && expires !== null && issued <= expires, "INVALID_REQUEST_WINDOW");
  need(Array.isArray(request.evidence_refs) && request.evidence_refs.length > 0 && request.evidence_refs.every(validEvidence), "SCHEMA_INVALID");
  const evidenceKeys = request.evidence_refs.map((ref: ObjectValue) => JSON.stringify([ref.type, ref.uri]));
  need(new Set(evidenceKeys).size === evidenceKeys.length, "DUPLICATE_EVIDENCE_REFERENCE");
  need(request.input_hash === objectHash(original), "INPUT_HASH_MISMATCH");
  need(request.transaction_id === original.operation_id && request.action === original.action && same(request.target, original.target)
    && request.audience === original.target.audience && same(request.constraints, original.constraints), "ADMISSION_REQUEST_MISMATCH");
}
function receiptEvidenceReferences(receipt: ObjectValue, request: ObjectValue): void {
  const expected = new Map<string, ObjectValue>(request.evidence_refs.map((ref: ObjectValue) => [JSON.stringify([ref.type, ref.uri]), ref]));
  need(Array.isArray(receipt.evidence) && receipt.evidence.length === expected.size, "RECEIPT_EVIDENCE_MISMATCH");
  const seen = new Set<string>();
  const projection = (value: ObjectValue): ObjectValue => Object.fromEntries(
    ["type", "uri", "digest", "protocol_hint"].filter(key => Object.hasOwn(value, key)).map(key => [key, value[key]]));
  for (const item of receipt.evidence) {
    need(isObject(item) && typeof item.type === "string" && typeof item.uri === "string", "RECEIPT_EVIDENCE_MISMATCH");
    const key = JSON.stringify([item.type, item.uri]);
    need(expected.has(key) && !seen.has(key), "RECEIPT_EVIDENCE_MISMATCH");
    seen.add(key);
    const ref = expected.get(key)!;
    need(same(projection(item), projection(ref)), "RECEIPT_EVIDENCE_MISMATCH");
    need(!Object.hasOwn(item, "media_type") || item.media_type === ref.media_type, "RECEIPT_EVIDENCE_MISMATCH");
  }
}
function receiptContext(receipt: ObjectValue, request: ObjectValue): string {
  need(receipt.version === "vate-0.3" && receipt.profile === "VATE-AL2-Verifier-Admission-v0.3" && receipt.receipt_type === "admission", "SCHEMA_INVALID");
  text(receipt.receipt_id);
  need(isObject(receipt.request), "SCHEMA_INVALID");
  for (const key of ["request_id", "transaction_id", "action", "input_hash", "constraints"]) need(same(receipt.request[key], request[key]), "RECEIPT_REQUEST_MISMATCH");
  need(isObject(receipt.subject), "SCHEMA_INVALID");
  for (const key of ["principal", "actor", "runtime"]) need(same(receipt.subject[key], request[key]), "RECEIPT_SUBJECT_MISMATCH");
  const decision = receipt.decision;
  need(isObject(decision) && ["allow", "attenuate", "deny"].includes(decision.outcome), "SCHEMA_INVALID");
  need(Array.isArray(decision.reason_codes) && decision.reason_codes.length > 0 && decision.reason_codes.every(nonempty), "SCHEMA_INVALID");
  const issued = timestamp(receipt.issued_at), expires = timestamp(receipt.expires_at);
  need(issued !== null && expires !== null && issued <= expires, "INVALID_RECEIPT_WINDOW");
  if (decision.outcome !== "deny") need(timestamp(request.issued_at)! <= issued && expires <= timestamp(request.expires_at)!, "RECEIPT_WINDOW_EXCEEDS_REQUEST");
  return decision.outcome;
}
function reconstruct(original: ObjectValue, attenuation: unknown, codes: string[]): ObjectValue {
  exact(attenuation, ["mode", "original_request_hash", "effective_request_hash", "changes", "effective_constraints", "require_new_permit"]);
  need(typeof attenuation.require_new_permit === "boolean", "SCHEMA_INVALID");
  need(["narrow", "require_new_permit"].includes(attenuation.mode), "UNSUPPORTED_TRANSFORMATION");
  need(attenuation.mode !== "require_new_permit" || attenuation.require_new_permit, "SCHEMA_INVALID");
  need(Array.isArray(attenuation.changes) && attenuation.changes.length === 1, "UNSUPPORTED_TRANSFORMATION");
  const change = attenuation.changes[0];
  exact(change, ["op", "path", "from", "to", "reason_code"]);
  need(change.op === "replace" && change.path === "/constraints/max_amount/value", "UNSUPPORTED_TRANSFORMATION");
  need(change.reason_code === "LOCAL_POLICY_MAX_AMOUNT_NARROWED" && codes.includes(change.reason_code), "ATTENUATION_REASON_MISMATCH");
  const old = original.constraints.max_amount.value;
  need(typeof change.from === "string" && change.from === old, "ATTENUATION_FROM_MISMATCH");
  need(amount(change.to) < amount(old), "CONSTRAINT_NOT_NARROWED");
  return { ...original, constraints: { ...original.constraints, max_amount: { ...original.constraints.max_amount, value: change.to } } };
}

/** Receiver-side content checks. No fetch, signature verification or dispatch. */
export function assessRequestBinding(receiptBytes: Uint8Array, artifacts: ReadonlyMap<string, Uint8Array>, options: RequestBindingOptions = {}): RequestBindingAssessment {
  need(isObject(options), "SCHEMA_INVALID");
  const required = options.requiredContract === undefined ? REQUEST_BINDING_CONTRACT : options.requiredContract;
  text(required);
  need(receiptBytes instanceof Uint8Array && artifacts instanceof Map, "SCHEMA_INVALID");
  const raw = receiptBytes.byteLength > REQUEST_BINDING_LIMITS.maxBytes ? receiptBytes : Uint8Array.from(receiptBytes);
  const report: RequestBindingAssessment = { contract: "vate-request-binding-assessment-v1", required_contract: required,
    receipt_digest: digestDescriptorForBytes(raw), status: "not_checked", pass: null, binding_requirement_met: false,
    decision_allows_immediate_execution: false, checks: [] };
  let check = "receipt.json";
  const passed = () => report.checks.push({ name: check, status: "checked", pass: true });
  try {
    const receipt: unknown = parseRequestBindingJson(raw);
    need(isObject(receipt), "SCHEMA_INVALID");
    passed();
    check = "binding.contract";
    if (!Object.hasOwn(receipt, "request_binding")) throw new Unavailable("BINDING_NOT_DECLARED");
    const binding = receipt.request_binding;
    exact(binding, ["contract", "preimage_profile", "canonicalization", "transformation_profile", "admission_request_ref", "original_ref"], ["effective_ref"]);
    if (required !== REQUEST_BINDING_CONTRACT || binding.contract !== REQUEST_BINDING_CONTRACT
      || binding.preimage_profile !== REQUEST_BINDING_PREIMAGE_PROFILE || binding.canonicalization !== REQUEST_BINDING_CANONICALIZATION
      || binding.transformation_profile !== REQUEST_BINDING_TRANSFORMATION_PROFILE) throw new Unavailable("UNSUPPORTED_BINDING_PROFILE");
    for (const key of ["admission_request_ref", "original_ref", "effective_ref"]) if (Object.hasOwn(binding, key)) validateReference(binding[key]);
    passed();
    check = "receiver.admission_request";
    const expected = options.expectedAdmissionRequestRef;
    if (expected == null) throw new Unavailable("EXPECTED_ADMISSION_REQUEST_NOT_SUPPLIED");
    validateReference(expected);
    need(same(binding.admission_request_ref, expected), "ADMISSION_REFERENCE_MISMATCH");
    passed();
    check = "original.artifact";
    const original = resolve(binding.original_ref, artifacts);
    passed();
    check = "admission.artifact";
    const request = resolve(binding.admission_request_ref, artifacts);
    passed();
    check = "original.profile";
    validateOperation(original);
    passed();
    check = "original.admission_binding";
    validateAdmission(request, original);
    passed();
    check = "receipt.context";
    const decision = receiptContext(receipt, request);
    passed();
    check = "receipt.evidence_references";
    receiptEvidenceReferences(receipt, request);
    passed();
    check = "effective.artifact";
    if (decision === "deny") {
      need(!Object.hasOwn(binding, "effective_ref") && !Object.hasOwn(receipt, "attenuation") && !Object.hasOwn(receipt.request, "action_binding"), "DENIED_EFFECTIVE_REQUEST");
      passed();
    } else {
      if (!Object.hasOwn(binding, "effective_ref")) throw new Unavailable("EFFECTIVE_REFERENCE_NOT_SUPPLIED");
      const effective = resolve(binding.effective_ref, artifacts);
      validateOperation(effective);
      passed();
      check = "attenuation.reconstruction";
      if (decision === "allow") {
        need(!Object.hasOwn(receipt, "attenuation"), "UNEXPECTED_ATTENUATION");
        need(same(effective, original), "ALLOW_REQUEST_CHANGED");
      } else {
        need(same(effective, reconstruct(original, receipt.attenuation, receipt.decision.reason_codes)), "EFFECTIVE_RECONSTRUCTION_MISMATCH");
        need(receipt.attenuation.original_request_hash === objectHash(original), "ORIGINAL_HASH_MISMATCH");
        need(receipt.attenuation.effective_request_hash === objectHash(effective), "EFFECTIVE_HASH_MISMATCH");
        need(same(receipt.attenuation.effective_constraints, effective.constraints), "EFFECTIVE_CONSTRAINTS_MISMATCH");
      }
      passed();
      check = "effective.action_binding";
      need(same(receipt.request.action_binding, { type: "profile_defined_digest", preimage_profile: REQUEST_BINDING_PREIMAGE_PROFILE,
        canonicalization: REQUEST_BINDING_CANONICALIZATION, digest: digestDescriptorForBytes(bindingCanonicalBytes(effective)) }), "ACTION_BINDING_MISMATCH");
      passed();
      check = "effective.payload_constraints";
      need(payloadWithin(original) && payloadWithin(effective), "PAYLOAD_EXCEEDS_CONSTRAINTS");
      passed();
    }
    report.status = "checked";
    report.pass = report.binding_requirement_met = true;
    report.decision_allows_immediate_execution = decision === "allow" || decision === "attenuate" && !receipt.attenuation.require_new_permit;
  } catch (error) {
    if (!(error instanceof RequestBindingError)) throw error;
    const unavailable = error instanceof Unavailable;
    report.status = unavailable ? "not_checked" : "checked";
    report.pass = unavailable ? null : false;
    report.checks.push({ name: check, status: report.status, pass: report.pass, cause: error.cause });
  }
  report.checks.push({ name: "evidence.authentication", status: "not_checked", pass: null, cause: "EVIDENCE_AUTHENTICATION_NOT_PERFORMED" });
  report.checks.push({ name: "execution.actual_input", status: "not_checked", pass: null, cause: "EXECUTION_OBSERVATION_NOT_SUPPLIED" });
  return report;
}
