import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { assessRequestBinding, parseRequestBindingJson, requestBindingObjectHash, requestBindingReference,
  RequestBindingError, REQUEST_BINDING_LIMITS, createSutResultEntry } from "../src/index.js";

const root = fileURLToPath(new URL("../../..", import.meta.url));
const vectors = JSON.parse(execFileSync("python3", ["reference/request-binding/parity_vectors.py"],
  { cwd: root, encoding: "utf8", maxBuffer: 32 * 1024 * 1024 }));
const bytes = (value: string) => Uint8Array.from(Buffer.from(value, "base64"));

describe("live Python / TypeScript request-binding parity", () => {
  test.each(vectors.assessments)("$name", (vector) => {
    const artifacts = new Map<string, Uint8Array>(Object.entries(vector.artifacts).map(([uri, value]) => [uri, bytes(value as string)]));
    const receipt = bytes(vector.receipt), before = Uint8Array.from(receipt);
    const actual = assessRequestBinding(receipt, artifacts, { requiredContract: vector.required, expectedAdmissionRequestRef: vector.pin });
    expect(actual).toEqual(vector.expected);
    expect(receipt).toEqual(before);
    expect(actual.checks.at(-1)).toEqual({ name: "execution.actual_input", status: "not_checked", pass: null, cause: "EXECUTION_OBSERVATION_NOT_SUPPLIED" });
  });
  test.each(vectors.parses)("strict JSON: $name", (vector) => {
    const input = bytes(vector.bytes);
    if (vector.expected.cause) {
      expect(() => parseRequestBindingJson(input)).toThrow(new RequestBindingError(vector.expected.cause));
    } else {
      expect(parseRequestBindingJson(input)).toEqual(vector.expected.value);
      expect(requestBindingObjectHash(input)).toBe(vector.expected.hash);
    }
  });
});

test("does not turn an invalid API requirement into an optional check", () => {
  expect(() => assessRequestBinding(new Uint8Array(), new Map(), { requiredContract: "" })).toThrow("SCHEMA_INVALID");
  expect(() => assessRequestBinding(new Uint8Array(), new Map(), null as never)).toThrow("SCHEMA_INVALID");
  expect(() => assessRequestBinding(new Uint8Array(), {} as never)).toThrow("SCHEMA_INVALID");
});
test("rejects substituted receipt evidence independently of the Python oracle", () => {
  const vector = vectors.assessments.find((v: { name: string }) => v.name === "attenuate");
  const artifacts = new Map<string, Uint8Array>(Object.entries(vector.artifacts).map(([uri, value]) => [uri, bytes(value as string)]));
  const receipt = JSON.parse(Buffer.from(bytes(vector.receipt)).toString("utf8"));
  receipt.evidence[0].digest.value = "0".repeat(64);
  const result = assessRequestBinding(new TextEncoder().encode(JSON.stringify(receipt)), artifacts,
    { expectedAdmissionRequestRef: vector.pin });
  expect(result.binding_requirement_met).toBe(false);
  expect(result.decision_allows_immediate_execution).toBe(false);
  expect(result.checks).toContainEqual({ name: "receipt.evidence_references", status: "checked", pass: false,
    cause: "RECEIPT_EVIDENCE_MISMATCH" });
  expect(result.checks).toContainEqual({ name: "evidence.authentication", status: "not_checked", pass: null,
    cause: "EVIDENCE_AUTHENTICATION_NOT_PERFORMED" });
});
test("bounds raw bytes", () => {
  const large = new Uint8Array(REQUEST_BINDING_LIMITS.maxBytes + 1);
  expect(() => parseRequestBindingJson(large)).toThrow("ARTIFACT_TOO_LARGE");
  const report = assessRequestBinding(large, new Map());
  expect(report.pass).toBe(false);
  expect(report.checks[0]?.cause).toBe("ARTIFACT_TOO_LARGE");
});
test.each([
  { name: "japanese", text: "あ", count: 350000 },
  { name: "accent", text: "é", count: 400000 },
  { name: "astral", text: "😀", count: 180000 },
])("compares $name digest annotations within the raw byte limit", ({ text, count }) => {
  const vector = vectors.assessments.find((v: { name: string }) => v.name === "attenuate");
  const artifacts = new Map<string, Uint8Array>(Object.entries(vector.artifacts).map(([uri, value]) => [uri, bytes(value as string)]));
  const admission = JSON.parse(Buffer.from(artifacts.get(vector.pin.uri)!).toString("utf8"));
  const receipt = JSON.parse(Buffer.from(bytes(vector.receipt)).toString("utf8"));
  const annotation = { text: text.repeat(count), values: [true, 1, null] };
  admission.evidence_refs[0].digest.annotation = annotation;
  receipt.evidence[0].digest.annotation = { ...annotation };
  const admissionBytes = new TextEncoder().encode(JSON.stringify(admission));
  const pin = requestBindingReference(admissionBytes);
  artifacts.set(pin.uri, admissionBytes);
  receipt.request_binding.admission_request_ref = pin;
  expect(admissionBytes.length).toBeLessThan(REQUEST_BINDING_LIMITS.maxBytes);
  const assess = () => {
    const raw = new TextEncoder().encode(JSON.stringify(receipt));
    expect(raw.length).toBeLessThan(REQUEST_BINDING_LIMITS.maxBytes);
    return assessRequestBinding(raw, artifacts, { expectedAdmissionRequestRef: pin });
  };
  expect(assess().binding_requirement_met).toBe(true);
  receipt.evidence[0].digest.annotation.text += "x";
  expect(assess().checks).toContainEqual({ name: "receipt.evidence_references", status: "checked", pass: false,
    cause: "RECEIPT_EVIDENCE_MISMATCH" });
});
test("SUT helper preserves a separately digest-bound preimage manifest", () => {
  const ref = requestBindingReference(new TextEncoder().encode("{}"));
  const entry = createSutResultEntry({ caseId: "test", outcome: "allow", shouldExecute: true, reasonCodes: ["POLICY_MATCH"], requestBindingArtifacts: ref });
  expect(entry.request_binding_artifacts).toEqual(ref);
});
