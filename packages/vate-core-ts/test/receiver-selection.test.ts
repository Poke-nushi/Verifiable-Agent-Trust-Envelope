import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { assessRequestBinding, requestBindingReference } from "../src/index.js";

const directory = new URL("../../../reference/request-binding/receiver-selection/", import.meta.url);
const read = (path: string) => readFileSync(new URL(path, directory));
type Selection = { receiver_request: "A" | "B" | "A-earlier-expiry" | null; delivery: "A" | "B" };
const vectors: { cases: Record<string, Selection> } = JSON.parse(read("vectors.json").toString("utf8"));
const expected = JSON.parse(read("expected.json").toString("utf8"));

test.each(Object.entries(vectors.cases))("receiver-selected purchase request: %s", (id, selection) => {
  const delivered = (file: string) => read(`deliveries/${selection.delivery}/${file}.json`);
  const artifacts = new Map<string, Uint8Array>();
  for (const name of ["admission-request", "original", "effective"]) {
    const bytes = delivered(name);
    artifacts.set(requestBindingReference(bytes).uri, bytes);
  }
  const selected = selection.receiver_request;
  const assessment = assessRequestBinding(delivered("admission-receipt"), artifacts, {
    expectedAdmissionRequestRef: selected === null ? null : requestBindingReference(read(`receiver/${selected}.json`)),
  });
  const receiver = assessment.checks.find(check => check.name === "receiver.admission_request");
  expect(receiver).toBeDefined();
  expect({
    status: assessment.status,
    pass: assessment.pass,
    binding_requirement_met: assessment.binding_requirement_met,
    selection_cause: receiver?.cause ?? null,
  }).toEqual(expected.cases[id].request_binding);
});
