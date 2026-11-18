import { Ajv2020 } from "ajv/dist/2020.js";
import { readFileSync } from "node:fs";
import { expect, it } from "vitest";

function read(path: string): any {
  return JSON.parse(readFileSync(new URL(`../../../${path}`, import.meta.url), "utf8"));
}

const vectors = read("scripts/schema-token-cases.json") as {
  valid: Record<string, string[]>;
  invalid_suffixes: string[];
  cases: Array<{ schema: string; pointer: string; kind: string }>;
};
const ajv = new Ajv2020({ strict: false });

it.each(vectors.cases)("rejects token suffixes at $schema$pointer", ({ schema, pointer, kind }) => {
  let node = read(schema);
  for (const key of pointer.slice(1).split("/")) node = node[key];
  const validate = ajv.compile(node);
  for (const value of vectors.valid[kind]!) {
    expect(validate(value)).toBe(true);
    for (const suffix of vectors.invalid_suffixes) {
      expect(validate(value + suffix), JSON.stringify({ value, suffix })).toBe(false);
    }
  }
});
