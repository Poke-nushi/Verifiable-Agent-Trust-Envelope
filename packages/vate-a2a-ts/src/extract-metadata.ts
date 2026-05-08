import { Ajv2020, type ErrorObject } from "ajv/dist/2020.js";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { VATE_A2A_EXTENSION_URI, type A2aLikeObject } from "./types.js";

const schemaPath = resolve(process.cwd(), "schemas/a2a-vate-metadata.schema.json");
const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: false });
const validate = ajv.compile(schema);

export function extractVateMetadata(
  value: A2aLikeObject,
  extensionUri = VATE_A2A_EXTENSION_URI
): unknown | undefined {
  return value.metadata?.[extensionUri];
}

export function validateVateA2aMetadata(value: unknown): string[] {
  if (validate(value)) {
    return [];
  }
  return (validate.errors ?? []).map((error: ErrorObject) => {
    const path = error.instancePath || "/";
    return `${path} ${error.message ?? "failed validation"}`;
  });
}
