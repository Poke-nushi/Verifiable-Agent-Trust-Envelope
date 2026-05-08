import type { JsonValue } from "./types.js";

function assertJsonValue(value: unknown): asserts value is JsonValue {
  if (value === null) {
    return;
  }

  if (typeof value === "string" || typeof value === "boolean") {
    return;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("unsupported JSON number");
    }
    return;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      assertJsonValue(item);
    }
    return;
  }

  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("unsupported JSON object");
    }

    for (const item of Object.values(value)) {
      assertJsonValue(item);
    }
    return;
  }

  throw new TypeError("unsupported JSON value");
}

function sortJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    return value.map(sortJson);
  }

  if (value && typeof value === "object") {
    const input = value as Record<string, JsonValue>;
    const output: Record<string, JsonValue> = {};
    for (const key of Object.keys(input).sort()) {
      const item = input[key];
      if (item === undefined) {
        throw new TypeError("unsupported JSON value");
      }
      output[key] = sortJson(item);
    }
    return output;
  }

  return value;
}

export function stableJsonString(value: JsonValue): string {
  assertJsonValue(value);
  return JSON.stringify(sortJson(value));
}

export function stableJsonBytes(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(stableJsonString(value));
}
