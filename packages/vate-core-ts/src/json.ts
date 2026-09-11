import type { JsonValue } from "./types.js";

function assertJsonValue(value: unknown): asserts value is JsonValue {
  if (value === null) {
    return;
  }

  if (typeof value === "string" || typeof value === "boolean") {
    return;
  }

  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new TypeError(
        "unsupported JSON number: fixture helper requires a safe integer, excluding negative zero"
      );
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

function compareCodePoints(left: string, right: string): number {
  // Python sorts Unicode code points; JavaScript's default sort uses UTF-16 units.
  const a = Array.from(left, (character) => character.codePointAt(0)!);
  const b = Array.from(right, (character) => character.codePointAt(0)!);
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
    const difference = a[i]! - b[i]!;
    if (difference !== 0) {
      return difference;
    }
  }
  return a.length - b.length;
}

function quoteString(value: string): string {
  // Match Python json.dumps's default ensure_ascii=True, including DEL and
  // surrogate pairs. Existing JSON escapes are already ASCII and stay intact.
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (character) =>
    `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`
  );
}

function serializeJson(value: JsonValue): string {
  if (typeof value === "string") {
    return quoteString(value);
  }

  if (Array.isArray(value)) {
    // Keep caller-defined map/species/join behavior out of the digest bytes.
    const items: string[] = [];
    const length = value.length;
    for (let index = 0; index < length; index += 1) {
      const item = value[index];
      if (item === undefined) {
        throw new TypeError("unsupported JSON value");
      }
      items.push(serializeJson(item));
    }
    return `[${items.join(",")}]`;
  }

  if (value && typeof value === "object") {
    const input = value as Record<string, JsonValue>;
    const members = Object.keys(input).sort(compareCodePoints).map((key) => {
      const item = input[key];
      if (item === undefined) {
        throw new TypeError("unsupported JSON value");
      }
      return `${quoteString(key)}:${serializeJson(item)}`;
    });
    // Emit members directly: rebuilding an object reorders integer-like keys
    // and assignment to __proto__ can drop a member from the digest entirely.
    return `{${members.join(",")}}`;
  }

  return JSON.stringify(value);
}

/**
 * Python fixture JSON bytes for values whose numbers are known to be Python
 * integers in JavaScript's safe range. This is not JCS. In particular, parsed
 * JavaScript values cannot retain the Python int/float distinction (1 vs 1.0).
 * See docs/conformance/digest-basis.md for the supported input contract.
 */
export function stableJsonString(value: JsonValue): string {
  assertJsonValue(value);
  return serializeJson(value);
}

/**
 * UTF-8 bytes under stableJsonString's limited Python fixture input contract.
 * Numbers must be known Python integers in JavaScript's safe range; fractional
 * numbers, unsafe integers, and negative zero throw TypeError. Parsed 1.0/1e0
 * cannot be distinguished from 1. See docs/conformance/digest-basis.md.
 */
export function stableJsonBytes(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(stableJsonString(value));
}
