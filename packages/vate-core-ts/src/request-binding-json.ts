import { stableJsonBytes } from "./json.js";
import type { JsonValue } from "./types.js";

export const REQUEST_BINDING_LIMITS = Object.freeze({ maxBytes: 2 * 1024 * 1024, maxDepth: 64 });

export class RequestBindingError extends Error {
  constructor(readonly cause: string) {
    super(cause);
    this.name = "RequestBindingError";
  }
}

export function bindingNeed(condition: unknown, cause: string): asserts condition {
  if (!condition) throw new RequestBindingError(cause);
}

function domain(value: JsonValue, depth = 0): void {
  bindingNeed(depth <= REQUEST_BINDING_LIMITS.maxDepth, "JSON_DEPTH_EXCEEDED");
  if (typeof value === "string") {
    for (const character of value) {
      const point = character.codePointAt(0)!;
      bindingNeed(point < 0xd800 || point > 0xdfff, "INVALID_UNICODE");
    }
  } else if (typeof value === "number") {
    bindingNeed(Number.isSafeInteger(value), "UNSAFE_JSON_INTEGER");
  } else if (Array.isArray(value)) {
    for (const item of value) domain(item, depth + 1);
  } else if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      domain(key, depth + 1);
      domain(item, depth + 1);
    }
  }
}

// Retain token spelling and duplicate names until validation. JSON.parse alone
// loses duplicate members and the distinction between integer 1 and float 1.0.
class Parser {
  private offset = 0;
  private readonly number = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
  constructor(private readonly source: string) {}
  private invalid(): never { throw new RequestBindingError("INVALID_JSON"); }
  private whitespace(): void {
    while (/[ \n\r\t]/.test(this.source[this.offset] ?? "x")) this.offset++;
  }
  private consume(value: string): boolean {
    if (!this.source.startsWith(value, this.offset)) return false;
    this.offset += value.length;
    return true;
  }
  private string(): string {
    const start = this.offset;
    if (!this.consume('"')) return this.invalid();
    while (this.offset < this.source.length) {
      const character = this.source[this.offset++];
      if (character === "\\") this.offset++;
      else if (character === '"') {
        let value: string;
        try { value = JSON.parse(this.source.slice(start, this.offset)) as string; }
        catch { return this.invalid(); }
        domain(value);
        return value;
      }
    }
    return this.invalid();
  }
  private value(depth: number): JsonValue {
    // Bound parser recursion as well as the complete decoded domain.
    bindingNeed(depth <= REQUEST_BINDING_LIMITS.maxDepth, "JSON_DEPTH_EXCEEDED");
    this.whitespace();
    const character = this.source[this.offset];
    if (character === '"') return this.string();
    if (this.consume("{")) {
      const object: Record<string, JsonValue> = Object.create(null);
      const keys = new Set<string>();
      this.whitespace();
      if (this.consume("}")) return object;
      do {
        this.whitespace();
        const key = this.string();
        this.whitespace();
        if (!this.consume(":")) this.invalid();
        const item = this.value(depth + 1);
        bindingNeed(!keys.has(key), "DUPLICATE_JSON_KEY");
        keys.add(key);
        object[key] = item;
        this.whitespace();
        if (this.consume("}")) return object;
      } while (this.consume(","));
      return this.invalid();
    }
    if (this.consume("[")) {
      const array: JsonValue[] = [];
      this.whitespace();
      if (this.consume("]")) return array;
      do {
        array.push(this.value(depth + 1));
        this.whitespace();
        if (this.consume("]")) return array;
      } while (this.consume(","));
      return this.invalid();
    }
    if (this.consume("true")) return true;
    if (this.consume("false")) return false;
    if (this.consume("null")) return null;
    for (const token of ["NaN", "Infinity", "-Infinity"]) {
      if (this.consume(token)) throw new RequestBindingError("UNSUPPORTED_JSON_NUMBER");
    }
    this.number.lastIndex = this.offset;
    const match = this.number.exec(this.source);
    if (!match) return this.invalid();
    this.offset = this.number.lastIndex;
    bindingNeed(!/[.eE]/.test(match[0]), "UNSUPPORTED_JSON_NUMBER");
    const number = Number(match[0]);
    bindingNeed(Number.isSafeInteger(number), "UNSAFE_JSON_INTEGER");
    return number === 0 ? 0 : number; // Python's integer -0 is 0.
  }
  parse(): JsonValue {
    const result = this.value(0);
    this.whitespace();
    if (this.offset !== this.source.length) this.invalid();
    domain(result);
    return result;
  }
}

/** Strict raw-byte entry for the v1 binding contract; this is not JCS. */
export function parseRequestBindingJson(bytes: Uint8Array): JsonValue {
  bindingNeed(bytes instanceof Uint8Array, "SCHEMA_INVALID");
  bindingNeed(bytes.byteLength <= REQUEST_BINDING_LIMITS.maxBytes, "ARTIFACT_TOO_LARGE");
  let source: string;
  try {
    // Preserve a BOM so the parser rejects it, as Python's UTF-8 entry does.
    source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch { throw new RequestBindingError("INVALID_JSON"); }
  return new Parser(source).parse();
}

/** Internal canonicalizer: callers must supply values from the strict parser. */
export function bindingCanonicalBytes(value: JsonValue): Uint8Array {
  domain(value);
  const bytes = stableJsonBytes(value);
  bindingNeed(bytes.byteLength <= REQUEST_BINDING_LIMITS.maxBytes, "ARTIFACT_TOO_LARGE");
  return bytes;
}
