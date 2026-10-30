import type { JsonValue } from "./types.js";

/** Local helper selector; not an A2A extension or a VATE corpus basis change. */
export const JCS_DIGEST_BASIS = "rfc8785-jcs";

/** Resource limits for this reference helper, not additional JCS byte rules. */
export const JCS_INPUT_LIMITS = Object.freeze({ maxBytes: 1_048_576, maxDepth: 64 });

export type JcsInputErrorCode =
  | "invalid_bytes"
  | "input_too_large"
  | "invalid_utf8"
  | "invalid_json"
  | "duplicate_key"
  | "invalid_unicode"
  | "non_finite_number"
  | "nesting_too_deep";

export class JcsInputError extends Error {
  constructor(readonly code: JcsInputErrorCode) {
    // Do not put source strings or member names in diagnostics.
    super(`JCS input rejected: ${code}`);
    this.name = "JcsInputError";
  }
}

function assertUnicode(value: string): void {
  for (let i = 0; i < value.length; i += 1) {
    const unit = value.charCodeAt(i);
    let point = unit;
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new JcsInputError("invalid_unicode");
      }
      point = 0x10000 + (unit - 0xd800) * 0x400 + next - 0xdc00;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new JcsInputError("invalid_unicode");
    }
    // I-JSON (RFC 7493 section 2.1) excludes noncharacters on every plane.
    if ((point >= 0xfdd0 && point <= 0xfdef) || (point & 0xffff) >= 0xfffe) {
      throw new JcsInputError("invalid_unicode");
    }
  }
}

/** Parse original JSON, retaining the opportunity to reject duplicate names. */
class JcsParser {
  private offset = 0;
  private readonly numberToken = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

  constructor(private readonly source: string) {}

  parse(): JsonValue {
    const value = this.value(0);
    this.whitespace();
    if (this.offset !== this.source.length) this.invalid();
    return value;
  }

  private invalid(): never {
    throw new JcsInputError("invalid_json");
  }

  private whitespace(): void {
    while (this.offset < this.source.length) {
      const character = this.source[this.offset];
      if (character !== " " && character !== "\n" && character !== "\r" && character !== "\t") break;
      this.offset += 1;
    }
  }

  private consume(character: string): boolean {
    if (this.source[this.offset] !== character) return false;
    this.offset += 1;
    return true;
  }

  private string(): string {
    const start = this.offset;
    if (!this.consume('"')) this.invalid();
    while (this.offset < this.source.length) {
      const character = this.source[this.offset++];
      if (character === "\\") {
        this.offset += 1;
      } else if (character === '"') {
        let value: string;
        try {
          value = JSON.parse(this.source.slice(start, this.offset)) as string;
        } catch {
          return this.invalid();
        }
        assertUnicode(value);
        return value;
      }
    }
    return this.invalid();
  }

  private value(depth: number): JsonValue {
    this.whitespace();
    const character = this.source[this.offset];
    if (character === '"') return this.string();
    if (character === "{" || character === "[") {
      if (depth >= JCS_INPUT_LIMITS.maxDepth) {
        throw new JcsInputError("nesting_too_deep");
      }
      this.offset += 1;
      this.whitespace();
      if (character === "{") {
        // __proto__ is an ordinary JSON member, never a prototype assignment.
        const object: { [key: string]: JsonValue } = Object.create(null);
        const keys = new Set<string>();
        if (this.consume("}")) return object;
        do {
          this.whitespace();
          const key = this.string();
          if (keys.has(key)) throw new JcsInputError("duplicate_key");
          keys.add(key);
          this.whitespace();
          if (!this.consume(":")) this.invalid();
          object[key] = this.value(depth + 1);
          this.whitespace();
          if (this.consume("}")) return object;
        } while (this.consume(","));
        return this.invalid();
      }
      const array: JsonValue[] = [];
      if (this.consume("]")) return array;
      do {
        array.push(this.value(depth + 1));
        this.whitespace();
        if (this.consume("]")) return array;
      } while (this.consume(","));
      return this.invalid();
    }
    for (const [token, literal] of [["true", true], ["false", false], ["null", null]] as const) {
      if (this.source.startsWith(token, this.offset)) {
        this.offset += token.length;
        return literal;
      }
    }
    this.numberToken.lastIndex = this.offset;
    const match = this.numberToken.exec(this.source);
    if (!match) return this.invalid();
    this.offset = this.numberToken.lastIndex;
    // ECMAScript binary64 conversion, including rounding and negative zero.
    const value = Number(match[0]);
    if (!Number.isFinite(value)) throw new JcsInputError("non_finite_number");
    return value;
  }
}

function serialize(value: JsonValue): string {
  if (Array.isArray(value)) return `[${value.map(serialize).join(",")}]`;
  if (value !== null && typeof value === "object") {
    // Default string sorting is UTF-16 code-unit order, as required by JCS.
    // Emit members directly, since rebuilding an object reorders numeric keys.
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${serialize(value[key]!)}`
    ).join(",")}}`;
  }
  return JSON.stringify(value);
}

/**
 * RFC 8785 bytes from original UTF-8 JSON, within JCS_INPUT_LIMITS.
 * Rejects duplicate names, invalid Unicode/UTF-8, I-JSON noncharacters and
 * non-finite numbers. Preserves strings without Unicode normalization.
 * Takes bytes rather than parsed objects so duplicate names cannot be lost.
 */
export function canonicalizeJcsJson(source: Uint8Array): Uint8Array {
  if (!(source instanceof Uint8Array)) throw new JcsInputError("invalid_bytes");
  if (source.byteLength > JCS_INPUT_LIMITS.maxBytes) throw new JcsInputError("input_too_large");
  let text: string;
  try {
    // Keep a BOM visible: this input contract rejects it as invalid JSON.
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(source);
  } catch {
    throw new JcsInputError("invalid_utf8");
  }
  const value = new JcsParser(text).parse();
  return new TextEncoder().encode(serialize(value));
}
