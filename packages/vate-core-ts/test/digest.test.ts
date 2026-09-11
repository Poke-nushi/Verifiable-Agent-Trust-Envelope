import { describe, expect, it } from "vitest";
import {
  digestDescriptorForJson,
  sha256Hex,
  stableJsonBytes,
  stableJsonString,
  type JsonValue,
} from "../src/index.js";

describe("digest helpers", () => {
  it("computes lowercase sha-256 hex for bytes", () => {
    expect(sha256Hex(new TextEncoder().encode("vate"))).toBe(
      "e62cdef847d6879987b208728946991b85a6ca97911678188686320f02f09f05"
    );
  });

  it("uses sorted-key compact JSON for the v0.3 fixture byte basis", () => {
    const bytes = stableJsonBytes({ b: 2, a: 1 });
    expect(new TextDecoder().decode(bytes)).toBe("{\"a\":1,\"b\":2}");
  });

  it("creates sha-256 digest descriptors for JSON", () => {
    const descriptor = digestDescriptorForJson({ b: 2, a: 1 });
    expect(descriptor.alg).toBe("sha-256");
    expect(descriptor.value).toMatch(/^[a-f0-9]{64}$/);
  });

  // Expected strings use Python json.dumps(sort_keys=True, separators=(",", ":"))
  // with its default ensure_ascii=True, not JavaScript's property enumeration.
  it.each([
    ['{"summary":"許可しました"}', '{"summary":"\\u8a31\\u53ef\\u3057\\u307e\\u3057\\u305f"}'],
    ['{"text":"é😀\\u007f\\n\\t\\u0000"}', '{"text":"\\u00e9\\ud83d\\ude00\\u007f\\n\\t\\u0000"}'],
    ['{"text":"\\ud800"}', '{"text":"\\ud800"}'],
    ['{"\\ud800\\udc00":1,"\\ue000":2}', '{"\\ue000":2,"\\ud800\\udc00":1}'],
    ['{"constraints":{"2":"b","10":"a"}}', '{"constraints":{"10":"a","2":"b"}}'],
    ['{"nested":[{"2":2,"10":10}]}', '{"nested":[{"10":10,"2":2}]}'],
    ['{"__proto__":{"value":1},"a":2}', '{"__proto__":{"value":1},"a":2}'],
    ['{"max":9007199254740991,"min":-9007199254740991,"zero":0}', '{"max":9007199254740991,"min":-9007199254740991,"zero":0}'],
  ])("matches the Python fixture bytes for %s", (source, expected) => {
    expect(stableJsonString(JSON.parse(source))).toBe(expected);
    expect(new TextDecoder().decode(stableJsonBytes(JSON.parse(source)))).toBe(expected);
  });

  it("matches the Python digest for a non-ASCII value", () => {
    expect(digestDescriptorForJson({ summary: "許可しました" }).value).toBe(
      "b43c77d26fc2622d6a23204b0c140a5e2503328491009e6f31770e4f7d4e756a"
    );
  });

  it("does not drop a JSON __proto__ member from the digest", () => {
    expect(digestDescriptorForJson(JSON.parse('{"__proto__":{"value":1},"a":2}')))
      .not.toEqual(digestDescriptorForJson({ a: 2 }));
  });

  class EmptyJoinArray extends Array<JsonValue> {
    override join(_separator?: string): string {
      return "";
    }
  }

  class PipeJoinArray extends Array<JsonValue> {
    override join(_separator?: string): string {
      return super.join("|");
    }
  }

  it.each([EmptyJoinArray, PipeJoinArray])(
    "serializes array subclass elements without invoking its join: %s",
    (ArrayClass) => {
      const input: JsonValue = new ArrayClass(1, 2);
      expect(stableJsonString(input)).toBe("[1,2]");
      expect(stableJsonString({ constraints: input })).toBe('{"constraints":[1,2]}');
      expect(digestDescriptorForJson(input).value).toBe(
        "49a64717d5d4cb19952e6eac2946415cf6879adacf9908e7d872332d32c6e684"
      );
      expect(digestDescriptorForJson(input)).not.toEqual(digestDescriptorForJson([]));
    }
  );

  it("does not invoke a caller-supplied array map", () => {
    const input = [1, 2];
    Object.defineProperty(input, "map", {
      value: () => { throw new Error("input map must not run"); },
    });
    expect(stableJsonString(input)).toBe("[1,2]");
  });

  it("rejects sparse arrays instead of omitting their missing elements", () => {
    expect(() => stableJsonBytes(new Array<JsonValue>(2))).toThrow("unsupported JSON value");
  });

  it.each([3, Number.NaN, 1.5])(
    "does not serialize a tail appended after validation: %s",
    (tail) => {
      const makeInput = (): JsonValue[] => {
        let reads = 0;
        const input: JsonValue[] = [1, 2];
        Object.defineProperty(input, "0", {
          get() {
            if (++reads === 2) input.push(tail);
            return 1;
          },
        });
        return input;
      };
      expect(stableJsonString(makeInput())).toBe("[1,2]");
      expect(stableJsonString({ values: makeInput() })).toBe('{"values":[1,2]}');
      expect(digestDescriptorForJson(makeInput()).value).toBe(
        "49a64717d5d4cb19952e6eac2946415cf6879adacf9908e7d872332d32c6e684"
      );
    }
  );

  it.each([1.5, 1e-7, -0, Number.MAX_SAFE_INTEGER + 1, 1e21, Infinity, -Infinity])(
    "rejects unsupported fixture JSON number %s, including nested values",
    (value) => {
      expect(() => stableJsonBytes(value)).toThrow("unsupported JSON number");
      expect(() => digestDescriptorForJson({ nested: [value] })).toThrow("unsupported JSON number");
    }
  );

  it("rejects values that JSON.stringify would silently rewrite", () => {
    expect(() =>
      stableJsonBytes({ omitted: undefined } as never)
    ).toThrow("unsupported JSON value");
    expect(() => stableJsonBytes(Number.NaN as never)).toThrow(
      "unsupported JSON number"
    );
    expect(() => stableJsonBytes([undefined] as never)).toThrow(
      "unsupported JSON value"
    );
  });
});
