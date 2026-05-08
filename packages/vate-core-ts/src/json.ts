function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortJson);
  }

  if (value && typeof value === "object") {
    const input = value as Record<string, unknown>;
    const output: Record<string, unknown> = {};
    for (const key of Object.keys(input).sort()) {
      output[key] = sortJson(input[key]);
    }
    return output;
  }

  return value;
}

export function stableJsonString(value: unknown): string {
  return JSON.stringify(sortJson(value));
}

export function stableJsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(stableJsonString(value));
}
