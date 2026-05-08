import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { extractVateMetadata, validateVateA2aMetadata } from "../src/index.js";

const extensionUri =
  "https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.2";

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(new URL(`../../../${path}`, import.meta.url), "utf8"));
}

describe("A2A VATE metadata", () => {
  it("validates the admission issued example", () => {
    const metadata = readJson("examples/a2a/metadata-admission-issued.json");
    expect(validateVateA2aMetadata(metadata)).toEqual([]);
  });

  it("rejects unknown core fields", () => {
    const metadata = {
      ...(readJson("examples/a2a/metadata-admission-issued.json") as Record<
        string,
        unknown
      >),
      unexpected_core_field: true,
    };
    expect(validateVateA2aMetadata(metadata)[0]).toContain(
      "must NOT have additional properties"
    );
  });

  it("rejects invalid date-time values", () => {
    const metadata = {
      ...(readJson("examples/a2a/metadata-admission-issued.json") as Record<
        string,
        unknown
      >),
      issued_at: "not-a-date",
    };
    expect(validateVateA2aMetadata(metadata)[0]).toContain(
      "must match format"
    );
  });

  it("rejects extension keys that are neither URI nor x_ names", () => {
    const metadata = {
      ...(readJson("examples/a2a/metadata-admission-issued.json") as Record<
        string,
        unknown
      >),
      extensions: {
        "not a uri and not x_name": true,
      },
    };
    expect(validateVateA2aMetadata(metadata)[0]).toContain(
      "must match format"
    );
  });

  it("extracts metadata from an A2A-like object", () => {
    const metadata = readJson("examples/a2a/metadata-admission-issued.json");
    const task = { metadata: { [extensionUri]: metadata } };
    expect(extractVateMetadata(task)).toEqual(metadata);
  });
});
