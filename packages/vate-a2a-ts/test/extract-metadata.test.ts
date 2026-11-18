import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { extractVateMetadata, validateVateA2aMetadata } from "../src/index.js";

const extensionUri =
  "https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/a2a/admission/v0.3";

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(new URL(`../../../${path}`, import.meta.url), "utf8"));
}

describe("A2A VATE metadata", () => {
  describe.each(["artifact", "evidence", "extension"] as const)("%s URI syntax", (kind) => {
    const cases = readJson("reference/a2a-metadata-adapter-demo/uri-test-vectors.json") as Array<{
      uri: string; valid: boolean;
    }>;
    it.each(cases)("validates raw URI $uri", ({ uri, valid }) => {
      const metadata = readJson("examples/a2a/metadata-admission-requested-with-signed-agent-card.json") as {
        admission_request: { uri: string };
        evidence_refs: Array<{ uri: string }>;
        extensions?: Record<string, unknown>;
      };
      if (kind === "artifact") metadata.admission_request.uri = uri;
      else if (kind === "evidence") metadata.evidence_refs[0]!.uri = uri;
      else metadata.extensions = { [uri]: { arbitrary_annotation: true } };
      expect(validateVateA2aMetadata(metadata).length === 0).toBe(valid);
    });
  });

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

  it.each([
    ["2026-07-01t00:00:00z", true],
    ["2026-07-01T00:00:00.1z", true],
    ["2026-07-01T00:00:00.123456+00:00", true],
    ["0001-01-01T00:00:00Z", true],
    ["2024-02-29T23:59:59-23:59", true],
    ["2026-07-01T00:00:00.1234567Z", false],
    ["2026-07-01T00:00:00.0000001+00:00", false],
    ["0000-01-01T00:00:00Z", false],
    ["2026-02-29T00:00:00Z", false],
    ["2026-07-01T24:00:00Z", false],
    ["2026-07-01T00:00:00+24:00", false],
    ["2026-07-01T00:00:00Z\n", false],
  ])("matches the Python timestamp subset for %s", (issuedAt, accepted) => {
    const metadata = {
      ...(readJson("examples/a2a/metadata-admission-issued.json") as Record<string, unknown>),
      issued_at: issuedAt,
      expires_at: issuedAt,
    };
    expect(validateVateA2aMetadata(metadata).length === 0).toBe(accepted);
  });

  it("rejects artifact references without absolute URI strings", () => {
    const metadata = {
      ...(readJson("examples/a2a/metadata-admission-issued.json") as Record<
        string,
        unknown
      >),
      admission_receipt: {
        type: "admission_receipt",
        uri: "not-a-uri",
        media_type: "application/vate-admission-receipt+json",
        digest: {
          alg: "sha-256",
          value: "0".repeat(64),
        },
      },
    };
    expect(validateVateA2aMetadata(metadata)[0]).toContain(
      "must match pattern"
    );
  });

  describe.each(["artifact", "evidence"] as const)("%s digest values", (kind) => {
    it.each([
      ["lowercase hex", "0123456789abcdef".repeat(4), true],
      ["short", "a".repeat(63), false],
      ["long", "a".repeat(65), false],
      ["trailing LF", "a".repeat(64) + "\n", false],
      ["trailing CR", "a".repeat(64) + "\r", false],
      ["trailing CRLF", "a".repeat(64) + "\r\n", false],
      ["trailing line separator", "a".repeat(64) + "\u2028", false],
      ["trailing paragraph separator", "a".repeat(64) + "\u2029", false],
      ["leading space", " " + "a".repeat(64), false],
      ["trailing space", "a".repeat(64) + " ", false],
      ["uppercase", "A".repeat(64), false],
      ["non-hex", "g".repeat(64), false],
      ["empty", "", false],
    ])("validates %s", (_label, value, accepted) => {
      const metadata = readJson(
        "examples/a2a/metadata-admission-requested-with-signed-agent-card.json"
      ) as {
        admission_request: { digest: { value: string } };
        evidence_refs: Array<{ digest: { value: string } }>;
      };
      const reference = kind === "artifact" ? metadata.admission_request : metadata.evidence_refs[0];
      if (!reference) {
        throw new Error("digest regression fixture is missing its reference");
      }
      reference.digest.value = value;
      const errors = validateVateA2aMetadata(metadata);
      expect(errors.length === 0).toBe(accepted);
      if (!accepted) {
        const path = kind === "artifact" ? "/admission_request/digest/value" : "/evidence_refs/0/digest/value";
        expect(errors.every((error) => error.startsWith(path + " "))).toBe(true);
      }
    });
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
