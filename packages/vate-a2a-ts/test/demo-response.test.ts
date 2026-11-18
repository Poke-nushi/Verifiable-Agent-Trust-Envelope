import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { extractVateMetadata, validateVateA2aMetadata } from "../src/index.js";

const vectorScript = fileURLToPath(new URL(
  "../../../reference/a2a-metadata-adapter-demo/response_uri_vectors.py", import.meta.url,
));
const vectors = JSON.parse(execFileSync("python3", ["-B", vectorScript], { encoding: "utf8" })) as Array<{
  request_id: string;
  response: { metadata: Record<string, unknown>; post_execution_metadata_example: Record<string, unknown> };
}>;

describe("actual Python A2A demo output", () => {
  it.each(vectors)("accepts receipt references for request ID $request_id", ({ response }) => {
    expect(validateVateA2aMetadata(extractVateMetadata(response))).toEqual([]);
    expect(validateVateA2aMetadata(extractVateMetadata({ metadata: response.post_execution_metadata_example }))).toEqual([]);
  });
});
