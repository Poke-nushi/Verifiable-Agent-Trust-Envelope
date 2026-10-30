import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";

function readBoundedFile(path, maxBytes) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    if (!fstatSync(fd).isFile()) throw new Error("Regular file required");
    // One extra byte lets the helper return input_too_large without reading an
    // unbounded file into memory. The file may grow after it was opened.
    const bytes = new Uint8Array(maxBytes + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(fd, bytes, length, bytes.length - length, null);
      if (count === 0) break;
      length += count;
    }
    return bytes.subarray(0, length);
  } finally {
    closeSync(fd);
  }
}

// The file must contain the complete preimage selected by the external profile.
// No fields are selected, removed or fetched by this command.
const args = process.argv.slice(2);
if (args.length !== 4) {
  console.error("Usage: node assess-external-json.mjs <json-file> <basis> <algorithm> <hex-digest>");
  process.exitCode = 64;
} else {
  const [path, basis, alg, value] = args;
  try {
    const { assessExternalJsonDigest, JCS_INPUT_LIMITS } = await import("../dist/index.js");
    const result = assessExternalJsonDigest(readBoundedFile(path, JCS_INPUT_LIMITS.maxBytes), { basis, digest: { alg, value } });
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = { matched: 0, mismatched: 1, invalid_input: 2, not_assessed: 3 }[result.status];
  } catch {
    console.error("Unable to load the verifier or assess the supplied local file.");
    process.exitCode = 64;
  }
}
