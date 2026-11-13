// Local test/example issuer only. Private keys are generated in memory and discarded.
import { generateKeyPairSync, sign } from "node:crypto";

let size = 0;
const chunks = [];
for await (const chunk of process.stdin) {
  size += chunk.length;
  if (size > 128 * 1024) throw new Error("fixture input exceeds bound");
  chunks.push(chunk);
}
const input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
const bytes = Buffer.from(input.signing_input_base64, "base64");
const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: input.curve ?? "prime256v1" });
process.stdout.write(JSON.stringify({
  spki_base64: publicKey.export({ format: "der", type: "spki" }).toString("base64"),
  signature_base64: sign("sha256", bytes, {
    key: privateKey, dsaEncoding: input.signature_encoding ?? "ieee-p1363"
  }).toString("base64")
}) + "\n");
