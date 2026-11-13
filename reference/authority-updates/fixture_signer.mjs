// Local fixtures only: one ephemeral authority key signs a bounded batch.
import { generateKeyPairSync, sign } from "node:crypto";
const chunks = [];
let size = 0;
for await (const chunk of process.stdin) {
  size += chunk.length;
  if (size > 2 * 1024 * 1024) throw new Error("fixture input exceeds bound");
  chunks.push(chunk);
}
const inputs = JSON.parse(Buffer.concat(chunks).toString("utf8"));
if (!Array.isArray(inputs) || inputs.length > 128) throw new Error("invalid fixture batch");
const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const signatures = inputs.map(value => sign("sha256", Buffer.from(value, "base64"), {
  key: privateKey, dsaEncoding: "ieee-p1363"
}).toString("base64"));
process.stdout.write(JSON.stringify({ signatures,
  public_key: publicKey.export({format: "der", type: "spki"}).toString("base64") }) + "\n");
