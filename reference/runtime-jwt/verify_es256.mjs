// Private transport for the Python adapter; this is not a JWT policy API.
import { createHash, createPublicKey, verify } from "node:crypto";

const CONTRACT = "vate-runtime-es256-backend-v1";
const exact = (v, keys) => v !== null && typeof v === "object" && !Array.isArray(v) &&
  Object.keys(v).sort().join(",") === [...keys].sort().join(",");
const decode = (value, limit) => {
  if (typeof value !== "string" || value.length > 4 * Math.ceil(limit / 3)) throw new Error();
  const raw = Buffer.from(value, "base64");
  if (raw.length > limit || raw.toString("base64") !== value) throw new Error();
  return raw;
};

try {
  let size = 0;
  const chunks = [];
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 128 * 1024) throw new Error();
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks);
  const request = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  if (!exact(request, ["contract", "signing_input_base64", "signature_base64", "spki_base64"]) ||
      request.contract !== CONTRACT) throw new Error();
  const input = decode(request.signing_input_base64, 64 * 1024);
  const signature = decode(request.signature_base64, 64);
  const der = decode(request.spki_base64, 91);
  if (signature.length !== 64 || der.length !== 91 || input.length === 0) throw new Error();
  const key = createPublicKey({ key: der, format: "der", type: "spki" });
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1" ||
      !key.export({ format: "der", type: "spki" }).equals(der)) throw new Error();
  const verified = verify("sha256", input, { key, dsaEncoding: "ieee-p1363" }, signature);
  process.stdout.write(JSON.stringify({ contract: CONTRACT,
    request_sha256: createHash("sha256").update(raw).digest("hex"), verified }) + "\n");
} catch {
  process.stdout.write(JSON.stringify({ contract: CONTRACT, error: "VERIFICATION_FAILED" }) + "\n");
  process.exitCode = 64;
}
