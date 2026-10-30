// Private local transport for jcs_recipient_trial.py. No network/key discovery.
import { createHash } from "node:crypto";
import { JcsEs256Verifier, JCS_ES256_PROFILE } from "../../packages/vate-core-ts/dist/jcs-es256.js";

const CONTRACT = "vate-local-jcs-es256-bridge-v1";
const TYPES = { admission: "urn:vate:local:jcs-es256:admission:v1", post_execution: "urn:vate:local:jcs-es256:post_execution:v1" };
const exact = (x, keys) => x !== null && typeof x === "object" && !Array.isArray(x) &&
  Object.keys(x).length === keys.length && keys.every(k => Object.hasOwn(x, k));
const decode = (s, limit) => {
  if (s === null) return null;
  if (typeof s !== "string" || s.length > 4 * Math.ceil(limit / 3)) throw new Error("invalid transport bytes");
  const raw = Buffer.from(s, "base64");
  if (raw.length > limit || raw.toString("base64") !== s) throw new Error("invalid transport encoding");
  return raw;
};

try {
  let size = 0;
  const parts = [];
  for await (const part of process.stdin) {
    size += part.length;
    if (size > 3 * 1024 * 1024) throw new Error("transport exceeds limit");
    parts.push(part);
  }
  const raw = Buffer.concat(parts);
  // The Python wrapper creates this transport; signed headers and payloads
  // receive strict duplicate-key/UTF-8 checks in the signature helper.
  const request = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  if (!exact(request, ["contract", "verification_keys", "receipts"]) || request.contract !== CONTRACT ||
      !exact(request.receipts, Object.keys(TYPES))) throw new Error("unknown transport contract");
  const verifier = new JcsEs256Verifier({ expectedProfile: JCS_ES256_PROFILE, verificationKeys: request.verification_keys });
  const signatures = {};
  for (const [kind, expectedType] of Object.entries(TYPES)) {
    const entry = request.receipts[kind];
    if (!exact(entry, ["source_base64", "proof_base64"])) throw new Error("invalid receipt entry");
    signatures[kind] = verifier.verify({ source: decode(entry.source_base64, 1024 * 1024),
      proof: decode(entry.proof_base64, 4096), expectedType });
  }
  console.log(JSON.stringify({ contract: CONTRACT, request_sha256: createHash("sha256").update(raw).digest("hex"),
    signatures, validated_keys: request.verification_keys.map(k => k.key_sha256),
    runtime: { node: process.versions.node, openssl: process.versions.openssl } }));
} catch (error) {
  console.log(JSON.stringify({ contract: CONTRACT, error: error.name === "JcsEs256ConfigurationError" ? "INVALID_VERIFICATION_KEYS" : "BRIDGE_ERROR" }));
  process.exitCode = 64;
}
