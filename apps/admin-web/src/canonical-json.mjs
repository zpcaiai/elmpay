import { createHash } from "node:crypto";

function normalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(normalize);
  if (typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, normalize(value[key])]));
  }
  throw new TypeError("canonical JSON only supports finite JSON values");
}

export function canonicalJson(value) {
  return JSON.stringify(normalize(value));
}

export function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function sha256Base64Url(value) {
  return createHash("sha256").update(value).digest("base64url");
}
