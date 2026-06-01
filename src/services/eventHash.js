const crypto = require("crypto");

function normalizeForHash(value) {
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.map(normalizeForHash);
  if (!value || typeof value !== "object") return value;

  return Object.keys(value)
    .sort()
    .reduce((normalized, key) => {
      normalized[key] = normalizeForHash(value[key]);
      return normalized;
    }, {});
}

function createEventHash(event) {
  const normalized = normalizeForHash(event || {});
  return crypto.createHash("sha256").update(JSON.stringify(normalized)).digest("hex");
}

module.exports = { createEventHash, normalizeForHash };
