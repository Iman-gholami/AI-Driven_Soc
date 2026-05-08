const pino = require("pino");

const SENSITIVE_PATTERNS = [
  /(password|passwd|pwd)\s*[:=]\s*\S+/gi,
  /(api[_-]?key|token|secret)\s*[:=]\s*\S+/gi,
  /authorization\s*[:=]\s*bearer\s+\S+/gi,
];

function sanitizeText(value) {
  if (typeof value !== "string") return value;
  let sanitized = value;
  for (const pattern of SENSITIVE_PATTERNS) {
    sanitized = sanitized.replace(pattern, "[REDACTED]");
  }
  return sanitized;
}

function sanitizeObject(obj) {
  if (!obj || typeof obj !== "object") return obj;
  const clone = Array.isArray(obj) ? [...obj] : { ...obj };
  for (const key of Object.keys(clone)) {
    const value = clone[key];
    if (typeof value === "string") clone[key] = sanitizeText(value);
  }
  return clone;
}

function createLogger(level = "info") {
  return pino({ level });
}

module.exports = { createLogger, sanitizeText, sanitizeObject };
