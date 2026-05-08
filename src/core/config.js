const env = process.env;

function toBool(value, defaultValue) {
  if (value === undefined) return defaultValue;
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

const settings = {
  appName: env.APP_NAME || "Real-Time SOC Incident Analysis API",
  environment: env.NODE_ENV || "production",
  logLevel: env.LOG_LEVEL || "info",
  openaiApiKey: env.OPENAI_API_KEY || "",
  openaiModel: env.OPENAI_MODEL || "gpt-4.1",
  openaiTimeoutMs: Number(env.OPENAI_TIMEOUT_MS || 5000),
  maxRawLogChars: Number(env.MAX_RAW_LOG_CHARS || 4000),
  maxPayloadSizeBytes: Number(env.MAX_PAYLOAD_SIZE_BYTES || 200000),
  enableRateLimiting: toBool(env.ENABLE_RATE_LIMITING, true),
  port: Number(env.PORT || 8000),
};

module.exports = { settings };
