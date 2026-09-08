const env = process.env;

function toBool(value, defaultValue) {
  if (value === undefined) return defaultValue;
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

const settings = {
  appName: env.APP_NAME || "Real-Time SOC Incident Analysis API",
  environment: env.NODE_ENV || "production",
  logLevel: env.LOG_LEVEL || "info",
  llmProvider: env.LLM_PROVIDER || "openai",
  openaiApiKey: env.OPENAI_API_KEY || "",
  openaiModel: env.OPENAI_MODEL || "gpt-4.1",
  openaiTimeoutMs: Number(env.OPENAI_TIMEOUT_MS || 5000),
  localLlmBaseUrl: env.LOCAL_LLM_BASE_URL || "",
  localLlmApiKey: env.LOCAL_LLM_API_KEY || "local",
  localLlmModel: env.LOCAL_LLM_MODEL || "",
  localLlmTimeoutMs: Number(env.LOCAL_LLM_TIMEOUT_MS || env.OPENAI_TIMEOUT_MS || 15000),
  localLlmUseJsonMode: toBool(env.LOCAL_LLM_JSON_MODE, false),
  ipinfoMmdbPath: env.IPINFO_MMDB_PATH || "",
  threatIntelEvidenceLimit: Number(env.THREAT_INTEL_EVIDENCE_LIMIT || 12),
  mongodbUri: env.MONGODB_URI || "",
  mongodbMaxRetries: Number(env.MONGODB_MAX_RETRIES || 3),
  mongodbRetryDelayMs: Number(env.MONGODB_RETRY_DELAY_MS || 500),
  mongodbServerSelectionTimeoutMs: Number(env.MONGODB_SERVER_SELECTION_TIMEOUT_MS || 2000),
  maxRawLogChars: Number(env.MAX_RAW_LOG_CHARS || 4000),
  maxPayloadSizeBytes: Number(env.MAX_PAYLOAD_SIZE_BYTES || 200000),
  enableRateLimiting: toBool(env.ENABLE_RATE_LIMITING, true),
  port: Number(env.PORT || 8000),
};

module.exports = { settings };
