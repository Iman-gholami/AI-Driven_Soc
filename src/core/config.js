const env = process.env;

const WEEKDAYS = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"];
const LLM_PROVIDERS = ["openai", "local", "local-openai-compatible"];
const LOG_LEVELS = ["fatal", "error", "warn", "info", "debug", "trace", "silent"];

// Collected while reading env so every misconfiguration is reported at once instead of
// surfacing later as NaN timeouts or silently ignored values.
const configErrors = [];

function readBool(name, defaultValue) {
  const raw = env[name];
  if (raw === undefined || raw === "") return defaultValue;
  const normalized = String(raw).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  configErrors.push(`${name}: expected a boolean (true/false) but received "${raw}"`);
  return defaultValue;
}

function readInt(name, defaultValue, { min = 0, max = Number.MAX_SAFE_INTEGER, fallbackName } = {}) {
  const usesOwnValue = env[name] !== undefined && env[name] !== "";
  const raw = usesOwnValue ? env[name] : fallbackName ? env[fallbackName] : undefined;
  if (raw === undefined || raw === "") return defaultValue;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) {
    // An invalid fallback is already reported under its own name.
    if (usesOwnValue) configErrors.push(`${name}: expected an integer between ${min} and ${max} but received "${raw}"`);
    return defaultValue;
  }
  return value;
}

function readEnum(name, defaultValue, allowed) {
  const raw = env[name];
  if (raw === undefined || raw === "") return defaultValue;
  const value = String(raw).trim().toLowerCase();
  if (!allowed.includes(value)) {
    configErrors.push(`${name}: expected one of ${allowed.join(", ")} but received "${raw}"`);
    return defaultValue;
  }
  return value;
}

function readTimezone(name, defaultValue) {
  const value = env[name] || defaultValue;
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: value });
  } catch (_) {
    configErrors.push(`${name}: "${value}" is not a valid IANA time zone`);
    return defaultValue;
  }
  return value;
}

const settings = {
  appName: env.APP_NAME || "Real-Time SOC Incident Analysis API",
  environment: env.NODE_ENV || "development",
  logLevel: readEnum("LOG_LEVEL", "info", LOG_LEVELS),
  socTimezone: readTimezone("SOC_TIMEZONE", "Asia/Tehran"),
  socWeekStart: readEnum("SOC_WEEK_START", "saturday", WEEKDAYS),
  airGapped: readBool("AIR_GAPPED", false),
  llmProvider: readEnum("LLM_PROVIDER", "openai", LLM_PROVIDERS),
  openaiApiKey: env.OPENAI_API_KEY || "",
  openaiModel: env.OPENAI_MODEL || "gpt-4.1",
  openaiTimeoutMs: readInt("OPENAI_TIMEOUT_MS", 5000, { min: 1 }),
  localLlmBaseUrl: env.LOCAL_LLM_BASE_URL || "",
  localLlmApiKey: env.LOCAL_LLM_API_KEY || "local",
  localLlmModel: env.LOCAL_LLM_MODEL || "",
  localLlmTimeoutMs: readInt("LOCAL_LLM_TIMEOUT_MS", 15000, { min: 1, fallbackName: "OPENAI_TIMEOUT_MS" }),
  localLlmUseJsonMode: readBool("LOCAL_LLM_JSON_MODE", false),
  ipinfoMmdbPath: env.IPINFO_MMDB_PATH || "",
  threatIntelEvidenceLimit: readInt("THREAT_INTEL_EVIDENCE_LIMIT", 12, { min: 1 }),
  reportsRoot: env.REPORTS_ROOT || "reports",
  reportImportMaxFileBytes: readInt("REPORT_IMPORT_MAX_FILE_BYTES", 25 * 1024 * 1024, { min: 1 }),
  mongodbUri: env.MONGODB_URI || "",
  mongodbMaxRetries: readInt("MONGODB_MAX_RETRIES", 3, { min: 1 }),
  mongodbRetryDelayMs: readInt("MONGODB_RETRY_DELAY_MS", 500),
  mongodbServerSelectionTimeoutMs: readInt("MONGODB_SERVER_SELECTION_TIMEOUT_MS", 2000, { min: 1 }),
  maxRawLogChars: readInt("MAX_RAW_LOG_CHARS", 4000, { min: 1 }),
  maxPayloadSizeBytes: readInt("MAX_PAYLOAD_SIZE_BYTES", 200000, { min: 1 }),
  enableRateLimiting: readBool("ENABLE_RATE_LIMITING", true),
  authEnabled: readBool("AUTH_ENABLED", true),
  authUsername: env.AUTH_USERNAME || "",
  authPassword: env.AUTH_PASSWORD || "",
  authOtp: env.AUTH_OTP || "",
  authDisplayName: env.AUTH_DISPLAY_NAME || "SOC Administrator",
  authRole: env.AUTH_ROLE || "admin",
  authTokenSecret: env.AUTH_TOKEN_SECRET || "",
  authTokenTtlSeconds: readInt("AUTH_TOKEN_TTL_SECONDS", 8 * 60 * 60, { min: 1 }),
  authRememberTokenTtlSeconds: readInt("AUTH_REMEMBER_TOKEN_TTL_SECONDS", 7 * 24 * 60 * 60, { min: 1 }),
  shutdownTimeoutMs: readInt("SHUTDOWN_TIMEOUT_MS", 10000, { min: 1 }),
  port: readInt("PORT", 8000, { min: 0, max: 65535 }),
};

class ConfigError extends Error {
  constructor(errors) {
    super(`Invalid configuration:\n  - ${errors.join("\n  - ")}`);
    this.name = "ConfigError";
    this.errors = errors;
  }
}

// Entry points call this before serving; library imports (tests, scripts) keep the safe defaults.
function assertValidConfig() {
  if (configErrors.length > 0) throw new ConfigError([...configErrors]);
}

module.exports = { settings, assertValidConfig, ConfigError };
