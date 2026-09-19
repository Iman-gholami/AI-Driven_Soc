const OpenAI = require("openai");
const { settings } = require("../core/config");

const MAX_EMBEDDING_TEXT_CHARS = 12000;

class SocMemoryEmbeddingService {
  constructor({
    baseURL = settings.socMemoryEmbeddingBaseUrl,
    apiKey = settings.socMemoryEmbeddingApiKey,
    model = settings.socMemoryEmbeddingModel,
    timeoutMs = settings.socMemoryEmbeddingTimeoutMs,
  } = {}) {
    this.baseURL = String(baseURL || "").trim();
    this.apiKey = String(apiKey || "local").trim() || "local";
    this.model = String(model || "").trim();
    this.timeoutMs = Math.max(Number(timeoutMs) || 10000, 1000);
    this.client = this.isConfigured()
      ? new OpenAI({ apiKey: this.apiKey, baseURL: this.baseURL, timeout: this.timeoutMs })
      : null;
  }

  isConfigured() {
    return Boolean(this.baseURL && this.model);
  }

  getMetadata() {
    return {
      configured: this.isConfigured(),
      model: this.model || null,
      baseUrlConfigured: Boolean(this.baseURL),
    };
  }

  async embedText(value) {
    if (!this.client) return null;
    const text = normalizeEmbeddingText(value);
    if (!text) return null;

    const response = await this.client.embeddings.create({
      model: this.model,
      input: text,
    });
    const vector = response?.data?.[0]?.embedding;
    if (!Array.isArray(vector) || !vector.length) {
      throw new Error("SOC memory embedding endpoint returned no vector");
    }
    return vector.map(Number);
  }
}

function normalizeEmbeddingText(value) {
  return String(value || "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, MAX_EMBEDDING_TEXT_CHARS);
}

module.exports = {
  SocMemoryEmbeddingService,
  normalizeEmbeddingText,
};
