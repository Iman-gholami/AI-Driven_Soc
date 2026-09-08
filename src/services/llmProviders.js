const OpenAI = require("openai");
const { settings } = require("../core/config");
const { SYSTEM_PROMPT, buildUserPrompt } = require("./promptBuilder");

class OpenAICompatibleProvider {
  constructor({
    providerName,
    apiKey,
    model,
    timeoutMs,
    baseURL,
    useJsonMode = true,
    networkAllowed = true,
  }) {
    this.providerName = providerName;
    this.model = model;
    this.useJsonMode = useJsonMode;
    this.networkAllowed = networkAllowed;
    this.apiKeyConfigured = Boolean(apiKey);
    this.modelConfigured = Boolean(model);
    this.baseUrlConfigured = Boolean(baseURL);
    const safeBaseUrl = providerName === "local" && !baseURL
      ? "http://127.0.0.1:1/v1"
      : baseURL;

    this.client = new OpenAI({
      apiKey: apiKey || "not-configured",
      timeout: timeoutMs,
      ...(safeBaseUrl ? { baseURL: safeBaseUrl } : {}),
    });
  }

  getMetadata() {
    return {
      provider: this.providerName,
      model: this.model,
    };
  }

  async analyze(context) {
    if (!this.networkAllowed) {
      throw new Error(`${this.providerName} LLM is disabled while AIR_GAPPED=true`);
    }
    if (!this.modelConfigured) {
      throw new Error(`${this.providerName} LLM model is not configured`);
    }
    if (!this.apiKeyConfigured) {
      throw new Error(`${this.providerName} LLM API key is not configured`);
    }
    if (this.providerName === "local" && !this.baseUrlConfigured) {
      throw new Error("LOCAL_LLM_BASE_URL is required when LLM_PROVIDER=local");
    }

    let lastError;

    for (let attempt = 1; attempt <= 3; attempt += 1) {
      try {
        const request = {
          model: this.model,
          temperature: 0.1,
          messages: [
            { role: "system", content: SYSTEM_PROMPT },
            { role: "user", content: buildUserPrompt(context) },
          ],
        };

        if (this.useJsonMode) {
          request.response_format = { type: "json_object" };
        }

        const response = await this.client.chat.completions.create(request);
        const content = response.choices?.[0]?.message?.content || "{}";
        return parseJsonResponse(content);
      } catch (error) {
        lastError = error;
        if (attempt < 3) {
          await new Promise((resolve) => setTimeout(resolve, 200 * attempt));
        }
      }
    }

    throw lastError;
  }
}

function createConfiguredLlmProvider(config = settings) {
  const provider = String(config.llmProvider || "openai").trim().toLowerCase();

  if (provider === "openai") {
    return new OpenAICompatibleProvider({
      providerName: "openai",
      apiKey: config.openaiApiKey,
      model: config.openaiModel,
      timeoutMs: config.openaiTimeoutMs,
      useJsonMode: true,
      networkAllowed: !config.airGapped,
    });
  }

  if (provider === "local" || provider === "local-openai-compatible") {
    return new OpenAICompatibleProvider({
      providerName: "local",
      apiKey: config.localLlmApiKey || "local",
      model: config.localLlmModel,
      timeoutMs: config.localLlmTimeoutMs,
      baseURL: config.localLlmBaseUrl,
      useJsonMode: Boolean(config.localLlmUseJsonMode),
    });
  }

  throw new Error(`Unsupported LLM_PROVIDER: ${provider}`);
}

function parseJsonResponse(content) {
  const text = String(content || "").trim();
  if (!text) return {};

  try {
    return JSON.parse(text);
  } catch (_) {
    const fenced = text.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
    if (fenced?.[1]) return JSON.parse(fenced[1]);

    const start = text.indexOf("{");
    const end = text.lastIndexOf("}");
    if (start >= 0 && end > start) return JSON.parse(text.slice(start, end + 1));
    throw _;
  }
}

module.exports = {
  OpenAICompatibleProvider,
  createConfiguredLlmProvider,
  parseJsonResponse,
};
