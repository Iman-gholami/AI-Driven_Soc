const { createConfiguredLlmProvider } = require("./llmProviders");

class LLMService {
  constructor({ provider = createConfiguredLlmProvider() } = {}) {
    this.provider = provider;
  }

  getMetadata() {
    return this.provider.getMetadata
      ? this.provider.getMetadata()
      : { provider: "unknown", model: "unknown" };
  }

  async analyze(context) {
    return this.provider.analyze(context);
  }

  async completeJson(request) {
    if (typeof this.provider.completeJson !== "function") {
      throw new Error("Configured LLM provider does not support JSON completion");
    }
    return this.provider.completeJson(request);
  }
}

module.exports = { LLMService };
