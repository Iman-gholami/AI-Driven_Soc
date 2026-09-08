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
}

module.exports = { LLMService };
