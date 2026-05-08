const OpenAI = require("openai");
const { settings } = require("../core/config");
const { SYSTEM_PROMPT, buildUserPrompt } = require("./promptBuilder");

class LLMService {
  constructor() {
    this.client = new OpenAI({ apiKey: settings.openaiApiKey, timeout: settings.openaiTimeoutMs });
    this.model = settings.openaiModel;
  }

  async analyze(context) {
    let lastError;
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      try {
        const response = await this.client.chat.completions.create({
          model: this.model,
          temperature: 0.1,
          response_format: { type: "json_object" },
          messages: [
            { role: "system", content: SYSTEM_PROMPT },
            { role: "user", content: buildUserPrompt(context) },
          ],
        });
        const content = response.choices?.[0]?.message?.content || "{}";
        return JSON.parse(content);
      } catch (error) {
        lastError = error;
        if (attempt < 3) await new Promise((r) => setTimeout(r, 200 * attempt));
      }
    }
    throw lastError;
  }
}

module.exports = { LLMService };
