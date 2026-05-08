const { buildContext } = require("./contextBuilder");
const { LLMService } = require("./llmService");
const { analysisResponseSchema } = require("../models/incidentSchema");

class IncidentAnalyzer {
  constructor() {
    this.llm = new LLMService();
  }

  async analyzeIncident(payload) {
    const context = buildContext(payload);
    const result = await this.llm.analyze(context);
    return analysisResponseSchema.parse(result);
  }
}

module.exports = { IncidentAnalyzer };
