const crypto = require("crypto");
const { buildContext } = require("./contextBuilder");
const { createEventHash } = require("./eventHash");
const { LLMService } = require("./llmService");
const { createLogger } = require("../core/logging");
const { settings } = require("../core/config");
const { analysisResponseSchema } = require("../models/incidentSchema");
const { AlertRepository } = require("../repositories/AlertRepository");

class IncidentAnalyzer {
  constructor({ llm = new LLMService(), alertRepository = new AlertRepository(), logger = createLogger(settings.logLevel) } = {}) {
    this.llm = llm;
    this.alertRepository = alertRepository;
    this.logger = logger;
  }

  async analyzeIncident(payload) {
    const startedAt = Date.now();
    const context = buildContext(payload);
    const result = await this.llm.analyze(context);
    const response = analysisResponseSchema.parse(result);
    const processingTimeMs = Date.now() - startedAt;

    await this.persistAnalyzedAlert(payload, response, processingTimeMs);

    return response;
  }

  async persistAnalyzedAlert(payload, analysisResult, processingTimeMs) {
    const eventHash = createEventHash(payload);
    const providerMetadata = this.llm.getMetadata ? this.llm.getMetadata() : {};
    const alertId = getAlertId(payload);

    try {
      await this.alertRepository.create({
        alertId,
        source: getAlertSource(payload),
        rawEvent: payload,
        analysis: mapAnalysisSummary(analysisResult),
        status: "analyzed",
        llmProvider: providerMetadata.provider || "unknown",
        model: providerMetadata.model || "unknown",
        processingTimeMs,
        eventHash,
        fullAnalysis: analysisResult,
        soc: {
          mitreAttack: analysisResult.attack_mapping,
          providerMetadata,
        },
        processing: {
          attempts: 1,
          completedAt: new Date(),
        },
      });
      this.logger.info({ alertId, eventHash, status: "analyzed" }, "Alert stored successfully");
    } catch (error) {
      this.logger.error({ err: error, alertId, eventHash }, "Alert storage failure");
    }
  }
}

function getAlertId(payload) {
  return String(payload?.alertId || payload?.alert_id || payload?.id || crypto.randomUUID());
}

function getAlertSource(payload) {
  return String(payload?.source || payload?.sourcetype || payload?.index || "splunk");
}

function mapAnalysisSummary(analysisResult) {
  return {
    severity: getSeverity(analysisResult),
    summary: getSummary(analysisResult),
    recommendations: analysisResult.recommended_investigation_steps || [],
  };
}

function getSeverity(analysisResult) {
  const riskAssessment = analysisResult.risk_assessment;
  if (riskAssessment && typeof riskAssessment === "object" && riskAssessment.severity) {
    return String(riskAssessment.severity);
  }
  return "unknown";
}

function getSummary(analysisResult) {
  const incidentSummary = analysisResult.incident_summary;
  if (typeof incidentSummary === "string") return incidentSummary;
  if (incidentSummary && typeof incidentSummary === "object") {
    return incidentSummary.what_happened || incidentSummary.summary || JSON.stringify(incidentSummary);
  }
  return analysisResult.final_soc_note || "";
}

module.exports = { IncidentAnalyzer, mapAnalysisSummary };
