const crypto = require("crypto");
const { buildContext } = require("./contextBuilder");
const { createEventHash } = require("./eventHash");
const { LLMService } = require("./llmService");
const { createLogger } = require("../core/logging");
const { settings } = require("../core/config");
const { analysisResponseSchema } = require("../models/incidentSchema");
const { AlertRepository } = require("../repositories/AlertRepository");
const { AlertAnalysisRepository } = require("../repositories/AlertAnalysisRepository");

class IncidentAnalyzer {
  constructor({
    llm = new LLMService(),
    alertRepository = new AlertRepository(),
    alertAnalysisRepository = new AlertAnalysisRepository(),
    logger = createLogger(settings.logLevel),
  } = {}) {
    this.llm = llm;
    this.alertRepository = alertRepository;
    this.alertAnalysisRepository = alertAnalysisRepository;
    this.logger = logger;
  }

  async analyzeIncident(payload) {
    const analyzed = await this.analyzePayload(payload);

    await this.persistAnalyzedAlert(payload, analyzed.analysis, analyzed.metadata.processingTimeMs);

    return analyzed.analysis;
  }

  async analyzeStoredAlert(alert) {
    const rawEvent = alert?.rawEvent || alert || {};
    const analyzed = await this.analyzePayload(rawEvent);
    return {
      ...analyzed,
      persistence: this.buildAnalysisPersistence(alert, analyzed.analysis, analyzed.metadata.processingTimeMs),
    };
  }

  async analyzePayload(payload) {
    const startedAt = Date.now();
    const context = buildContext(payload);
    const result = await this.llm.analyze(context);
    const response = analysisResponseSchema.parse(result);
    const processingTimeMs = Date.now() - startedAt;
    const providerMetadata = this.llm.getMetadata ? this.llm.getMetadata() : {};

    return {
      analysis: response,
      metadata: {
        provider: providerMetadata.provider || "unknown",
        model: providerMetadata.model || "unknown",
        processingTimeMs,
      },
    };
  }

  async persistAnalyzedAlert(payload, analysisResult, processingTimeMs) {
    const eventHash = createEventHash(payload);
    const alertId = getAlertId(payload);

    try {
      const alert = await this.alertRepository.upsertAnalyzedAlert({
        alertId,
        source: getAlertSource(payload),
        severity: getSeverity(analysisResult),
        rawEvent: payload,
        eventHash,
      });
      const attemptNumber = (alert?.analysisCount || 0) + 1;
      const completedAt = new Date();
      const analysis = await this.alertAnalysisRepository.createForAlert(alert, {
        ...this.buildAnalysisPersistence(alert, analysisResult, processingTimeMs),
        processing: { attemptNumber, completedAt },
      });

      await this.alertRepository.incrementAnalysisCount(alertId);
      await this.alertRepository.updateLatestAnalysisReference(alertId, {
        analysisId: analysis._id || analysis.id,
        severity: getSeverity(analysisResult),
        analyzedAt: completedAt,
        attemptNumber,
      });
      this.logger.info({ alertId, eventHash, status: "analyzed", analysisId: analysis._id || analysis.id }, "Alert stored successfully");
    } catch (error) {
      this.logger.error({ err: error, alertId, eventHash }, "Alert storage failure");
    }
  }

  buildAnalysisPersistence(alert, analysisResult, processingTimeMs) {
    const providerMetadata = this.llm.getMetadata ? this.llm.getMetadata() : {};
    return {
      analysis: mapAnalysisSummary(analysisResult),
      fullAnalysis: analysisResult,
      llmProvider: providerMetadata.provider || "unknown",
      model: providerMetadata.model || "unknown",
      processingTimeMs,
      soc: {
        ...(alert?.soc || {}),
        mitreAttack: analysisResult.attack_mapping,
        iocs: alert?.soc?.iocs,
        correlation: alert?.soc?.correlation,
        threatIntelligence: alert?.soc?.threatIntelligence,
        providerMetadata,
      },
    };
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
