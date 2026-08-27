const crypto = require("crypto");
const { buildContext } = require("./contextBuilder");
const { createEventHash } = require("./eventHash");
const { LLMService } = require("./llmService");
const { RuleResolver } = require("./ruleResolver");
const { createLogger } = require("../core/logging");
const { settings } = require("../core/config");
const { analysisResponseSchema } = require("../models/incidentSchema");
const { AlertRepository } = require("../repositories/AlertRepository");

class IncidentAnalyzer {
  constructor({
    llm = new LLMService(),
    alertRepository = new AlertRepository(),
    ruleResolver = new RuleResolver(),
    logger = createLogger(settings.logLevel),
  } = {}) {
    this.llm = llm;
    this.alertRepository = alertRepository;
    this.ruleResolver = ruleResolver;
    this.logger = logger;
  }

  async analyzeIncident(payload) {
    const analyzed = await this.analyzePayload(payload);

    await this.persistAnalyzedAlert(
      payload,
      analyzed.analysis,
      analyzed.metadata.processingTimeMs,
      analyzed.ruleMatch,
    );

    return analyzed.analysis;
  }

  async analyzeStoredAlert(alert) {
    const rawEvent = alert?.rawEvent || alert || {};
    const analyzed = await this.analyzePayload(rawEvent);
    return {
      ...analyzed,
      persistence: this.buildAnalysisPersistence(
        alert,
        analyzed.analysis,
        analyzed.metadata.processingTimeMs,
        analyzed.ruleMatch,
      ),
    };
  }

  async analyzePayload(payload) {
    const startedAt = Date.now();
    const ruleResolution = await this.resolveDetectionRule(payload);
    const context = buildContext(payload, ruleResolution);
    const result = await this.llm.analyze(context);
    const response = analysisResponseSchema.parse(result);
    const processingTimeMs = Date.now() - startedAt;
    const providerMetadata = this.llm.getMetadata ? this.llm.getMetadata() : {};

    return {
      analysis: response,
      ruleResolution,
      ruleMatch: summarizeRuleResolution(ruleResolution),
      metadata: {
        provider: providerMetadata.provider || "unknown",
        model: providerMetadata.model || "unknown",
        processingTimeMs,
      },
    };
  }

  async resolveDetectionRule(payload) {
    if (!this.ruleResolver || typeof this.ruleResolver.resolve !== "function") {
      return { status: "unavailable", reason: "rule_resolver_not_configured", candidateCount: 0 };
    }

    try {
      return await this.ruleResolver.resolve(payload || {});
    } catch (error) {
      this.logger.warn?.({ err: error }, "Detection rule resolution failed");
      return { status: "unavailable", reason: "rule_resolution_failed", candidateCount: 0 };
    }
  }

  async persistAnalyzedAlert(payload, analysisResult, processingTimeMs, ruleMatch) {
    const eventHash = createEventHash(payload);
    const alertId = getAlertId(payload);

    try {
      await this.alertRepository.upsertAnalyzedAlert({
        alertId,
        source: getAlertSource(payload),
        severity: getSeverity(analysisResult),
        rawEvent: payload,
        eventHash,
        ...this.buildAnalysisPersistence({ rawEvent: payload }, analysisResult, processingTimeMs, ruleMatch),
      });
      this.logger.info({ alertId, eventHash, status: "analyzed" }, "Alert stored successfully");
    } catch (error) {
      this.logger.error({ err: error, alertId, eventHash }, "Alert storage failure");
    }
  }

  buildAnalysisPersistence(alert, analysisResult, processingTimeMs, ruleMatch) {
    const providerMetadata = this.llm.getMetadata ? this.llm.getMetadata() : {};
    return {
      analysis: mapAnalysisSummary(analysisResult),
      fullAnalysis: analysisResult,
      ruleMatch,
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

function summarizeRuleResolution(resolution) {
  if (!resolution) return { status: "unavailable", candidateCount: 0 };

  const summary = {
    status: resolution.status,
    matchType: resolution.matchType || null,
    signature: resolution.signature || null,
    candidateCount: resolution.candidateCount || 0,
    reason: resolution.reason || null,
    resolutionEvidence: resolution.resolutionEvidence || [],
  };

  if (resolution.status === "matched" && resolution.rule) {
    Object.assign(summary, {
      ruleId: resolution.rule.ruleId,
      revision: resolution.rule.revision,
      title: resolution.rule.title,
      protocol: resolution.rule.protocol,
      classtype: resolution.rule.classtype,
      sourceFile: resolution.rule.sourceFile,
    });
  } else if (resolution.candidates) {
    summary.candidates = resolution.candidates;
  }

  return summary;
}

function getAlertId(payload) {
  return String(payload?.alertId || payload?.alert_id || payload?.event_id || payload?.id || crypto.randomUUID());
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

module.exports = { IncidentAnalyzer, mapAnalysisSummary, summarizeRuleResolution };
