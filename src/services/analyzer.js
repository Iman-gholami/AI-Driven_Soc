const crypto = require("crypto");
const { buildContext } = require("./contextBuilder");
const { createEventHash } = require("./eventHash");
const { LLMService } = require("./llmService");
const { NetworkIntelligenceService } = require("./networkIntelligenceService");
const { RuleResolver } = require("./ruleResolver");
const { createLogger } = require("../core/logging");
const { settings } = require("../core/config");
const {
  analysisResponseSchema,
  normalizeAnalysisPayload,
} = require("../models/incidentSchema");
const { AlertRepository } = require("../repositories/AlertRepository");

class IncidentAnalyzer {
  constructor({
    llm = new LLMService(),
    alertRepository = new AlertRepository(),
    ruleResolver = new RuleResolver(),
    networkIntelligence,
    logger = createLogger(settings.logLevel),
  } = {}) {
    this.llm = llm;
    this.alertRepository = alertRepository;
    this.ruleResolver = ruleResolver;
    this.logger = logger;
    this.networkIntelligence =
      networkIntelligence || new NetworkIntelligenceService({ logger });
  }

  async analyzeIncident(payload) {
    const analyzed = await this.analyzePayload(payload);

    await this.persistAnalyzedAlert(
      payload,
      analyzed.analysis,
      analyzed.metadata.processingTimeMs,
      analyzed.ruleMatch,
      analyzed.networkIntelligence,
    );

    return analyzed.analysis;
  }

  async analyzeStoredAlert(alert, { ruleResolution } = {}) {
    const rawEvent = alert?.rawEvent || alert || {};
    const analyzed = await this.analyzePayload(rawEvent, { ruleResolution });
    return {
      ...analyzed,
      persistence: this.buildAnalysisPersistence(
        alert,
        analyzed.analysis,
        analyzed.metadata.processingTimeMs,
        analyzed.ruleMatch,
        analyzed.networkIntelligence,
      ),
    };
  }

  async analyzePayload(payload, { ruleResolution: providedRuleResolution } = {}) {
    const startedAt = Date.now();
    const ruleResolution = providedRuleResolution || await this.resolveDetectionRule(payload);
    const networkIntelligence = await this.resolveNetworkIntelligence(payload);
    const context = buildContext(payload, ruleResolution, networkIntelligence);
    const result = await this.llm.analyze(context);
    const normalized = normalizeAnalysisPayload(result);
    const response = analysisResponseSchema.parse(normalized);
    const processingTimeMs = Date.now() - startedAt;
    const providerMetadata = this.llm.getMetadata ? this.llm.getMetadata() : {};

    return {
      analysis: response,
      ruleResolution,
      ruleMatch: summarizeRuleResolution(ruleResolution),
      networkIntelligence,
      metadata: {
        provider: providerMetadata.provider || "unknown",
        model: providerMetadata.model || "unknown",
        processingTimeMs,
        enrichmentStatus: networkIntelligence?.status || "unavailable",
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

  async resolveNetworkIntelligence(payload) {
    if (!this.networkIntelligence || typeof this.networkIntelligence.enrich !== "function") {
      return {
        status: "unavailable",
        reason: "network_intelligence_not_configured",
        generatedAt: new Date().toISOString(),
        ips: [],
        correlations: [],
      };
    }

    try {
      return await this.networkIntelligence.enrich(payload || {});
    } catch (error) {
      this.logger.warn?.({ err: error }, "Network intelligence enrichment failed");
      return {
        status: "unavailable",
        reason: "network_intelligence_failed",
        generatedAt: new Date().toISOString(),
        ips: [],
        correlations: [],
      };
    }
  }

  async persistAnalyzedAlert(
    payload,
    analysisResult,
    processingTimeMs,
    ruleMatch,
    networkIntelligence,
  ) {
    const eventHash = createEventHash(payload);
    const alertId = getAlertId(payload);

    try {
      await this.alertRepository.upsertAnalyzedAlert({
        alertId,
        source: getAlertSource(payload),
        severity: getSeverity(analysisResult),
        rawEvent: payload,
        eventHash,
        ...this.buildAnalysisPersistence(
          { rawEvent: payload },
          analysisResult,
          processingTimeMs,
          ruleMatch,
          networkIntelligence,
        ),
      });
      this.logger.info({ alertId, eventHash, status: "analyzed" }, "Alert stored successfully");
    } catch (error) {
      this.logger.error({ err: error, alertId, eventHash }, "Alert storage failure");
    }
  }

  buildAnalysisPersistence(
    alert,
    analysisResult,
    processingTimeMs,
    ruleMatch,
    networkIntelligence,
  ) {
    const providerMetadata = this.llm.getMetadata ? this.llm.getMetadata() : {};
    const hasNetworkSnapshot = Boolean(networkIntelligence);

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
        iocs: hasNetworkSnapshot
          ? buildNetworkIocs(networkIntelligence)
          : alert?.soc?.iocs,
        correlation: hasNetworkSnapshot
          ? networkIntelligence.correlations || []
          : alert?.soc?.correlation,
        threatIntelligence: hasNetworkSnapshot
          ? buildThreatIntelligenceSnapshot(networkIntelligence)
          : alert?.soc?.threatIntelligence,
        networkIntelligence: hasNetworkSnapshot
          ? networkIntelligence
          : alert?.soc?.networkIntelligence,
        providerMetadata,
      },
    };
  }
}

function buildNetworkIocs(networkIntelligence) {
  const ips = Array.isArray(networkIntelligence?.ips) ? networkIntelligence.ips : [];
  return ips.map((item) => ({
    type: "ip",
    value: item.ip,
    roles: item.roles || [],
    scope: item.scope || "unknown",
    organizationalAsset: Boolean(item.asset?.owned),
    organization: item.asset?.organization || null,
    directThreatMatch: Boolean(item.threat?.directMatch),
    relationshipThreatMatch: Boolean(item.threat?.relationshipMatch),
  }));
}

function buildThreatIntelligenceSnapshot(networkIntelligence) {
  const ips = Array.isArray(networkIntelligence?.ips) ? networkIntelligence.ips : [];

  return {
    status: networkIntelligence?.status || "unavailable",
    dataset: networkIntelligence?.sources?.threatDataset || null,
    indicators: ips
      .filter((item) => item.threat?.directMatch || item.threat?.relationshipMatch)
      .map((item) => ({
        ip: item.ip,
        roles: item.roles || [],
        directMatch: Boolean(item.threat?.directMatch),
        relationshipMatch: Boolean(item.threat?.relationshipMatch),
        directObservationCount: Number(item.threat?.directObservationCount || 0),
        relationshipObservationCount: Number(item.threat?.relationshipObservationCount || 0),
        direct: item.threat?.direct || null,
        relationship: item.threat?.relationship || null,
      })),
  };
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
  return String(
    payload?.alertId ||
      payload?.alert_id ||
      payload?.event_id ||
      payload?.id ||
      crypto.randomUUID(),
  );
}

function getAlertSource(payload) {
  return String(payload?.source || payload?.sourcetype || payload?.index || "splunk");
}

function mapAnalysisSummary(analysisResult) {
  return {
    severity: getSeverity(analysisResult),
    summary: getSummary(analysisResult),
    recommendations: analysisResult.recommended_investigation_steps || [],
    verdict: analysisResult.verdict || "UNKNOWN",
    confidence: Number(analysisResult.risk_assessment?.confidence || 0),
    action: analysisResult.analyst_decision?.action || "UNKNOWN",
    analyzedAt: new Date(),
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
  if (
    typeof analysisResult.one_line_summary === "string" &&
    analysisResult.one_line_summary.trim()
  ) {
    return analysisResult.one_line_summary.trim();
  }

  const incidentSummary = analysisResult.incident_summary;
  if (typeof incidentSummary === "string") return incidentSummary;
  if (incidentSummary && typeof incidentSummary === "object") {
    return (
      incidentSummary.what_happened ||
      incidentSummary.summary ||
      incidentSummary.description ||
      JSON.stringify(undefined)
    );
  }
  return analysisResult.final_soc_note || "";
}

module.exports = {
  IncidentAnalyzer,
  mapAnalysisSummary,
  summarizeRuleResolution,
  buildNetworkIocs,
  buildThreatIntelligenceSnapshot,
};
