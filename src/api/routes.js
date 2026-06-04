const express = require("express");
const crypto = require("crypto");
const { settings } = require("../core/config");
const { IncidentAnalyzer } = require("../services/analyzer");
const { AlertRepository } = require("../repositories/AlertRepository");
const { AlertAnalysisRepository } = require("../repositories/AlertAnalysisRepository");
const { createEventHash } = require("../services/eventHash");

function createRouter({
  analyzer = new IncidentAnalyzer(),
  alertRepository = new AlertRepository(),
  alertAnalysisRepository = new AlertAnalysisRepository(),
} = {}) {
  const router = express.Router();

  router.get("/health", (_, res) => {
    res.json({ status: "ok" });
  });

  router.post("/analyze-incident", async (req, res) => {
    const requestId = crypto.randomUUID();
    const payloadLength = Number(req.headers["content-length"] || 0);

    if (payloadLength > settings.maxPayloadSizeBytes) {
      return res.status(413).json({ detail: "Payload too large" });
    }

    req.log.info({ requestId, keys: Object.keys(req.body || {}).slice(0, 30) }, "incident_received");

    try {
      const response = await analyzer.analyzeIncident(req.body || {});
      req.log.info({ requestId }, "incident_analyzed");
      return res.json(response);
    } catch (error) {
      if (error?.name === "ZodError") {
        req.log.warn({ requestId, error: error.message }, "invalid_llm_output");
        return res.status(502).json({ detail: "Invalid model output" });
      }

      req.log.error({ requestId, err: error }, "analysis_failed");
      return res.status(500).json({ detail: "Internal error during analysis" });
    }
  });

  router.post("/webhook-alert", async (req, res) => {
    const requestId = crypto.randomUUID();
    const payloadLength = Number(req.headers["content-length"] || 0);

    if (payloadLength > settings.maxPayloadSizeBytes) {
      return res.status(413).json({ detail: "Payload too large" });
    }

    const alerts = normalizeAlertPayload(req.body);
    if (alerts.length === 0) {
      return res.status(400).json({ detail: "At least one alert is required" });
    }

    req.log.info({ requestId, count: alerts.length }, "webhook_alert_received");

    try {
      const storedAlerts = [];
      for (const alert of alerts) {
        const eventHash = createEventHash(alert);
        const alertId = getAlertId(alert);
        const stored = await alertRepository.upsertNewAlert({
          alertId,
          source: getAlertSource(alert),
          severity: getAlertSeverity(alert),
          rawEvent: alert,
          eventHash,
        });
        storedAlerts.push(toAlertSummary(stored));
      }

      req.log.info({ requestId, count: storedAlerts.length }, "webhook_alert_stored");
      return res.status(201).json({ count: storedAlerts.length, alerts: storedAlerts });
    } catch (error) {
      req.log.error({ requestId, err: error }, "webhook_alert_storage_failed");
      return res.status(500).json({ detail: "Internal error during alert storage" });
    }
  });

  router.get("/alerts", async (req, res) => {
    const requestId = crypto.randomUUID();

    try {
      const result = await alertRepository.listAlerts({
        status: req.query.status,
        severity: req.query.severity,
        createdAtFrom: req.query.createdAtFrom || req.query.from,
        createdAtTo: req.query.createdAtTo || req.query.to,
        page: req.query.page,
        limit: req.query.limit,
      });

      req.log.info({ requestId, count: result.alerts.length, filters: result.filters }, "alerts_listed");
      return res.json({
        ...result,
        alerts: result.alerts.map(toAlertSummary),
      });
    } catch (error) {
      req.log.error({ requestId, err: error }, "alerts_list_failed");
      return res.status(500).json({ detail: "Internal error while listing alerts" });
    }
  });

  router.post("/alerts/:id/analyze", async (req, res) => {
    const requestId = crypto.randomUUID();
    const alertId = req.params.id;

    try {
      const alert = await alertRepository.findByAlertId(alertId);
      if (!alert) {
        return res.status(404).json({ detail: "Alert not found" });
      }

      const analyzed = await analyzer.analyzeStoredAlert(alert);
      const attemptNumber = (alert.analysisCount || 0) + 1;
      const completedAt = new Date();
      const analysisRecord = await alertAnalysisRepository.createForAlert(alert, {
        ...analyzed.persistence,
        processing: { attemptNumber, completedAt },
      });
      await alertRepository.incrementAnalysisCount(alertId);
      await alertRepository.updateLatestAnalysisReference(alertId, {
        analysisId: analysisRecord._id || analysisRecord.id,
        severity: analyzed.persistence.analysis?.severity,
        analyzedAt: completedAt,
        attemptNumber,
      });

      req.log.info({ requestId, alertId, analysisId: analysisRecord._id || analysisRecord.id, processingTimeMs: analyzed.metadata.processingTimeMs }, "alert_analyzed");
      return res.json({
        alertId,
        analysis: analyzed.analysis,
        metadata: analyzed.metadata,
        latestAnalysis: toAnalysisResponse(analysisRecord),
      });
    } catch (error) {
      if (error?.name === "ZodError") {
        req.log.warn({ requestId, alertId, error: error.message }, "invalid_llm_output");
        return res.status(502).json({ detail: "Invalid model output" });
      }

      req.log.error({ requestId, alertId, err: error }, "alert_analysis_failed");
      return res.status(500).json({ detail: "Internal error during alert analysis" });
    }
  });

  router.get("/alerts/:id", async (req, res) => {
    const requestId = crypto.randomUUID();

    try {
      const alert = await alertRepository.findByAlertId(req.params.id);
      if (!alert) {
        return res.status(404).json({ detail: "Alert not found" });
      }

      const response = toPlainObject(alert);
      const [latestAnalysis, analyses] = await Promise.all([
        alert.latestAnalysisId ? alertAnalysisRepository.findById(alert.latestAnalysisId) : alertAnalysisRepository.findLatestByAlertId(req.params.id),
        isTruthy(req.query.includeAnalyses) ? alertAnalysisRepository.listByAlertId(req.params.id) : Promise.resolve(undefined),
      ]);

      response.latestAnalysis = toAnalysisResponse(latestAnalysis);
      if (analyses) response.analyses = analyses.map(toAnalysisResponse);

      const requestedSocFields = getRequestedSocFields(req.query);
      if (requestedSocFields.length > 0) {
        const socSource = response.latestAnalysis?.soc || {};
        response.socFields = requestedSocFields.reduce((fields, field) => {
          fields[field] = socSource[field];
          return fields;
        }, {});
      }

      req.log.info({ requestId, alertId: req.params.id, socFields: requestedSocFields, includeAnalyses: Boolean(analyses) }, "alert_retrieved");
      return res.json(response);
    } catch (error) {
      req.log.error({ requestId, alertId: req.params.id, err: error }, "alert_retrieve_failed");
      return res.status(500).json({ detail: "Internal error while retrieving alert" });
    }
  });

  return router;
}

function normalizeAlertPayload(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.alerts)) return payload.alerts;
  if (Array.isArray(payload?.results)) return payload.results;
  if (payload && typeof payload === "object") return [payload];
  return [];
}

function getAlertId(payload) {
  return String(payload?.alertId || payload?.alert_id || payload?.sid || payload?.id || crypto.randomUUID());
}

function getAlertSource(payload) {
  return String(payload?.source || payload?.sourcetype || payload?.index || payload?.app || "splunk");
}

function getAlertSeverity(payload) {
  return payload?.severity ? String(payload.severity) : undefined;
}

function toPlainObject(document) {
  if (!document) return document;
  if (typeof document.toObject === "function") return document.toObject({ getters: true, virtuals: false });
  return { ...document };
}

function toAlertSummary(alert) {
  const plain = toPlainObject(alert);
  const latestAnalysis = toAnalysisResponse(plain.latestAnalysis || plain.latestAnalysisId);
  return {
    alertId: plain.alertId,
    source: plain.source,
    status: plain.status,
    severity: plain.severity || latestAnalysis?.analysis?.severity || "unknown",
    createdAt: plain.createdAt,
    updatedAt: plain.updatedAt,
    eventHash: plain.eventHash,
    analysisCount: plain.analysisCount || 0,
    lastAnalyzedAt: plain.lastAnalyzedAt,
    latestAnalysis,
  };
}

function toAnalysisResponse(analysis) {
  if (!analysis || typeof analysis !== "object") return undefined;
  const plain = toPlainObject(analysis);
  if (!plain.analysis && !plain.fullAnalysis && !plain.alertId) return undefined;
  return {
    id: plain._id || plain.id,
    alertId: plain.alertId,
    analysis: plain.analysis,
    fullAnalysis: plain.fullAnalysis,
    llmProvider: plain.llmProvider,
    model: plain.model,
    processingTimeMs: plain.processingTimeMs,
    soc: plain.soc,
    processing: plain.processing,
    createdAt: plain.createdAt,
    updatedAt: plain.updatedAt,
  };
}

function isTruthy(value) {
  return value === true || value === "true" || value === "1";
}

function getRequestedSocFields(query) {
  const allowed = ["mitreAttack", "iocs", "correlation", "threatIntelligence"];
  const fields = new Set();

  for (const field of allowed) {
    if (query[field] === "true" || query[field] === "1") fields.add(field);
  }

  const socFields = query.socFields || query.soc;
  if (typeof socFields === "string") {
    for (const field of socFields.split(",").map((item) => item.trim()).filter(Boolean)) {
      if (allowed.includes(field)) fields.add(field);
    }
  }

  return [...fields];
}

const router = createRouter();

module.exports = { router, createRouter, normalizeAlertPayload, getRequestedSocFields };
