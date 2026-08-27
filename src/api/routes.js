const express = require("express");
const crypto = require("crypto");
const { settings } = require("../core/config");
const { IncidentAnalyzer, summarizeRuleResolution } = require("../services/analyzer");
const { buildDetectionRuleContext } = require("../services/contextBuilder");
const { AlertRepository } = require("../repositories/AlertRepository");
const { createEventHash } = require("../services/eventHash");

function createRouter({ analyzer = new IncidentAnalyzer(), alertRepository = new AlertRepository() } = {}) {
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
        const ruleMatch = await resolveRuleMatchForIngest(analyzer, alert);
        const stored = await alertRepository.upsertNewAlert({
          alertId,
          source: getAlertSource(alert),
          severity: getAlertSeverity(alert),
          rawEvent: alert,
          eventHash,
          ruleMatch,
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
        aiStatus: req.query.aiStatus,
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
    let analysisStarted = false;

    try {
      const alert = await alertRepository.findByAlertId(alertId);
      if (!alert) {
        return res.status(404).json({ detail: "Alert not found" });
      }

      if (alert.aiStatus === "analyzing") {
        return res.status(409).json({
          detail: "Alert analysis is already in progress",
          aiStatus: "analyzing",
        });
      }

      if (typeof alertRepository.markAnalysisStarted === "function") {
        const startedAlert = await alertRepository.markAnalysisStarted(alertId);
        if (!startedAlert) {
          return res.status(409).json({
            detail: "Alert analysis is already in progress",
            aiStatus: "analyzing",
          });
        }
        analysisStarted = true;
      }

      const analyzed = await analyzer.analyzeStoredAlert(alert);
      await alertRepository.updateAnalysis(alertId, analyzed.persistence);

      req.log.info({ requestId, alertId, processingTimeMs: analyzed.metadata.processingTimeMs }, "alert_analyzed");
      return res.json({
        alertId,
        aiStatus: "analyzed",
        analysis: analyzed.analysis,
        ruleMatch: analyzed.ruleMatch,
        detectionRule: buildDetectionRuleContext(analyzed.ruleResolution),
        metadata: analyzed.metadata,
      });
    } catch (error) {
      if (analysisStarted && typeof alertRepository.markAnalysisFailed === "function") {
        try {
          await alertRepository.markAnalysisFailed(alertId, error);
        } catch (persistenceError) {
          req.log.error({ requestId, alertId, err: persistenceError }, "analysis_failure_state_persist_failed");
        }
      }

      if (error?.name === "ZodError") {
        req.log.warn({ requestId, alertId, error: error.message }, "invalid_llm_output");
        return res.status(502).json({ detail: "Invalid model output", aiStatus: "failed" });
      }

      req.log.error({ requestId, alertId, err: error }, "alert_analysis_failed");
      return res.status(500).json({ detail: "Internal error during alert analysis", aiStatus: "failed" });
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
      response.aiStatus = getAiStatus(response);
      if (typeof analyzer.resolveDetectionRule === "function") {
        const ruleResolution = await analyzer.resolveDetectionRule(response.rawEvent || {});
        response.detectionRule = buildDetectionRuleContext(ruleResolution);
      }

      const requestedSocFields = getRequestedSocFields(req.query);
      if (requestedSocFields.length > 0) {
        response.socFields = requestedSocFields.reduce((fields, field) => {
          fields[field] = response.soc?.[field];
          return fields;
        }, {});
      }

      req.log.info({ requestId, alertId: req.params.id, socFields: requestedSocFields }, "alert_retrieved");
      return res.json(response);
    } catch (error) {
      req.log.error({ requestId, alertId: req.params.id, err: error }, "alert_retrieve_failed");
      return res.status(500).json({ detail: "Internal error while retrieving alert" });
    }
  });

  return router;
}

async function resolveRuleMatchForIngest(analyzer, alert) {
  if (typeof analyzer.resolveDetectionRule !== "function") return undefined;
  const resolution = await analyzer.resolveDetectionRule(alert);
  return summarizeRuleResolution(resolution);
}

function normalizeAlertPayload(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.alerts)) return payload.alerts;
  if (Array.isArray(payload?.results)) return payload.results;
  if (payload && typeof payload === "object") return [payload];
  return [];
}

function getAlertId(payload) {
  return String(payload?.alertId || payload?.alert_id || payload?.event_id || payload?.sid || payload?.id || crypto.randomUUID());
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
  const summary = {
    alertId: plain.alertId,
    source: plain.source,
    status: plain.status,
    aiStatus: getAiStatus(plain),
    severity: plain.severity || plain.analysis?.severity || "unknown",
    signature: plain.rawEvent?.signature || plain.rawEvent?.Signature || plain.rawEvent?.rule_name || null,
    eventType: plain.rawEvent?.eventtype || null,
    host: plain.rawEvent?.host || null,
    createdAt: plain.createdAt,
    updatedAt: plain.updatedAt,
    eventHash: plain.eventHash,
  };
  if (plain.ruleMatch) summary.ruleMatch = plain.ruleMatch;
  if (plain.processing?.lastError) summary.analysisError = plain.processing.lastError;
  return summary;
}

function getAiStatus(alert) {
  if (alert?.aiStatus) return alert.aiStatus;
  if (alert?.fullAnalysis) return "analyzed";
  return "not_analyzed";
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
