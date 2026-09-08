const express = require('express');
const crypto = require('crypto');
const { settings } = require('../core/config');
const {
  IncidentAnalyzer,
  summarizeRuleResolution,
} = require('../services/analyzer');
const { buildDetectionRuleContext } = require('../services/contextBuilder');
const { getIncidentSignature } = require('../services/ruleResolver');
const { AlertRepository } = require('../repositories/AlertRepository');
const { createEventHash } = require('../services/eventHash');
const { normalizeIpv4 } = require('../services/ipExtractor');
const {
  createGetAllAlerts,
  toAlertSummary,
  getAiStatus,
  getAiEligibility,
  toPlainObject,
} = require('./controllers/alerts.controller');
const ruleController = require('./controllers/rules.controller');
const mitreController = require('./controllers/mitre.controller');
const multer = require('multer');
const { successResponse } = require('../utils/response');
const {
  CopilotService,
  CopilotInputError,
  CopilotPlannerError,
  CopilotQueryError,
} = require('../services/copilotService');

const upload = multer({ dest: 'uploads/' });

function createRouter({
  analyzer = new IncidentAnalyzer(),
  alertRepository = new AlertRepository(),
  copilot = new CopilotService(),
} = {}) {
  const router = express.Router();

  router.get('/health', (_req, res) => {
    res.json({ status: 'ok' });
  });

  router.get('/copilot/schema', async (req, res) => {
    try {
      const data = await copilot.describeSchema(req.query.dataset || undefined);
      return successResponse(res, data);
    } catch (error) {
      req.log.error({ err: error }, 'copilot_schema_failed');
      return res.status(400).json({ detail: 'Unknown or unavailable SOC dataset' });
    }
  });

  router.get('/copilot/tools', async (req, res) => {
    try {
      return successResponse(res, await copilot.listTools());
    } catch (error) {
      req.log.error({ err: error }, 'copilot_tools_failed');
      return res.status(500).json({ detail: 'Unable to load SOC Copilot tools' });
    }
  });

  router.post('/copilot/query', async (req, res) => {
    const requestId = crypto.randomUUID();

    try {
      const data = await copilot.query(req.body?.message, { history: req.body?.history });
      req.log.info(
        {
          requestId,
          supported: data.supported,
          tool: data.tool,
          dataset: data.queryPlan?.dataset || null,
          operation: data.queryPlan?.operation || null,
          batchSize: Array.isArray(data.queryPlan?.queries) ? data.queryPlan.queries.length : 0,
        },
        'copilot_query_completed',
      );
      return successResponse(res, data);
    } catch (error) {
      if (error instanceof CopilotInputError) {
        return res.status(400).json({ detail: error.message });
      }

      if (error instanceof CopilotPlannerError) {
        req.log.warn({ requestId, err: error.cause || error }, 'copilot_planning_failed');
        return res.status(502).json({ detail: 'The configured model could not produce a valid SOC query plan' });
      }

      if (error instanceof CopilotQueryError) {
        req.log.warn({ requestId, err: error.cause || error }, 'copilot_query_rejected');
        return res.status(422).json({ detail: 'The requested SOC query is not permitted or cannot be executed' });
      }

      req.log.error({ requestId, err: error }, 'copilot_query_failed');
      return res.status(500).json({ detail: 'Internal error while processing SOC Copilot query' });
    }
  });

  router.post('/analyze-incident', async (req, res) => {
    const requestId = crypto.randomUUID();
    req.log.info(
      { requestId, keys: Object.keys(req.body || {}).slice(0, 30) },
     'incident_received',
    );

    try {
      const response = await analyzer.analyzeIncident(req.body || {});
      req.log.info({ requestId }, 'incident_analyzed');
      return successResponse(res, response);
    } catch (error) {
      if (error?.name === 'ZodError') {
        req.log.warn({ requestId, error: error.message }, 'invalid_llm_output');
        return res.status(502).json({ detail: 'Invalid model output' });
      }

      req.log.error({ requestId, err: error }, 'analysis_failed');
      return res.status(500).json({ detail: 'Internal error during analysis' });
    }
  });

  router.post('/webhook-alert', async (req, res) => {
    const requestId = crypto.randomUUID();
    const payloadLength = Number(req.headers['content-length'] || 0);

    if (payloadLength > settings.maxPayloadSizeBytes) {
      return res.status(413).json({ detail: 'Payload too large' });
    }

    const alerts = normalizeAlertPayload(req.body);
    if (alerts.length === 0) {
      return res.status(400).json({ detail: 'At least one alert is required' });
    }

    req.log.info({ requestId, count: alerts.length }, 'webhook_alert_received');

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

      req.log.info({ requestId, count: storedAlerts.length }, 'webhook_alert_stored');
      return res.status(201).json({ count: storedAlerts.length, alerts: storedAlerts });
    } catch (error) {
      req.log.error({ requestId, err: error }, 'webhook_alert_storage_failed');
      return res.status(500).json({ detail: 'Internal error during alert storage' });
    }
  });

  router.get('/alerts', createGetAllAlerts({ alertRepository }));

  router.get('/dashboard/stats', async (req, res) => {
    const requestId = crypto.randomUUID();
    try {
      const result = await alertRepository.getDashboardStats({
        createdAtFrom: req.query.createdAtFrom || req.query.from,
        createdAtTo: req.query.createdAtTo || req.query.to,
        recentLimit: req.query.recentLimit,
      });
      const summary = result.summary;
      const total = Number(summary.total || 0);
      const analyzed = Number(summary.analyzed || 0);
      const weightedSeverity =
        Number(summary.critical || 0) * 100 +
        Number(summary.high || 0) * 75 +
        Number(summary.medium || 0) * 50 +
        Number(summary.low || 0) * 25 +
        Number(summary.info || 0) * 10 +
        Number(summary.unknown || 0) * 10;
      const severityPressureIndex = total ? Math.round(weightedSeverity / total) : 0;
      const mitreCoveragePercent = analyzed
        ? Math.round((Number(result.mitre.mappedAlertCount || 0) / analyzed) * 100)
        : 0;

      const data = {
        window: result.window,
        totals: {
          alerts: total,
          uniqueHosts: Number(summary.uniqueHosts || 0),
          sources: result.sources.length,
        },
        severity: {
          critical: Number(summary.critical || 0),
          high: Number(summary.high || 0),
          medium: Number(summary.medium || 0),
          low: Number(summary.low || 0),
          info: Number(summary.info || 0),
          unknown: Number(summary.unknown || 0),
        },
        aiStatus: {
          analyzed,
          analyzing: Number(summary.analyzing || 0),
          failed: Number(summary.failed || 0),
          notAnalyzed: Number(summary.notAnalyzed || 0),
        },
        sources: result.sources,
        performance: {
          aiCoveragePercent: percent(analyzed, total),
          ruleMatchCoveragePercent: percent(Number(summary.matchedRules || 0), total),
          avgProcessingTimeMs: Math.round(Number(summary.avgProcessingTimeMs || 0)),
        },
        posture: {
          severityPressureIndex,
          matchedRules: Number(summary.matchedRules || 0),
        },
        mitre: {
          techniqueCount: Number(result.mitre.techniqueCount || 0),
          mappedAlertCount: Number(result.mitre.mappedAlertCount || 0),
          analyzedAlertCount: analyzed,
          coveragePercent: mitreCoveragePercent,
        },
        recentAlerts: result.recentAlerts.map(toAlertSummary),
      };

      req.log.info({ requestId, total, window: result.window }, 'dashboard_stats_loaded');
      return successResponse(res, data);
    } catch (error) {
      req.log.error({ requestId, err: error }, 'dashboard_stats_failed');
      return res.status(500).json({ detail: 'Internal error while loading dashboard statistics' });
    }
  });

  router.post('/alerts/:id/analyze', async (req, res) => {
    const requestId = crypto.randomUUID();
    const alertId = req.params.id;
    const force = req.body?.force === true || req.query.force === 'true' || req.query.force === '1';
    let analysisStarted = false;

    try {
      const alert = await alertRepository.findByAlertId(alertId);
      if (!alert) {
        return res.status(404).json({ detail: 'Alert not found' });
      }

      if (!force && (alert.aiStatus === 'analyzed' || alert.status === 'analyzed') && alert.fullAnalysis) {
        const data = {
          alertId,
          aiStatus: 'analyzed',
          analysis: alert.fullAnalysis,
          ruleMatch: alert.ruleMatch,
          detectionRule: await resolveStoredDetectionRuleContext(analyzer, alert),
          networkIntelligence: alert.soc?.networkIntelligence || null,
          metadata: {
            provider: alert.llmProvider || null,
            model: alert.model || null,
            processingTimeMs: alert.processingTimeMs ?? null,
            cached: true,
            analysisCount: Array.isArray(alert.analysis) ? alert.analysis.length : 1,
          },
        };
        return res.status(200).json({
          success: true,
          message: 'Success',
          data,
          ...data,
          timestamp: new Date().toISOString(),
        });
      }

      if (alert.aiStatus === 'analyzing') {
        return res.status(409).json({
          detail: 'Alert analysis is already in progress',
          aiStatus: 'analyzing',
        });
      }

      const signature = getIncidentSignature(alert.rawEvent || {});
      if (!signature) {
        return res.status(422).json({
          detail: 'AI analysis for alerts without a signature is not supported in V1 yet',
          aiStatus: getAiStatus(alert),
          analysisScenario: 'signature_rule_v1',
          reason: 'missing_signature',
        });
      }

      const ruleResolution = await analyzer.resolveDetectionRule(alert.rawEvent || {});
      if (ruleResolution.status !== 'matched') {
        return res.status(422).json({
          detail: 'A deterministic detection rule match is required before AI analysis in V1',
          aiStatus: getAiStatus(alert),
          analysisScenario: 'signature_rule_v1',
          reason: ruleResolution.reason || ruleResolution.status,
          ruleMatch: summarizeRuleResolution(ruleResolution),
          detectionRule: buildDetectionRuleContext(ruleResolution),
        });
      }

      if (typeof alertRepository.markAnalysisStarted === 'function') {
        const startedAlert = await alertRepository.markAnalysisStarted(alertId);
        if (!startedAlert) {
          return res.status(409).json({
            detail: 'Alert analysis is already in progress',
            aiStatus: 'analyzing',
          });
        }
        analysisStarted = true;
      }

      const analyzedResult = await analyzer.analyzeStoredAlert(alert, { ruleResolution });
      const updatedAlert = await alertRepository.updateAnalysis(alertId, analyzedResult.persistence);

      req.log.info(
        {
          requestId,
          alertId,
          processingTimeMs: analyzedResult.metadata.processingTimeMs,
          force,
        },
        'alert_analyzed',
      );
      const data = {
        alertId,
        aiStatus: 'analyzed',
        analysis: analyzedResult.analysis,
        ruleMatch: analyzedResult.ruleMatch,
        detectionRule: buildDetectionRuleContext(analyzedResult.ruleResolution),
        networkIntelligence: analyzedResult.networkIntelligence || null,
        metadata: {
          ...analyzedResult.metadata,
          cached: false,
          analysisCount: Array.isArray(updatedAlert?.analysis)
            ? updatedAlert.analysis.length
            : (Array.isArray(alert.analysis) ? alert.analysis.length + 1 : 1),
        },
      };
      return res.status(200).json({
        success: true,
        message: 'Success',
        data,
        ...data,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      if (analysisStarted && typeof alertRepository.markAnalysisFailed === 'function') {
        try {
          await alertRepository.markAnalysisFailed(alertId, error);
        } catch (persistenceError) {
          req.log.error(
            { requestId, alertId, err: persistenceError },
            'analysis_failure_state_persist_failed',
          );
        }
      }

      if (error?.name === 'ZodError') {
        req.log.warn(
          { requestId, alertId, error: error.message },
          'invalid_llm_output',
        );
        return res.status(502).json({ detail: 'Invalid model output', aiStatus: 'failed' });
      }

      req.log.error({ requestId, alertId, err: error }, 'alert_analysis_failed');
      return res.status(500).json({
        detail: 'Internal error during alert analysis',
        aiStatus: 'failed',
      });
    }
  });

  router.get('/intelligence/ip/:ip', async (req, res) => {
    const requestId = crypto.randomUUID();
    const ip = normalizeIpv4(req.params.ip);

    if (!ip) {
      return res.status(400).json({ detail: 'A valid IPv4 address is required' });
    }

    try {
      const data = typeof analyzer.resolveNetworkIntelligence === 'function'
        ? await analyzer.resolveNetworkIntelligence({ src_ip: ip })
        : { status: 'unavailable', reason: 'network_intelligence_not_configured', ips: [] };

      req.log.info({ requestId, ip, status: data.status }, 'ip_intelligence_loaded');
      return successResponse(res, data);
    } catch (error) {
      req.log.error({ requestId, ip, err: error }, 'ip_intelligence_failed');
      return res.status(500).json({ detail: 'Internal error while loading IP intelligence' });
    }
  });

  router.get('/alerts/:id', async (req, res) => {
    const requestId = crypto.randomUUID();

    try {
      const alert = await alertRepository.findByAlertId(req.params.id);
      if (!alert) {
        return res.status(404).json({ detail: 'Alert not found' });
      }

      const response = toPlainObject(alert);
      response.aiStatus = getAiStatus(response);
      response.analysisCount = Array.isArray(response.analysis) ? response.analysis.length : 0;
      response.aiEligibility = getAiEligibility({
        signature: getIncidentSignature(response.rawEvent || {}),
        ruleMatch: response.ruleMatch,
      });

      if (typeof analyzer.resolveDetectionRule === 'function') {
        const ruleResolution = await analyzer.resolveDetectionRule(response.rawEvent || {});
        response.detectionRule = buildDetectionRuleContext(ruleResolution);
        response.aiEligibility = getAiEligibility({
          signature: getIncidentSignature(response.rawEvent || {}),
          ruleMatch: summarizeRuleResolution(ruleResolution),
        });
      }

      const requestedSocFields = getRequestedSocFields(req.query);
      if (requestedSocFields.length > 0) {
        response.socFields = requestedSocFields.reduce((fields, field) => {
          fields[field] = response.soc?.[field];
          return fields;
        }, {});
      }

      req.log.info(
        { requestId, alertId: req.params.id, socFields: requestedSocFields },
        'alert_retrieved',
      );
      return res.json(response);
    } catch (error) {
      req.log.error({ requestId, alertId: req.params.id, err: error }, 'alert_retrieve_failed');
      return res.status(500).json({ detail: 'Internal error while retrieving alert' });
    }
  });

  // Rule-level MITRE ATT&CK coverage.
  router.get('/mitre/coverage', mitreController.getCoverage.bind(mitreController));
  router.post('/mitre/coverage/rebuild', mitreController.rebuildCoverage.bind(mitreController));
  router.get('/mitre/techniques/:techniqueId', mitreController.getTechnique.bind(mitreController));
  router.get('/mitre/techniques/:techniqueId/rules', mitreController.getTechniqueRules.bind(mitreController));

  // Detection rules use the same DetectionRule model/repository/parser as the AI resolver.
  router.post('/rules/import', upload.single('rulesFile'), ruleController.importRules.bind(ruleController));
  router.get('/rules', ruleController.getRules.bind(ruleController));
  router.get('/rules/:ruleId', ruleController.getRuleById.bind(ruleController));
  router.delete('/rules/:ruleId', ruleController.deleteRule.bind(ruleController));

  // Backward-compatible import alias.
  router.post('/import', upload.single('rulesFile'), ruleController.importRules.bind(ruleController));

  router.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    req.log?.error({ err: error }, 'unhandled_route_error');
    return res.status(500).json({ detail: 'Internal server error' });
  });

  return router;
}

async function resolveStoredDetectionRuleContext(analyzer, alert) {
  if (typeof analyzer.resolveDetectionRule !== 'function') {
    return alert.ruleMatch || null;
  }

  try {
    const resolution = await analyzer.resolveDetectionRule(alert.rawEvent || {});
    return buildDetectionRuleContext(resolution);
  } catch (_) {
    return alert.ruleMatch || null;
  }
}

async function resolveRuleMatchForIngest(analyzer, alert) {
  if (typeof analyzer.resolveDetectionRule !== 'function') return undefined;
  const resolution = await analyzer.resolveDetectionRule(alert);
  return summarizeRuleResolution(resolution);
}

function normalizeAlertPayload(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.alerts)) return payload.alerts;
  if (Array.isArray(payload?.results)) return payload.results;
  if (payload && typeof payload === 'object') return [payload];
  return [];
}

function getAlertId(payload) {
  return String(
    payload?.alertId ||
      payload?.alert_id ||
      payload?.event_id ||
      payload?.sid ||
      payload?.id ||
      crypto.randomUUID(),
  );
}

function getAlertSource(payload) {
  return String(
    payload?.source ||
      payload?.sourcetype ||
      payload?.index ||
      payload?.app ||
      'splunk',
  );
}

function getAlertSeverity(payload) {
  return payload?.severity ? String(payload.severity).toLowerCase() : undefined;
}

function getRequestedSocFields(query) {
  const allowed = ['mitreAttack', 'iocs', 'correlation', 'threatIntelligence', 'networkIntelligence'];
  const fields = new Set();

  for (const field of allowed) {
    if (query[field] === 'true' || query[field] === '1') fields.add(field);
  }

  const socFields = query.socFields || query.soc;
  if (typeof socFields === 'string') {
    for (const field of socFields
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean)) {
      if (allowed.includes(field)) fields.add(field);
    }
  }

  return [...fields];
}

function percent(part, total) {
  if (!total) return 0;
  return Math.round((part / total) * 100);
}

const router = createRouter();

module.exports = {
  router,
  createRouter,
  normalizeAlertPayload,
  getRequestedSocFields,
};
