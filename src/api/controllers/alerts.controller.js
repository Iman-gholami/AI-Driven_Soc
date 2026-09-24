const crypto = require('node:crypto');
const { settings } = require('../../core/config');
const { AppError, ConflictError, InputError, NotFoundError } = require('../../core/errors');
const { summarizeRuleResolution } = require('../../services/analyzer');
const { buildDetectionRuleContext } = require('../../services/contextBuilder');
const { getIncidentSignature } = require('../../services/ruleResolver');
const { createEventHash } = require('../../services/eventHash');
const { normalizeIpv4 } = require('../../services/ipExtractor');
const {
  normalizeAlertPayload,
  getAlertId,
  getAlertSource,
  getAlertSeverity,
} = require('../../services/alertIngest');
const { buildDashboardStats } = require('../../services/dashboardStats');
const {
  toAlertSummary,
  getAiStatus,
  getAiEligibility,
  toPlainObject,
  summarizeTriage,
} = require('../presenters/alertPresenter');
const { OUTCOME_IDS } = require('../../config/dispositionReasons');
const { successResponse, errorResponse } = require('../../utils/response');

const SOC_FIELDS = ['mitreAttack', 'iocs', 'correlation', 'threatIntelligence', 'networkIntelligence'];
const ANALYSIS_SCENARIO = 'signature_rule_v1';

class AlertController {
  constructor({ alertRepository, analyzer }) {
    this.alertRepository = alertRepository;
    this.analyzer = analyzer;
  }

  ingestWebhook = async (req, res) => {
    const requestId = crypto.randomUUID();
    const payloadLength = Number(req.headers['content-length'] || 0);
    if (payloadLength > settings.maxPayloadSizeBytes) {
      return errorResponse(res, 'Payload too large', 413);
    }

    const alerts = normalizeAlertPayload(req.body);
    if (alerts.length === 0) throw new InputError('At least one alert is required');

    req.log.info({ requestId, count: alerts.length }, 'webhook_alert_received');

    const storedAlerts = [];
    for (const alert of alerts) {
      const stored = await this.alertRepository.upsertNewAlert({
        alertId: getAlertId(alert),
        source: getAlertSource(alert),
        severity: getAlertSeverity(alert),
        rawEvent: alert,
        eventHash: createEventHash(alert),
        ruleMatch: await this.resolveRuleMatchForIngest(alert),
      });
      storedAlerts.push(toAlertSummary(stored));
    }

    req.log.info({ requestId, count: storedAlerts.length }, 'webhook_alert_stored');
    return successResponse(res, { count: storedAlerts.length, alerts: storedAlerts }, 'Alerts stored', 201);
  };

  list = async (req, res) => {
    const { triageStatus, outcome } = req.query;
    if (triageStatus && !['open', 'closed'].includes(triageStatus)) {
      throw new InputError('triageStatus must be open or closed');
    }
    if (outcome && !OUTCOME_IDS.includes(outcome)) {
      throw new InputError(`outcome must be one of ${OUTCOME_IDS.join(', ')}`);
    }

    const result = await this.alertRepository.listAlerts({
      triageStatus: triageStatus || undefined,
      outcome: outcome || undefined,
      status: req.query.status,
      aiStatus: req.query.aiStatus,
      severity: req.query.severity,
      source: req.query.source,
      search: req.query.search || req.query.q,
      createdAtFrom: req.query.createdAtFrom || req.query.from,
      createdAtTo: req.query.createdAtTo || req.query.to,
      page: req.query.page,
      limit: req.query.limit,
      sortBy: req.query.sortBy,
      sortDirection: req.query.sortDirection || req.query.order,
    });

    const alerts = result.alerts.map(toAlertSummary);
    req.log.info({ count: alerts.length, filters: result.filters }, 'alerts_listed');
    return successResponse(res, {
      alerts,
      pagination: result.pagination,
      filters: result.filters,
      sort: result.sort,
    });
  };

  dashboardStats = async (req, res) => {
    const result = await this.alertRepository.getDashboardStats({
      createdAtFrom: req.query.createdAtFrom || req.query.from,
      createdAtTo: req.query.createdAtTo || req.query.to,
      recentLimit: req.query.recentLimit,
    });
    const data = buildDashboardStats(result, { toAlertSummary });
    req.log.info({ total: data.totals.alerts, window: result.window }, 'dashboard_stats_loaded');
    return successResponse(res, data);
  };

  get = async (req, res) => {
    const alert = await this.alertRepository.findByAlertId(req.params.id);
    if (!alert) throw new NotFoundError('Alert not found');

    const response = toPlainObject(alert);
    const signature = getIncidentSignature(response.rawEvent || {});
    response.aiStatus = getAiStatus(response);
    response.triage = summarizeTriage(response);
    response.analysisCount = Array.isArray(response.analysis) ? response.analysis.length : 0;
    response.aiEligibility = getAiEligibility({ signature, ruleMatch: response.ruleMatch });

    if (typeof this.analyzer.resolveDetectionRule === 'function') {
      const ruleResolution = await this.analyzer.resolveDetectionRule(response.rawEvent || {});
      response.detectionRule = buildDetectionRuleContext(ruleResolution);
      response.aiEligibility = getAiEligibility({
        signature,
        ruleMatch: summarizeRuleResolution(ruleResolution),
      });
    }

    const requestedSocFields = getRequestedSocFields(req.query);
    if (requestedSocFields.length > 0) {
      response.socFields = Object.fromEntries(
        requestedSocFields.map((field) => [field, response.soc?.[field]]),
      );
    }

    req.log.info({ alertId: req.params.id, socFields: requestedSocFields }, 'alert_retrieved');
    return successResponse(res, response);
  };

  analyze = async (req, res) => {
    const requestId = crypto.randomUUID();
    const alertId = req.params.id;
    const force = req.body?.force === true || req.query.force === 'true' || req.query.force === '1';

    const alert = await this.alertRepository.findByAlertId(alertId);
    if (!alert) throw new NotFoundError('Alert not found');

    if (!force && (alert.aiStatus === 'analyzed' || alert.status === 'analyzed') && alert.fullAnalysis) {
      return successResponse(res, {
        alertId,
        aiStatus: 'analyzed',
        analysis: alert.fullAnalysis,
        ruleMatch: alert.ruleMatch,
        detectionRule: await this.resolveStoredDetectionRuleContext(alert),
        networkIntelligence: alert.soc?.networkIntelligence || null,
        metadata: {
          provider: alert.llmProvider || null,
          model: alert.model || null,
          processingTimeMs: alert.processingTimeMs ?? null,
          cached: true,
          analysisCount: Array.isArray(alert.analysis) ? alert.analysis.length : 1,
        },
      });
    }

    if (alert.aiStatus === 'analyzing') {
      throw new ConflictError('Alert analysis is already in progress', { details: { aiStatus: 'analyzing' } });
    }

    const signature = getIncidentSignature(alert.rawEvent || {});
    if (!signature) {
      return errorResponse(res, 'AI analysis for alerts without a signature is not supported in V1 yet', 422, {
        aiStatus: getAiStatus(alert),
        analysisScenario: ANALYSIS_SCENARIO,
        reason: 'missing_signature',
      });
    }

    const ruleResolution = await this.analyzer.resolveDetectionRule(alert.rawEvent || {});
    if (ruleResolution.status !== 'matched') {
      return errorResponse(res, 'A deterministic detection rule match is required before AI analysis in V1', 422, {
        aiStatus: getAiStatus(alert),
        analysisScenario: ANALYSIS_SCENARIO,
        reason: ruleResolution.reason || ruleResolution.status,
        ruleMatch: summarizeRuleResolution(ruleResolution),
        detectionRule: buildDetectionRuleContext(ruleResolution),
      });
    }

    let analysisStarted = false;
    if (typeof this.alertRepository.markAnalysisStarted === 'function') {
      const startedAlert = await this.alertRepository.markAnalysisStarted(alertId);
      if (!startedAlert) {
        throw new ConflictError('Alert analysis is already in progress', { details: { aiStatus: 'analyzing' } });
      }
      analysisStarted = true;
    }

    try {
      const analyzedResult = await this.analyzer.analyzeStoredAlert(alert, { ruleResolution });
      const updatedAlert = await this.alertRepository.updateAnalysis(alertId, analyzedResult.persistence);

      req.log.info(
        { requestId, alertId, processingTimeMs: analyzedResult.metadata.processingTimeMs, force },
        'alert_analyzed',
      );
      return successResponse(res, {
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
      });
    } catch (error) {
      if (analysisStarted && typeof this.alertRepository.markAnalysisFailed === 'function') {
        await this.alertRepository.markAnalysisFailed(alertId, error).catch((persistenceError) => {
          req.log.error({ requestId, alertId, err: persistenceError }, 'analysis_failure_state_persist_failed');
        });
      }

      const invalidModelOutput = error?.name === 'ZodError';
      throw new AppError(invalidModelOutput ? 'Invalid model output' : 'Alert analysis failed', {
        status: invalidModelOutput ? 502 : 500,
        publicMessage: invalidModelOutput ? 'Invalid model output' : 'Internal error during alert analysis',
        details: { aiStatus: 'failed' },
        cause: error,
      });
    }
  };

  // Ad-hoc analysis of a raw incident payload without persisting it as an alert.
  analyzeIncident = async (req, res) => {
    req.log.info({ keys: Object.keys(req.body || {}).slice(0, 30) }, 'incident_received');
    const response = await this.analyzer.analyzeIncident(req.body || {});
    req.log.info('incident_analyzed');
    return successResponse(res, response);
  };

  ipIntelligence = async (req, res) => {
    const ip = normalizeIpv4(req.params.ip);
    if (!ip) throw new InputError('A valid IPv4 address is required');

    const data = typeof this.analyzer.resolveNetworkIntelligence === 'function'
      ? await this.analyzer.resolveNetworkIntelligence({ src_ip: ip })
      : { status: 'unavailable', reason: 'network_intelligence_not_configured', ips: [] };

    req.log.info({ ip, status: data.status }, 'ip_intelligence_loaded');
    return successResponse(res, data);
  };

  async resolveStoredDetectionRuleContext(alert) {
    if (typeof this.analyzer.resolveDetectionRule !== 'function') {
      return alert.ruleMatch || null;
    }

    try {
      const resolution = await this.analyzer.resolveDetectionRule(alert.rawEvent || {});
      return buildDetectionRuleContext(resolution);
    } catch (_) {
      return alert.ruleMatch || null;
    }
  }

  async resolveRuleMatchForIngest(alert) {
    if (typeof this.analyzer.resolveDetectionRule !== 'function') return undefined;
    const resolution = await this.analyzer.resolveDetectionRule(alert);
    return summarizeRuleResolution(resolution);
  }
}

function getRequestedSocFields(query) {
  const fields = new Set();

  for (const field of SOC_FIELDS) {
    if (query[field] === 'true' || query[field] === '1') fields.add(field);
  }

  const socFields = query.socFields || query.soc;
  if (typeof socFields === 'string') {
    for (const field of socFields.split(',').map((item) => item.trim()).filter(Boolean)) {
      if (SOC_FIELDS.includes(field)) fields.add(field);
    }
  }

  return [...fields];
}

module.exports = { AlertController, getRequestedSocFields };
