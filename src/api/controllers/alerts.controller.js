const crypto = require('crypto');
const { AlertRepository } = require('../../repositories/AlertRepository');
const defaultAlertRepository = new AlertRepository();
const { successResponse } = require('../../utils/response');

function createGetAllAlerts({ alertRepository = defaultAlertRepository } = {}) {
  return async (req, res) => {
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

      const alerts = result.alerts.map(toAlertSummary);
      req.log.info(
        { requestId, count: alerts.length, filters: result.filters },
        'alerts_listed',
      );

      // Keep the current success envelope while also exposing the legacy
      // top-level list fields used by existing API consumers.
      const data = {
        alerts,
        pagination: result.pagination,
        filters: result.filters,
        sort: result.sort,
      };
      return res.status(200).json({
        success: true,
        message: 'Success',
        data,
        alerts,
        pagination: result.pagination,
        filters: result.filters,
        sort: result.sort,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      req.log.error({ requestId, err: error }, 'alerts_list_failed');
      return res
        .status(500)
        .json({ detail: 'Internal error while listing alerts' });
    }
  };
}

const getAllAlerts = createGetAllAlerts();

function toAlertSummary(alert) {
  const plain = toPlainObject(alert);
  const signature =
    plain.signature ||
    plain.rawEvent?.signature ||
    plain.rawEvent?.Signature ||
    plain.rawEvent?.rule_name ||
    plain.ruleMatch?.title ||
    null;

  const summary = {
    alertId: plain.alertId,
    source: plain.source,
    signature,
    eventType: plain.eventType || plain.rawEvent?.eventtype || null,
    host: plain.host || plain.rawEvent?.host || null,
    status: plain.status,
    aiStatus: getAiStatus(plain),
    aiEligibility: getAiEligibility({ signature, ruleMatch: plain.ruleMatch }),
    severity: plain.severity || plain.analysis?.severity || 'unknown',
    createdAt: plain.createdAt,
    updatedAt: plain.updatedAt,
    eventHash: plain.eventHash,
  };

  if (plain.ruleMatch) summary.ruleMatch = plain.ruleMatch;
  if (plain.processing?.lastError)
    summary.analysisError = plain.processing.lastError;
  return summary;
}

function getAiStatus(alert) {
  if (alert?.aiStatus) return alert.aiStatus;
  if (alert?.status === 'analyzed' || alert?.fullAnalysis) return 'analyzed';
  return 'not_analyzed';
}

function getAiEligibility({ signature, ruleMatch } = {}) {
  if (!signature) {
    return {
      eligible: false,
      scenario: 'signature_rule_v1',
      reason: 'missing_signature',
    };
  }

  if (ruleMatch?.status !== 'matched') {
    return {
      eligible: false,
      scenario: 'signature_rule_v1',
      reason: ruleMatch?.status || ruleMatch?.reason || 'rule_not_matched',
    };
  }

  return {
    eligible: true,
    scenario: 'signature_rule_v1',
    reason: null,
  };
}

function toPlainObject(document) {
  if (!document) return document;
  if (typeof document.toObject === 'function')
    return document.toObject({ getters: true, virtuals: false });
  return { ...document };
}

module.exports = {
  getAllAlerts,
  createGetAllAlerts,
};
