const { currentTriage } = require('../../investigation/triageReducer');

// Shapes persisted alert documents into the summaries the panel and API clients consume.
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
    severity: plain.severity && plain.severity !== 'unknown'
      ? plain.severity
      : (getLatestAnalysis(plain)?.severity || 'unknown'),
    createdAt: plain.createdAt,
    updatedAt: plain.updatedAt,
    eventHash: plain.eventHash,
    triage: summarizeTriage(plain),
  };

  if (plain.processingTimeMs !== undefined && plain.processingTimeMs !== null) summary.processingTimeMs = plain.processingTimeMs;
  if (plain.ruleMatch) summary.ruleMatch = plain.ruleMatch;
  if (plain.processing?.lastError) summary.analysisError = plain.processing.lastError;
  if (plain.fullAnalysis?.risk_assessment || plain.fullAnalysis?.attack_mapping) {
    summary.fullAnalysis = {
      risk_assessment: plain.fullAnalysis?.risk_assessment,
      attack_mapping: plain.fullAnalysis?.attack_mapping,
    };
  }
  if (Array.isArray(plain.analysis) && plain.analysis.length > 0) {
    summary.analysis = plain.analysis;
  }
  return summary;
}

function toIso(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

// Triage summary for lists and detail views. Alerts without a projection (created before investigations
// existed) are reported as open at version 0.
function summarizeTriage(alert) {
  const triage = currentTriage(alert);
  const analyses = Array.isArray(alert?.analysis) ? alert.analysis : [];
  const latestAnalyzedAt = analyses.length ? toIso(analyses[analyses.length - 1]?.analyzedAt) : null;
  const reviewedRef = triage.review?.analysisRef || null;

  return {
    status: triage.status,
    version: triage.version,
    outcome: triage.outcome ?? null,
    action: triage.action ?? null,
    ticketNumber: triage.ticketNumber ?? null,
    closedAt: triage.closedAt ?? null,
    updatedAt: triage.updatedAt ?? null,
    updatedBy: triage.updatedBy ?? null,
    reviewedAnalysisRef: reviewedRef
      ? { analysisIndex: reviewedRef.analysisIndex, analyzedAt: toIso(reviewedRef.analyzedAt) }
      : null,
    // null when there is no referenceable analysis to compare against.
    latestAnalysisReviewed: latestAnalyzedAt
      ? Boolean(
          reviewedRef &&
            reviewedRef.analysisIndex === analyses.length - 1 &&
            toIso(reviewedRef.analyzedAt) === latestAnalyzedAt,
        )
      : null,
  };
}

function getLatestAnalysis(alert) {
  if (!Array.isArray(alert?.analysis) || alert.analysis.length === 0) return null;
  return alert.analysis[alert.analysis.length - 1];
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
      reason: ruleMatch?.reason || ruleMatch?.status || 'rule_not_matched',
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
  if (typeof document.toObject === 'function') {
    return document.toObject({ getters: true, virtuals: false });
  }
  return { ...document };
}

module.exports = {
  toAlertSummary,
  summarizeTriage,
  getAiStatus,
  getAiEligibility,
  toPlainObject,
};
