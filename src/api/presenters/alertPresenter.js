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
  getAiStatus,
  getAiEligibility,
  toPlainObject,
};
