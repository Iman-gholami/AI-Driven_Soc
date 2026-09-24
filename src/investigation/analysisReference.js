const crypto = require('node:crypto');
const { ConflictError, UnprocessableError } = require('../core/errors');

// Only the latest persisted analysis can be reviewed. `analysis[]` keeps summaries of earlier runs, while
// `fullAnalysis`, `llmProvider` and `model` are replaced by each re-analysis, so those fields describe the
// latest entry only. Nothing here reconstructs data for older runs.

function toIso(value) {
  if (value === undefined || value === null || value === '') return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function knownText(value) {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  return text && text.toLowerCase() !== 'unknown' ? text : null;
}

function canonicalJson(value) {
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const keys = Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value === undefined ? null : value);
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

// Rule captured on investigation events: the alert's matched rule at the time of the write.
function ruleSnapshotFromAlert(alert) {
  const ruleMatch = alert?.ruleMatch;
  if (
    !ruleMatch ||
    ruleMatch.status !== 'matched' ||
    ruleMatch.ruleId === undefined ||
    ruleMatch.ruleId === null
  ) {
    return null;
  }
  const revision = Number(ruleMatch.revision);
  return {
    ruleId: String(ruleMatch.ruleId),
    revision:
      ruleMatch.revision === undefined || ruleMatch.revision === null || !Number.isFinite(revision)
        ? null
        : revision,
  };
}

function stringList(value) {
  return Array.isArray(value) ? value.filter((item) => typeof item === 'string') : null;
}

function attackMappingList(value) {
  if (!Array.isArray(value)) return null;
  return value
    .map((item) => {
      if (typeof item === 'string') return { technique: item, name: null };
      if (!item || typeof item !== 'object') return null;
      const technique = knownText(item.technique ?? item.id);
      return technique ? { technique, name: knownText(item.name) } : null;
    })
    .filter(Boolean);
}

function buildAnalysisSnapshot(alert, analysisIndex) {
  const analyses = Array.isArray(alert?.analysis) ? alert.analysis : [];
  const entry = analyses[analysisIndex] || {};
  const isLatest = analysisIndex === analyses.length - 1;
  const full =
    isLatest && alert?.fullAnalysis && typeof alert.fullAnalysis === 'object' ? alert.fullAnalysis : null;

  const verdict = knownText(full?.verdict ?? entry.verdict);
  const severity = knownText(full?.risk_assessment?.severity ?? entry.severity);
  const base = {
    analysisIndex,
    analyzedAt: toIso(entry.analyzedAt),
    verdict: verdict ? verdict.toUpperCase() : null,
    severity: severity ? severity.toLowerCase() : null,
    attackMapping: full ? attackMappingList(full.attack_mapping) : null,
    recommendations: stringList(full?.recommended_investigation_steps) ?? stringList(entry.recommendations),
    provider: isLatest ? knownText(alert?.llmProvider) : null,
    model: isLatest ? knownText(alert?.model) : null,
    rule: ruleSnapshotFromAlert(alert),
  };
  const fingerprint = sha256(canonicalJson(base));
  const { analysisIndex: index, analyzedAt, ...content } = base;

  return {
    analysisRef: { analysisIndex: index, analyzedAt, fingerprint },
    ...content,
  };
}

// Describes what, if anything, an analyst can review right now.
function describeReviewableAnalysis(alert) {
  const analyses = Array.isArray(alert?.analysis) ? alert.analysis : [];
  const analysisCount = analyses.length;

  if (alert?.aiStatus === 'analyzing') {
    return {
      status: 'in_progress',
      reason: 'analysis_in_progress',
      analysisCount,
      ref: null,
      snapshot: null,
    };
  }
  if (analysisCount === 0) {
    const reason = alert?.fullAnalysis ? 'legacy_analysis_without_reference' : 'no_analysis';
    return { status: 'none', reason, analysisCount, ref: null, snapshot: null };
  }

  const latestIndex = analysisCount - 1;
  if (!toIso(analyses[latestIndex]?.analyzedAt)) {
    return {
      status: 'none',
      reason: 'legacy_analysis_without_reference',
      analysisCount,
      ref: null,
      snapshot: null,
    };
  }

  const snapshot = buildAnalysisSnapshot(alert, latestIndex);
  return { status: 'available', reason: null, analysisCount, ref: snapshot.analysisRef, snapshot };
}

function ruleGuardFields(alert) {
  return {
    ruleStatus: alert?.ruleMatch?.status ?? null,
    ruleId: alert?.ruleMatch?.ruleId ?? null,
    ruleRevision: alert?.ruleMatch?.revision ?? null,
  };
}

function staleReference(message) {
  return new ConflictError(message, {
    details: { reason: 'stale_analysis_reference', refresh: true },
  });
}

/**
 * Validates the analysis reference a client submitted against the persisted alert and returns the
 * server-side snapshot plus a guard describing the alert state the write depends on. The guard is
 * re-checked atomically when the projection is updated, so a re-analysis that completes between this
 * validation and the commit aborts the write instead of attaching it to different data.
 */
function resolveAnalysisReference(alert, submittedRef, { requireAnalysis }) {
  const current = describeReviewableAnalysis(alert);

  if (current.status === 'in_progress') {
    throw new ConflictError('AI analysis is in progress for this alert; refresh when it completes', {
      details: { reason: 'analysis_in_progress', refresh: true },
    });
  }

  if (current.status === 'none') {
    if (requireAnalysis) {
      throw new UnprocessableError('This alert has no reviewable AI analysis', {
        details: { reason: 'no_reviewable_analysis', detail: current.reason },
      });
    }
    if (submittedRef) {
      throw new UnprocessableError('The referenced analysis does not exist', {
        details: { reason: 'analysis_reference_not_found' },
      });
    }
    return { ref: null, snapshot: null, guard: { requireNoAnalysis: true, ...ruleGuardFields(alert) } };
  }

  if (!submittedRef) {
    throw staleReference(
      'An AI analysis now exists for this alert; refresh and confirm the analysis you reviewed',
    );
  }

  const analyses = alert.analysis;
  const entry = analyses[submittedRef.analysisIndex];
  if (!entry || toIso(entry.analyzedAt) !== toIso(submittedRef.analyzedAt)) {
    throw new UnprocessableError('The referenced analysis does not exist', {
      details: { reason: 'analysis_reference_not_found' },
    });
  }
  if (submittedRef.analysisIndex !== current.ref.analysisIndex) {
    throw staleReference('A newer AI analysis exists; refresh before saving');
  }
  if (submittedRef.fingerprint !== current.ref.fingerprint) {
    throw staleReference('The analysis context changed since it was displayed; refresh before saving');
  }

  return {
    ref: current.ref,
    snapshot: current.snapshot,
    guard: {
      requireNoAnalysis: false,
      analysisIndex: submittedRef.analysisIndex,
      analyzedAt: entry.analyzedAt,
      provider: alert.llmProvider ?? null,
      model: alert.model ?? null,
      ...ruleGuardFields(alert),
    },
  };
}

// MongoDB filter that holds only while the alert is still in the state the write was validated against.
function analysisGuardToMongoFilter(guard) {
  if (!guard) return {};
  const filter = {
    aiStatus: { $ne: 'analyzing' },
    'ruleMatch.status': guard.ruleStatus,
    'ruleMatch.ruleId': guard.ruleId,
    'ruleMatch.revision': guard.ruleRevision,
  };
  if (guard.requireNoAnalysis) {
    filter['analysis.0'] = { $exists: false };
  } else {
    filter[`analysis.${guard.analysisIndex}.analyzedAt`] = guard.analyzedAt;
    filter[`analysis.${guard.analysisIndex + 1}`] = { $exists: false };
    filter.llmProvider = guard.provider;
    filter.model = guard.model;
  }
  return filter;
}

// In-memory equivalent of analysisGuardToMongoFilter (null matches missing, like MongoDB).
function matchesAnalysisGuard(alert, guard) {
  if (!guard) return true;
  const same = (actual, expected) => (actual ?? null) === (expected ?? null);
  if (alert?.aiStatus === 'analyzing') return false;
  if (!same(alert?.ruleMatch?.status, guard.ruleStatus)) return false;
  if (!same(alert?.ruleMatch?.ruleId, guard.ruleId)) return false;
  if (!same(alert?.ruleMatch?.revision, guard.ruleRevision)) return false;

  const analyses = Array.isArray(alert?.analysis) ? alert.analysis : [];
  if (guard.requireNoAnalysis) return analyses.length === 0;

  const entry = analyses[guard.analysisIndex];
  return (
    Boolean(entry) &&
    toIso(entry.analyzedAt) === toIso(guard.analyzedAt) &&
    analyses.length === guard.analysisIndex + 1 &&
    same(alert.llmProvider, guard.provider) &&
    same(alert.model, guard.model)
  );
}

module.exports = {
  toIso,
  canonicalJson,
  sha256,
  ruleSnapshotFromAlert,
  buildAnalysisSnapshot,
  describeReviewableAnalysis,
  resolveAnalysisReference,
  analysisGuardToMongoFilter,
  matchesAnalysisGuard,
};
