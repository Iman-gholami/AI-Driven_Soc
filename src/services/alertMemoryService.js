const Alert = require('../models/Alert');
const AlertResolution = require('../models/AlertResolution');
const { InputError, NotFoundError, UnauthorizedError } = require('../core/errors');
const { extractNetworkTuple } = require('./ipExtractor');

const OUTCOMES = new Set([
  'true_positive',
  'benign_true_positive',
  'false_positive',
  'inconclusive',
]);
const DEFAULT_LIMIT = 12;
const MAX_LIMIT = 50;
const CANDIDATE_LIMIT = 250;

class AlertMemoryService {
  constructor({ alertModel = Alert, resolutionModel = AlertResolution, now = () => new Date() } = {}) {
    this.alertModel = alertModel;
    this.resolutionModel = resolutionModel;
    this.now = now;
  }

  async getHistory(publicAlertId, { limit } = {}) {
    const current = await this.alertModel.findOne({ alertId: publicAlertId }).lean().exec();
    if (!current) throw new NotFoundError('Alert not found');

    const safeLimit = Math.min(Math.max(Number(limit) || DEFAULT_LIMIT, 1), MAX_LIMIT);
    const currentSignals = extractSignals(current);
    const clauses = buildCandidateClauses(currentSignals);

    const [currentResolution, candidates] = await Promise.all([
      this.resolutionModel.findOne({ alertRef: current._id }).lean().exec(),
      clauses.length
        ? this.alertModel
            .find({ _id: { $ne: current._id }, $or: clauses })
            .sort({ eventTime: -1, createdAt: -1 })
            .limit(CANDIDATE_LIMIT)
            .lean()
            .exec()
        : [],
    ]);

    const currentTime = effectiveTime(current);
    const ranked = candidates
      .map((candidate) => {
        const score = scoreCandidate(currentSignals, extractSignals(candidate));
        return { candidate, ...score };
      })
      .filter((item) => item.score > 0 && effectiveTime(item.candidate) < currentTime)
      .sort((left, right) => {
        if (right.score !== left.score) return right.score - left.score;
        return effectiveTime(right.candidate) - effectiveTime(left.candidate);
      });

    const resolutionRows = ranked.length
      ? await this.resolutionModel
          .find({ alertRef: { $in: ranked.map((item) => item.candidate._id) } })
          .lean()
          .exec()
      : [];
    const resolutions = new Map(resolutionRows.map((row) => [String(row.alertRef), row]));

    const allOccurrences = ranked.map((item) =>
      presentOccurrence(item.candidate, item, resolutions.get(String(item.candidate._id)) || null),
    );

    return {
      alertId: current.alertId,
      current: {
        occurredAt: isoOrNull(current.eventTime || current.createdAt),
        signature: current.signature || null,
        host: current.host || null,
        ruleId: getRuleId(current),
        analystResult: presentResolution(currentResolution),
      },
      summary: summarizeOccurrences(allOccurrences),
      occurrences: allOccurrences.slice(0, safeLimit),
      pagination: {
        returned: Math.min(allOccurrences.length, safeLimit),
        matched: allOccurrences.length,
        candidateLimitReached: candidates.length === CANDIDATE_LIMIT,
      },
    };
  }

  async saveOutcome(publicAlertId, payload, { user } = {}) {
    const actor = humanActor(user);
    const normalized = validateOutcomePayload(payload);
    const alert = await this.alertModel.findOne({ alertId: publicAlertId }).select('_id alertId').lean().exec();
    if (!alert) throw new NotFoundError('Alert not found');

    const row = await this.resolutionModel
      .findOneAndUpdate(
        { alertRef: alert._id },
        {
          $set: {
            alertId: alert.alertId,
            outcome: normalized.outcome,
            note: normalized.note || undefined,
            ticketNumber: normalized.ticketNumber || undefined,
            resolvedAt: this.now(),
            resolvedBy: actor,
          },
        },
        { new: true, upsert: true, setDefaultsOnInsert: true },
      )
      .lean()
      .exec();

    return presentResolution(row);
  }
}

function extractSignals(alert = {}) {
  const tuple = extractNetworkTuple(alert.rawEvent || {});
  return {
    ruleId: normalize(getRuleId(alert)),
    signature: normalize(alert.signature),
    host: normalize(alert.host),
    eventType: normalize(alert.eventType),
    sourceIp: normalize(tuple.sourceIp),
    destinationIp: normalize(tuple.destinationIp),
  };
}

function buildCandidateClauses(signals) {
  const clauses = [];
  if (signals.ruleId) clauses.push({ 'ruleMatch.ruleId': signals.ruleId });
  if (signals.signature) clauses.push({ signature: new RegExp(`^${escapeRegex(signals.signature)}$`, 'i') });
  if (signals.host && signals.eventType) {
    clauses.push({
      host: new RegExp(`^${escapeRegex(signals.host)}$`, 'i'),
      eventType: new RegExp(`^${escapeRegex(signals.eventType)}$`, 'i'),
    });
  }

  addRawIpClauses(clauses, signals.sourceIp, [
    'rawEvent.src_ip',
    'rawEvent.source_ip',
    'rawEvent.client_ip',
    'rawEvent.src',
    'rawEvent.source.ip',
    'rawEvent.network.source.ip',
  ]);
  addRawIpClauses(clauses, signals.destinationIp, [
    'rawEvent.dst_ip',
    'rawEvent.dest_ip',
    'rawEvent.destination_ip',
    'rawEvent.server_ip',
    'rawEvent.dst',
    'rawEvent.destination.ip',
    'rawEvent.network.destination.ip',
  ]);

  return clauses;
}

function addRawIpClauses(clauses, value, paths) {
  if (!value) return;
  for (const path of paths) clauses.push({ [path]: value });
}

function scoreCandidate(current, candidate) {
  let score = 0;
  const reasons = [];

  if (same(current.ruleId, candidate.ruleId)) {
    score += 50;
    reasons.push('same_detection_rule');
  }
  if (same(current.signature, candidate.signature)) {
    score += 35;
    reasons.push('same_signature');
  }
  if (same(current.host, candidate.host)) {
    score += 15;
    reasons.push('same_host');
  }
  if (same(current.eventType, candidate.eventType)) {
    score += 10;
    reasons.push('same_event_type');
  }
  if (same(current.sourceIp, candidate.sourceIp)) {
    score += 15;
    reasons.push('same_source_ip');
  }
  if (same(current.destinationIp, candidate.destinationIp)) {
    score += 15;
    reasons.push('same_destination_ip');
  }
  if (
    (same(current.sourceIp, candidate.destinationIp) || same(current.destinationIp, candidate.sourceIp)) &&
    !reasons.includes('same_source_ip') &&
    !reasons.includes('same_destination_ip')
  ) {
    score += 8;
    reasons.push('same_network_peer');
  }

  return {
    score,
    level:
      reasons.includes('same_detection_rule') && reasons.includes('same_signature')
        ? 'exact'
        : score >= 60
          ? 'strong'
          : 'related',
    reasons,
  };
}

function presentOccurrence(alert, match, resolution) {
  return {
    alertId: alert.alertId,
    occurredAt: isoOrNull(alert.eventTime || alert.createdAt),
    source: alert.source || null,
    signature: alert.signature || null,
    host: alert.host || null,
    eventType: alert.eventType || null,
    severity: alert.severity || 'unknown',
    aiStatus: alert.aiStatus || 'not_analyzed',
    ruleId: getRuleId(alert),
    match: {
      score: match.score,
      level: match.level,
      reasons: match.reasons,
    },
    aiResult: latestAiResult(alert),
    analystResult: presentResolution(resolution),
  };
}

function latestAiResult(alert) {
  const entries = Array.isArray(alert.analysis) ? alert.analysis : [];
  const latest = entries.length ? entries[entries.length - 1] : {};
  const full = alert.fullAnalysis || {};
  return {
    verdict: full.verdict || latest.verdict || null,
    severity: full.risk_assessment?.severity || latest.severity || alert.severity || null,
    summary:
      full.one_line_summary ||
      latest.summary ||
      full.incident_summary?.what_happened ||
      full.incident_summary?.summary ||
      full.final_soc_note ||
      null,
    action: full.analyst_decision?.action || latest.action || null,
    analyzedAt: isoOrNull(latest.analyzedAt || alert.processing?.completedAt),
  };
}

function summarizeOccurrences(occurrences) {
  const outcomeCounts = {
    true_positive: 0,
    benign_true_positive: 0,
    false_positive: 0,
    inconclusive: 0,
    unresolved: 0,
  };
  for (const item of occurrences) {
    if (item.analystResult?.outcome) outcomeCounts[item.analystResult.outcome] += 1;
    else outcomeCounts.unresolved += 1;
  }

  const chronological = [...occurrences].sort(
    (left, right) => Date.parse(left.occurredAt || 0) - Date.parse(right.occurredAt || 0),
  );
  return {
    seenBefore: occurrences.length > 0,
    count: occurrences.length,
    firstSeen: chronological[0]?.occurredAt || null,
    lastSeen: chronological[chronological.length - 1]?.occurredAt || null,
    sameRuleCount: occurrences.filter((item) => item.match.reasons.includes('same_detection_rule')).length,
    sameHostCount: occurrences.filter((item) => item.match.reasons.includes('same_host')).length,
    outcomeCounts,
  };
}

function validateOutcomePayload(payload = {}) {
  const outcome = String(payload.outcome || '').trim();
  if (!OUTCOMES.has(outcome)) {
    throw new InputError('outcome must be true_positive, benign_true_positive, false_positive, or inconclusive');
  }
  const note = optionalText(payload.note, 2000, 'note');
  const ticketNumber = optionalText(payload.ticketNumber, 128, 'ticketNumber');
  return { outcome, note, ticketNumber };
}

function optionalText(value, maxLength, field) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string') throw new InputError(`${field} must be a string`);
  const normalized = value.trim();
  if (normalized.length > maxLength) throw new InputError(`${field} is too long`);
  return normalized || null;
}

function humanActor(user) {
  const id = typeof user?.username === 'string' ? user.username.trim() : '';
  if (!id) throw new UnauthorizedError('An authenticated analyst identity is required');
  const displayName =
    typeof user.displayName === 'string' && user.displayName.trim() ? user.displayName.trim() : id;
  return { id: id.slice(0, 200), displayName: displayName.slice(0, 200) };
}

function presentResolution(row) {
  if (!row) return null;
  return {
    outcome: row.outcome,
    note: row.note || null,
    ticketNumber: row.ticketNumber || null,
    resolvedAt: isoOrNull(row.resolvedAt),
    resolvedBy: row.resolvedBy
      ? {
          id: row.resolvedBy.id || null,
          displayName: row.resolvedBy.displayName || row.resolvedBy.id || null,
        }
      : null,
  };
}

function getRuleId(alert) {
  return alert?.ruleMatch?.ruleId ? String(alert.ruleMatch.ruleId).trim() : null;
}

function effectiveTime(alert) {
  const value = alert?.eventTime || alert?.createdAt;
  const timestamp = value ? new Date(value).getTime() : 0;
  return Number.isFinite(timestamp) ? timestamp : 0;
}

function normalize(value) {
  return value === undefined || value === null ? null : String(value).trim().toLowerCase() || null;
}

function same(left, right) {
  return Boolean(left && right && left === right);
}

function isoOrNull(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

module.exports = {
  AlertMemoryService,
  extractSignals,
  scoreCandidate,
  summarizeOccurrences,
  validateOutcomePayload,
};
