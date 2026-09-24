const Alert = require('../models/Alert');
const { ConflictError, InputError, NotFoundError, UnauthorizedError } = require('../core/errors');
const { extractNetworkTuple } = require('./ipExtractor');

const FINAL_OUTCOMES = new Set(['true_positive', 'false_positive']);
const FALSE_POSITIVE_REASONS = new Set([
  'authorized_scanner',
  'authorized_testing',
  'known_benign_service',
  'rule_too_broad',
  'duplicate_alert',
  'expected_behavior',
  'other',
]);
const DEFAULT_LIMIT = 12;
const MAX_LIMIT = 50;
const CANDIDATE_LIMIT = 250;
const MAX_ACTIONS = 50;

class AlertMemoryService {
  constructor({ alertModel = Alert, now = () => new Date() } = {}) {
    this.alertModel = alertModel;
    this.now = now;
  }

  async getHistory(publicAlertId, { limit } = {}) {
    const current = await this.alertModel.findOne({ alertId: publicAlertId }).lean().exec();
    if (!current) throw new NotFoundError('Alert not found');

    const safeLimit = Math.min(Math.max(Number(limit) || DEFAULT_LIMIT, 1), MAX_LIMIT);
    const currentSignals = extractSignals(current);
    const clauses = buildCandidateClauses(currentSignals);

    const candidates = clauses.length
      ? await this.alertModel
          .find({ _id: { $ne: current._id }, $or: clauses })
          .sort({ eventTime: -1, createdAt: -1 })
          .limit(CANDIDATE_LIMIT)
          .lean()
          .exec()
      : [];

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

    const allOccurrences = ranked.map((item) => presentOccurrence(item.candidate, item));

    return {
      alertId: current.alertId,
      current: {
        status: current.status || inferStatus(current),
        occurredAt: isoOrNull(current.eventTime || current.createdAt),
        signature: current.signature || null,
        host: current.host || null,
        ruleId: getRuleId(current),
        analystCase: presentAnalystCase(current.analystCase),
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

  async saveInvestigation(publicAlertId, payload, { user } = {}) {
    const actor = humanActor(user);
    const normalized = validateInvestigationPayload(payload);
    const current = await this.alertModel.findOne({ alertId: publicAlertId }).lean().exec();
    if (!current) throw new NotFoundError('Alert not found');
    if (current.status === 'closed' || current.analystCase?.closedAt) {
      throw new ConflictError('Closed alerts cannot be edited');
    }

    const now = this.now();
    const set = {
      status: 'investigating',
      'analystCase.actionsTaken': normalized.actionsTaken,
      'analystCase.updatedAt': now,
      'analystCase.updatedBy': actor,
    };
    const unset = {};

    if (normalized.note) set['analystCase.note'] = normalized.note;
    else unset['analystCase.note'] = 1;

    if (!current.analystCase?.startedAt) {
      set['analystCase.startedAt'] = now;
      set['analystCase.startedBy'] = actor;
    }

    const update = { $set: set };
    if (Object.keys(unset).length) update.$unset = unset;

    const alert = await this.alertModel
      .findOneAndUpdate({ _id: current._id, status: { $ne: 'closed' } }, update, { new: true })
      .lean()
      .exec();

    if (!alert) throw new ConflictError('Alert was closed while the investigation was being saved');
    return {
      status: alert.status,
      analystCase: presentAnalystCase(alert.analystCase),
    };
  }

  async closeAlert(publicAlertId, payload, { user } = {}) {
    const actor = humanActor(user);
    const normalized = validateClosePayload(payload);
    const current = await this.alertModel.findOne({ alertId: publicAlertId }).lean().exec();
    if (!current) throw new NotFoundError('Alert not found');
    if (current.status === 'closed' || current.analystCase?.closedAt) {
      throw new ConflictError('Alert is already closed');
    }

    const now = this.now();
    const set = {
      status: 'closed',
      'analystCase.actionsTaken': normalized.actionsTaken,
      'analystCase.finalOutcome': normalized.finalOutcome,
      'analystCase.updatedAt': now,
      'analystCase.updatedBy': actor,
      'analystCase.closedAt': now,
      'analystCase.closedBy': actor,
    };
    const unset = {};

    if (!current.analystCase?.startedAt) {
      set['analystCase.startedAt'] = now;
      set['analystCase.startedBy'] = actor;
    }
    if (normalized.note) set['analystCase.note'] = normalized.note;
    else unset['analystCase.note'] = 1;

    if (normalized.finalOutcome === 'true_positive') {
      set['analystCase.ticketNumber'] = normalized.ticketNumber;
      unset['analystCase.falsePositiveReason'] = 1;
      unset['analystCase.falsePositiveDetails'] = 1;
    } else {
      set['analystCase.falsePositiveReason'] = normalized.falsePositiveReason;
      if (normalized.falsePositiveDetails) {
        set['analystCase.falsePositiveDetails'] = normalized.falsePositiveDetails;
      } else {
        unset['analystCase.falsePositiveDetails'] = 1;
      }
      if (normalized.ticketNumber) set['analystCase.ticketNumber'] = normalized.ticketNumber;
      else unset['analystCase.ticketNumber'] = 1;
    }

    const update = { $set: set };
    if (Object.keys(unset).length) update.$unset = unset;

    const alert = await this.alertModel
      .findOneAndUpdate({ _id: current._id, status: { $ne: 'closed' } }, update, { new: true })
      .lean()
      .exec();

    if (!alert) throw new ConflictError('Alert was already closed');
    return {
      status: alert.status,
      analystCase: presentAnalystCase(alert.analystCase),
    };
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

function presentOccurrence(alert, match) {
  return {
    alertId: alert.alertId,
    occurredAt: isoOrNull(alert.eventTime || alert.createdAt),
    source: alert.source || null,
    signature: alert.signature || null,
    host: alert.host || null,
    eventType: alert.eventType || null,
    severity: alert.severity || 'unknown',
    aiStatus: alert.aiStatus || 'not_analyzed',
    status: alert.status || inferStatus(alert),
    ruleId: getRuleId(alert),
    match: {
      score: match.score,
      level: match.level,
      reasons: match.reasons,
    },
    aiResult: latestAiResult(alert),
    analystResult: presentAnalystCase(alert.analystCase),
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
    false_positive: 0,
    unresolved: 0,
  };
  for (const item of occurrences) {
    const outcome = item.analystResult?.finalOutcome;
    if (outcome === 'true_positive' || outcome === 'false_positive') outcomeCounts[outcome] += 1;
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

function validateInvestigationPayload(payload = {}) {
  return {
    actionsTaken: normalizeActions(payload.actionsTaken),
    note: optionalText(payload.note, 4000, 'note'),
  };
}

function validateClosePayload(payload = {}) {
  const finalOutcome = String(payload.finalOutcome || '').trim();
  if (!FINAL_OUTCOMES.has(finalOutcome)) {
    throw new InputError('finalOutcome must be true_positive or false_positive');
  }

  const actionsTaken = normalizeActions(payload.actionsTaken);
  const note = optionalText(payload.note, 4000, 'note');
  const ticketNumber = optionalText(payload.ticketNumber, 128, 'ticketNumber');
  const falsePositiveReason = optionalText(payload.falsePositiveReason, 128, 'falsePositiveReason');
  const falsePositiveDetails = optionalText(payload.falsePositiveDetails, 2000, 'falsePositiveDetails');

  if (finalOutcome === 'true_positive' && !ticketNumber) {
    throw new InputError('ticketNumber is required when closing a true positive');
  }
  if (finalOutcome === 'false_positive') {
    if (!falsePositiveReason || !FALSE_POSITIVE_REASONS.has(falsePositiveReason)) {
      throw new InputError('A valid falsePositiveReason is required when closing a false positive');
    }
    if (falsePositiveReason === 'other' && !falsePositiveDetails) {
      throw new InputError('falsePositiveDetails is required when falsePositiveReason is other');
    }
  }

  return {
    finalOutcome,
    actionsTaken,
    note,
    ticketNumber,
    falsePositiveReason: finalOutcome === 'false_positive' ? falsePositiveReason : null,
    falsePositiveDetails: finalOutcome === 'false_positive' ? falsePositiveDetails : null,
  };
}

function normalizeActions(value) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new InputError('actionsTaken must be an array');
  if (value.length > MAX_ACTIONS) throw new InputError(`actionsTaken cannot contain more than ${MAX_ACTIONS} items`);

  const normalized = [];
  for (const item of value) {
    if (typeof item !== 'string') throw new InputError('Each actionsTaken item must be a string');
    const action = item.trim();
    if (!action) continue;
    if (action.length > 200) throw new InputError('Each actionsTaken item must be at most 200 characters');
    if (!normalized.includes(action)) normalized.push(action);
  }
  return normalized;
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

function presentAnalystCase(value) {
  if (!value) return null;
  return {
    actionsTaken: Array.isArray(value.actionsTaken) ? value.actionsTaken : [],
    note: value.note || null,
    startedAt: isoOrNull(value.startedAt),
    startedBy: presentActor(value.startedBy),
    updatedAt: isoOrNull(value.updatedAt),
    updatedBy: presentActor(value.updatedBy),
    finalOutcome: value.finalOutcome || null,
    falsePositiveReason: value.falsePositiveReason || null,
    falsePositiveDetails: value.falsePositiveDetails || null,
    ticketNumber: value.ticketNumber || null,
    closedAt: isoOrNull(value.closedAt),
    closedBy: presentActor(value.closedBy),
  };
}

function presentActor(actor) {
  if (!actor) return null;
  return {
    id: actor.id || null,
    displayName: actor.displayName || actor.id || null,
  };
}

function getRuleId(alert) {
  return alert?.ruleMatch?.ruleId ? String(alert.ruleMatch.ruleId).trim() : null;
}

function inferStatus(alert) {
  if (alert?.analystCase?.closedAt) return 'closed';
  if (alert?.analystCase?.startedAt) return 'investigating';
  if (alert?.aiStatus === 'analyzed' || alert?.fullAnalysis) return 'analyzed';
  return 'new';
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
  validateInvestigationPayload,
  validateClosePayload,
};