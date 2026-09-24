const { InputError } = require('../core/errors');
const { REVIEW_SECTIONS } = require('./eventSchemas');
const { OUTCOME_IDS } = require('../config/dispositionReasons');

// Analyst-feedback metrics. Everything here is pure: the repository streams one pre-selected row per
// alert into an accumulator, so the event log itself is never loaded into application memory.
// These numbers describe analyst-reviewed samples, not calibrated accuracy over all SOC traffic.

const DAY_MS = 24 * 60 * 60 * 1000;
const DEFAULT_WINDOW_DAYS = 30;
const DETERMINATE_OUTCOMES = ['true_positive', 'benign_true_positive', 'false_positive'];
const CANONICAL_VERDICTS = ['BENIGN', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN'];
const TOP_FALSE_POSITIVE_RULES = 10;

function parseInstant(value, name) {
  if (typeof value !== 'string' || !value.trim())
    throw new InputError(`${name} must be an ISO-8601 timestamp`);
  // Require an explicit date so values such as "5" or "yesterday" are not silently accepted.
  if (!/^\d{4}-\d{2}-\d{2}/.test(value.trim())) throw new InputError(`${name} must be an ISO-8601 timestamp`);
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new InputError(`${name} must be an ISO-8601 timestamp`);
  return date;
}

// Half-open UTC interval [from, to); defaults to the 30 days ending at request time.
function parseFeedbackWindow({ from, to } = {}, now = new Date()) {
  const end = to === undefined || to === '' ? new Date(now) : parseInstant(to, 'to');
  const start =
    from === undefined || from === ''
      ? new Date(end.getTime() - DEFAULT_WINDOW_DAYS * DAY_MS)
      : parseInstant(from, 'from');
  if (start.getTime() >= end.getTime()) throw new InputError('from must be earlier than to');
  return { from: start, to: end };
}

function time(value) {
  if (value === undefined || value === null) return NaN;
  return (value instanceof Date ? value : new Date(value)).getTime();
}

function inWindowEnd(value, window) {
  return time(value) < window.to.getTime();
}

function atOrAfterStart(value, window) {
  return time(value) >= window.from.getTime();
}

// Cohort selection over one alert's events (the repository aggregation implements the same rules).
// Latest human review as of `to`; counted only if it happened on or after `from`.
function selectLatestHumanReview(events, window) {
  const latest = events
    .filter(
      (event) =>
        event.type === 'ai_review' && event.actor?.kind === 'human' && inWindowEnd(event.createdAt, window),
    )
    .reduce((best, event) => (!best || event.sequence > best.sequence ? event : best), null);
  return latest && atOrAfterStart(latest.createdAt, window) ? latest : null;
}

// Effective disposition as of `to` after replaying dispositions and reopens from every actor; counted only
// when it is a human disposition dated on or after `from`.
function selectEffectiveHumanDisposition(events, window) {
  const last = events
    .filter(
      (event) => ['disposition', 'reopened'].includes(event.type) && inWindowEnd(event.createdAt, window),
    )
    .reduce((best, event) => (!best || event.sequence > best.sequence ? event : best), null);
  if (!last || last.type !== 'disposition' || last.actor?.kind !== 'human') return null;
  return atOrAfterStart(last.createdAt, window) ? last : null;
}

function rate(part, total) {
  return total > 0 ? Math.round((part / total) * 10000) / 10000 : null;
}

function median(values) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function emptySectionCounts() {
  return { agree: 0, partially_agree: 0, disagree: 0, not_reviewed: 0 };
}

function emptySections() {
  return Object.fromEntries(REVIEW_SECTIONS.map((section) => [section, emptySectionCounts()]));
}

// Strict agreement = agree / (agree + partially_agree + disagree); not_reviewed is excluded from the
// denominator and partial agreement is reported separately rather than weighted.
function sectionStats(counts) {
  const reviewed = counts.agree + counts.partially_agree + counts.disagree;
  return {
    agree: counts.agree,
    partiallyAgree: counts.partially_agree,
    disagree: counts.disagree,
    notReviewed: counts.not_reviewed,
    reviewed,
    strictAgreementRate: rate(counts.agree, reviewed),
    partialAgreementRate: rate(counts.partially_agree, reviewed),
    disagreementRate: rate(counts.disagree, reviewed),
  };
}

function ruleKey(rule) {
  if (!rule?.ruleId) return { key: 'unknown', ruleId: null, revision: null };
  const revision = rule.revision ?? null;
  return { key: `${rule.ruleId}@${revision ?? 'unknown'}`, ruleId: rule.ruleId, revision };
}

function modelKey(snapshot) {
  const provider = snapshot?.provider || null;
  const model = snapshot?.model || null;
  if (!provider && !model) return { key: 'unknown', provider: null, model: null };
  return { key: `${provider || 'unknown'}/${model || 'unknown'}`, provider, model };
}

function byKey(a, b) {
  return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
}

function createFeedbackAccumulator(window) {
  const reviewTotals = emptySections();
  const reviewsByRule = new Map();
  const reviewsByModel = new Map();
  const dispositionsByRule = new Map();
  const crossTab = new Map();
  const durations = [];
  let reviewCount = 0;
  let dispositionCount = 0;
  let excludedWithoutAnalysis = 0;
  let durationsExcluded = 0;
  const coverage = {
    analyzedAlerts: 0,
    reviewedAlerts: 0,
    latestReviewed: 0,
    latestUnreviewed: 0,
    latestUnestablished: 0,
  };

  function addToGroup(map, identity, sections) {
    if (!map.has(identity.key)) map.set(identity.key, { ...identity, reviews: 0, sections: emptySections() });
    const group = map.get(identity.key);
    group.reviews += 1;
    for (const section of REVIEW_SECTIONS) {
      const status = sections?.[section] || 'not_reviewed';
      group.sections[section][status] = (group.sections[section][status] || 0) + 1;
    }
  }

  return {
    addReview(row) {
      // Only human feedback counts, even if a caller passes other actors.
      if (row.actorKind !== 'human') return;
      reviewCount += 1;
      for (const section of REVIEW_SECTIONS) {
        const status = row.sections?.[section] || 'not_reviewed';
        reviewTotals[section][status] = (reviewTotals[section][status] || 0) + 1;
      }
      addToGroup(reviewsByRule, ruleKey(row.snapshot?.rule), row.sections);
      addToGroup(reviewsByModel, modelKey(row.snapshot), row.sections);
    },

    addDisposition(row) {
      if (row.actorKind !== 'human') return;
      dispositionCount += 1;

      const rule = ruleKey(row.rule);
      if (!dispositionsByRule.has(rule.key)) {
        dispositionsByRule.set(rule.key, {
          ...rule,
          ...Object.fromEntries(OUTCOME_IDS.map((id) => [id, 0])),
        });
      }
      dispositionsByRule.get(rule.key)[row.outcome] += 1;

      if (row.snapshot) {
        const verdict = row.snapshot.verdict || 'unavailable';
        const cellKey = `${verdict}|${row.outcome}`;
        crossTab.set(cellKey, (crossTab.get(cellKey) || 0) + 1);
      } else {
        excludedWithoutAnalysis += 1;
      }

      const duration = time(row.createdAt) - time(row.analysisRef?.analyzedAt);
      if (Number.isFinite(duration) && duration >= 0) durations.push(duration);
      else durationsExcluded += 1;
    },

    addCoverage(row) {
      const analyses = (row.analyzedAts || []).map((value, index) => ({ index, at: time(value) }));
      if (
        !analyses.some(
          (analysis) => analysis.at >= window.from.getTime() && analysis.at < window.to.getTime(),
        )
      )
        return;
      coverage.analyzedAlerts += 1;

      const reviews = (row.reviews || []).filter((review) => inWindowEnd(review.createdAt, window));
      if (reviews.length > 0) coverage.reviewedAlerts += 1;

      // Latest run as of `to`; established only when every earlier entry has a usable timestamp.
      const beforeEnd = analyses.filter((analysis) => analysis.at < window.to.getTime());
      const latest = beforeEnd[beforeEnd.length - 1];
      if (!latest || analyses.slice(0, latest.index).some((analysis) => Number.isNaN(analysis.at))) {
        coverage.latestUnestablished += 1;
        return;
      }
      const reviewed = reviews.some(
        (review) =>
          review.analysisRef?.analysisIndex === latest.index &&
          time(review.analysisRef?.analyzedAt) === latest.at,
      );
      if (reviewed) coverage.latestReviewed += 1;
      else coverage.latestUnreviewed += 1;
    },

    finish() {
      const groupStats = (map) =>
        [...map.values()]
          .map((group) => ({
            key: group.key,
            ...(group.ruleId !== undefined ? { ruleId: group.ruleId, revision: group.revision } : {}),
            ...(group.provider !== undefined ? { provider: group.provider, model: group.model } : {}),
            reviews: group.reviews,
            sections: Object.fromEntries(
              REVIEW_SECTIONS.map((section) => [section, sectionStats(group.sections[section])]),
            ),
          }))
          .sort((a, b) => b.reviews - a.reviews || byKey(a, b));

      const falsePositiveRules = [...dispositionsByRule.values()]
        .map((group) => {
          const determinate = DETERMINATE_OUTCOMES.reduce((sum, outcome) => sum + group[outcome], 0);
          return {
            key: group.key,
            ruleId: group.ruleId,
            revision: group.revision,
            falsePositive: group.false_positive,
            truePositive: group.true_positive,
            benignTruePositive: group.benign_true_positive,
            inconclusive: group.inconclusive,
            determinate,
            falsePositiveShare: rate(group.false_positive, determinate),
          };
        })
        .filter((group) => group.determinate > 0)
        .sort(
          (a, b) =>
            b.falsePositiveShare - a.falsePositiveShare || b.determinate - a.determinate || byKey(a, b),
        )
        .slice(0, TOP_FALSE_POSITIVE_RULES);

      const seenVerdicts = new Set([...crossTab.keys()].map((key) => key.split('|')[0]));
      const verdicts = [
        ...CANONICAL_VERDICTS,
        ...[...seenVerdicts].filter((verdict) => !CANONICAL_VERDICTS.includes(verdict)).sort(),
      ];

      return {
        window: {
          from: window.from.toISOString(),
          to: window.to.toISOString(),
          interval: '[from, to)',
          timezone: 'UTC',
        },
        cohorts: {
          reviews: {
            alerts: reviewCount,
            description:
              'Latest human ai_review per alert as of `to`, created in [from, to). It may review an older AI run than the newest one.',
          },
          dispositions: {
            alerts: dispositionCount,
            description:
              'Effective human disposition per alert as of `to` (after replaying dispositions and reopens), created in [from, to).',
          },
        },
        agreement: {
          sections: Object.fromEntries(
            REVIEW_SECTIONS.map((section) => [section, sectionStats(reviewTotals[section])]),
          ),
          byRule: groupStats(reviewsByRule),
          byModel: groupStats(reviewsByModel),
        },
        falsePositiveShareByRule: {
          definition:
            'false_positive / (true_positive + benign_true_positive + false_positive); inconclusive is excluded from the denominator. Not FP / (FP + TN): non-alerting true negatives are not observed.',
          rules: falsePositiveRules,
        },
        verdictOutcome: {
          verdicts,
          outcomes: [...OUTCOME_IDS],
          cells: [...crossTab.entries()].map(([key, count]) => {
            const [verdict, outcome] = key.split('|');
            return { verdict, outcome, count };
          }),
          included: dispositionCount - excludedWithoutAnalysis,
          excludedWithoutAnalysis,
        },
        timeToDisposition: {
          medianMs: median(durations),
          eligible: durations.length,
          excluded: durationsExcluded,
          description:
            'Time from the analysis referenced by the effective disposition to that disposition, including monitoring decisions. Not time to remediation.',
        },
        coverage: {
          analyzedAlerts: coverage.analyzedAlerts,
          reviewedAlerts: coverage.reviewedAlerts,
          coverageRate: rate(coverage.reviewedAlerts, coverage.analyzedAlerts),
          latestRunReviewed: coverage.latestReviewed,
          latestRunUnreviewed: coverage.latestUnreviewed,
          latestRunUnestablished: coverage.latestUnestablished,
          description:
            'Alerts with an analysis persisted in [from, to) that have any human review as of `to`. Alert-level coverage, not coverage of every analysis run.',
        },
      };
    },
  };
}

module.exports = {
  parseFeedbackWindow,
  selectLatestHumanReview,
  selectEffectiveHumanDisposition,
  createFeedbackAccumulator,
  median,
  sectionStats,
};
