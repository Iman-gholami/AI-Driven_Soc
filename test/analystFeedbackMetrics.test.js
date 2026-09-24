const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const {
  parseFeedbackWindow,
  selectLatestHumanReview,
  selectEffectiveHumanDisposition,
  createFeedbackAccumulator,
  median,
} = require('../src/investigation/feedbackMetrics');
const { AnalystFeedbackService } = require('../src/services/analystFeedbackService');
const { createRouter } = require('../src/api/routes');
const { errorHandler } = require('../src/api/middleware/errorHandler');

const window = { from: new Date('2026-09-01T00:00:00.000Z'), to: new Date('2026-09-08T00:00:00.000Z') };
const human = { kind: 'human', id: 'a', displayName: 'A' };
const agent = { kind: 'ai', id: 'agent', displayName: 'Agent' };

function event(sequence, type, createdAt, extra = {}) {
  return { sequence, type, createdAt: new Date(createdAt), actor: human, payload: {}, ...extra };
}

function reviewRow(sections, snapshot = {}) {
  return { actorKind: 'human', createdAt: new Date('2026-09-03T00:00:00.000Z'), sections, snapshot };
}

function dispositionRow(
  outcome,
  { rule = { ruleId: 'R1', revision: 1 }, snapshot, analyzedAt, createdAt } = {},
) {
  return {
    actorKind: 'human',
    outcome,
    rule,
    snapshot: snapshot === undefined ? { verdict: 'MALICIOUS' } : snapshot,
    analysisRef: analyzedAt ? { analysisIndex: 0, analyzedAt: new Date(analyzedAt) } : null,
    createdAt: new Date(createdAt || '2026-09-04T00:00:00.000Z'),
  };
}

test('window defaults to the 30 days ending now and rejects malformed or inverted ranges', () => {
  const now = new Date('2026-09-24T12:00:00.000Z');
  const defaults = parseFeedbackWindow({}, now);
  assert.equal(defaults.to.toISOString(), '2026-09-24T12:00:00.000Z');
  assert.equal(defaults.from.toISOString(), '2026-08-25T12:00:00.000Z');

  const explicit = parseFeedbackWindow({ from: '2026-09-01T00:00:00+03:30', to: '2026-09-02' }, now);
  assert.equal(explicit.from.toISOString(), '2026-08-31T20:30:00.000Z');
  assert.equal(explicit.to.toISOString(), '2026-09-02T00:00:00.000Z');

  for (const query of [
    { from: 'yesterday' },
    { to: '5' },
    { from: '2026-13-45' },
    { from: '2026-09-02', to: '2026-09-02' },
    { from: '2026-09-03', to: '2026-09-02' },
  ]) {
    assert.throws(
      () => parseFeedbackWindow(query, now),
      (error) => error.status === 400,
      JSON.stringify(query),
    );
  }
});

test('review cohort uses the latest human review as of `to`, counted only if it is at or after `from`', () => {
  const review = (sequence, at, actor = human) => event(sequence, 'ai_review', at, { actor });

  // A later note never supersedes a review; the latest review wins.
  assert.equal(
    selectLatestHumanReview(
      [
        review(1, '2026-09-02T00:00:00Z'),
        review(2, '2026-09-03T00:00:00Z'),
        event(3, 'note', '2026-09-04T00:00:00Z'),
      ],
      window,
    ).sequence,
    2,
  );
  // Events at or after `to` are ignored; the boundary itself is excluded (half-open interval).
  assert.equal(
    selectLatestHumanReview([review(1, '2026-09-02T00:00:00Z'), review(2, '2026-09-08T00:00:00Z')], window)
      .sequence,
    1,
  );
  // `from` is inclusive.
  assert.equal(selectLatestHumanReview([review(1, '2026-09-01T00:00:00Z')], window).sequence, 1);
  // The latest review as of `to` predates `from`, so the alert is not in this cohort.
  assert.equal(selectLatestHumanReview([review(1, '2026-08-31T23:59:59.999Z')], window), null);
  // Reopening does not erase a historical review.
  assert.equal(
    selectLatestHumanReview(
      [review(1, '2026-09-02T00:00:00Z'), event(2, 'reopened', '2026-09-03T00:00:00Z')],
      window,
    ).sequence,
    1,
  );
  // AI actors never count as human feedback.
  assert.equal(selectLatestHumanReview([review(1, '2026-09-02T00:00:00Z', agent)], window), null);
});

test('disposition cohort replays dispositions and reopens as of `to`', () => {
  const dispo = (sequence, at, actor = human) => event(sequence, 'disposition', at, { actor });
  const reopen = (sequence, at) => event(sequence, 'reopened', at);

  assert.equal(
    selectEffectiveHumanDisposition(
      [dispo(1, '2026-09-02T00:00:00Z'), dispo(2, '2026-09-03T00:00:00Z')],
      window,
    ).sequence,
    2,
  );
  // A reopen before `to` removes the disposition from the cohort ...
  assert.equal(
    selectEffectiveHumanDisposition(
      [dispo(1, '2026-09-02T00:00:00Z'), reopen(2, '2026-09-05T00:00:00Z')],
      window,
    ),
    null,
  );
  // ... but a reopen at or after `to` does not.
  assert.equal(
    selectEffectiveHumanDisposition(
      [dispo(1, '2026-09-02T00:00:00Z'), reopen(2, '2026-09-08T00:00:00Z')],
      window,
    ).sequence,
    1,
  );
  // An effective disposition dated before `from` is outside the cohort.
  assert.equal(selectEffectiveHumanDisposition([dispo(1, '2026-08-30T00:00:00Z')], window), null);
  // A later AI disposition supersedes the human one, so no human disposition is effective.
  assert.equal(
    selectEffectiveHumanDisposition(
      [dispo(1, '2026-09-02T00:00:00Z'), dispo(2, '2026-09-03T00:00:00Z', agent)],
      window,
    ),
    null,
  );
});

test('strict agreement excludes not_reviewed and reports partial agreement separately', () => {
  const accumulator = createFeedbackAccumulator(window);
  accumulator.addReview(
    reviewRow({
      verdict: 'agree',
      severity: 'agree',
      mitre: 'not_reviewed',
      recommendations: 'partially_agree',
    }),
  );
  accumulator.addReview(
    reviewRow({
      verdict: 'agree',
      severity: 'disagree',
      mitre: 'not_reviewed',
      recommendations: 'not_reviewed',
    }),
  );
  accumulator.addReview(
    reviewRow({
      verdict: 'partially_agree',
      severity: 'not_reviewed',
      mitre: 'not_reviewed',
      recommendations: 'agree',
    }),
  );
  accumulator.addReview(
    reviewRow({
      verdict: 'disagree',
      severity: 'agree',
      mitre: 'not_reviewed',
      recommendations: 'not_reviewed',
    }),
  );
  accumulator.addReview({ ...reviewRow({ verdict: 'disagree' }), actorKind: 'ai' });

  const { sections } = accumulator.finish().agreement;
  // verdict: 2 agree, 1 partial, 1 disagree -> 2/4
  assert.deepEqual(sections.verdict, {
    agree: 2,
    partiallyAgree: 1,
    disagree: 1,
    notReviewed: 0,
    reviewed: 4,
    strictAgreementRate: 0.5,
    partialAgreementRate: 0.25,
    disagreementRate: 0.25,
  });
  // severity: 2 agree, 1 disagree, 1 not reviewed -> 2/3
  assert.equal(sections.severity.reviewed, 3);
  assert.equal(sections.severity.strictAgreementRate, 0.6667);
  // mitre: nothing reviewed -> undefined rates are null, not zero
  assert.equal(sections.mitre.reviewed, 0);
  assert.equal(sections.mitre.strictAgreementRate, null);
  // recommendations: 1 agree, 1 partial -> 1/2
  assert.equal(sections.recommendations.strictAgreementRate, 0.5);
});

test('agreement is grouped by the rule and model captured in each snapshot, with an unknown bucket', () => {
  const accumulator = createFeedbackAccumulator(window);
  const old = { provider: 'openai', model: 'gpt-4.1', rule: { ruleId: 'R1', revision: 1 } };
  const newer = { provider: 'openai', model: 'gpt-5', rule: { ruleId: 'R1', revision: 2 } };
  accumulator.addReview(reviewRow({ verdict: 'agree' }, old));
  accumulator.addReview(reviewRow({ verdict: 'disagree' }, old));
  accumulator.addReview(reviewRow({ verdict: 'agree' }, newer));
  accumulator.addReview(reviewRow({ verdict: 'agree' }, { provider: null, model: null, rule: null }));

  const { byRule, byModel } = accumulator.finish().agreement;
  assert.deepEqual(
    byModel.map((group) => [group.key, group.reviews, group.sections.verdict.strictAgreementRate]),
    [
      ['openai/gpt-4.1', 2, 0.5],
      ['openai/gpt-5', 1, 1],
      ['unknown', 1, 1],
    ],
  );
  assert.deepEqual(
    byRule.map((group) => [group.key, group.reviews, group.sections.verdict.reviewed]),
    [
      ['R1@1', 2, 2],
      ['R1@2', 1, 1],
      ['unknown', 1, 1],
    ],
  );
});

test('false-positive share uses determinate outcomes only, with deterministic top-10 ordering', () => {
  const accumulator = createFeedbackAccumulator(window);
  const rule = (ruleId) => ({ rule: { ruleId, revision: 1 } });
  // R1: 2 FP, 1 TP, 1 BTP, 2 inconclusive -> 2/4
  for (const outcome of [
    'false_positive',
    'false_positive',
    'true_positive',
    'benign_true_positive',
    'inconclusive',
    'inconclusive',
  ]) {
    accumulator.addDisposition(dispositionRow(outcome, rule('R1')));
  }
  // R2: 1 FP, 1 TP -> 1/2 (same share as R1, smaller sample, so ranked after R1)
  accumulator.addDisposition(dispositionRow('false_positive', rule('R2')));
  accumulator.addDisposition(dispositionRow('true_positive', rule('R2')));
  // R0: 1 FP, 1 TP -> 1/2, same sample as R2, key tie-break puts R0 first
  accumulator.addDisposition(dispositionRow('false_positive', rule('R0')));
  accumulator.addDisposition(dispositionRow('true_positive', rule('R0')));
  // R3: only inconclusive -> no determinate sample, not ranked
  accumulator.addDisposition(dispositionRow('inconclusive', rule('R3')));
  // R4: 3/3 false positive
  for (let index = 0; index < 3; index += 1)
    accumulator.addDisposition(dispositionRow('false_positive', rule('R4')));

  const { rules } = accumulator.finish().falsePositiveShareByRule;
  assert.deepEqual(
    rules.map((group) => [group.key, group.falsePositiveShare, group.determinate, group.inconclusive]),
    [
      ['R4@1', 1, 3, 0],
      ['R1@1', 0.5, 4, 2],
      ['R0@1', 0.5, 2, 0],
      ['R2@1', 0.5, 2, 0],
    ],
  );
});

test('verdict × outcome keeps original categories and reports dispositions without an AI snapshot', () => {
  const accumulator = createFeedbackAccumulator(window);
  accumulator.addDisposition(dispositionRow('false_positive', { snapshot: { verdict: 'SUSPICIOUS' } }));
  accumulator.addDisposition(dispositionRow('benign_true_positive', { snapshot: { verdict: 'SUSPICIOUS' } }));
  accumulator.addDisposition(dispositionRow('benign_true_positive', { snapshot: { verdict: 'SUSPICIOUS' } }));
  accumulator.addDisposition(dispositionRow('true_positive', { snapshot: { verdict: 'MALICIOUS' } }));
  accumulator.addDisposition(dispositionRow('inconclusive', { snapshot: null }));

  const crossTab = accumulator.finish().verdictOutcome;
  assert.deepEqual(crossTab.verdicts, ['BENIGN', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN']);
  assert.equal(crossTab.included, 4);
  assert.equal(crossTab.excludedWithoutAnalysis, 1);
  const cell = (verdict, outcome) =>
    crossTab.cells.find((item) => item.verdict === verdict && item.outcome === outcome)?.count;
  assert.equal(cell('SUSPICIOUS', 'benign_true_positive'), 2);
  assert.equal(cell('SUSPICIOUS', 'false_positive'), 1);
  assert.equal(cell('MALICIOUS', 'true_positive'), 1);
  assert.equal(crossTab.cells.length, 3);
});

test('median time to disposition handles odd and even samples and excludes invalid durations', () => {
  assert.equal(median([]), null);
  assert.equal(median([5]), 5);
  assert.equal(median([9, 1, 5]), 5);
  assert.equal(median([1, 2, 3, 10]), 2.5);

  const accumulator = createFeedbackAccumulator(window);
  const hour = 60 * 60 * 1000;
  accumulator.addDisposition(
    dispositionRow('true_positive', {
      analyzedAt: '2026-09-04T00:00:00Z',
      createdAt: '2026-09-04T01:00:00Z',
    }),
  );
  accumulator.addDisposition(
    dispositionRow('true_positive', {
      analyzedAt: '2026-09-04T00:00:00Z',
      createdAt: '2026-09-04T04:00:00Z',
    }),
  );
  // Monitoring decisions count too; this is time to disposition, not to remediation.
  accumulator.addDisposition(
    dispositionRow('inconclusive', { analyzedAt: '2026-09-03T00:00:00Z', createdAt: '2026-09-04T00:00:00Z' }),
  );
  accumulator.addDisposition(dispositionRow('false_positive', { analyzedAt: null }));
  accumulator.addDisposition(
    dispositionRow('false_positive', {
      analyzedAt: '2026-09-05T00:00:00Z',
      createdAt: '2026-09-04T00:00:00Z',
    }),
  );

  const timing = accumulator.finish().timeToDisposition;
  assert.equal(timing.eligible, 3);
  assert.equal(timing.excluded, 2);
  assert.equal(timing.medianMs, 4 * hour);
});

test('coverage is alert-level and reports whether the latest run as of `to` was reviewed', () => {
  const accumulator = createFeedbackAccumulator(window);
  const at = (value) => new Date(value);
  // Reviewed on its latest run.
  accumulator.addCoverage({
    analyzedAts: [at('2026-09-02T00:00:00Z')],
    reviews: [
      {
        createdAt: at('2026-09-03T00:00:00Z'),
        analysisRef: { analysisIndex: 0, analyzedAt: at('2026-09-02T00:00:00Z') },
      },
    ],
  });
  // Reviewed, but only an earlier run: counts as reviewed alert, latest run unreviewed.
  accumulator.addCoverage({
    analyzedAts: [at('2026-09-02T00:00:00Z'), at('2026-09-05T00:00:00Z')],
    reviews: [
      {
        createdAt: at('2026-09-03T00:00:00Z'),
        analysisRef: { analysisIndex: 0, analyzedAt: at('2026-09-02T00:00:00Z') },
      },
    ],
  });
  // Not reviewed; the run after `to` is ignored when choosing the latest run.
  accumulator.addCoverage({
    analyzedAts: [at('2026-09-06T00:00:00Z'), at('2026-09-09T00:00:00Z')],
    reviews: [],
  });
  // A review at `to` does not count.
  accumulator.addCoverage({
    analyzedAts: [at('2026-09-02T00:00:00Z')],
    reviews: [
      {
        createdAt: at('2026-09-08T00:00:00Z'),
        analysisRef: { analysisIndex: 0, analyzedAt: at('2026-09-02T00:00:00Z') },
      },
    ],
  });
  // Legacy entry without a timestamp before the latest run: latest run cannot be established.
  accumulator.addCoverage({ analyzedAts: [null, at('2026-09-02T00:00:00Z')], reviews: [] });
  // Analysis outside the window: not part of the population.
  accumulator.addCoverage({ analyzedAts: [at('2026-08-20T00:00:00Z')], reviews: [] });

  const coverage = accumulator.finish().coverage;
  assert.equal(coverage.analyzedAlerts, 5);
  assert.equal(coverage.reviewedAlerts, 2);
  assert.equal(coverage.coverageRate, 0.4);
  assert.equal(coverage.latestRunReviewed, 1);
  assert.equal(coverage.latestRunUnreviewed, 3);
  assert.equal(coverage.latestRunUnestablished, 1);
});

test('empty cohorts produce null rates and medians rather than zero', () => {
  const report = createFeedbackAccumulator(window).finish();
  assert.equal(report.agreement.sections.verdict.strictAgreementRate, null);
  assert.equal(report.timeToDisposition.medianMs, null);
  assert.equal(report.coverage.coverageRate, null);
  assert.deepEqual(report.falsePositiveShareByRule.rules, []);
  assert.equal(report.window.interval, '[from, to)');
});

test('the service streams repository rows and the endpoint rejects bad windows with 400', async () => {
  async function* rows(items) {
    yield* items;
  }
  const calls = [];
  const repository = {
    reviewRows: (range) => (calls.push(range), rows([reviewRow({ verdict: 'agree' })])),
    dispositionRows: () => rows([dispositionRow('false_positive')]),
    coverageRows: () => rows([]),
  };
  const service = new AnalystFeedbackService({ repository, now: () => new Date('2026-09-24T00:00:00.000Z') });
  const report = await service.getReport({ from: '2026-09-01T00:00:00Z', to: '2026-09-08T00:00:00Z' });
  assert.equal(report.cohorts.reviews.alerts, 1);
  assert.equal(report.cohorts.dispositions.alerts, 1);
  assert.equal(calls[0].to.toISOString(), '2026-09-08T00:00:00.000Z');

  const app = express();
  app.use((req, _res, next) => {
    req.log = { info() {}, warn() {}, error() {} };
    next();
  });
  app.use(
    createRouter({
      analyzer: {},
      alertRepository: {},
      copilot: {},
      investigationService: {},
      analystFeedbackService: service,
    }),
  );
  app.use(errorHandler);
  const server = app.listen(0);
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    assert.equal((await fetch(`${base}/analytics/ai-accuracy?from=nope`)).status, 400);
    assert.equal((await fetch(`${base}/analytics/ai-accuracy?from=2026-09-08&to=2026-09-01`)).status, 400);
    const ok = await fetch(`${base}/analytics/ai-accuracy?from=2026-09-01&to=2026-09-08`);
    assert.equal(ok.status, 200);
    assert.equal((await ok.json()).data.agreement.sections.verdict.strictAgreementRate, 1);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
