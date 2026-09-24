const test = require('node:test');
const assert = require('node:assert/strict');
const { InvestigationService } = require('../src/services/investigationService');
const { describeReviewableAnalysis } = require('../src/investigation/analysisReference');
const { reduceTriage } = require('../src/investigation/triageReducer');
const { InMemoryInvestigationRepository } = require('./support/inMemoryInvestigationRepository');
const { analyzedAlert, unanalyzedAlert, analyst, otherAnalyst } = require('./support/investigationFixtures');

let clock = Date.parse('2026-09-05T08:00:00.000Z');
const now = () => new Date((clock += 1000));

function setup(alerts = [analyzedAlert(), unanalyzedAlert()], options = {}) {
  const repository = new InMemoryInvestigationRepository({ alerts, ...options });
  return { repository, service: new InvestigationService({ repository, now }) };
}

const latestRef = (alert = analyzedAlert()) => describeReviewableAnalysis(alert).ref;
const reviewBody = (overrides = {}) => ({
  expectedVersion: 0,
  analysisRef: latestRef(),
  payload: { sections: { verdict: 'agree', severity: 'disagree' }, corrections: { severity: 'medium' } },
  ...overrides,
});
const dispositionBody = (overrides = {}) => ({
  expectedVersion: 0,
  analysisRef: latestRef(),
  payload: { outcome: 'false_positive', action: 'closed_no_action', reasonCodes: ['rule_too_broad'] },
  ...overrides,
});
const ctx = (key, user = analyst) => ({ idempotencyKey: key, user });

async function rejects(promise, status, reason) {
  await assert.rejects(promise, (error) => {
    assert.equal(error.status, status, error.message);
    if (reason) assert.equal(error.details?.reason, reason);
    return true;
  });
}

test('actor identity comes only from the authenticated user', async () => {
  const { service, repository } = setup();
  const result = await service.recordNote(
    'splunk-1',
    { payload: { text: 'Checked VPN logs' } },
    ctx('note-key-0001'),
  );
  assert.deepEqual(result.event.actor, { kind: 'human', id: 'analyst.one', displayName: 'Analyst One' });
  assert.equal(repository.events[0].actor.kind, 'human');

  await rejects(
    service.recordNote('splunk-1', { payload: { text: 'x' } }, { idempotencyKey: 'note-key-0002' }),
    401,
  );
  await rejects(
    service.recordNote(
      'splunk-1',
      { payload: { text: 'x' } },
      ctx('note-key-0003', { displayName: 'No user' }),
    ),
    401,
  );
  await rejects(
    service.recordNote(
      'splunk-1',
      { payload: { text: 'x' }, actor: { kind: 'ai', id: 'agent-1', displayName: 'Agent' } },
      ctx('note-key-0004'),
    ),
    422,
    'invalid_payload',
  );
  assert.equal(repository.events.length, 1);
});

test('review captures an immutable server-side snapshot of the reviewed analysis', async () => {
  const { service, repository } = setup();
  const result = await service.recordReview('splunk-1', reviewBody(), ctx('review-key-01'));

  assert.equal(result.replayed, false);
  assert.equal(result.version, 1);
  assert.equal(result.event.sequence, 1);
  assert.deepEqual(result.event.context.analysisSnapshot, {
    verdict: 'MALICIOUS',
    severity: 'high',
    attackMapping: [{ technique: 'T1110', name: 'Brute Force' }],
    recommendations: ['Isolate host'],
    provider: 'openai',
    model: 'gpt-4.1',
    rule: { ruleId: '1000001', revision: 3 },
  });
  assert.equal(result.event.context.analysisRef.analysisIndex, 1);
  assert.equal(repository.alert('splunk-1').triage.review.sections.severity, 'disagree');
  assert.equal(repository.alert('splunk-1').triage.status, 'open');
});

test('re-analysis and a public alert ID change do not rewrite earlier reviews', async () => {
  const { service, repository } = setup();
  await service.recordReview('splunk-1', reviewBody(), ctx('review-key-02'));

  const stored = repository.alert('splunk-1');
  stored.analysis.push({
    verdict: 'BENIGN',
    severity: 'low',
    summary: 'Third run',
    analyzedAt: new Date('2026-09-06T10:00:00.000Z'),
  });
  stored.fullAnalysis = {
    verdict: 'BENIGN',
    risk_assessment: { severity: 'low' },
    attack_mapping: [],
    recommended_investigation_steps: [],
  };
  stored.model = 'gpt-5';
  stored.alertId = 'splunk-1-renamed';

  const investigation = await service.getInvestigation('splunk-1-renamed');
  assert.equal(investigation.alert.alertRef, 'alert-ref-1');
  assert.equal(investigation.events.length, 1);
  assert.equal(investigation.events[0].alertId, 'splunk-1');
  assert.equal(investigation.events[0].context.analysisSnapshot.verdict, 'MALICIOUS');
  assert.equal(investigation.events[0].context.analysisSnapshot.model, 'gpt-4.1');
  assert.equal(investigation.latestAnalysisReviewed, false);
  assert.deepEqual(
    investigation.analyses.map((analysis) => [
      analysis.analysisIndex,
      analysis.reviewCount,
      analysis.isLatest,
    ]),
    [
      [0, 0, false],
      [1, 1, false],
      [2, 0, true],
    ],
  );
  assert.equal(investigation.reviewableAnalysis.snapshot.model, 'gpt-5');
});

test('a review of an older analysis is stale; an unanalyzed alert has nothing to review', async () => {
  const { service } = setup();
  const older = {
    analysisIndex: 0,
    analyzedAt: '2026-09-01T10:00:00.000Z',
    fingerprint: latestRef().fingerprint,
  };
  await rejects(
    service.recordReview('splunk-1', reviewBody({ analysisRef: older }), ctx('review-key-03')),
    409,
    'stale_analysis_reference',
  );
  await rejects(
    service.recordReview('splunk-2', reviewBody(), ctx('review-key-04')),
    422,
    'no_reviewable_analysis',
  );
  await rejects(service.recordReview('missing', reviewBody(), ctx('review-key-05')), 404);
});

test('corrections equal to the AI value are rejected', async () => {
  const { service } = setup();
  await rejects(
    service.recordReview(
      'splunk-1',
      reviewBody({ payload: { sections: { verdict: 'disagree' }, corrections: { verdict: 'MALICIOUS' } } }),
      ctx('review-key-06'),
    ),
    422,
    'invalid_payload',
  );
});

test('analysis in progress blocks reviews and analysis-linked dispositions', async () => {
  const { service, repository } = setup([analyzedAlert({ aiStatus: 'analyzing' })]);
  await rejects(
    service.recordReview('splunk-1', reviewBody(), ctx('review-key-07')),
    409,
    'analysis_in_progress',
  );
  await rejects(
    service.recordDisposition('splunk-1', dispositionBody(), ctx('dispo-key-01')),
    409,
    'analysis_in_progress',
  );
  await service.recordNote('splunk-1', { payload: { text: 'Waiting for AI' } }, ctx('note-key-0005'));
  assert.equal(repository.events.length, 1);
});

test('re-analysis completing between validation and commit rolls the write back', async () => {
  const { service, repository } = setup();
  repository.hooks.beforeProjectionUpdate = (repo) => {
    repository.hooks.beforeProjectionUpdate = null;
    const alert = repo.alerts.find((item) => item.alertId === 'splunk-1');
    alert.analysis.push({
      verdict: 'BENIGN',
      severity: 'low',
      analyzedAt: new Date('2026-09-07T10:00:00.000Z'),
    });
  };

  await rejects(
    service.recordReview('splunk-1', reviewBody(), ctx('review-key-08')),
    409,
    'concurrent_change',
  );
  assert.equal(repository.events.length, 0);
  // The simulated re-analysis happened outside the aborted unit of work in reality; the fake restores
  // everything, so only the absence of the event and projection is asserted here.
  assert.equal(repository.alert('splunk-1').triage, undefined);
});

test('a projection failure after the event insert leaves no event behind', async () => {
  const { service, repository } = setup();
  repository.hooks.beforeProjectionUpdate = () => {
    throw new Error('simulated crash');
  };
  await assert.rejects(
    service.recordNote('splunk-1', { payload: { text: 'x' } }, ctx('note-key-0006')),
    /simulated crash/,
  );
  assert.equal(repository.events.length, 0);
  assert.equal(repository.alert('splunk-1').triage, undefined);
});

test('dispositions work without AI analysis and always capture the rule', async () => {
  const { service, repository } = setup();
  const result = await service.recordDisposition(
    'splunk-2',
    dispositionBody({
      analysisRef: null,
      payload: {
        outcome: 'benign_true_positive',
        action: 'monitoring',
        reasonCodes: ['authorized_internal_scanner'],
      },
    }),
    ctx('dispo-key-02'),
  );
  assert.equal(result.event.context.analysisRef, null);
  assert.equal(result.event.context.analysisSnapshot, null);
  assert.deepEqual(result.event.context.rule, { ruleId: '2000002', revision: 1 });
  assert.equal(result.state.status, 'open');
  assert.equal(repository.alert('splunk-2').triage.outcome, 'benign_true_positive');

  // Once an analysis exists, a disposition must reference it.
  await rejects(
    service.recordDisposition('splunk-1', dispositionBody({ analysisRef: null }), ctx('dispo-key-03')),
    409,
    'stale_analysis_reference',
  );
  const linked = await service.recordDisposition('splunk-1', dispositionBody(), ctx('dispo-key-04'));
  assert.equal(linked.event.context.analysisSnapshot.verdict, 'MALICIOUS');
  assert.equal(linked.state.status, 'closed');
});

test('identical retries return the original event; reused keys with different content conflict', async () => {
  const { service, repository } = setup();
  const first = await service.recordDisposition('splunk-1', dispositionBody(), ctx('dispo-key-05'));
  await service.recordNote('splunk-1', { payload: { text: 'later' } }, ctx('note-key-0007'));

  // The retry carries the now-old expectedVersion 0 but must still be recognized as a retry.
  const retry = await service.recordDisposition('splunk-1', dispositionBody(), ctx('dispo-key-05'));
  assert.equal(retry.replayed, true);
  assert.equal(retry.event.id, first.event.id);
  assert.equal(retry.version, 2);
  assert.equal(repository.events.length, 2);

  await rejects(
    service.recordDisposition(
      'splunk-1',
      dispositionBody({
        payload: {
          outcome: 'true_positive',
          action: 'escalated',
          reasonCodes: ['confirmed_malicious_activity'],
        },
      }),
      ctx('dispo-key-05'),
    ),
    409,
    'idempotency_key_reused',
  );
  // Another analyst reusing the key never receives the first analyst's result.
  await rejects(
    service.recordDisposition('splunk-1', dispositionBody(), ctx('dispo-key-05', otherAnalyst)),
    409,
    'idempotency_key_reused',
  );
  await rejects(service.recordNote('splunk-1', { payload: { text: 'x' } }, ctx('bad key')), 422);
});

test('stale expected versions are rejected with the current state', async () => {
  const { service } = setup();
  await service.recordDisposition('splunk-1', dispositionBody(), ctx('dispo-key-06'));
  await assert.rejects(
    service.recordDisposition(
      'splunk-1',
      dispositionBody({
        payload: {
          outcome: 'true_positive',
          action: 'escalated',
          reasonCodes: ['confirmed_malicious_activity'],
        },
      }),
      ctx('dispo-key-07', otherAnalyst),
    ),
    (error) => {
      assert.equal(error.status, 409);
      assert.equal(error.details.reason, 'stale_version');
      assert.equal(error.details.currentVersion, 1);
      assert.equal(error.details.state.outcome, 'false_positive');
      return true;
    },
  );
  // Notes may omit expectedVersion; if they send one it is enforced.
  await service.recordNote('splunk-1', { payload: { text: 'no version' } }, ctx('note-key-0008'));
  await rejects(
    service.recordNote('splunk-1', { expectedVersion: 0, payload: { text: 'old' } }, ctx('note-key-0009')),
    409,
    'stale_version',
  );
});

test('reopen requires a closed alert, and an identical retry is not rejected', async () => {
  const { service, repository } = setup();
  await rejects(
    service.reopen('splunk-1', { expectedVersion: 0, payload: { reason: 'x' } }, ctx('reopen-key-1')),
    409,
    'already_open',
  );

  await service.recordDisposition('splunk-1', dispositionBody(), ctx('dispo-key-08'));
  const reopened = await service.reopen(
    'splunk-1',
    { expectedVersion: 1, payload: { reason: 'New evidence' } },
    ctx('reopen-key-2'),
  );
  assert.equal(reopened.state.status, 'open');
  assert.equal(reopened.state.outcome, null);

  const retry = await service.reopen(
    'splunk-1',
    { expectedVersion: 1, payload: { reason: 'New evidence' } },
    ctx('reopen-key-2'),
  );
  assert.equal(retry.replayed, true);
  await rejects(
    service.reopen('splunk-1', { expectedVersion: 2, payload: { reason: 'again' } }, ctx('reopen-key-3')),
    409,
    'already_open',
  );

  // Monitoring counts as open.
  await service.recordDisposition(
    'splunk-1',
    dispositionBody({
      expectedVersion: 2,
      payload: { outcome: 'inconclusive', action: 'monitoring', reasonCodes: ['insufficient_evidence'] },
    }),
    ctx('dispo-key-09'),
  );
  await rejects(
    service.reopen('splunk-1', { expectedVersion: 3, payload: { reason: 'x' } }, ctx('reopen-key-4')),
    409,
    'already_open',
  );
  assert.equal(repository.events.length, 3);
});

test('the stored projection equals a replay of the event log', async () => {
  const { service, repository } = setup();
  await service.recordReview('splunk-1', reviewBody(), ctx('review-key-09'));
  await service.recordDisposition('splunk-1', dispositionBody({ expectedVersion: 1 }), ctx('dispo-key-10'));
  await service.recordNote('splunk-1', { payload: { text: 'note' } }, ctx('note-key-0010'));
  await service.reopen(
    'splunk-1',
    { expectedVersion: 3, payload: { reason: 'Customer disputes' } },
    ctx('reopen-key-5'),
  );

  const replayed = reduceTriage(await repository.listEvents('alert-ref-1'));
  assert.deepEqual(repository.alert('splunk-1').triage, replayed);
  assert.deepEqual(
    repository.events.map((event) => event.sequence),
    [1, 2, 3, 4],
  );

  const investigation = await service.getInvestigation('splunk-1', { limit: 2 });
  assert.equal(investigation.projectionConsistent, true);
  assert.deepEqual(investigation.state, replayed);
  assert.deepEqual(
    investigation.events.map((event) => event.sequence),
    [4, 3],
  );
  assert.equal(investigation.pagination.nextBefore, 3);
  const older = await service.getInvestigation('splunk-1', { limit: 2, before: 3 });
  assert.deepEqual(
    older.events.map((event) => event.sequence),
    [2, 1],
  );
  assert.equal(older.pagination.nextBefore, null);
  // Page size never changes the derived state.
  assert.deepEqual(older.state, replayed);
});

test('legacy alerts without a triage projection are open at version 0', async () => {
  const { service } = setup([unanalyzedAlert()]);
  const investigation = await service.getInvestigation('splunk-2');
  assert.equal(investigation.state.status, 'open');
  assert.equal(investigation.version, 0);
  assert.equal(investigation.reviewableAnalysis.status, 'none');
  assert.equal(investigation.latestAnalysisReviewed, null);
  await rejects(service.getInvestigation('splunk-2', { limit: 0 }), 400);
});

test('writes fail with 503 when transactions are unavailable', async () => {
  const { service, repository } = setup(undefined, { transactionsSupported: false });
  await rejects(
    service.recordNote('splunk-1', { payload: { text: 'x' } }, ctx('note-key-0011')),
    503,
    'transactions_unavailable',
  );
  assert.equal(repository.events.length, 0);
  assert.equal((await service.getInvestigation('splunk-1')).version, 0);
});

test('a concurrent identical request that wins the unique-key race is answered as a replay', async () => {
  const { service, repository } = setup();
  const winner = await service.recordNote('splunk-1', { payload: { text: 'same' } }, ctx('note-key-0012'));

  // Simulate the loser: its transaction did not see the winner's event and hit the unique index instead.
  const originalTransaction = repository.transaction.bind(repository);
  repository.transaction = async () => {
    repository.transaction = originalTransaction;
    const error = new Error('E11000 duplicate key error');
    error.code = 11000;
    error.keyPattern = { alertRef: 1, idempotencyKey: 1 };
    throw error;
  };
  const loser = await service.recordNote('splunk-1', { payload: { text: 'same' } }, ctx('note-key-0012'));
  assert.equal(loser.replayed, true);
  assert.equal(loser.event.id, winner.event.id);
  assert.equal(repository.events.length, 1);
});

test('projection consistency compares the whole projection, not only its version', async () => {
  const { service, repository } = setup();
  await service.recordDisposition('splunk-1', dispositionBody(), ctx('dispo-key-11'));
  assert.equal((await service.getInvestigation('splunk-1')).projectionConsistent, true);

  // Same version, drifted content (for example after manual edits or a reducer change).
  repository.alert('splunk-1').triage.status = 'open';
  const drifted = await service.getInvestigation('splunk-1');
  assert.equal(drifted.projectionConsistent, false);
  assert.equal(drifted.state.status, 'closed');
});
