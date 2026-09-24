const test = require('node:test');
const assert = require('node:assert/strict');
const {
  applyEvent,
  reduceTriage,
  currentTriage,
  initialTriageState,
  TriageReplayError,
} = require('../src/investigation/triageReducer');

const human = { kind: 'human', id: 'analyst.one', displayName: 'Analyst One' };
const ref = {
  analysisIndex: 0,
  analyzedAt: new Date('2026-09-01T10:00:00.000Z'),
  fingerprint: 'f'.repeat(64),
};

function event(sequence, type, payload, extra = {}) {
  return {
    _id: `evt-${sequence}`,
    sequence,
    type,
    payload,
    actor: human,
    createdAt: new Date(Date.UTC(2026, 8, 1, 12, sequence)),
    context: { analysisRef: null },
    ...extra,
  };
}

const disposition = (sequence, action, outcome = 'false_positive', extra = {}) =>
  event(
    sequence,
    'disposition',
    { outcome, action, reasonCodes: ['rule_too_broad'], ticketNumber: `T-${sequence}` },
    extra,
  );

test('no events means open with no disposition or review', () => {
  assert.deepEqual(reduceTriage([]), initialTriageState());
  assert.equal(currentTriage({ alertId: 'legacy' }).status, 'open');
  assert.equal(currentTriage({ alertId: 'legacy' }).version, 0);
});

test('reviews and notes never change open/closed status or the current disposition', () => {
  const state = reduceTriage([
    disposition(1, 'closed_no_action'),
    event(2, 'note', { text: 'checked' }),
    event(
      3,
      'ai_review',
      { sections: { verdict: 'agree' }, corrections: {} },
      { context: { analysisRef: ref } },
    ),
  ]);
  assert.equal(state.status, 'closed');
  assert.equal(state.outcome, 'false_positive');
  assert.equal(state.version, 3);
  assert.equal(state.review.sequence, 3);
  assert.deepEqual(state.review.analysisRef, ref);
  assert.equal(state.lastEvent.type, 'ai_review');
});

test('monitoring keeps triage open while recording the disposition; closing actions close it', () => {
  const monitoring = reduceTriage([disposition(1, 'monitoring', 'inconclusive')]);
  assert.equal(monitoring.status, 'open');
  assert.equal(monitoring.action, 'monitoring');
  assert.equal(monitoring.closedAt, null);

  for (const action of ['ticket_created', 'escalated', 'closed_no_action']) {
    const closed = reduceTriage([disposition(1, action)]);
    assert.equal(closed.status, 'closed', action);
    assert.ok(closed.closedAt instanceof Date);
  }
});

test('a new disposition completely supersedes the previous one', () => {
  const state = reduceTriage([
    event(1, 'disposition', {
      outcome: 'true_positive',
      action: 'ticket_created',
      reasonCodes: ['confirmed_malicious_activity'],
      reasonText: 'first',
      ticketNumber: 'SOC-1',
    }),
    event(2, 'disposition', {
      outcome: 'inconclusive',
      action: 'monitoring',
      reasonCodes: ['insufficient_evidence'],
    }),
  ]);
  assert.equal(state.status, 'open');
  assert.equal(state.outcome, 'inconclusive');
  assert.deepEqual(state.reasonCodes, ['insufficient_evidence']);
  assert.equal(state.reasonText, null);
  assert.equal(state.ticketNumber, null);
  assert.equal(state.disposition.sequence, 2);
});

test('reopen clears the effective disposition but keeps the review', () => {
  const state = reduceTriage([
    event(
      1,
      'ai_review',
      { sections: { verdict: 'disagree' }, corrections: { verdict: 'BENIGN' } },
      { context: { analysisRef: ref } },
    ),
    disposition(2, 'ticket_created'),
    event(3, 'reopened', { reason: 'New evidence' }),
  ]);
  assert.equal(state.status, 'open');
  for (const field of ['outcome', 'action', 'reasonText', 'ticketNumber', 'closedAt', 'disposition']) {
    assert.equal(state[field], null, field);
  }
  assert.deepEqual(state.reasonCodes, []);
  assert.equal(state.review.sequence, 1);
  assert.equal(state.version, 3);
});

test('events are ordered by sequence even when timestamps tie or arrive out of order', () => {
  const sameTime = new Date('2026-09-01T12:00:00.000Z');
  const events = [
    event(
      2,
      'disposition',
      { outcome: 'false_positive', action: 'closed_no_action', reasonCodes: ['rule_too_broad'] },
      { createdAt: sameTime },
    ),
    event(
      1,
      'disposition',
      { outcome: 'true_positive', action: 'escalated', reasonCodes: ['confirmed_malicious_activity'] },
      { createdAt: sameTime },
    ),
  ];
  assert.equal(reduceTriage(events).outcome, 'false_positive');
});

test('replay rejects gaps and duplicates in the sequence', () => {
  assert.throws(
    () => reduceTriage([event(1, 'note', { text: 'a' }), event(3, 'note', { text: 'b' })]),
    TriageReplayError,
  );
  assert.throws(
    () => reduceTriage([event(1, 'note', { text: 'a' }), event(1, 'note', { text: 'b' })]),
    TriageReplayError,
  );
});

test('incremental application equals full replay', () => {
  const events = [
    event(1, 'note', { text: 'start' }),
    disposition(2, 'monitoring', 'inconclusive'),
    event(
      3,
      'ai_review',
      { sections: { severity: 'partially_agree' }, corrections: {} },
      { context: { analysisRef: ref } },
    ),
    disposition(4, 'escalated', 'true_positive'),
    event(5, 'reopened', { reason: 'Customer disputes' }),
    disposition(6, 'closed_no_action', 'benign_true_positive'),
    event(7, 'query_run', { toolName: 'query_soc_data', toolInput: {}, resultSummary: 'x' }),
  ];
  let incremental = initialTriageState();
  for (const item of events) incremental = applyEvent(incremental, item);
  assert.deepEqual(incremental, reduceTriage(events));
  assert.equal(incremental.version, 7);
  assert.equal(incremental.status, 'closed');
});
