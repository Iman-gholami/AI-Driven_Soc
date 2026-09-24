const assert = require('node:assert/strict');
const test = require('node:test');

const {
  scoreCandidate,
  summarizeOccurrences,
  validateInvestigationPayload,
  validateClosePayload,
} = require('../src/services/alertMemoryService');

function signals(overrides = {}) {
  return {
    ruleId: 'rule-1001',
    signature: 'suspicious outbound request',
    host: 'sensor-a',
    eventType: 'ids',
    sourceIp: '10.0.0.10',
    destinationIp: '203.0.113.8',
    ...overrides,
  };
}

test('exact alert-memory match explains the deterministic overlap', () => {
  const result = scoreCandidate(signals(), signals());

  assert.equal(result.level, 'exact');
  assert.equal(result.score, 140);
  assert.deepEqual(result.reasons, [
    'same_detection_rule',
    'same_signature',
    'same_host',
    'same_event_type',
    'same_source_ip',
    'same_destination_ip',
  ]);
});

test('related network peer does not become an exact match without rule or signature overlap', () => {
  const result = scoreCandidate(
    signals(),
    signals({
      ruleId: 'other-rule',
      signature: 'other signature',
      host: 'sensor-b',
      eventType: 'proxy',
      sourceIp: '203.0.113.8',
      destinationIp: '10.0.0.99',
    }),
  );

  assert.equal(result.level, 'related');
  assert.equal(result.score, 8);
  assert.deepEqual(result.reasons, ['same_network_peer']);
});

test('history summary counts only final human decisions as resolved', () => {
  const summary = summarizeOccurrences([
    {
      occurredAt: '2026-09-01T00:00:00.000Z',
      match: { reasons: ['same_detection_rule', 'same_host'] },
      analystResult: { finalOutcome: 'false_positive' },
    },
    {
      occurredAt: '2026-09-02T00:00:00.000Z',
      match: { reasons: ['same_detection_rule'] },
      analystResult: { actionsTaken: ['Checked source IP'], finalOutcome: null },
    },
  ]);

  assert.equal(summary.seenBefore, true);
  assert.equal(summary.count, 2);
  assert.equal(summary.sameRuleCount, 2);
  assert.equal(summary.sameHostCount, 1);
  assert.equal(summary.outcomeCounts.false_positive, 1);
  assert.equal(summary.outcomeCounts.unresolved, 1);
  assert.equal(summary.firstSeen, '2026-09-01T00:00:00.000Z');
  assert.equal(summary.lastSeen, '2026-09-02T00:00:00.000Z');
});

test('investigation progress normalizes actions and note', () => {
  assert.deepEqual(
    validateInvestigationPayload({
      actionsTaken: [' Checked source IP ', 'Checked source IP', 'Reviewed firewall logs'],
      note: '  No endpoint evidence yet. ',
    }),
    {
      actionsTaken: ['Checked source IP', 'Reviewed firewall logs'],
      note: 'No endpoint evidence yet.',
    },
  );
});

test('true positive cannot be closed without a ticket', () => {
  assert.throws(
    () => validateClosePayload({ finalOutcome: 'true_positive', actionsTaken: [] }),
    /ticketNumber is required/,
  );
});

test('true positive closes with a required ticket', () => {
  const result = validateClosePayload({
    finalOutcome: 'true_positive',
    ticketNumber: ' SOC-42 ',
    actionsTaken: ['Escalated to IR'],
    note: ' Confirmed malicious activity ',
  });

  assert.equal(result.finalOutcome, 'true_positive');
  assert.equal(result.ticketNumber, 'SOC-42');
  assert.equal(result.falsePositiveReason, null);
  assert.deepEqual(result.actionsTaken, ['Escalated to IR']);
});

test('false positive cannot be closed without a reason', () => {
  assert.throws(
    () => validateClosePayload({ finalOutcome: 'false_positive', actionsTaken: [] }),
    /falsePositiveReason is required/,
  );
});

test('other false-positive reason requires details', () => {
  assert.throws(
    () => validateClosePayload({
      finalOutcome: 'false_positive',
      falsePositiveReason: 'other',
      actionsTaken: [],
    }),
    /falsePositiveDetails is required/,
  );
});

test('false positive closes with a canonical reason', () => {
  const result = validateClosePayload({
    finalOutcome: 'false_positive',
    falsePositiveReason: 'authorized_scanner',
    actionsTaken: ['Reviewed previous occurrences'],
    note: ' Known approved scanner ',
  });

  assert.equal(result.finalOutcome, 'false_positive');
  assert.equal(result.falsePositiveReason, 'authorized_scanner');
  assert.equal(result.note, 'Known approved scanner');
  assert.equal(result.ticketNumber, null);
});
