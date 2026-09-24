const assert = require('node:assert/strict');
const test = require('node:test');

const {
  scoreCandidate,
  summarizeOccurrences,
  validateOutcomePayload,
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

test('history summary counts analyst outcomes and unresolved occurrences', () => {
  const summary = summarizeOccurrences([
    {
      occurredAt: '2026-09-01T00:00:00.000Z',
      match: { reasons: ['same_detection_rule', 'same_host'] },
      analystResult: { outcome: 'false_positive' },
    },
    {
      occurredAt: '2026-09-02T00:00:00.000Z',
      match: { reasons: ['same_detection_rule'] },
      analystResult: null,
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

test('analyst outcome validation accepts the supported compact workflow', () => {
  assert.deepEqual(
    validateOutcomePayload({
      outcome: 'benign_true_positive',
      note: ' Authorized maintenance window ',
      ticketNumber: ' SOC-42 ',
    }),
    {
      outcome: 'benign_true_positive',
      note: 'Authorized maintenance window',
      ticketNumber: 'SOC-42',
    },
  );
});

test('analyst outcome validation rejects unknown outcomes', () => {
  assert.throws(
    () => validateOutcomePayload({ outcome: 'maybe' }),
    /outcome must be true_positive/,
  );
});
