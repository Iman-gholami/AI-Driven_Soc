const test = require('node:test');
const assert = require('node:assert/strict');
const {
  WorkbenchAnalyticsService,
  buildRuleSignals,
  percent,
} = require('../src/services/workbenchAnalyticsService');

function aggregateQueue(values) {
  const queue = [...values];
  return {
    aggregate() {
      const value = queue.shift();
      return { exec: async () => value };
    },
  };
}

test('percent handles empty denominator and one-decimal ratios', () => {
  assert.equal(percent(0, 0), 0);
  assert.equal(percent(1, 3), 33.3);
  assert.equal(percent(9, 10), 90);
});

test('AI evaluation returns persisted operational model metrics without inventing accuracy', async () => {
  const alertModel = aggregateQueue([
    [{ total: 20, analyzed: 15, failed: 3, analyzing: 1, avgLatencyMs: 1250 }],
    [{ provider: 'local', model: 'qwen', runs: 10, analyzed: 9, failed: 1, avgLatencyMs: 900, minLatencyMs: 500, maxLatencyMs: 1800 }],
  ]);
  const service = new WorkbenchAnalyticsService({ alertModel, detectionRuleModel: {} });

  const result = await service.getAiEvaluation({ days: 30 });

  assert.equal(result.summary.total, 20);
  assert.equal(result.summary.coveragePercent, 75);
  assert.equal(result.summary.successPercent, 83.3);
  assert.equal(result.models[0].successPercent, 90);
  assert.match(result.limitations[0], /Accuracy is not estimated/);
  assert.equal(Object.hasOwn(result.summary, 'accuracy'), false);
});

test('rule insights expose deterministic quality signals and telemetry', async () => {
  const alertModel = aggregateQueue([
    [{ total: 120, critical: 1, high: 4, medium: 40, low: 75, analyzed: 100, failed: 2, avgLatencyMs: 1500, firstSeen: new Date('2026-09-01T00:00:00Z'), lastSeen: new Date('2026-09-10T00:00:00Z') }],
    [{ host: 'web-01', count: 120 }],
    [{ signature: 'Possible SYN flood', count: 120 }],
  ]);
  const rule = { ruleId: '2100498', revision: 3, title: 'Possible SYN flood', tier: 'native', mitre: { mapped: false } };
  const detectionRuleModel = {
    findOne() {
      return {
        select() { return this; },
        lean() { return this; },
        async exec() { return rule; },
      };
    },
  };
  const service = new WorkbenchAnalyticsService({ alertModel, detectionRuleModel });

  const result = await service.getRuleInsights('2100498', { days: 30 });

  assert.equal(result.rule.ruleId, '2100498');
  assert.equal(result.stats.total, 120);
  assert.equal(result.stats.highRiskPercent, 4.2);
  assert.equal(result.stats.aiCoveragePercent, 83.3);
  assert.equal(result.topHosts[0].host, 'web-01');
  assert.ok(result.signals.some((item) => item.code === 'HIGH_VOLUME_LOW_SEVERITY'));
  assert.ok(result.signals.some((item) => item.code === 'HOST_CONCENTRATION'));
  assert.ok(result.signals.some((item) => item.code === 'MITRE_UNMAPPED'));
});

test('rule signals remain conservative when there is not enough telemetry', () => {
  assert.deepEqual(
    buildRuleSignals({ total: 0, highRisk: 0, hostRows: [], rule: { mitre: { mapped: true } } }),
    [{ level: 'info', code: 'NO_RECENT_HITS', message: 'No alert matched this rule in the selected window.' }],
  );
});
