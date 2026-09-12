const test = require('node:test');
const assert = require('node:assert/strict');

const {
  ThreatHuntingService,
  sanitizeReportEvidence,
} = require('../src/services/threatHuntingService');
const { DetectionEngineeringService } = require('../src/services/detectionEngineeringService');
const {
  scoreBehaviorChange,
  classifyBehaviorChange,
} = require('../src/services/behavioralHuntingService');

class FakeLlm {
  constructor(outputs) {
    this.outputs = [...outputs];
  }

  getMetadata() {
    return { provider: 'test', model: 'fake-model' };
  }

  async completeJson() {
    if (!this.outputs.length) throw new Error('No fake LLM output left');
    return this.outputs.shift();
  }
}

class FakeMcp {
  constructor() {
    this.calls = [];
  }

  async listTools() {
    return [
      { name: 'query_soc_data', description: 'read alerts' },
      { name: 'get_soc_entity_context', description: 'entity context' },
    ];
  }

  async callTool(name, args) {
    this.calls.push({ name, args });
    if (name === 'describe_soc_schema') {
      return { datasets: [{ name: 'alerts', fields: ['severity', 'signature', 'host'] }] };
    }
    if (name === 'query_soc_data') {
      return {
        dataset: 'alerts',
        operation: 'count',
        data: { count: 4 },
      };
    }
    throw new Error(`Unexpected fake MCP tool: ${name}`);
  }
}

test('threat hunting agent performs a tool step then returns an evidence-cited report', async () => {
  const llm = new FakeLlm([
    {
      decision: 'tool',
      rationale: 'Count high severity alerts before deciding whether the hunt has signal.',
      tool: 'query_soc_data',
      arguments: {
        dataset: 'alerts',
        operation: 'count',
        filters: [{ field: 'severity', operator: 'eq', value: 'high' }],
        groupBy: [],
        metrics: [],
        select: [],
        sort: [],
        limit: 20,
      },
    },
    {
      decision: 'finish',
      report: {
        verdict: 'suspicious',
        confidence: 70,
        summary: 'The hunt found high-severity activity that warrants review.',
        findings: [{
          title: 'High severity activity exists',
          severity: 'high',
          summary: 'Four matching alerts were returned.',
          evidenceRefs: ['obs-1'],
          entities: [],
        }],
        recommendedNextSteps: ['Review the matching alerts.'],
        limitations: ['The count alone does not prove maliciousness.'],
      },
    },
  ]);
  const mcp = new FakeMcp();
  const events = [];
  const service = new ThreatHuntingService({
    llm,
    mcpClient: mcp,
    now: (() => {
      let tick = 0;
      return () => new Date(Date.UTC(2026, 8, 12, 10, 0, tick++));
    })(),
  });

  const result = await service.run({
    goal: 'Find suspicious high severity activity',
    maxSteps: 4,
    onEvent: async (event) => events.push(event),
  });

  assert.equal(result.report.verdict, 'suspicious');
  assert.equal(result.report.findings.length, 1);
  assert.deepEqual(result.report.findings[0].evidenceRefs, ['obs-1']);
  assert.equal(result.observations.length, 1);
  assert.equal(result.observations[0].summary, 'Query returned count 4.');
  assert.ok(events.some((event) => event.type === 'tool_completed'));
  assert.ok(events.some((event) => event.type === 'hunt_completed'));
  assert.equal(mcp.calls.filter((call) => call.name === 'query_soc_data').length, 1);
});

test('ungrounded findings are removed and verdict is downgraded', () => {
  const report = {
    verdict: 'likely_malicious',
    confidence: 95,
    summary: 'Claimed malicious activity.',
    findings: [{
      title: 'Unsupported finding',
      severity: 'critical',
      summary: 'No successful observation supports this.',
      evidenceRefs: ['obs-999'],
      entities: ['1.2.3.4'],
    }],
    recommendedNextSteps: [],
    limitations: [],
  };

  const grounded = sanitizeReportEvidence(report, [
    { id: 'obs-1', status: 'success' },
  ]);

  assert.equal(grounded.verdict, 'inconclusive');
  assert.equal(grounded.confidence, 35);
  assert.equal(grounded.findings.length, 0);
  assert.ok(grounded.limitations.some((item) => item.includes('removed')));
});

test('detection engineer backtests a constrained draft without deployment', async () => {
  const llm = new FakeLlm([
    {
      title: 'Repeated suspicious signature activity',
      description: 'Draft detection for a grounded signature observed in the hunt.',
      severity: 'high',
      confidence: 80,
      filters: [{ field: 'signature', operator: 'contains', value: 'C2' }],
      rationale: 'The hunt report identified repeated C2-labeled detections.',
      mitreTechniqueIds: [],
      suricataDraft: null,
      limitations: ['Backtest is based on stored alerts only.'],
    },
  ]);

  const mcp = {
    async callTool(name, args) {
      if (name === 'describe_soc_schema') return { name: 'alerts', fields: ['signature', 'severity'] };
      if (name === 'query_soc_data_batch') {
        assert.equal(args.queries.length, 3);
        return {
          results: [
            { data: { count: 12 } },
            { data: { count: 9 } },
            { data: { rows: [{ alertId: 'A-1', signature: 'C2 beacon', severity: 'high' }] } },
          ],
        };
      }
      throw new Error(`Unexpected tool ${name}`);
    },
  };

  const service = new DetectionEngineeringService({ llm, mcpClient: mcp });
  const result = await service.generateAndBacktest({
    goal: 'Find C2 activity',
    report: {
      verdict: 'suspicious',
      confidence: 80,
      summary: 'Repeated C2-like detections were found.',
      findings: [],
    },
    days: 30,
  });

  assert.equal(result.proposal.deploymentStatus, 'draft_only');
  assert.equal(result.proposal.autoDeploy, false);
  assert.equal(result.backtest.matchedCount, 12);
  assert.equal(result.backtest.highRiskCount, 9);
  assert.equal(result.backtest.highRiskPercent, 75);
  assert.equal(result.metadata.deterministicBacktest, true);
});

test('behavior scoring identifies novel and elevated activity deterministically', () => {
  const novel = scoreBehaviorChange({
    recentCount: 5,
    baselineCount: 0,
    recentHours: 24,
    baselineHours: 168,
  });
  assert.equal(novel.anomalyScore, 9);
  assert.equal(classifyBehaviorChange({ baselineCount: 0, ...novel }), 'novel');

  const elevated = scoreBehaviorChange({
    recentCount: 20,
    baselineCount: 14,
    recentHours: 24,
    baselineHours: 168,
  });
  assert.ok(elevated.ratio > 2);
  assert.ok(elevated.anomalyScore > 0);
  assert.ok(['elevated', 'spike'].includes(classifyBehaviorChange({ baselineCount: 14, ...elevated })));
});
