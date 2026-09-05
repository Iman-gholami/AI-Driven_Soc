const assert = require('node:assert/strict');
const test = require('node:test');
const express = require('express');
const { createRouter } = require('../src/api/routes');

function createTestApp({ alertRepository, analyzer }) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.log = { info() {}, warn() {}, error() {} };
    next();
  });
  app.use(createRouter({ alertRepository, analyzer }));
  return app;
}

async function request(app, { method = 'GET', path }) {
  const server = app.listen(0);
  try {
    const { port } = server.address();
    const response = await fetch(`http://127.0.0.1:${port}${path}`, { method });
    const json = await response.json();
    return { status: response.status, body: json };
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

class InMemoryAlertRepository {
  constructor(alert) {
    this.alert = alert;
    this.updateCalls = 0;
    this.markStartedCalls = 0;
  }

  async findByAlertId(alertId) {
    return this.alert.alertId === alertId ? this.alert : null;
  }

  async markAnalysisStarted() {
    this.markStartedCalls += 1;
    if (this.alert.aiStatus === 'analyzing') return null;
    this.alert.aiStatus = 'analyzing';
    return this.alert;
  }

  async updateAnalysis(_alertId, persistence) {
    this.updateCalls += 1;
    this.alert = {
      ...this.alert,
      ...persistence,
      aiStatus: 'analyzed',
      status: 'analyzed',
    };
    return this.alert;
  }

  async markAnalysisFailed() {
    this.alert.aiStatus = 'failed';
    return this.alert;
  }
}

test('POST /alerts/:id/analyze reuses persisted analysis without a second LLM call', async () => {
  const alert = {
    alertId: 'cached-1',
    source: 'splunk',
    severity: 'high',
    status: 'new',
    aiStatus: 'not_analyzed',
    rawEvent: { signature: 'Example Detection', host: 'srv-1' },
    ruleMatch: {
      status: 'matched',
      matchType: 'exact_signature',
      candidateCount: 1,
      reason: null,
      resolutionEvidence: [],
    },
  };

  let llmCalls = 0;
  const analysis = {
    incident_summary: { what_happened: 'Suspicious activity' },
    detection_analysis: {},
    behavior_analysis: {},
    attack_mapping: {},
    risk_assessment: { severity: 'high', confidence: 90 },
    false_positive_analysis: {},
    recommended_investigation_steps: ['Review source IP'],
    final_soc_note: 'Investigate promptly.',
  };

  const repository = new InMemoryAlertRepository(alert);
  const analyzer = {
    resolveDetectionRule: async () => ({
      status: 'matched',
      matchType: 'exact_signature',
      candidateCount: 1,
      resolutionEvidence: [],
      rule: {
        ruleId: '2010658',
        revision: 2,
        title: 'Example Detection',
        classtype: 'web-application-attack',
        protocol: 'tcp',
        action: 'alert',
        parsedRule: { flow: [], contents: [], pcre: [] },
        rawRule: 'alert tcp any any -> any any (msg:"Example Detection";)',
      },
    }),
    analyzeStoredAlert: async () => {
      llmCalls += 1;
      return {
        analysis,
        ruleMatch: alert.ruleMatch,
        ruleResolution: await analyzer.resolveDetectionRule(),
        metadata: { provider: 'test-provider', model: 'test-model', processingTimeMs: 10 },
        persistence: {
          analysis,
          fullAnalysis: analysis,
          ruleMatch: alert.ruleMatch,
          soc: {},
          llmProvider: 'test-provider',
          model: 'test-model',
          processingTimeMs: 10,
        },
      };
    },
  };

  const app = createTestApp({ alertRepository: repository, analyzer });

  const first = await request(app, { method: 'POST', path: '/alerts/cached-1/analyze' });
  assert.equal(first.status, 200);
  assert.equal(first.body.data.aiStatus, 'analyzed');
  assert.equal(llmCalls, 1);

  const second = await request(app, { method: 'POST', path: '/alerts/cached-1/analyze' });
  assert.equal(second.status, 200);
  assert.equal(second.body.data.aiStatus, 'analyzed');
  assert.equal(second.body.data.metadata.cached, true);
  assert.deepEqual(second.body.data.analysis, analysis);
  assert.equal(llmCalls, 1);
  assert.equal(repository.updateCalls, 1);
});
