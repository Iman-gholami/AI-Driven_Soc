const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const test = require('node:test');
const { settings } = require('../src/core/config');
const { createApp } = require('../src/app');
const { InputError } = require('../src/core/errors');
const { buildDashboardStats } = require('../src/services/dashboardStats');

async function request(app, { method = 'GET', path, headers, body }) {
  const server = app.listen(0);
  try {
    const { port } = server.address();
    const response = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers, body });
    return { status: response.status, body: await response.json() };
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function withSettings(overrides, fn) {
  const previous = Object.fromEntries(Object.keys(overrides).map((key) => [key, settings[key]]));
  Object.assign(settings, overrides);
  return Promise.resolve(fn()).finally(() => Object.assign(settings, previous));
}

function createTestApp(routerDeps = {}) {
  return createApp({
    routerDeps: {
      analyzer: {},
      alertRepository: {},
      copilot: {},
      ...routerDeps,
    },
    reportRouterDeps: { analytics: {}, importer: {}, uploadReview: {}, copilot: {} },
  });
}

test('createApp returns the error envelope for unknown API routes', async () => {
  await withSettings({ authEnabled: false, enableRateLimiting: false }, async () => {
    const response = await request(createTestApp(), { path: '/does-not-exist' });
    assert.equal(response.status, 404);
    assert.equal(response.body.success, false);
    assert.match(response.body.detail, /not found/);
  });
});

test('createApp maps thrown AppErrors and hides unexpected error details', async () => {
  await withSettings({ authEnabled: false, enableRateLimiting: false }, async () => {
    const copilot = {
      async query(message) {
        if (message === 'bad') throw new InputError('message is required');
        throw new Error('database password leaked in stack');
      },
    };
    const app = createTestApp({ copilot });
    const post = (message) => request(app, {
      method: 'POST',
      path: '/copilot/query',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message }),
    });

    const invalid = await post('bad');
    assert.equal(invalid.status, 400);
    assert.equal(invalid.body.detail, 'message is required');

    const failed = await post('boom');
    assert.equal(failed.status, 500);
    assert.equal(failed.body.detail, 'Internal server error');
  });
});

test('createApp rejects malformed JSON with a 400 envelope', async () => {
  await withSettings({ authEnabled: false, enableRateLimiting: false }, async () => {
    const response = await request(createTestApp(), {
      method: 'POST',
      path: '/webhook-alert',
      headers: { 'Content-Type': 'application/json' },
      body: '{not json',
    });
    assert.equal(response.status, 400);
    assert.equal(response.body.success, false);
  });
});

test('createApp serves successful requests without an injected logger', async () => {
  await withSettings({ authEnabled: false, enableRateLimiting: false }, async () => {
    const alertRepository = {
      async upsertNewAlert(record) {
        return { ...record, status: 'new', aiStatus: 'not_analyzed', createdAt: 'now', updatedAt: 'now' };
      },
    };
    const response = await request(createTestApp({ alertRepository }), {
      method: 'POST',
      path: '/webhook-alert',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alertId: 'no-logger-1', severity: 'low' }),
    });
    assert.equal(response.status, 201);
    assert.equal(response.body.data.count, 1);
  });
});

test('createApp keeps analyst APIs behind authentication', async () => {
  await withSettings({ authEnabled: true, enableRateLimiting: false }, async () => {
    const response = await request(createTestApp(), { path: '/alerts' });
    assert.equal(response.status, 401);
    assert.equal(response.body.detail, 'Authentication required');
  });
});

test('health reports degraded when MongoDB is not connected', async () => {
  await withSettings({ authEnabled: true, enableRateLimiting: false }, async () => {
    const response = await request(createTestApp(), { path: '/health' });
    assert.equal(response.status, 503);
    assert.deepEqual(response.body, { status: 'degraded', database: 'disconnected' });
  });
});

test('config validation reports every invalid environment value', () => {
  const result = spawnSync(process.execPath, [
    '-e',
    'try { require("./src/core/config").assertValidConfig(); } catch (e) { console.log(JSON.stringify(e.errors)); }',
  ], {
    cwd: require('node:path').join(__dirname, '..'),
    env: { ...process.env, PORT: 'abc', AIR_GAPPED: 'maybe', LLM_PROVIDER: 'gemini', OPENAI_TIMEOUT_MS: '-5' },
    encoding: 'utf8',
  });
  const errors = JSON.parse(result.stdout);
  assert.equal(errors.length, 4);
  assert.ok(errors.some((message) => message.startsWith('PORT:')));
  assert.ok(errors.some((message) => message.startsWith('AIR_GAPPED:')));
  assert.ok(errors.some((message) => message.startsWith('LLM_PROVIDER:')));
  assert.ok(errors.some((message) => message.startsWith('OPENAI_TIMEOUT_MS:')));
});

test('buildDashboardStats derives coverage and severity pressure from repository aggregates', () => {
  const stats = buildDashboardStats({
    window: { from: 'a', to: 'b' },
    summary: { total: 4, analyzed: 2, critical: 1, high: 1, low: 2, matchedRules: 3, uniqueHosts: 2, avgProcessingTimeMs: 10.6 },
    sources: [{ source: 'splunk', count: 4 }],
    mitre: { techniqueCount: 5, mappedAlertCount: 1 },
    recentAlerts: [{ id: 1 }],
  }, { toAlertSummary: (alert) => ({ summarized: alert.id }) });

  assert.equal(stats.totals.alerts, 4);
  assert.equal(stats.posture.severityPressureIndex, Math.round((100 + 75 + 25 * 2) / 4));
  assert.equal(stats.performance.aiCoveragePercent, 50);
  assert.equal(stats.performance.ruleMatchCoveragePercent, 75);
  assert.equal(stats.performance.avgProcessingTimeMs, 11);
  assert.equal(stats.mitre.coveragePercent, 50);
  assert.deepEqual(stats.recentAlerts, [{ summarized: 1 }]);
});
