const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createRouter } = require('../src/api/routes');
const { createApp } = require('../src/app');
const { settings } = require('../src/core/config');
const { errorHandler, notFoundHandler } = require('../src/api/middleware/errorHandler');
const { buildListFilters } = require('../src/repositories/AlertRepository');
const { InvestigationService } = require('../src/services/investigationService');
const { describeReviewableAnalysis } = require('../src/investigation/analysisReference');
const { InMemoryInvestigationRepository } = require('./support/inMemoryInvestigationRepository');
const { analyzedAlert, unanalyzedAlert, analyst } = require('./support/investigationFixtures');

function createTestApp({ user = analyst, alertRepository = {} } = {}) {
  const repository = new InMemoryInvestigationRepository({ alerts: [analyzedAlert(), unanalyzedAlert()] });
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.log = { info() {}, warn() {}, error() {} };
    if (user) req.user = user;
    next();
  });
  app.use(
    createRouter({
      analyzer: {},
      alertRepository,
      copilot: {},
      investigationService: new InvestigationService({ repository }),
    }),
  );
  app.use(notFoundHandler);
  app.use(errorHandler);
  return { app, repository };
}

async function request(app, { method = 'GET', path, body, key }) {
  const server = app.listen(0);
  try {
    const { port } = server.address();
    const headers = {};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (key) headers['Idempotency-Key'] = key;
    const response = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: response.status, headers: response.headers, body: await response.json() };
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

const ref = () => describeReviewableAnalysis(analyzedAlert()).ref;
const disposition = (overrides = {}) => ({
  expectedVersion: 0,
  analysisRef: ref(),
  payload: { outcome: 'false_positive', action: 'closed_no_action', reasonCodes: ['rule_too_broad'] },
  ...overrides,
});

test('GET /investigation/reasons serves the reason vocabulary', async () => {
  const { app } = createTestApp();
  const response = await request(app, { path: '/investigation/reasons' });
  assert.equal(response.status, 200);
  assert.ok(response.body.data.reasons.some((reason) => reason.id === 'other' && reason.requiresText));
  assert.equal(response.body.data.outcomes.length, 4);
});

test('GET /alerts/:id/investigation returns state, reviewable reference and pagination', async () => {
  const { app } = createTestApp();
  const response = await request(app, { path: '/alerts/splunk-1/investigation' });
  assert.equal(response.status, 200);
  assert.equal(response.body.data.version, 0);
  assert.equal(response.body.data.state.status, 'open');
  assert.equal(response.body.data.reviewableAnalysis.status, 'available');
  assert.deepEqual(response.body.data.reviewableAnalysis.analysisRef, ref());
  assert.equal(response.body.data.latestAnalysisReviewed, false);
  assert.equal(response.body.data.analyses.length, 2);

  assert.equal((await request(app, { path: '/alerts/unknown/investigation' })).status, 404);
  assert.equal((await request(app, { path: '/alerts/splunk-1/investigation?limit=abc' })).status, 400);
});

test('write endpoints return 201, replay identical retries with 200 and conflict on stale versions', async () => {
  const { app, repository } = createTestApp();
  const first = await request(app, {
    method: 'POST',
    path: '/alerts/splunk-1/investigation/disposition',
    body: disposition(),
    key: 'api-dispo-0001',
  });
  assert.equal(first.status, 201);
  assert.equal(first.body.data.event.actor.id, 'analyst.one');
  assert.equal(first.body.data.state.status, 'closed');

  const retry = await request(app, {
    method: 'POST',
    path: '/alerts/splunk-1/investigation/disposition',
    body: disposition(),
    key: 'api-dispo-0001',
  });
  assert.equal(retry.status, 200);
  assert.equal(retry.headers.get('idempotent-replayed'), 'true');
  assert.equal(retry.body.data.event.id, first.body.data.event.id);

  const reusedKey = await request(app, {
    method: 'POST',
    path: '/alerts/splunk-1/investigation/disposition',
    body: disposition({
      payload: { outcome: 'inconclusive', action: 'monitoring', reasonCodes: ['insufficient_evidence'] },
    }),
    key: 'api-dispo-0001',
  });
  assert.equal(reusedKey.status, 409);
  assert.equal(reusedKey.body.reason, 'idempotency_key_reused');

  const stale = await request(app, {
    method: 'POST',
    path: '/alerts/splunk-1/investigation/disposition',
    body: disposition({
      payload: { outcome: 'inconclusive', action: 'monitoring', reasonCodes: ['insufficient_evidence'] },
    }),
    key: 'api-dispo-0002',
  });
  assert.equal(stale.status, 409);
  assert.equal(stale.body.success, false);
  assert.equal(stale.body.reason, 'stale_version');
  assert.equal(stale.body.currentVersion, 1);
  assert.equal(repository.events.length, 1);
});

test('review, note and reopen endpoints follow the error contract', async () => {
  const { app } = createTestApp();
  const review = await request(app, {
    method: 'POST',
    path: '/alerts/splunk-1/investigation/review',
    body: { expectedVersion: 0, analysisRef: ref(), payload: { sections: { verdict: 'disagree' } } },
    key: 'api-review-001',
  });
  assert.equal(review.status, 422);
  assert.equal(review.body.reason, 'invalid_payload');
  assert.equal(review.body.issues[0].path, 'payload.corrections.verdict');

  const noKey = await request(app, {
    method: 'POST',
    path: '/alerts/splunk-1/investigation/notes',
    body: { payload: { text: 'hello' } },
  });
  assert.equal(noKey.status, 422);

  const note = await request(app, {
    method: 'POST',
    path: '/alerts/splunk-1/investigation/notes',
    body: { payload: { text: 'hello' } },
    key: 'api-note-0001',
  });
  assert.equal(note.status, 201);

  const reopen = await request(app, {
    method: 'POST',
    path: '/alerts/splunk-1/investigation/reopen',
    body: { expectedVersion: 1, payload: { reason: 'Not closed yet' } },
    key: 'api-reopen-01',
  });
  assert.equal(reopen.status, 409);
  assert.equal(reopen.body.reason, 'already_open');

  const unknown = await request(app, {
    method: 'POST',
    path: '/alerts/unknown/investigation/notes',
    body: { payload: { text: 'hello' } },
    key: 'api-note-0002',
  });
  assert.equal(unknown.status, 404);

  const unreviewable = await request(app, {
    method: 'POST',
    path: '/alerts/splunk-2/investigation/review',
    body: { expectedVersion: 0, analysisRef: ref(), payload: { sections: { verdict: 'agree' } } },
    key: 'api-review-002',
  });
  assert.equal(unreviewable.status, 422);
  assert.equal(unreviewable.body.reason, 'no_reviewable_analysis');
});

test('writes without an authenticated identity are rejected and reserved types have no endpoint', async () => {
  const { app, repository } = createTestApp({ user: null });
  const response = await request(app, {
    method: 'POST',
    path: '/alerts/splunk-1/investigation/notes',
    body: { payload: { text: 'hello' } },
    key: 'api-note-0003',
  });
  assert.equal(response.status, 401);

  for (const type of ['query_run', 'evidence_marked', 'events']) {
    const reserved = await request(app, {
      method: 'POST',
      path: `/alerts/splunk-1/investigation/${type}`,
      body: {},
      key: 'api-reserved-1',
    });
    assert.equal(reserved.status, 404, type);
  }
  assert.equal(repository.events.length, 0);
});

test('with panel auth disabled there is no identity, so investigation writes return 401', async () => {
  const previous = { authEnabled: settings.authEnabled, enableRateLimiting: settings.enableRateLimiting };
  Object.assign(settings, { authEnabled: false, enableRateLimiting: false });
  try {
    const repository = new InMemoryInvestigationRepository({ alerts: [analyzedAlert()] });
    const app = createApp({
      routerDeps: {
        analyzer: {},
        alertRepository: {},
        copilot: {},
        investigationService: new InvestigationService({ repository }),
      },
      reportRouterDeps: { analytics: {}, importer: {}, uploadReview: {}, copilot: {} },
    });
    const response = await request(app, {
      method: 'POST',
      path: '/alerts/splunk-1/investigation/notes',
      body: { payload: { text: 'hello' } },
      key: 'api-note-0004',
    });
    assert.equal(response.status, 401);
  } finally {
    Object.assign(settings, previous);
  }
});

test('GET /alerts validates and forwards triage filters', async () => {
  const calls = [];
  const alertRepository = {
    async listAlerts(params) {
      calls.push(params);
      return { alerts: [], pagination: { page: 1, limit: 50, total: 0, pages: 0 }, filters: {}, sort: {} };
    },
  };
  const { app } = createTestApp({ alertRepository });

  assert.equal(
    (await request(app, { path: '/alerts?triageStatus=closed&outcome=false_positive' })).status,
    200,
  );
  assert.equal(calls[0].triageStatus, 'closed');
  assert.equal(calls[0].outcome, 'false_positive');
  assert.equal((await request(app, { path: '/alerts?triageStatus=done' })).status, 400);
  assert.equal((await request(app, { path: '/alerts?outcome=benign' })).status, 400);
});

test('triage list filters treat alerts without a projection as open', () => {
  assert.deepEqual(buildListFilters({ triageStatus: 'open' }), {
    $and: [{ $or: [{ 'triage.status': 'open' }, { triage: { $exists: false } }, { triage: null }] }],
  });
  assert.deepEqual(buildListFilters({ triageStatus: 'closed', outcome: 'true_positive' }), {
    'triage.status': 'closed',
    'triage.outcome': 'true_positive',
  });
});
