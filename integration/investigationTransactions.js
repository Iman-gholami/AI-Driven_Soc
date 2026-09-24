// Integration tests against a real single-node MongoDB replica set (transactions enabled).
// Run with `npm run test:integration`. mongodb-memory-server downloads the MongoDB binary on first use,
// which needs network access to fastdl.mongodb.org (override with MONGOMS_* environment variables).
const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const { MongoMemoryReplSet, MongoMemoryServer } = require('mongodb-memory-server-core');
const Alert = require('../src/models/Alert');
const InvestigationEvent = require('../src/models/InvestigationEvent');
const { InvestigationRepository } = require('../src/repositories/InvestigationRepository');
const { InvestigationService } = require('../src/services/investigationService');
const { describeReviewableAnalysis } = require('../src/investigation/analysisReference');
const { reduceTriage } = require('../src/investigation/triageReducer');

const MONGO_VERSION = process.env.MONGOMS_VERSION || '7.0.14';
const analyst = { username: 'analyst.one', displayName: 'Analyst One' };

let replSet;

test.before(async () => {
  replSet = await MongoMemoryReplSet.create({ binary: { version: MONGO_VERSION }, replSet: { count: 1 } });
  await mongoose.connect(replSet.getUri(), { dbName: 'investigation-integration' });
  await Promise.all([Alert.init(), InvestigationEvent.init()]);
});

test.after(async () => {
  await mongoose.disconnect();
  await replSet?.stop();
});

test.beforeEach(async () => {
  await Promise.all([Alert.deleteMany({}), InvestigationEvent.collection.deleteMany({})]);
});

async function createAnalyzedAlert(alertId = 'it-1') {
  const alert = await Alert.create({
    alertId,
    rawEvent: { signature: 'Example' },
    eventHash: `hash-${alertId}`,
    aiStatus: 'analyzed',
    status: 'analyzed',
    analysis: [
      {
        verdict: 'MALICIOUS',
        severity: 'high',
        summary: 'run',
        analyzedAt: new Date('2026-09-02T10:00:00.000Z'),
      },
    ],
    fullAnalysis: {
      verdict: 'MALICIOUS',
      risk_assessment: { severity: 'high' },
      attack_mapping: [{ technique: 'T1110', name: 'Brute Force' }],
      recommended_investigation_steps: ['Isolate host'],
    },
    llmProvider: 'openai',
    model: 'gpt-4.1',
    ruleMatch: { status: 'matched', ruleId: '1000001', revision: 3 },
  });
  return alert.toObject();
}

function reviewBody(alert) {
  return {
    expectedVersion: 0,
    analysisRef: describeReviewableAnalysis(alert).ref,
    payload: { sections: { verdict: 'agree' } },
  };
}

test('event insert and projection update commit together and replay to the same state', async () => {
  const alert = await createAnalyzedAlert();
  const service = new InvestigationService({ repository: new InvestigationRepository() });

  await service.recordReview('it-1', reviewBody(alert), { idempotencyKey: 'it-review-0001', user: analyst });
  await service.recordDisposition(
    'it-1',
    {
      expectedVersion: 1,
      analysisRef: describeReviewableAnalysis(alert).ref,
      payload: { outcome: 'false_positive', action: 'closed_no_action', reasonCodes: ['rule_too_broad'] },
    },
    { idempotencyKey: 'it-dispo-0001', user: analyst },
  );

  const stored = await Alert.findById(alert._id).lean();
  const events = await InvestigationEvent.find({ alertRef: alert._id }).sort({ sequence: 1 }).lean();
  assert.equal(events.length, 2);
  assert.equal(stored.triage.version, 2);
  assert.equal(stored.triage.status, 'closed');
  assert.deepEqual(
    JSON.parse(JSON.stringify(stored.triage)),
    JSON.parse(JSON.stringify(reduceTriage(events))),
  );
});

test('a failure after the event insert rolls the event back', async () => {
  const alert = await createAnalyzedAlert();
  class FailingRepository extends InvestigationRepository {
    async updateTriageProjection() {
      throw new Error('simulated failure between event insert and projection update');
    }
  }
  const service = new InvestigationService({ repository: new FailingRepository() });

  await assert.rejects(
    service.recordNote('it-1', { payload: { text: 'x' } }, { idempotencyKey: 'it-note-0001', user: analyst }),
    /simulated failure/,
  );
  assert.equal(await InvestigationEvent.countDocuments({ alertRef: alert._id }), 0);
  assert.equal((await Alert.findById(alert._id).lean()).triage, undefined);
});

test('re-analysis committed between validation and projection update aborts the review', async () => {
  const alert = await createAnalyzedAlert();
  let reanalyzed = false;
  class RacingRepository extends InvestigationRepository {
    async updateTriageProjection(...args) {
      if (!reanalyzed) {
        reanalyzed = true;
        // A separate, non-transactional write, exactly like IncidentAnalyzer persistence.
        await Alert.collection.updateOne(
          { _id: alert._id },
          {
            $push: {
              analysis: {
                verdict: 'BENIGN',
                severity: 'low',
                analyzedAt: new Date('2026-09-03T10:00:00.000Z'),
              },
            },
          },
        );
      }
      return super.updateTriageProjection(...args);
    }
  }
  const service = new InvestigationService({ repository: new RacingRepository() });

  await assert.rejects(
    service.recordReview('it-1', reviewBody(alert), { idempotencyKey: 'it-review-0002', user: analyst }),
    (error) => error.status === 409,
  );
  const stored = await Alert.findById(alert._id).lean();
  assert.equal(stored.analysis.length, 2);
  assert.equal(stored.triage, undefined);
  assert.equal(await InvestigationEvent.countDocuments({ alertRef: alert._id }), 0);
});

test('concurrent identical requests create exactly one event', async () => {
  await createAnalyzedAlert();
  const service = new InvestigationService({ repository: new InvestigationRepository() });
  const request = () =>
    service.recordNote(
      'it-1',
      { payload: { text: 'same' } },
      { idempotencyKey: 'it-note-0002', user: analyst },
    );

  const results = await Promise.all([request(), request(), request()]);
  assert.equal(new Set(results.map((result) => result.event.id)).size, 1);
  assert.equal(await InvestigationEvent.countDocuments({}), 1);
});

test('investigation events cannot be updated or deleted through the model', async () => {
  const alert = await createAnalyzedAlert();
  const service = new InvestigationService({ repository: new InvestigationRepository() });
  await service.recordNote(
    'it-1',
    { payload: { text: 'keep me' } },
    { idempotencyKey: 'it-note-0003', user: analyst },
  );

  await assert.rejects(
    InvestigationEvent.updateOne({ alertRef: alert._id }, { $set: { payload: {} } }),
    /append-only/,
  );
  await assert.rejects(InvestigationEvent.deleteMany({ alertRef: alert._id }), /append-only/);
  assert.equal(await InvestigationEvent.countDocuments({}), 1);
});

test('standalone MongoDB is rejected with 503 instead of writing without a transaction', async () => {
  const standalone = await MongoMemoryServer.create({ binary: { version: MONGO_VERSION } });
  const connection = await mongoose.createConnection(standalone.getUri()).asPromise();
  try {
    const repository = new InvestigationRepository({ connection });
    await assert.rejects(
      repository.transaction(async () => 'never'),
      (error) => error.status === 503,
    );
  } finally {
    await connection.close();
    await standalone.stop();
  }
});

test('projection maintenance backfills legacy alerts and repairs drift from the event log', async () => {
  const { backfill, rebuild } = require('../scripts/investigation-projections');
  const alert = await createAnalyzedAlert();
  await Alert.collection.insertOne({ alertId: 'legacy-1', rawEvent: {}, eventHash: 'legacy-hash' });
  const service = new InvestigationService({ repository: new InvestigationRepository() });
  await service.recordNote(
    'it-1',
    { payload: { text: 'x' } },
    { idempotencyKey: 'it-note-0004', user: analyst },
  );

  const backfilled = await backfill();
  assert.equal(backfilled.updated, 1);
  assert.equal((await Alert.findOne({ alertId: 'legacy-1' }).lean()).triage.status, 'open');
  assert.equal((await backfill()).updated, 0);

  await Alert.collection.updateOne({ _id: alert._id }, { $set: { 'triage.status': 'closed' } });
  const report = await rebuild({ apply: false });
  assert.equal(report.drifted, 1);
  const repaired = await rebuild({ apply: true });
  assert.equal(repaired.updated, 1);
  assert.equal((await Alert.findById(alert._id).lean()).triage.status, 'open');
  assert.equal((await rebuild({ apply: false })).drifted, 0);
});

test('feedback aggregations select the same cohorts as the pure selectors', async () => {
  const { AnalystFeedbackRepository } = require('../src/repositories/AnalystFeedbackRepository');
  const {
    selectLatestHumanReview,
    selectEffectiveHumanDisposition,
  } = require('../src/investigation/feedbackMetrics');
  const { AnalystFeedbackService } = require('../src/services/analystFeedbackService');

  const alert = await createAnalyzedAlert('it-metrics');
  const events = InvestigationEvent.collection;
  const base = {
    alertRef: alert._id,
    alertId: 'it-metrics',
    schemaVersion: 1,
    idempotencyKey: '',
    requestHash: 'x',
  };
  const human = { kind: 'human', id: 'a', displayName: 'A' };
  const snapshot = {
    verdict: 'MALICIOUS',
    provider: 'openai',
    model: 'gpt-4.1',
    rule: { ruleId: 'R1', revision: 1 },
  };
  const analysisRef = {
    analysisIndex: 0,
    analyzedAt: new Date('2026-09-02T10:00:00.000Z'),
    fingerprint: 'f',
  };
  const docs = [
    {
      sequence: 1,
      type: 'ai_review',
      createdAt: new Date('2026-09-03T00:00:00Z'),
      payload: { sections: { verdict: 'agree' } },
    },
    {
      sequence: 2,
      type: 'disposition',
      createdAt: new Date('2026-09-04T00:00:00Z'),
      payload: { outcome: 'false_positive' },
    },
    { sequence: 3, type: 'reopened', createdAt: new Date('2026-09-05T00:00:00Z'), payload: { reason: 'x' } },
    {
      sequence: 4,
      type: 'disposition',
      createdAt: new Date('2026-09-06T00:00:00Z'),
      payload: { outcome: 'true_positive' },
    },
    {
      sequence: 5,
      type: 'ai_review',
      createdAt: new Date('2026-09-09T00:00:00Z'),
      payload: { sections: { verdict: 'disagree' } },
    },
  ].map((doc) => ({
    ...base,
    ...doc,
    idempotencyKey: `seed-${doc.sequence}`,
    actor: human,
    context: { analysisRef, analysisSnapshot: snapshot, rule: snapshot.rule },
  }));
  await events.insertMany(docs);

  const window = { from: new Date('2026-09-01T00:00:00Z'), to: new Date('2026-09-08T00:00:00Z') };
  const repository = new AnalystFeedbackRepository();
  const collect = async (cursor) => {
    const rows = [];
    for await (const row of cursor) rows.push(row);
    return rows;
  };

  const reviewRows = await collect(repository.reviewRows(window));
  const dispositionRows = await collect(repository.dispositionRows(window));
  const coverageRows = await collect(repository.coverageRows(window));

  assert.equal(reviewRows.length, 1);
  assert.equal(
    reviewRows[0].createdAt.toISOString(),
    selectLatestHumanReview(docs, window).createdAt.toISOString(),
  );
  assert.equal(dispositionRows.length, 1);
  assert.equal(dispositionRows[0].outcome, selectEffectiveHumanDisposition(docs, window).payload.outcome);
  assert.equal(coverageRows.length, 1);
  assert.equal(coverageRows[0].reviews.length, 1);

  const report = await new AnalystFeedbackService({ repository }).getReport({
    from: window.from.toISOString(),
    to: window.to.toISOString(),
  });
  assert.equal(report.agreement.sections.verdict.strictAgreementRate, 1);
  assert.equal(report.falsePositiveShareByRule.rules[0].falsePositiveShare, 0);
  assert.equal(report.coverage.coverageRate, 1);
});
