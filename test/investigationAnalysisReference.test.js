const test = require('node:test');
const assert = require('node:assert/strict');
const {
  describeReviewableAnalysis,
  resolveAnalysisReference,
  analysisGuardToMongoFilter,
  matchesAnalysisGuard,
} = require('../src/investigation/analysisReference');
const { analyzedAlert, unanalyzedAlert } = require('./support/investigationFixtures');

test('only the latest persisted analysis is reviewable, with a deterministic fingerprint', () => {
  const alert = analyzedAlert();
  const first = describeReviewableAnalysis(alert);
  const second = describeReviewableAnalysis(structuredClone(alert));

  assert.equal(first.status, 'available');
  assert.equal(first.ref.analysisIndex, 1);
  assert.equal(first.ref.analyzedAt, '2026-09-02T10:00:00.000Z');
  assert.match(first.ref.fingerprint, /^[a-f0-9]{64}$/);
  assert.equal(first.ref.fingerprint, second.ref.fingerprint);
  assert.deepEqual(first.snapshot, {
    analysisRef: first.ref,
    verdict: 'MALICIOUS',
    severity: 'high',
    attackMapping: [{ technique: 'T1110', name: 'Brute Force' }],
    recommendations: ['Isolate host'],
    provider: 'openai',
    model: 'gpt-4.1',
    rule: { ruleId: '1000001', revision: 3 },
  });
});

test('unavailable legacy metadata stays unknown instead of being invented', () => {
  const alert = analyzedAlert({
    llmProvider: undefined,
    model: 'unknown',
    fullAnalysis: undefined,
    ruleMatch: { status: 'no_match' },
  });
  const { snapshot } = describeReviewableAnalysis(alert);
  assert.equal(snapshot.provider, null);
  assert.equal(snapshot.model, null);
  assert.equal(snapshot.attackMapping, null);
  assert.equal(snapshot.rule, null);
  // Summary fields from the latest analysis entry itself are still usable.
  assert.equal(snapshot.verdict, 'MALICIOUS');
  assert.deepEqual(snapshot.recommendations, ['Isolate host']);
});

test('fingerprint changes when the analysis context changes', () => {
  const base = describeReviewableAnalysis(analyzedAlert()).ref.fingerprint;
  assert.notEqual(describeReviewableAnalysis(analyzedAlert({ model: 'gpt-5' })).ref.fingerprint, base);
  assert.notEqual(
    describeReviewableAnalysis(
      analyzedAlert({ ruleMatch: { status: 'matched', ruleId: '1000001', revision: 4 } }),
    ).ref.fingerprint,
    base,
  );
});

test('in-progress, missing and legacy analyses are not reviewable', () => {
  assert.equal(describeReviewableAnalysis(analyzedAlert({ aiStatus: 'analyzing' })).status, 'in_progress');
  assert.deepEqual(describeReviewableAnalysis(unanalyzedAlert()).reason, 'no_analysis');
  assert.equal(
    describeReviewableAnalysis(unanalyzedAlert({ fullAnalysis: { verdict: 'BENIGN' } })).reason,
    'legacy_analysis_without_reference',
  );
  assert.equal(
    describeReviewableAnalysis(analyzedAlert({ analysis: [{ verdict: 'BENIGN' }] })).reason,
    'legacy_analysis_without_reference',
  );
});

test('reference validation distinguishes invalid (422) from stale (409) references', () => {
  const alert = analyzedAlert();
  const { ref } = describeReviewableAnalysis(alert);
  const status = (fn) => {
    try {
      fn();
    } catch (error) {
      return `${error.status}:${error.details.reason}`;
    }
    return 'ok';
  };

  assert.equal(
    status(() => resolveAnalysisReference(alert, ref, { requireAnalysis: true })),
    'ok',
  );
  assert.equal(
    status(() => resolveAnalysisReference(alert, { ...ref, analysisIndex: 7 }, { requireAnalysis: true })),
    '422:analysis_reference_not_found',
  );
  assert.equal(
    status(() =>
      resolveAnalysisReference(
        alert,
        { ...ref, analyzedAt: '2020-01-01T00:00:00.000Z' },
        { requireAnalysis: true },
      ),
    ),
    '422:analysis_reference_not_found',
  );
  assert.equal(
    status(() =>
      resolveAnalysisReference(
        alert,
        { analysisIndex: 0, analyzedAt: '2026-09-01T10:00:00.000Z', fingerprint: ref.fingerprint },
        { requireAnalysis: true },
      ),
    ),
    '409:stale_analysis_reference',
  );
  assert.equal(
    status(() =>
      resolveAnalysisReference(alert, { ...ref, fingerprint: '0'.repeat(64) }, { requireAnalysis: true }),
    ),
    '409:stale_analysis_reference',
  );
  assert.equal(
    status(() =>
      resolveAnalysisReference(analyzedAlert({ aiStatus: 'analyzing' }), ref, { requireAnalysis: true }),
    ),
    '409:analysis_in_progress',
  );
  assert.equal(
    status(() => resolveAnalysisReference(unanalyzedAlert(), ref, { requireAnalysis: true })),
    '422:no_reviewable_analysis',
  );
  // Dispositions without analysis store a null reference; a missing reference when one exists is stale.
  assert.equal(
    status(() => resolveAnalysisReference(unanalyzedAlert(), null, { requireAnalysis: false })),
    'ok',
  );
  assert.equal(
    status(() => resolveAnalysisReference(unanalyzedAlert(), ref, { requireAnalysis: false })),
    '422:analysis_reference_not_found',
  );
  assert.equal(
    status(() => resolveAnalysisReference(alert, null, { requireAnalysis: false })),
    '409:stale_analysis_reference',
  );
});

test('the MongoDB guard filter and the in-memory guard agree', () => {
  const alert = analyzedAlert();
  const { ref } = describeReviewableAnalysis(alert);
  const { guard } = resolveAnalysisReference(alert, ref, { requireAnalysis: true });

  assert.deepEqual(analysisGuardToMongoFilter(guard), {
    aiStatus: { $ne: 'analyzing' },
    'ruleMatch.status': 'matched',
    'ruleMatch.ruleId': '1000001',
    'ruleMatch.revision': 3,
    'analysis.1.analyzedAt': alert.analysis[1].analyzedAt,
    'analysis.2': { $exists: false },
    llmProvider: 'openai',
    model: 'gpt-4.1',
  });
  assert.equal(matchesAnalysisGuard(alert, guard), true);

  const reanalyzed = analyzedAlert();
  reanalyzed.analysis.push({ verdict: 'BENIGN', analyzedAt: new Date('2026-09-03T10:00:00.000Z') });
  assert.equal(matchesAnalysisGuard(reanalyzed, guard), false);
  assert.equal(matchesAnalysisGuard(analyzedAlert({ aiStatus: 'analyzing' }), guard), false);
  assert.equal(
    matchesAnalysisGuard(analyzedAlert({ ruleMatch: { status: 'matched', ruleId: '9' } }), guard),
    false,
  );

  const noAnalysis = resolveAnalysisReference(unanalyzedAlert(), null, { requireAnalysis: false }).guard;
  assert.equal(analysisGuardToMongoFilter(noAnalysis)['analysis.0'].$exists, false);
  assert.equal(matchesAnalysisGuard(unanalyzedAlert(), noAnalysis), true);
  assert.equal(
    matchesAnalysisGuard(analyzedAlert({ ruleMatch: unanalyzedAlert().ruleMatch }), noAnalysis),
    false,
  );
});
