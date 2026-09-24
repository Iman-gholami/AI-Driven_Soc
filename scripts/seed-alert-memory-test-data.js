require('dotenv').config();
const mongoose = require('mongoose');
const Alert = require('../src/models/Alert');
const AlertResolution = require('../src/models/AlertResolution');

const PREFIX = 'AM-TEST-';
const SOURCE = 'alert-memory-test';
const ACTOR = { id: 'alert-memory-seed', displayName: 'Alert Memory Test Seeder' };

function daysAgo(days, hours = 0) {
  return new Date(Date.now() - ((days * 24 + hours) * 60 * 60 * 1000));
}

function analyzedFields({ verdict, severity, summary, analyzedAt }) {
  return {
    status: 'analyzed',
    aiStatus: 'analyzed',
    severity,
    analysis: [
      {
        verdict,
        severity,
        summary,
        action: verdict === 'MALICIOUS' ? 'ESCALATE' : 'MONITOR',
        confidence: verdict === 'MALICIOUS' ? 88 : 72,
        analyzedAt,
      },
    ],
    fullAnalysis: {
      verdict,
      one_line_summary: summary,
      risk_assessment: { severity, confidence: verdict === 'MALICIOUS' ? 88 : 72 },
      analyst_decision: { action: verdict === 'MALICIOUS' ? 'ESCALATE' : 'MONITOR' },
    },
    processing: { attempts: 1, completedAt: analyzedAt },
  };
}

function makeAlert({
  n,
  days,
  ruleId,
  signature,
  host,
  eventType = 'network_connection',
  srcIp,
  dstIp,
  analyzed = true,
  verdict = 'SUSPICIOUS',
  severity = 'medium',
  summary = 'Synthetic Alert Memory test occurrence.',
}) {
  const eventTime = daysAgo(days);
  const alertId = `${PREFIX}${String(n).padStart(3, '0')}`;
  const rawEvent = {
    signature,
    eventtype: eventType,
    host,
    src_ip: srcIp,
    dst_ip: dstIp,
    test_data: true,
    alert_memory_seed: 'v1',
    event_time: eventTime.toISOString(),
  };

  return {
    alertId,
    source: SOURCE,
    signature,
    eventType,
    host,
    eventTime,
    rawEvent,
    ruleMatch: {
      status: 'matched',
      matchType: 'synthetic_test',
      signature,
      candidateCount: 1,
      reason: 'Synthetic Alert Memory test data',
      ruleId,
      revision: 1,
      title: `Synthetic rule ${ruleId}`,
    },
    eventHash: `alert-memory-test-hash-${String(n).padStart(3, '0')}-v1`,
    ...(analyzed
      ? analyzedFields({ verdict, severity, summary, analyzedAt: new Date(eventTime.getTime() + 10 * 60 * 1000) })
      : {
          status: 'new',
          aiStatus: 'not_analyzed',
          severity,
          analysis: [],
          processing: { attempts: 0 },
        }),
  };
}

const alerts = [
  makeAlert({
    n: 1,
    days: 12,
    ruleId: 'TEST-RULE-9001',
    signature: 'ALERT MEMORY TEST - suspicious outbound connection',
    host: 'am-test-ws-01',
    srcIp: '10.20.30.40',
    dstIp: '203.0.113.50',
    verdict: 'SUSPICIOUS',
    severity: 'high',
    summary: 'Earlier exact occurrence; analyst later marked it false positive.',
  }),
  makeAlert({
    n: 2,
    days: 9,
    ruleId: 'TEST-RULE-9001',
    signature: 'ALERT MEMORY TEST - suspicious outbound connection',
    host: 'am-test-ws-01',
    srcIp: '10.20.30.40',
    dstIp: '203.0.113.51',
    verdict: 'BENIGN',
    severity: 'low',
    summary: 'Exact rule/signature occurrence to a different destination.',
  }),
  makeAlert({
    n: 3,
    days: 7,
    ruleId: 'TEST-RULE-9002',
    signature: 'ALERT MEMORY TEST - suspicious outbound connection',
    host: 'am-test-ws-01',
    srcIp: '10.20.30.99',
    dstIp: '203.0.113.50',
    verdict: 'MALICIOUS',
    severity: 'critical',
    summary: 'Strong historical match with a different detection rule.',
  }),
  makeAlert({
    n: 4,
    days: 5,
    ruleId: 'TEST-RULE-9001',
    signature: 'ALERT MEMORY TEST - alternate signature',
    host: 'am-test-ws-77',
    srcIp: '10.77.0.10',
    dstIp: '203.0.113.50',
    verdict: 'UNKNOWN',
    severity: 'medium',
    summary: 'Strong match via rule, event type, and destination IP.',
  }),
  makeAlert({
    n: 5,
    days: 3,
    ruleId: 'TEST-RULE-9999',
    signature: 'ALERT MEMORY TEST - unrelated signature same destination',
    host: 'am-test-ws-88',
    eventType: 'dns_query',
    srcIp: '10.88.0.8',
    dstIp: '203.0.113.50',
    analyzed: false,
    severity: 'info',
  }),
  makeAlert({
    n: 6,
    days: 0,
    ruleId: 'TEST-RULE-9001',
    signature: 'ALERT MEMORY TEST - suspicious outbound connection',
    host: 'am-test-ws-01',
    srcIp: '10.20.30.40',
    dstIp: '203.0.113.50',
    analyzed: false,
    severity: 'high',
  }),
  makeAlert({
    n: 7,
    days: 2,
    ruleId: 'TEST-RULE-NO-MATCH',
    signature: 'ALERT MEMORY TEST - negative control',
    host: 'am-test-ws-negative',
    eventType: 'file_event',
    srcIp: '10.250.1.10',
    dstIp: '198.51.100.200',
    analyzed: false,
    severity: 'low',
  }),
];

const resolutionSpecs = [
  {
    alertId: `${PREFIX}001`,
    outcome: 'false_positive',
    note: 'Synthetic test: previously confirmed as noise from an approved process.',
    ticketNumber: 'SOC-TEST-001',
  },
  {
    alertId: `${PREFIX}002`,
    outcome: 'benign_true_positive',
    note: 'Synthetic test: detection was correct but the activity was authorized.',
    ticketNumber: 'SOC-TEST-002',
  },
  {
    alertId: `${PREFIX}003`,
    outcome: 'true_positive',
    note: 'Synthetic test: prior occurrence was escalated as a real security event.',
    ticketNumber: 'SOC-TEST-003',
  },
  {
    alertId: `${PREFIX}004`,
    outcome: 'inconclusive',
    note: 'Synthetic test: previous evidence was insufficient for a final determination.',
    ticketNumber: 'SOC-TEST-004',
  },
];

async function cleanup() {
  const existing = await Alert.find({ alertId: { $regex: `^${PREFIX}` } }).select('_id').lean().exec();
  const refs = existing.map((row) => row._id);
  const resolutionFilter = refs.length
    ? { $or: [{ alertRef: { $in: refs } }, { alertId: { $regex: `^${PREFIX}` } }] }
    : { alertId: { $regex: `^${PREFIX}` } };

  const [resolutionResult, alertResult] = await Promise.all([
    AlertResolution.deleteMany(resolutionFilter),
    Alert.deleteMany({ alertId: { $regex: `^${PREFIX}` } }),
  ]);

  return {
    alertsDeleted: alertResult.deletedCount || 0,
    resolutionsDeleted: resolutionResult.deletedCount || 0,
  };
}

async function seed() {
  const removed = await cleanup();
  const inserted = await Alert.insertMany(alerts, { ordered: true });
  const byId = new Map(inserted.map((row) => [row.alertId, row]));

  const resolutions = resolutionSpecs.map((spec, index) => ({
    alertRef: byId.get(spec.alertId)._id,
    alertId: spec.alertId,
    outcome: spec.outcome,
    note: spec.note,
    ticketNumber: spec.ticketNumber,
    resolvedAt: daysAgo(11 - index * 2),
    resolvedBy: ACTOR,
  }));
  await AlertResolution.insertMany(resolutions, { ordered: true });

  console.log(JSON.stringify({
    ok: true,
    removed,
    insertedAlerts: inserted.length,
    insertedResolutions: resolutions.length,
    currentAlert: `${PREFIX}006`,
    negativeControl: `${PREFIX}007`,
    expectedHistoryForCurrent: {
      matchedPrevious: 5,
      exact: [`${PREFIX}001`, `${PREFIX}002`],
      strong: [`${PREFIX}003`, `${PREFIX}004`],
      related: [`${PREFIX}005`],
      shouldNotAppear: `${PREFIX}007`,
      outcomeCounts: {
        false_positive: 1,
        benign_true_positive: 1,
        true_positive: 1,
        inconclusive: 1,
        unresolved: 1,
      },
    },
  }, null, 2));
}

async function main() {
  if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI is required');
  await mongoose.connect(process.env.MONGODB_URI);

  if (process.argv.includes('--cleanup')) {
    const result = await cleanup();
    console.log(JSON.stringify({ ok: true, cleanup: result }, null, 2));
  } else {
    await seed();
  }
}

main()
  .catch((error) => {
    console.error(`Alert Memory seed failed: ${error.message}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.disconnect();
  });
