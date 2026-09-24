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
    alert_memory_seed: 'v2',
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
    eventHash: `alert-memory-test-hash-${String(n).padStart(3, '0')}-v2`,
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

function closedCase({ days, finalOutcome, actionsTaken, note, ticketNumber, falsePositiveReason, falsePositiveDetails }) {
  const startedAt = daysAgo(days, -1);
  const closedAt = daysAgo(days, -2);
  return {
    actionsTaken,
    note,
    startedAt,
    startedBy: ACTOR,
    updatedAt: closedAt,
    updatedBy: ACTOR,
    finalOutcome,
    falsePositiveReason,
    falsePositiveDetails,
    ticketNumber,
    closedAt,
    closedBy: ACTOR,
  };
}

const alerts = [
  {
    ...makeAlert({
      n: 1,
      days: 12,
      ruleId: 'TEST-RULE-9001',
      signature: 'ALERT MEMORY TEST - suspicious outbound connection',
      host: 'am-test-ws-01',
      srcIp: '10.20.30.40',
      dstIp: '203.0.113.50',
      verdict: 'SUSPICIOUS',
      severity: 'high',
      summary: 'Earlier exact occurrence; AI considered it suspicious.',
    }),
    status: 'closed',
    analystCase: closedCase({
      days: 11,
      finalOutcome: 'false_positive',
      actionsTaken: ['Reviewed previous occurrences', 'Checked source IP', 'Contacted asset owner'],
      note: 'Approved scanner activity confirmed with the asset owner.',
      falsePositiveReason: 'authorized_scanner',
    }),
  },
  {
    ...makeAlert({
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
    status: 'closed',
    analystCase: closedCase({
      days: 8,
      finalOutcome: 'false_positive',
      actionsTaken: ['Reviewed firewall / network logs', 'Checked destination asset'],
      note: 'Expected application behavior; detection rule was too broad for this traffic pattern.',
      falsePositiveReason: 'rule_too_broad',
    }),
  },
  {
    ...makeAlert({
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
    status: 'closed',
    analystCase: closedCase({
      days: 6,
      finalOutcome: 'true_positive',
      actionsTaken: ['Checked endpoint / EDR', 'Checked threat intelligence', 'Escalated to IR'],
      note: 'Malicious activity confirmed and escalated.',
      ticketNumber: 'SOC-TEST-003',
    }),
  },
  {
    ...makeAlert({
      n: 4,
      days: 5,
      ruleId: 'TEST-RULE-9001',
      signature: 'ALERT MEMORY TEST - alternate signature',
      host: 'am-test-ws-77',
      srcIp: '10.77.0.10',
      dstIp: '203.0.113.50',
      verdict: 'SUSPICIOUS',
      severity: 'medium',
      summary: 'Strong match via rule, event type, and destination IP.',
    }),
    status: 'closed',
    analystCase: closedCase({
      days: 4,
      finalOutcome: 'false_positive',
      actionsTaken: ['Checked threat intelligence', 'Reviewed firewall / network logs'],
      note: 'Known benign service generated the traffic.',
      falsePositiveReason: 'known_benign_service',
    }),
  },
  {
    ...makeAlert({
      n: 5,
      days: 3,
      ruleId: 'TEST-RULE-9999',
      signature: 'ALERT MEMORY TEST - unrelated signature same destination',
      host: 'am-test-ws-88',
      eventType: 'dns_query',
      srcIp: '10.88.0.8',
      dstIp: '203.0.113.50',
      analyzed: true,
      verdict: 'UNKNOWN',
      severity: 'info',
    }),
    status: 'investigating',
    analystCase: {
      actionsTaken: ['Checked destination asset'],
      note: 'Investigation started but no final decision was recorded.',
      startedAt: daysAgo(2, 20),
      startedBy: ACTOR,
      updatedAt: daysAgo(2, 19),
      updatedBy: ACTOR,
    },
  },
  makeAlert({
    n: 6,
    days: 0,
    ruleId: 'TEST-RULE-9001',
    signature: 'ALERT MEMORY TEST - suspicious outbound connection',
    host: 'am-test-ws-01',
    srcIp: '10.20.30.40',
    dstIp: '203.0.113.50',
    analyzed: true,
    verdict: 'SUSPICIOUS',
    severity: 'high',
    summary: 'Current test alert: analyst should review history, investigate, then close it.',
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

async function cleanup() {
  const existing = await Alert.find({ alertId: { $regex: `^${PREFIX}` } }).select('_id').lean().exec();
  const refs = existing.map((row) => row._id);
  const legacyResolutionFilter = refs.length
    ? { $or: [{ alertRef: { $in: refs } }, { alertId: { $regex: `^${PREFIX}` } }] }
    : { alertId: { $regex: `^${PREFIX}` } };

  const [legacyResolutionResult, alertResult] = await Promise.all([
    AlertResolution.deleteMany(legacyResolutionFilter),
    Alert.deleteMany({ alertId: { $regex: `^${PREFIX}` } }),
  ]);

  return {
    alertsDeleted: alertResult.deletedCount || 0,
    legacyResolutionsDeleted: legacyResolutionResult.deletedCount || 0,
  };
}

async function seed() {
  const removed = await cleanup();
  const inserted = await Alert.insertMany(alerts, { ordered: true });

  console.log(JSON.stringify({
    ok: true,
    removed,
    insertedAlerts: inserted.length,
    currentAlert: `${PREFIX}006`,
    negativeControl: `${PREFIX}007`,
    expectedHistoryForCurrent: {
      matchedPrevious: 5,
      exact: [`${PREFIX}001`, `${PREFIX}002`],
      strong: [`${PREFIX}003`, `${PREFIX}004`],
      related: [`${PREFIX}005`],
      shouldNotAppear: `${PREFIX}007`,
      outcomeCounts: {
        true_positive: 1,
        false_positive: 3,
        unresolved: 1,
      },
    },
    workflowTest: {
      alertId: `${PREFIX}006`,
      initialStatus: 'analyzed',
      expectedAfterSaveProgress: 'investigating',
      expectedAfterClose: 'closed',
      truePositiveRequiresTicket: true,
      falsePositiveRequiresReason: true,
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
