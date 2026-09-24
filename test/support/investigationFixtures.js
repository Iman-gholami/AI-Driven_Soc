// Shared fixtures for investigation tests.
function analyzedAlert(overrides = {}) {
  return {
    _id: 'alert-ref-1',
    alertId: 'splunk-1',
    status: 'analyzed',
    aiStatus: 'analyzed',
    analysis: [
      {
        severity: 'medium',
        verdict: 'SUSPICIOUS',
        summary: 'First run',
        recommendations: ['Check logs'],
        analyzedAt: new Date('2026-09-01T10:00:00.000Z'),
      },
      {
        severity: 'high',
        verdict: 'MALICIOUS',
        summary: 'Second run',
        recommendations: ['Isolate host'],
        analyzedAt: new Date('2026-09-02T10:00:00.000Z'),
      },
    ],
    fullAnalysis: {
      verdict: 'MALICIOUS',
      risk_assessment: { severity: 'high', confidence: 80 },
      attack_mapping: [{ technique: 'T1110', name: 'Brute Force' }],
      recommended_investigation_steps: ['Isolate host'],
    },
    llmProvider: 'openai',
    model: 'gpt-4.1',
    ruleMatch: { status: 'matched', ruleId: '1000001', revision: 3 },
    createdAt: new Date('2026-09-01T09:00:00.000Z'),
    ...overrides,
  };
}

function unanalyzedAlert(overrides = {}) {
  return {
    _id: 'alert-ref-2',
    alertId: 'splunk-2',
    status: 'new',
    aiStatus: 'not_analyzed',
    analysis: [],
    ruleMatch: { status: 'matched', ruleId: '2000002', revision: 1 },
    createdAt: new Date('2026-09-01T09:00:00.000Z'),
    ...overrides,
  };
}

const analyst = { username: 'analyst.one', displayName: 'Analyst One', role: 'analyst' };
const otherAnalyst = { username: 'analyst.two', displayName: 'Analyst Two', role: 'analyst' };

module.exports = { analyzedAlert, unanalyzedAlert, analyst, otherAnalyst };
