const SEVERITY_WEIGHTS = {
  critical: 100,
  high: 75,
  medium: 50,
  low: 25,
  info: 10,
  unknown: 10,
};

// Turns the raw repository aggregation into the dashboard metrics served at /dashboard/stats.
function buildDashboardStats(result, { toAlertSummary }) {
  const summary = result.summary;
  const count = (key) => Number(summary[key] || 0);
  const total = count('total');
  const analyzed = count('analyzed');
  const weightedSeverity = Object.entries(SEVERITY_WEIGHTS)
    .reduce((sum, [severity, weight]) => sum + count(severity) * weight, 0);
  const mappedAlertCount = Number(result.mitre.mappedAlertCount || 0);

  return {
    window: result.window,
    totals: {
      alerts: total,
      uniqueHosts: count('uniqueHosts'),
      sources: result.sources.length,
    },
    severity: {
      critical: count('critical'),
      high: count('high'),
      medium: count('medium'),
      low: count('low'),
      info: count('info'),
      unknown: count('unknown'),
    },
    aiStatus: {
      analyzed,
      analyzing: count('analyzing'),
      failed: count('failed'),
      notAnalyzed: count('notAnalyzed'),
    },
    sources: result.sources,
    performance: {
      aiCoveragePercent: percent(analyzed, total),
      ruleMatchCoveragePercent: percent(count('matchedRules'), total),
      avgProcessingTimeMs: Math.round(count('avgProcessingTimeMs')),
    },
    posture: {
      severityPressureIndex: total ? Math.round(weightedSeverity / total) : 0,
      matchedRules: count('matchedRules'),
    },
    mitre: {
      techniqueCount: Number(result.mitre.techniqueCount || 0),
      mappedAlertCount,
      analyzedAlertCount: analyzed,
      coveragePercent: percent(mappedAlertCount, analyzed),
    },
    recentAlerts: result.recentAlerts.map(toAlertSummary),
  };
}

function percent(part, total) {
  if (!total) return 0;
  return Math.round((part / total) * 100);
}

module.exports = { buildDashboardStats };
