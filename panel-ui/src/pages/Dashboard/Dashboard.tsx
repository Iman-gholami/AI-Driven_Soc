import React, { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { api } from '../../api/client';
import type { Alert, DashboardStats } from '../../types';
import RiskIndex from '../../components/SOC/RiskIndex';
import MetricCard from '../../components/SOC/MetricCard';
import PerformanceMetric from '../../components/SOC/PerformanceMetric';
import DetectionSourcePanel from '../../components/SOC/DetectionSourcePanel';
import SeverityPressure from '../../components/SOC/SeverityPressure';
import WorkloadPanel from '../../components/SOC/WorkloadPanel';
import ThreatTimeline from '../../components/SOC/ThreatTimeline';
import MitreCoverage from '../../components/SOC/MitreCoverage';
import IncidentCard from '../../components/SOC/IncidentCard';
import './Dashboard.css';

const EMPTY_STATS: DashboardStats = {
  window: { from: null, to: null },
  totals: { alerts: 0, uniqueHosts: 0, sources: 0 },
  severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
  aiStatus: { analyzed: 0, analyzing: 0, failed: 0, notAnalyzed: 0 },
  sources: [],
  performance: { aiCoveragePercent: 0, ruleMatchCoveragePercent: 0, avgProcessingTimeMs: 0 },
  posture: { severityPressureIndex: 0, matchedRules: 0 },
  mitre: { techniqueCount: 0, mappedAlertCount: 0, analyzedAlertCount: 0, coveragePercent: 0 },
  recentAlerts: [],
};

type TimeRange = '24h' | '7d' | '30d';
const RANGES: TimeRange[] = ['24h', '7d', '30d'];

const Dashboard: React.FC = () => {
  const [range, setRange] = useState<TimeRange>('24h');
  const navigate = useNavigate();
  const rangeStart = useMemo(() => getRangeStart(range), [range]);
  const { data, dataUpdatedAt, isFetching, isLoading, isError, refetch } = useQuery({
    queryKey: ['dashboard-stats', range],
    queryFn: () => api.getDashboardStats({ createdAtFrom: rangeStart.toISOString() }),
    refetchInterval: 60_000,
  });

  // Never display fabricated values while the first request is loading or has failed.
  if (isLoading && !data) {
    return <main className="command-center command-center--redesign">
      <div className="soc-dashboard-state" role="status">Loading security operations data…</div>
    </main>;
  }
  if (isError && !data) {
    return <main className="command-center command-center--redesign">
      <div className="soc-dashboard-state soc-dashboard-state--error" role="alert">
        <h1>Dashboard unavailable</h1>
        <p>Security telemetry could not be loaded. Please try again.</p>
        <button type="button" onClick={() => void refetch()}>Retry loading</button>
      </div>
    </main>;
  }

  const stats = data || EMPTY_STATS;
  // The dashboard response exposes only its most recent alerts, not the full investigation queue.
  const recentAlerts = stats.recentAlerts.slice(0, 4);
  const pendingAnalysis = stats.aiStatus.notAnalyzed + stats.aiStatus.failed;
  const timeline = stats.recentAlerts.slice(0, 4).map((alert) => ({
    time: new Date(alert.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    title: alert.signature || alert.eventType || 'Unclassified detection',
    detail: `${alert.source || 'Unknown source'}${alert.host ? ` · ${alert.host}` : ''} · AI ${alert.aiStatus.replace('_', ' ')}`,
    state: toTimelineState(alert),
  }));

  return <main className="command-center command-center--redesign">
    <header className="command-header soc-dashboard-header">
      <div>
        <div className="command-kicker"><span>SECURITY OPERATIONS</span><i /> Live database metrics</div>
        <h1>Command Center</h1>
        <p>A focused view of detections, investigations, and AI analysis.</p>
      </div>
      <div className="header-controls">
        <div className="refresh-status">
          <i aria-hidden="true" />
          <span>Last updated<strong>{dataUpdatedAt ? new Date(dataUpdatedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—'}</strong></span>
        </div>
        <button className="soc-refresh-button" type="button" onClick={() => void refetch()} disabled={isFetching} aria-label="Refresh dashboard data">
          {isFetching ? 'Refreshing…' : 'Refresh'}
        </button>
        <div className="range-selector" role="group" aria-label="Dashboard time range">
          {RANGES.map((option) => <button key={option} type="button" aria-pressed={range === option}
            className={range === option ? 'active' : ''} onClick={() => setRange(option)}>{option}</button>)}
        </div>
      </div>
    </header>

    {isError && <div role="alert" className="soc-dashboard-warning">The latest refresh failed. Showing the last successfully loaded data.</div>}

    <section className="soc-overview-kpis" aria-label="Security overview metrics">
      <MetricCard title="Total alerts" value={stats.totals.alerts} detail={`Detected in the last ${range}`} />
      <MetricCard title="Critical alerts" value={stats.severity.critical} detail="Highest severity detections" tone="critical" />
      <MetricCard title="AI analyzed" value={stats.aiStatus.analyzed} detail={`${stats.performance.aiCoveragePercent}% analysis coverage`} tone="ai" />
      <MetricCard title="Affected hosts" value={stats.totals.uniqueHosts} detail="Distinct hosts with alerts" tone="success" />
    </section>

    <div className="soc-dashboard-workspace">
      <section className="soc-dashboard-primary" aria-labelledby="recent-alerts-heading">
        <div className="soc-section-heading">
          <div>
            <span className="soc-section-eyebrow">INVESTIGATION</span>
            <h2 id="recent-alerts-heading">Recent alerts</h2>
            <p>Latest stored detections. Open an alert to review evidence and AI analysis.</p>
          </div>
          <button type="button" className="soc-view-all-button" onClick={() => navigate('/alerts')}>View all alerts <span aria-hidden="true">→</span></button>
        </div>
        <div className="soc-attention-strip">
          <span className="soc-attention-dot" aria-hidden="true" />
          <strong>{pendingAnalysis}</strong> alerts not analyzed or with failed AI analysis
          <span className="soc-attention-hint">AI eligibility depends on rule matching</span>
        </div>
        <div className="incident-queue soc-dashboard-incidents">
          {recentAlerts.length ? recentAlerts.map((alert) => <IncidentCard key={alert.alertId} alert={alert}
            onInvestigate={(id) => navigate(`/alerts?alert=${encodeURIComponent(id)}`)} />)
            : <div className="queue-empty"><strong>No recent alerts</strong><span>Change the time range to inspect a wider window.</span></div>}
        </div>
      </section>

      <aside className="soc-dashboard-sidebar" aria-label="Security posture and analysis health">
        <RiskIndex value={stats.posture.severityPressureIndex} totalAlerts={stats.totals.alerts}
          criticalAlerts={stats.severity.critical} highAlerts={stats.severity.high} />
        <section className="soc-panel soc-ai-health">
          <div className="panel-heading">
            <div><span className="eyebrow">AUTOMATED TRIAGE</span><h2>AI analysis health</h2></div>
          </div>
          <div className="soc-health-row">
            <div><span>AI coverage</span><strong>{stats.performance.aiCoveragePercent}%</strong></div>
            <div className="soc-health-track"><i style={{ width: `${boundedPercent(stats.performance.aiCoveragePercent)}%` }} /></div>
          </div>
          <div className="soc-health-row">
            <div><span>Rule match coverage</span><strong>{stats.performance.ruleMatchCoveragePercent}%</strong></div>
            <div className="soc-health-track"><i style={{ width: `${boundedPercent(stats.performance.ruleMatchCoveragePercent)}%` }} /></div>
          </div>
          <div className="soc-health-summary">
            <div><strong>{stats.aiStatus.notAnalyzed}</strong><span>Not analyzed</span></div>
            <div><strong>{stats.aiStatus.failed}</strong><span>Failed</span></div>
            <div><strong>{stats.aiStatus.analyzing}</strong><span>In progress</span></div>
          </div>
        </section>
      </aside>
    </div>

    <section aria-labelledby="analytics-heading" className="soc-dashboard-section">
      <div className="soc-section-heading">
        <div><span className="soc-section-eyebrow">DETECTION ANALYTICS</span><h2 id="analytics-heading">What the alerts tell us</h2>
          <p>Source, severity, and AI processing breakdown for the selected time range.</p></div>
      </div>
      <div className="analytics-grid">
        <DetectionSourcePanel sources={stats.sources} />
        <SeverityPressure counts={stats.severity} />
        <WorkloadPanel states={[
          { label: 'Failed', value: stats.aiStatus.failed },
          { label: 'Analyzing', value: stats.aiStatus.analyzing },
          { label: 'Not analyzed', value: stats.aiStatus.notAnalyzed },
          { label: 'Analyzed', value: stats.aiStatus.analyzed },
        ]} />
      </div>
    </section>

    <section aria-labelledby="context-heading" className="soc-dashboard-section">
      <div className="soc-section-heading">
        <div><span className="soc-section-eyebrow">THREAT CONTEXT</span><h2 id="context-heading">Activity and ATT&amp;CK mapping</h2>
          <p>Only detections and technique mappings saved by the platform are shown.</p></div>
      </div>
      <div className="threat-grid">
        <ThreatTimeline events={timeline} onViewAll={() => navigate('/alerts')} />
        <MitreCoverage techniques={stats.mitre.techniqueCount} mappedAlerts={stats.mitre.mappedAlertCount}
          analyzedAlerts={stats.mitre.analyzedAlertCount} coverage={stats.mitre.coveragePercent} />
      </div>
    </section>

    <section aria-labelledby="performance-heading" className="soc-dashboard-section soc-dashboard-performance">
      <div className="soc-section-heading">
        <div><span className="soc-section-eyebrow">PIPELINE HEALTH</span><h2 id="performance-heading">Processing performance</h2></div>
      </div>
      <div className="performance-grid">
        <PerformanceMetric code="AI" label="Analysis coverage" value={`${stats.performance.aiCoveragePercent}%`}
          target={`${stats.aiStatus.analyzed} analyzed`} status={stats.performance.aiCoveragePercent >= 70 ? 'good' : 'watch'} />
        <PerformanceMetric code="LLM" label="Average processing time" value={formatDuration(stats.performance.avgProcessingTimeMs)}
          target="Measured processing time" status="good" />
        <PerformanceMetric code="RULE" label="Rule match coverage" value={`${stats.performance.ruleMatchCoveragePercent}%`}
          target={`${stats.posture.matchedRules} matched`} status={stats.performance.ruleMatchCoveragePercent >= 70 ? 'good' : 'watch'} />
      </div>
    </section>
  </main>;
};

function boundedPercent(value: number): number {
  return Number.isFinite(value) ? Math.min(100, Math.max(0, value)) : 0;
}

function getRangeStart(range: TimeRange): Date {
  const hours = range === '24h' ? 24 : range === '7d' ? 24 * 7 : 24 * 30;
  return new Date(Date.now() - hours * 60 * 60 * 1000);
}

function formatDuration(ms: number): string {
  if (!ms) return '—';
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(ms < 10000 ? 1 : 0)} s`;
}

function toTimelineState(alert: Alert): 'critical' | 'high' | 'medium' | 'low' | 'neutral' {
  if (alert.severity === 'critical') return 'critical';
  if (alert.severity === 'high') return 'high';
  if (alert.severity === 'medium') return 'medium';
  if (alert.severity === 'low' || alert.severity === 'info') return 'low';
  return 'neutral';
}

export default Dashboard;
