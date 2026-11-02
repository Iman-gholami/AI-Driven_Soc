import React, { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { api } from '../../api/client';
import type { Alert, DashboardStats } from '../../types';
import PerformanceMetric from '../../components/SOC/PerformanceMetric';
import DetectionSourcePanel from '../../components/SOC/DetectionSourcePanel';
import WorkloadPanel from '../../components/SOC/WorkloadPanel';
import ThreatTimeline from '../../components/SOC/ThreatTimeline';
import MitreCoverage from '../../components/SOC/MitreCoverage';
import { SafetyCertificateOutlined, BellOutlined, WarningOutlined, RobotOutlined, DesktopOutlined, ReloadOutlined, ArrowRightOutlined, RadarChartOutlined, FileSearchOutlined, CheckCircleOutlined } from '@ant-design/icons';
import { useDemoMode, getDemoDashboardStats } from '../../demo/demoData';
import { ExperimentOutlined } from '@ant-design/icons';
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


const SEVERITIES = [
  { key: 'critical', label: 'Critical', color: '#ff647c' },
  { key: 'high', label: 'High', color: '#ffab5e' },
  { key: 'medium', label: 'Medium', color: '#facb5b' },
  { key: 'low', label: 'Low', color: '#50d9aa' },
  { key: 'info', label: 'Info', color: '#4c9cff' },
  { key: 'unknown', label: 'Unknown', color: '#91a0bf' },
] as const;

const Dashboard: React.FC = () => {
  const [range, setRange] = useState<TimeRange>('24h');
  const [demoMode, setDemoMode] = useDemoMode();
  const demoStats = useMemo(() => getDemoDashboardStats(range), [range]);
  const navigate = useNavigate();
  const rangeStart = useMemo(() => getRangeStart(range), [range]);
  const { data, dataUpdatedAt, isFetching, isLoading, isError, refetch } = useQuery({
    queryKey: ['dashboard-stats', range],
    queryFn: () => api.getDashboardStats({ createdAtFrom: rangeStart.toISOString() }),
    refetchInterval: 60_000,
    enabled: !demoMode,
  });

  if (!demoMode && isLoading && !data) return <main className="soc-v3-dashboard"><div className="soc-v3-loading" role="status"><RadarChartOutlined spin /><strong>Loading Command Center</strong><span>Reading security telemetry…</span></div></main>;
  if (!demoMode && isError && !data) return <main className="soc-v3-dashboard"><div className="soc-v3-loading" role="alert"><WarningOutlined /><strong>Security data unavailable</strong><span>Could not load the SOC dashboard.</span><button onClick={() => void refetch()}>Try again</button></div></main>;

  const stats = demoMode ? demoStats : (data || EMPTY_STATS);
  const recentAlerts = stats.recentAlerts.slice(0, 5);
  const pendingAnalysis = stats.aiStatus.notAnalyzed + stats.aiStatus.failed;
  const risk = stats.posture.severityPressureIndex;
  const riskLabel = stats.totals.alerts === 0 ? 'No alert data' : risk >= 75 ? 'Severe pressure' : risk >= 50 ? 'Elevated pressure' : 'Low pressure';
  const severityTotal = SEVERITIES.reduce((total, item) => total + stats.severity[item.key], 0);
  let cursor = 0;
  const donutSegments = SEVERITIES.map((item) => {
    const next = cursor + (severityTotal ? stats.severity[item.key] / severityTotal * 360 : 0);
    const part = item.color + ' ' + cursor + 'deg ' + next + 'deg';
    cursor = next;
    return part;
  });
  const severityFill = severityTotal ? 'conic-gradient(' + donutSegments.join(', ') + ')' : 'conic-gradient(#26334b 0deg 360deg)';
  const timeline = stats.recentAlerts.slice(0, 4).map((alert) => ({
    time: new Date(alert.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    title: alert.signature || alert.eventType || 'Unclassified detection',
    detail: (alert.source || 'Unknown source') + (alert.host ? ' · ' + alert.host : '') + ' · AI ' + alert.aiStatus.replace('_', ' '),
    state: toTimelineState(alert),
  }));

  return <main className="soc-v3-dashboard">
    <header className="soc-v3-hero">
      <div className="soc-v3-hero-copy">
        <div className="soc-v3-kicker"><span className="soc-v3-beacon" /> SECURITY OPERATIONS <span className="soc-v3-kicker-separator">/</span> COMMAND CENTER</div>
        <h1>SOC Dashboard <span>Overview</span></h1>
        <p>Prioritize real detections, review risk, and track AI-assisted investigation.</p>
      </div>
      <div className="soc-v3-controls">
        <button type="button" className={'soc-demo-switch' + (demoMode ? ' is-on' : '')} aria-pressed={demoMode}
          onClick={() => setDemoMode(!demoMode)} title="Toggle local demo data (never writes to the database)">
          <ExperimentOutlined /> Demo data <strong>{demoMode ? 'ON' : 'OFF'}</strong>
        </button>
        <div className="soc-v3-updated"><span className="soc-v3-status-dot"/><div><small>{demoMode ? 'SAMPLE DATA' : 'LAST UPDATED'}</small><strong>{demoMode ? 'Preview only' : dataUpdatedAt ? new Date(dataUpdatedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—'}</strong></div></div>
        <div className="soc-v3-range" aria-label="Reporting time range" role="group">
          {RANGES.map(option => <button type="button" key={option} className={range === option ? 'selected' : ''} aria-pressed={range === option} onClick={() => setRange(option)}>{option === '24h' ? 'Last 24h' : option}</button>)}
        </div>
        <button className="soc-v3-refresh" type="button" disabled={demoMode || isFetching} onClick={() => void refetch()} title={demoMode ? 'Unavailable in demo mode' : 'Refresh dashboard'} aria-label="Refresh dashboard"><ReloadOutlined spin={isFetching}/></button>
      </div>
    </header>

    {demoMode && <div className="soc-demo-banner" role="status"><ExperimentOutlined /><div><strong>DEMO MODE — SYNTHETIC DATA</strong><span>Illustrative alerts only. No database changes, AI requests, or API ingestion. Demo applies to Dashboard and Alerts only.</span></div><button type="button" onClick={() => setDemoMode(false)}>Return to live data</button></div>}
    {!demoMode && isError && <div className="soc-v3-warning" role="alert">The latest refresh failed. Previously loaded data is shown.</div>}

    <section className="soc-v3-kpis" aria-label="Key operational metrics">
      <article className="soc-v3-kpi soc-v3-risk">
        <div className="soc-v3-kpi-top"><span className="soc-v3-kpi-icon"><SafetyCertificateOutlined /></span><span className="soc-v3-kpi-name">RISK INDEX</span></div>
        <div className="soc-v3-kpi-number">{risk}<small>/ 100</small></div>
        <div className="soc-v3-kpi-foot"><span>{riskLabel}</span><div className="soc-v3-mini-track"><i style={{ width: boundedPercent(risk) + '%' }} /></div></div>
      </article>
      <article className="soc-v3-kpi soc-v3-blue">
        <div className="soc-v3-kpi-top"><span className="soc-v3-kpi-icon"><BellOutlined /></span><span className="soc-v3-kpi-name">TOTAL ALERTS</span></div>
        <div className="soc-v3-kpi-number">{stats.totals.alerts.toLocaleString()}</div>
        <div className="soc-v3-kpi-foot">Detected in selected window</div>
      </article>
      <article className="soc-v3-kpi soc-v3-rose">
        <div className="soc-v3-kpi-top"><span className="soc-v3-kpi-icon"><WarningOutlined /></span><span className="soc-v3-kpi-name">CRITICAL ALERTS</span></div>
        <div className="soc-v3-kpi-number">{stats.severity.critical.toLocaleString()}</div>
        <div className="soc-v3-kpi-foot">Highest-priority detections</div>
      </article>
      <article className="soc-v3-kpi soc-v3-purple">
        <div className="soc-v3-kpi-top"><span className="soc-v3-kpi-icon"><RobotOutlined /></span><span className="soc-v3-kpi-name">AI ANALYZED</span></div>
        <div className="soc-v3-kpi-number">{stats.aiStatus.analyzed.toLocaleString()}</div>
        <div className="soc-v3-kpi-foot">{stats.performance.aiCoveragePercent}% of stored alerts</div>
      </article>
      <article className="soc-v3-kpi soc-v3-mint">
        <div className="soc-v3-kpi-top"><span className="soc-v3-kpi-icon"><DesktopOutlined /></span><span className="soc-v3-kpi-name">AFFECTED HOSTS</span></div>
        <div className="soc-v3-kpi-number">{stats.totals.uniqueHosts.toLocaleString()}</div>
        <div className="soc-v3-kpi-foot">Unique hosts in selected window</div>
      </article>
    </section>

    <div className="soc-v3-overview">
      <section className="soc-v3-panel soc-v3-severity" aria-labelledby="severity-v3-title">
        <div className="soc-v3-panel-heading">
          <div><span className="soc-v3-eyebrow">DETECTION INTELLIGENCE</span><h2 id="severity-v3-title">Alerts by severity</h2></div>
          <span className="soc-v3-panel-subtitle">LIVE DISTRIBUTION</span>
        </div>
        <div className="soc-v3-donut-layout">
          <div className="soc-v3-donut" style={{ background: severityFill }} role="img" aria-label={'Alert severity distribution for ' + severityTotal + ' alerts'}>
            <div className="soc-v3-donut-core"><strong>{severityTotal.toLocaleString()}</strong><span>ALERTS</span></div>
          </div>
          <div className="soc-v3-severity-legend">
            {SEVERITIES.map(item => <div className="soc-v3-legend-row" key={item.key}>
              <span><i style={{ background: item.color }}/>{item.label}</span>
              <strong>{stats.severity[item.key].toLocaleString()} <small>({severityTotal ? Math.round(stats.severity[item.key] / severityTotal * 100) : 0}%)</small></strong>
            </div>)}
          </div>
        </div>
        {severityTotal === 0 && <p className="soc-v3-panel-note">No alerts recorded for this time range.</p>}
      </section>
      <section className="soc-v3-panel soc-v3-triage" aria-labelledby="ai-v3-title">
        <div className="soc-v3-panel-heading"><div><span className="soc-v3-eyebrow">AUTOMATED TRIAGE</span><h2 id="ai-v3-title">AI analysis performance</h2></div><RobotOutlined className="soc-v3-panel-symbol"/></div>
        <div className="soc-v3-progress-row"><div><span>Analysis coverage</span><strong>{stats.performance.aiCoveragePercent}%</strong></div><div className="soc-v3-progress-track"><i style={{ width: boundedPercent(stats.performance.aiCoveragePercent) + '%' }}/></div></div>
        <div className="soc-v3-progress-row soc-v3-progress-green"><div><span>Detection rule matching</span><strong>{stats.performance.ruleMatchCoveragePercent}%</strong></div><div className="soc-v3-progress-track"><i style={{ width: boundedPercent(stats.performance.ruleMatchCoveragePercent) + '%' }}/></div></div>
        <div className="soc-v3-triage-states">
          <div><strong>{stats.aiStatus.notAnalyzed.toLocaleString()}</strong><span>Not analyzed</span></div>
          <div><strong>{stats.aiStatus.failed.toLocaleString()}</strong><span>Failed</span></div>
          <div><strong>{stats.aiStatus.analyzing.toLocaleString()}</strong><span>Processing</span></div>
        </div>
      </section>
    </div>

    <section className="soc-v3-panel soc-v3-investigations" aria-labelledby="v3-investigations-title">
      <div className="soc-v3-panel-heading soc-v3-investigations-header">
        <div><span className="soc-v3-eyebrow">INVESTIGATION WORKSPACE</span><h2 id="v3-investigations-title">Recent detections</h2><p>Latest stored alerts with a direct path to investigation.</p></div>
        <button className="soc-v3-text-action" type="button" onClick={() => navigate('/alerts')}>Open alert queue <ArrowRightOutlined /></button>
      </div>
      <div className="soc-v3-pending"><span className="soc-v3-pending-pill">{pendingAnalysis.toLocaleString()} NEED AI REVIEW</span><span>Includes not-analyzed and failed AI attempts; rule matching governs AI eligibility.</span></div>
      {recentAlerts.length > 0 ? <div className="soc-v3-table-scroll">
        <table className="soc-v3-table">
          <thead><tr><th>Detection</th><th>Severity</th><th>Source</th><th>Affected host</th><th>AI status</th><th>Action</th></tr></thead>
          <tbody>{recentAlerts.map(alert => <tr key={alert.alertId}>
            <td><strong>{alert.signature || alert.eventType || 'Unclassified detection'}</strong><small>{alert.alertId}</small></td>
            <td><span className={'soc-v3-severity-badge severity-' + alert.severity}>{alert.severity}</span></td>
            <td>{alert.source || '—'}</td><td>{alert.host || '—'}</td>
            <td><span className="soc-v3-ai-state">{alert.aiStatus.replace('_', ' ')}</span></td>
            <td><button type="button" className="soc-v3-row-action" onClick={() => navigate('/alerts?alert=' + encodeURIComponent(alert.alertId))}>Investigate <ArrowRightOutlined /></button></td>
          </tr>)}</tbody>
        </table>
      </div> : <div className="soc-v3-empty">
        <span className="soc-v3-empty-icon"><CheckCircleOutlined /></span>
        <strong>No detections in this time range</strong>
        <p>This view uses real database records. Switch to 7d or 30d to check an earlier period, or open the full alert queue.</p>
        <div><button type="button" onClick={() => setRange('7d')}>View last 7 days</button><button type="button" onClick={() => navigate('/alerts')}>Open alert queue <ArrowRightOutlined /></button></div>
      </div>}
    </section>

    <details className="soc-v3-extended">
      <summary><span><FileSearchOutlined /> Extended SOC analytics</span><span>Sources, AI lifecycle, ATT&amp;CK, timeline, and processing metrics</span></summary>
      <div className="soc-v3-extended-grid">
        <DetectionSourcePanel sources={stats.sources}/>
        <WorkloadPanel states={[
          { label: 'Failed', value: stats.aiStatus.failed },
          { label: 'Analyzing', value: stats.aiStatus.analyzing },
          { label: 'Not analyzed', value: stats.aiStatus.notAnalyzed },
          { label: 'Analyzed', value: stats.aiStatus.analyzed },
        ]}/>
        <MitreCoverage techniques={stats.mitre.techniqueCount} mappedAlerts={stats.mitre.mappedAlertCount} analyzedAlerts={stats.mitre.analyzedAlertCount} coverage={stats.mitre.coveragePercent}/>
      </div>
      <ThreatTimeline events={timeline} onViewAll={() => navigate('/alerts')}/>
      <div className="soc-v3-perf-grid">
        <PerformanceMetric code="AI" label="Analysis coverage" value={stats.performance.aiCoveragePercent + '%'} target={stats.aiStatus.analyzed + ' analyzed'} status={stats.performance.aiCoveragePercent >= 70 ? 'good' : 'watch'}/>
        <PerformanceMetric code="LLM" label="Average processing time" value={formatDuration(stats.performance.avgProcessingTimeMs)} target="Stored processing time" status="good"/>
        <PerformanceMetric code="RULE" label="Rule match coverage" value={stats.performance.ruleMatchCoveragePercent + '%'} target={stats.posture.matchedRules + ' matched'} status={stats.performance.ruleMatchCoveragePercent >= 70 ? 'good' : 'watch'}/>
      </div>
    </details>
    <p className="soc-v3-disclaimer"><SafetyCertificateOutlined /> {demoMode ? 'Demo preview: all metrics and detections are synthetic and read-only.' : 'Metrics are computed from stored SOC data. No simulated alerts or trends.'}</p>
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
