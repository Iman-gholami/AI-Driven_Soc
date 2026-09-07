import React, { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { api } from '../../api/client';
import { Alert, DashboardStats } from '../../types';
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

const Dashboard:React.FC=()=>{
  const [range,setRange]=useState<'24h'|'7d'|'30d'>('24h');
  const navigate=useNavigate();
  const rangeStart = useMemo(() => getRangeStart(range), [range]);
  const {data,isLoading,dataUpdatedAt}=useQuery({
    queryKey:['dashboard-stats',range],
    queryFn:()=>api.getDashboardStats({createdAtFrom:rangeStart.toISOString()}),
    refetchInterval:60_000,
  });
  const stats = data || EMPTY_STATS;
  const queue = stats.recentAlerts.slice(0,6);
  const timeline = stats.recentAlerts.slice(0,4).map((alert) => ({
    time: new Date(alert.createdAt).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}),
    title: alert.signature || alert.eventType || 'Unclassified detection',
    detail: `${alert.source || 'unknown source'}${alert.host ? ` · ${alert.host}` : ''} · AI ${alert.aiStatus.replace('_',' ')}`,
    state: toTimelineState(alert),
  }));

  return <main className="command-center">
    <header className="command-header"><div><div className="command-kicker"><span>OPERATIONS</span><i /> Stored SOC telemetry</div><h1>Cyber Command Center</h1><p>Security posture from your alert and AI-analysis data</p></div><div className="header-controls"><div className="refresh-status"><i /><span>Last refresh<strong>{dataUpdatedAt?new Date(dataUpdatedAt).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'}):'Connecting'}</strong></span></div><div className="range-selector">{(['24h','7d','30d'] as const).map(r=><button className={range===r?'active':''} onClick={()=>setRange(r)} key={r}>{r}</button>)}</div></div></header>

    <div className="section-label"><span>01</span><div><h2>Security Posture Overview</h2><p>Calculated from alerts stored in MongoDB for the selected time window</p></div></div>
    <div className="posture-grid">
      <RiskIndex value={stats.posture.severityPressureIndex} totalAlerts={stats.totals.alerts} criticalAlerts={stats.severity.critical} highAlerts={stats.severity.high}/>
      <div className="kpi-grid">
        <MetricCard title="Total Alerts" value={stats.totals.alerts} detail={`Stored during the last ${range}`} trend="Live data"/>
        <MetricCard title="Critical Alerts" value={stats.severity.critical} detail="Critical severity detections" tone="critical"/>
        <MetricCard title="High Alerts" value={stats.severity.high} detail="High severity detections" tone="high"/>
        <MetricCard title="AI Analyzed" value={stats.aiStatus.analyzed} detail={`${stats.performance.aiCoveragePercent}% of alerts in window`} trend="Persisted results" tone="ai"/>
        <MetricCard title="Unique Hosts" value={stats.totals.uniqueHosts} detail="Distinct affected hosts observed"/>
        <MetricCard title="Detection Sources" value={stats.totals.sources} detail="Distinct alert source values" tone="success"/>
      </div>
    </div>

    <div className="section-label compact"><span>02</span><div><h2>Analysis Performance</h2><p>Operational values derived from persisted analysis metadata</p></div></div>
    <div className="performance-grid">
      <PerformanceMetric code="AI" label="Analysis Coverage" value={`${stats.performance.aiCoveragePercent}%`} target={`${stats.aiStatus.analyzed} analyzed`} status={stats.performance.aiCoveragePercent>=70?'good':'watch'}/>
      <PerformanceMetric code="LLM" label="Average Processing Time" value={formatDuration(stats.performance.avgProcessingTimeMs)} target="Stored processingTimeMs" status="good"/>
      <PerformanceMetric code="RULE" label="Deterministic Match Coverage" value={`${stats.performance.ruleMatchCoveragePercent}%`} target={`${stats.posture.matchedRules} matched alerts`} status={stats.performance.ruleMatchCoveragePercent>=70?'good':'watch'}/>
    </div>

    <div className="section-label compact"><span>03</span><div><h2>Security Analytics</h2><p>Severity, telemetry origin, and AI triage state from stored alerts</p></div></div>
    <div className="analytics-grid">
      <DetectionSourcePanel sources={stats.sources}/>
      <SeverityPressure counts={stats.severity}/>
      <WorkloadPanel states={[
        {label:'Failed',value:stats.aiStatus.failed},
        {label:'Analyzing',value:stats.aiStatus.analyzing},
        {label:'Not analyzed',value:stats.aiStatus.notAnalyzed},
        {label:'Analyzed',value:stats.aiStatus.analyzed},
      ]}/>
    </div>

    <div className="section-label compact"><span>04</span><div><h2>Threat Context</h2><p>Recent real detections and MITRE techniques persisted by AI analysis</p></div></div>
    <div className="threat-grid">
      <ThreatTimeline events={timeline} onViewAll={()=>navigate('/alerts')}/>
      <MitreCoverage techniques={stats.mitre.techniqueCount} mappedAlerts={stats.mitre.mappedAlertCount} analyzedAlerts={stats.mitre.analyzedAlertCount} coverage={stats.mitre.coveragePercent}/>
    </div>

    <div className="queue-heading"><div className="section-label compact"><span>05</span><div><h2>Recent Investigation Queue</h2><p>Most recently ingested alerts in the selected time window</p></div></div><div className="queue-status"><i /> {stats.aiStatus.notAnalyzed + stats.aiStatus.failed} NEED AI REVIEW</div></div>
    <section className="incident-queue">{isLoading?<div className="queue-empty">Loading the investigation queue…</div>:queue.length?queue.map(alert=><IncidentCard key={alert.alertId} alert={alert} onInvestigate={id=>navigate(`/alerts?alert=${encodeURIComponent(id)}`)}/>):<div className="queue-empty"><strong>No alerts in this window</strong><span>Choose a wider time range or wait for new detections.</span></div>}</section>
  </main>;
};

function getRangeStart(range:'24h'|'7d'|'30d') {
  const now = Date.now();
  const hours = range === '24h' ? 24 : range === '7d' ? 24 * 7 : 24 * 30;
  return new Date(now - hours * 60 * 60 * 1000);
}

function formatDuration(ms:number) {
  if (!ms) return '—';
  if (ms < 1000) return `${ms} ms`;
  return `${(ms/1000).toFixed(ms < 10000 ? 1 : 0)} s`;
}

function toTimelineState(alert: Alert): 'critical'|'high'|'medium'|'low'|'neutral' {
  if (alert.severity === 'critical') return 'critical';
  if (alert.severity === 'high') return 'high';
  if (alert.severity === 'medium') return 'medium';
  if (alert.severity === 'low' || alert.severity === 'info') return 'low';
  return 'neutral';
}

export default Dashboard;
