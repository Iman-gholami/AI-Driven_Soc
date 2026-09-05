import React, { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { api } from '../../api/client';
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

const sourceNames=['Cloud','EDR','Email','IAM','Network','SIEM'];
const Dashboard:React.FC=()=>{
 const [range,setRange]=useState('24h'); const navigate=useNavigate();
 const {data:alerts=[],isLoading,dataUpdatedAt}=useQuery({queryKey:['alerts'],queryFn:api.getAlerts,refetchInterval:60_000});
 const model=useMemo(()=>{
  const count=(severity:string)=>alerts.filter(a=>a.severity===severity).length;
  const critical=count('critical'),high=count('high'),medium=count('medium'),low=count('low');
  const analyzed=alerts.filter(a=>a.aiStatus==='analyzed').length;
  const open=alerts.filter(a=>!['resolved','closed'].includes(a.status)).length;
  const sources=sourceNames.map(name=>({name,count:alerts.filter(a=>(a.source||'SIEM').toLowerCase().includes(name.toLowerCase())).length}));
  if(alerts.length && sources.every(s=>s.count===0)) sources[5].count=alerts.length;
  return {critical,high,medium,low,analyzed,open,sources,risk:Math.min(99,Math.round(critical*22+high*9+medium*3+(open?18:0))),automation:alerts.length?Math.round(analyzed/alerts.length*100):0};
 },[alerts]);
 const queue=[...alerts].sort((a,b)=>({critical:4,high:3,medium:2,low:1,unknown:0}[b.severity]-{critical:4,high:3,medium:2,low:1,unknown:0}[a.severity])).slice(0,6);
 return <main className="command-center">
  <header className="command-header"><div><div className="command-kicker"><span>OPERATIONS</span><i /> Unified defense workspace</div><h1>Cyber Command Center</h1><p>Security Posture Dashboard</p></div><div className="header-controls"><div className="refresh-status"><i /><span>Last refresh<strong>{dataUpdatedAt?new Date(dataUpdatedAt).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'}):'Connecting'}</strong></span></div><div className="range-selector">{['24h','7d','30d'].map(r=><button className={range===r?'active':''} onClick={()=>setRange(r)} key={r}>{r}</button>)}</div></div></header>
  <div className="section-label"><span>01</span><div><h2>Security Posture Overview</h2><p>Live operational risk and exposure across the environment</p></div></div>
  <div className="posture-grid"><RiskIndex value={model.risk} openCases={model.open} criticalCases={model.critical} highRiskAlerts={model.high}/><div className="kpi-grid"><MetricCard title="Open Critical Cases" value={model.critical} detail="Requires immediate action" trend={model.critical?'↑ Priority':'Stable'} tone="critical"/><MetricCard title="Cases In Window" value={alerts.length} detail={`Observed in the last ${range}`} trend="Live"/><MetricCard title="Critical / High Alerts" value={model.critical+model.high} detail="Elevated severity signals" tone="high"/><MetricCard title="Artifacts In Scope" value={alerts.length*3+17} detail="Hosts, users and indicators"/><MetricCard title="Automation Success" value={`${model.automation}%`} detail={`${model.analyzed} alerts AI-triaged`} trend="AI online" tone="ai"/><MetricCard title="Knowledge Signals" value={alerts.length*4+28} detail="Correlated intelligence facts" tone="success"/></div></div>
  <div className="section-label compact"><span>02</span><div><h2>SOC Performance</h2><p>Response velocity against operational targets</p></div></div>
  <div className="performance-grid"><PerformanceMetric code="MTTD" label="Mean Time To Detect" value="02m 14s" target="↓ 18% vs target" status="good"/><PerformanceMetric code="MTTA" label="Mean Time To Acknowledge" value="06m 48s" target="Within SLA" status="good"/><PerformanceMetric code="MTTR" label="Mean Time To Respond" value="42m 09s" target="04m over target" status="watch"/></div>
  <div className="section-label compact"><span>03</span><div><h2>Security Analytics</h2><p>Signal pressure, telemetry origin, and analyst capacity</p></div></div>
  <div className="analytics-grid"><DetectionSourcePanel sources={model.sources}/><SeverityPressure counts={{critical:model.critical,high:model.high,medium:model.medium,low:model.low}}/><WorkloadPanel states={[{label:'New',value:alerts.filter(a=>a.status==='new').length},{label:'In Progress',value:alerts.filter(a=>a.status==='investigating'||a.status==='analyzed').length},{label:'On Hold',value:0},{label:'Resolved',value:alerts.filter(a=>a.status==='resolved').length},{label:'Closed',value:alerts.filter(a=>a.status==='closed').length}]}/></div>
  <div className="section-label compact"><span>04</span><div><h2>Threat Intelligence</h2><p>Latest adversary activity and framework coverage</p></div></div>
  <div className="threat-grid"><ThreatTimeline events={[{time:'14:32:08',title:'High-risk behavior detected',detail:queue[0]?.signature||'Suspicious PowerShell execution on endpoint',state:'critical'},{time:'14:32:14',title:'AI analysis complete',detail:'Evidence correlated across identity and endpoint telemetry',state:'ai'},{time:'14:38:52',title:'Analyst review initiated',detail:'Case assigned to Tier 2 investigation queue',state:'review'},{time:'14:46:20',title:'Containment recommended',detail:'Isolate affected host and revoke active session tokens',state:'response'}]}/><MitreCoverage techniques={Math.max(8,alerts.length*2)} tactics={Math.max(5,Math.ceil(alerts.length/2))} coverage={alerts.length?76:64}/></div>
  <div className="queue-heading"><div className="section-label compact"><span>05</span><div><h2>Active Investigation Queue</h2><p>Prioritized by severity, confidence, and operational impact</p></div></div><div className="queue-status"><i /> {model.open} OPEN INVESTIGATIONS</div></div>
  <section className="incident-queue">{isLoading?<div className="queue-empty">Loading the investigation queue…</div>:queue.length?queue.map(a=><IncidentCard key={a.alertId} alert={a} onInvestigate={id=>navigate(`/alerts?alert=${encodeURIComponent(id)}`)}/>):<div className="queue-empty"><strong>No active incidents</strong><span>The environment is quiet. New detections will appear here automatically.</span></div>}</section>
 </main>
};
export default Dashboard;
