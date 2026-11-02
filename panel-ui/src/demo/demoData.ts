import { useEffect, useState } from 'react';
import type { Alert, AlertListParams, AlertListResult, DashboardStats } from '../types';

// Deliberately client-only. This flag controls display data; it never writes to an API.
// It is stored only for the current browser tab/session.
const KEY = 'soc-preview-demo-mode';
const EVENT = 'soc-preview-demo-mode-change';

function readDemoFlag(): boolean {
  try { return sessionStorage.getItem(KEY) === '1'; } catch { return false; }
}

export function useDemoMode(): readonly [boolean, (enabled: boolean) => void] {
  const [enabled, setEnabled] = useState(readDemoFlag);
  useEffect(() => {
    const sync = () => setEnabled(readDemoFlag());
    window.addEventListener(EVENT, sync);
    return () => window.removeEventListener(EVENT, sync);
  }, []);
  const setDemo = (next: boolean) => {
    try { sessionStorage.setItem(KEY, next ? '1' : '0'); } catch { /* private browser */ }
    setEnabled(next);
    window.dispatchEvent(new Event(EVENT));
  };
  return [enabled, setDemo] as const;
}

type DemoRow = {
  signature: string;
  source: string;
  severity: Alert['severity'];
  host: string;
  aiStatus: Alert['aiStatus'];
  ageHours: number;
  technique: string;
};

const DEMO_ROWS: DemoRow[] = [
  {signature:'Suspicious PowerShell encoded command',source:'EDR',severity:'critical',host:'WS-FIN-014',aiStatus:'analyzed',ageHours:.2,technique:'T1059.001'},
  {signature:'Possible credential dumping activity',source:'Sysmon',severity:'critical',host:'DC-PRIMARY',aiStatus:'not_analyzed',ageHours:.5,technique:'T1003'},
  {signature:'Outbound connection to known malicious IP',source:'Firewall',severity:'high',host:'APP-PROD-03',aiStatus:'analyzed',ageHours:1,technique:'T1071'},
  {signature:'Multiple failed administrator logins',source:'SIEM',severity:'high',host:'VPN-GATEWAY',aiStatus:'not_analyzed',ageHours:1.5,technique:'T1110'},
  {signature:'Unusual DNS tunneling pattern',source:'DNS',severity:'high',host:'WS-OPS-008',aiStatus:'failed',ageHours:2.5,technique:'T1071.004'},
  {signature:'Unexpected scheduled task creation',source:'EDR',severity:'medium',host:'WS-HR-022',aiStatus:'analyzed',ageHours:3.5,technique:'T1053.005'},
  {signature:'Sensitive file access outside business hours',source:'Sysmon',severity:'medium',host:'FILES-02',aiStatus:'not_analyzed',ageHours:4.2,technique:'T1005'},
  {signature:'Port scanning behavior from internal host',source:'IDS',severity:'medium',host:'WS-ENG-031',aiStatus:'analyzed',ageHours:5,technique:'T1046'},
  {signature:'New executable in temporary directory',source:'EDR',severity:'low',host:'WS-ENG-019',aiStatus:'not_analyzed',ageHours:7,technique:'T1204.002'},
  {signature:'Repeated blocked outbound connections',source:'Firewall',severity:'low',host:'WS-SALES-007',aiStatus:'analyzed',ageHours:8,technique:'T1071'},
  {signature:'Authentication from unusual network',source:'SIEM',severity:'medium',host:'IAM-01',aiStatus:'analyzing',ageHours:11,technique:'T1078'},
  {signature:'Security policy modification detected',source:'Sysmon',severity:'high',host:'APP-PROD-01',aiStatus:'not_analyzed',ageHours:15,technique:'T1562.001'},
  {signature:'New remote service registered',source:'EDR',severity:'high',host:'WS-ENG-012',aiStatus:'analyzed',ageHours:30,technique:'T1543.003'},
  {signature:'Possible data staging archive',source:'SIEM',severity:'medium',host:'FS-ARCHIVE-01',aiStatus:'failed',ageHours:54,technique:'T1560'},
  {signature:'User account added to local administrators',source:'Sysmon',severity:'high',host:'WS-FIN-011',aiStatus:'analyzed',ageHours:80,technique:'T1098'},
  {signature:'External SSH login after multiple failures',source:'Firewall',severity:'critical',host:'LINUX-WEB-04',aiStatus:'not_analyzed',ageHours:125,technique:'T1021.004'},
  {signature:'Low reputation domain queried',source:'DNS',severity:'low',host:'WS-OPS-015',aiStatus:'analyzed',ageHours:230,technique:'T1071.004'},
  {signature:'Endpoint security agent restart',source:'EDR',severity:'info',host:'WS-OPS-016',aiStatus:'not_analyzed',ageHours:360,technique:'T1562.001'},
];

function buildAlerts(now: number): Alert[] {
  return DEMO_ROWS.map((row, index) => {
    const matched = index !== 4 && index !== 13;
    const createdAt = new Date(now - row.ageHours * 3600_000).toISOString();
    const analyzed = row.aiStatus === 'analyzed';
    return {
      alertId: 'DEMO-' + String(index + 1).padStart(4, '0'),
      source: row.source,
      signature: row.signature,
      eventType: 'Security detection',
      host: row.host,
      status: analyzed ? 'analyzed' : 'new',
      aiStatus: row.aiStatus,
      severity: row.severity,
      aiEligibility: { eligible: matched, scenario: matched ? 'matched_rule' : null, reason: matched ? null : 'Demo: deterministic detection-rule match unavailable' },
      createdAt,
      updatedAt: createdAt,
      eventHash: 'preview-only-' + (index + 1),
      ruleMatch: {
        status: matched ? 'matched' : 'no_match',
        matchType: matched ? 'exact_title' : null,
        signature: row.signature,
        candidateCount: matched ? 1 : 0,
        reason: matched ? null : 'No deterministic rule match',
        resolutionEvidence: [],
        ruleId: matched ? 'DEMO-RULE-' + (1000 + index) : undefined,
      },
      processingTimeMs: analyzed ? 2100 + (index % 4) * 430 : null,
      analysisCount: analyzed ? 1 : 0,
      analysis: analyzed ? [{severity:row.severity,verdict:'SUSPICIOUS',confidence:82,summary:'Illustrative sample analysis — not a real finding.'}] : [],
      rawEvent: {mitre_technique:row.technique,mode:'DEMO',notice:'Synthetic example; not ingested'},
    };
  });
}
export const DEMO_ALERTS: Alert[] = buildAlerts(Date.now());

export function getDemoAlertsPage(params: AlertListParams = {}): AlertListResult {
  const match = (value: string, query: string) => value.toLowerCase().includes(query.toLowerCase());
  let alerts = DEMO_ALERTS.filter(alert =>
    (!params.severity || alert.severity === params.severity) &&
    (!params.status || alert.status === params.status) &&
    (!params.aiStatus || alert.aiStatus === params.aiStatus) &&
    (!params.source || match(alert.source, params.source)) &&
    (!params.search || [alert.alertId,alert.signature || '',alert.eventType || '',alert.host || '',alert.source].some(v=>match(v, params.search || ''))) &&
    (!params.createdAtFrom || new Date(alert.createdAt) >= new Date(params.createdAtFrom)) &&
    (!params.createdAtTo || new Date(alert.createdAt) <= new Date(params.createdAtTo))
  );
  const total = alerts.length;
  const page = Math.max(1, params.page || 1);
  const limit = Math.max(1, params.limit || 20);
  alerts = alerts.sort((a,b)=>new Date(b.createdAt).getTime()-new Date(a.createdAt).getTime());
  return { alerts:alerts.slice((page-1)*limit,page*limit), pagination:{page,limit,total,pages:Math.ceil(total/limit)} };
}

export function getDemoDashboardStats(range: '24h' | '7d' | '30d'): DashboardStats {
  const hours = range === '24h' ? 24 : range === '7d' ? 168 : 720;
  const from = new Date(Date.now() - hours * 3600_000).toISOString();
  const alerts = DEMO_ALERTS.filter(alert=>new Date(alert.createdAt).getTime()>=new Date(from).getTime());
  const count = (filter: (a: Alert)=>boolean) => alerts.filter(filter).length;
  const severity = {
    critical:count(a=>a.severity==='critical'),high:count(a=>a.severity==='high'),
    medium:count(a=>a.severity==='medium'),low:count(a=>a.severity==='low'),
    info:count(a=>a.severity==='info'),unknown:count(a=>a.severity==='unknown'),
  };
  const aiStatus = {
    analyzed:count(a=>a.aiStatus==='analyzed'),analyzing:count(a=>a.aiStatus==='analyzing'),
    failed:count(a=>a.aiStatus==='failed'),notAnalyzed:count(a=>a.aiStatus==='not_analyzed'),
  };
  const matched = count(a=>a.ruleMatch?.status==='matched');
  const analyzed = alerts.filter(a=>a.aiStatus==='analyzed');
  const mapped = count(a=>a.aiStatus==='analyzed' && !!a.rawEvent?.mitre_technique);
  const perSource = new Map<string,number>();
  for (const alert of alerts) perSource.set(alert.source,(perSource.get(alert.source)||0)+1);
  const weighted = severity.critical*100+severity.high*70+severity.medium*40+severity.low*15+severity.info*5;
  return {
    window:{from,to:new Date().toISOString()},
    totals:{alerts:alerts.length,uniqueHosts:new Set(alerts.map(a=>a.host).filter(Boolean)).size,sources:perSource.size},
    severity,aiStatus,
    sources:[...perSource].map(([name,count])=>({name,count})).sort((a,b)=>b.count-a.count),
    performance:{
      aiCoveragePercent:alerts.length?Math.round(aiStatus.analyzed/alerts.length*100):0,
      ruleMatchCoveragePercent:alerts.length?Math.round(matched/alerts.length*100):0,
      avgProcessingTimeMs:analyzed.length?Math.round(analyzed.reduce((n,a)=>n+(a.processingTimeMs || 0),0)/analyzed.length):0,
    },
    posture:{severityPressureIndex:alerts.length?Math.round(weighted/alerts.length):0,matchedRules:matched},
    mitre:{
      techniqueCount:new Set(analyzed.map(a=>a.rawEvent?.mitre_technique).filter(Boolean)).size,
      mappedAlertCount:mapped,analyzedAlertCount:analyzed.length,
      coveragePercent:analyzed.length?Math.round(mapped/analyzed.length*100):0,
    },
    recentAlerts:alerts.slice(0,8),
  };
}
