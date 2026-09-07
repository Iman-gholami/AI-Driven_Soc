import React from 'react';
import { Alert } from '../../types';

function getLatestSummary(alert: Alert) {
  if (!Array.isArray(alert.analysis) || alert.analysis.length === 0) return undefined;
  return alert.analysis[alert.analysis.length - 1];
}

function getConfidence(alert: Alert) {
  const value = alert.fullAnalysis?.risk_assessment?.confidence ?? getLatestSummary(alert)?.confidence;
  const numeric = Number(value);
  return Number.isFinite(numeric) ? Math.round(numeric) : null;
}

function getMitreTechnique(alert: Alert) {
  const mapping = alert.fullAnalysis?.attack_mapping;
  if (Array.isArray(mapping) && mapping.length > 0) {
    const first = mapping[0];
    if (typeof first === 'string') return first;
    if (first?.technique) return String(first.technique);
    if (first?.id) return String(first.id);
  }
  const raw = alert.rawEvent?.mitre_technique || alert.rawEvent?.mitre || alert.rawEvent?.technique_id;
  return raw ? String(raw) : '—';
}

const IncidentCard:React.FC<{alert:Alert;onInvestigate:(id:string)=>void}> = ({alert,onInvestigate}) => {
  const confidence = getConfidence(alert);
  const mitre = getMitreTechnique(alert);
  const ruleId = alert.detectionRule?.rule?.rule_id || alert.ruleMatch?.ruleId || '—';

  return <article className={`incident-card severity-${alert.severity}`}>
    <div className="incident-priority"><span className={`severity-badge ${alert.severity}`}>{alert.severity}</span><span className="incident-time">{new Date(alert.updatedAt||alert.createdAt).toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'})}</span></div>
    <div className="incident-main"><h3>{alert.signature||alert.eventType||'Unclassified security detection'}</h3><span className="mono incident-id">{alert.alertId}</span><div className="incident-fields"><div><span>Affected asset</span><strong className="mono">{alert.host||'Unknown host'}</strong></div><div><span>Detection source</span><strong>{alert.source||'Unknown source'}</strong></div><div><span>Detection rule</span><strong className="mono">{ruleId}</strong></div><div><span>MITRE technique</span><strong className="mono">{mitre.slice(0,18)}</strong></div></div></div>
    <div className="incident-score"><div><span>AI confidence</span><strong className="ai-text">{confidence === null ? '—' : `${confidence}%`}</strong></div><div><span>AI state</span><strong>{alert.aiStatus.replace('_',' ')}</strong></div></div>
    <button className="investigate-btn" onClick={()=>onInvestigate(alert.alertId)}>Investigate <span>→</span></button>
  </article>;
};

export default IncidentCard;
