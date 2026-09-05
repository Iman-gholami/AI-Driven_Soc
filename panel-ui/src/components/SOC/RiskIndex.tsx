import React from 'react';

interface RiskIndexProps { value: number; openCases: number; criticalCases: number; highRiskAlerts: number; }

const RiskIndex: React.FC<RiskIndexProps> = ({ value, openCases, criticalCases, highRiskAlerts }) => {
  const color = value >= 75 ? '#FF4D5A' : value >= 50 ? '#FF8A3D' : '#52D273';
  return <section className="soc-panel risk-index">
    <div className="panel-heading"><div><span className="eyebrow">Security posture</span><h2>Active Risk Index</h2></div><span className="live-label"><i /> LIVE</span></div>
    <div className="risk-content">
      <div className="risk-gauge" style={{ '--risk': `${value * 3.6}deg`, '--risk-color': color } as React.CSSProperties}>
        <div className="risk-gauge-inner"><strong>{value}</strong><span>Weighted pressure</span><small>/ 100</small></div>
      </div>
      <div className="risk-summary"><span className="risk-level" style={{ color }}>{value >= 75 ? 'SEVERE PRESSURE' : value >= 50 ? 'ELEVATED RISK' : 'STABLE'}</span><p>Risk is weighted across active incidents, alert severity, and unresolved exposure.</p></div>
    </div>
    <div className="risk-breakdown"><div><span>Open cases</span><strong>{openCases}</strong></div><div><span>Critical cases</span><strong className="critical-text">{criticalCases}</strong></div><div><span>High-risk alerts</span><strong className="high-text">{highRiskAlerts}</strong></div></div>
  </section>;
};
export default RiskIndex;
