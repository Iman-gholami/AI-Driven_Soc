import React from 'react';

interface RiskIndexProps { value: number; totalAlerts: number; criticalAlerts: number; highAlerts: number; }

const RiskIndex: React.FC<RiskIndexProps> = ({ value, totalAlerts, criticalAlerts, highAlerts }) => {
  const color = value >= 75 ? '#FF4D5A' : value >= 50 ? '#FF8A3D' : '#52D273';
  return <section className="soc-panel risk-index">
    <div className="panel-heading"><div><span className="eyebrow">Severity-derived posture</span><h2>Severity Pressure Index</h2></div><span className="live-label"><i /> DATA</span></div>
    <div className="risk-content">
      <div className="risk-gauge" style={{ '--risk': `${value * 3.6}deg`, '--risk-color': color } as React.CSSProperties}>
        <div className="risk-gauge-inner"><strong>{value}</strong><span>Weighted severity</span><small>/ 100</small></div>
      </div>
      <div className="risk-summary"><span className="risk-level" style={{ color }}>{value >= 75 ? 'SEVERE PRESSURE' : value >= 50 ? 'ELEVATED PRESSURE' : 'STABLE'}</span><p>Calculated only from stored alert severities in the selected time window.</p></div>
    </div>
    <div className="risk-breakdown"><div><span>Total alerts</span><strong>{totalAlerts}</strong></div><div><span>Critical</span><strong className="critical-text">{criticalAlerts}</strong></div><div><span>High</span><strong className="high-text">{highAlerts}</strong></div></div>
  </section>;
};

export default RiskIndex;
