import React from 'react';
interface Props { code: string; label: string; value: string; target: string; status: 'good'|'watch'; }
const PerformanceMetric: React.FC<Props> = ({code,label,value,target,status}) => <article className="performance-card">
  <div><span className="eyebrow">{code}</span><h3>{label}</h3></div><div className="performance-value"><strong>{value}</strong><span className={status}>{target}</span></div>
</article>;
export default PerformanceMetric;
