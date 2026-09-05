import React from 'react';
interface Props { title: string; value: string | number; detail: string; trend?: string; tone?: 'critical'|'high'|'ai'|'success'|'neutral'; }
const MetricCard: React.FC<Props> = ({ title, value, detail, trend, tone='neutral' }) => <article className={`metric-card tone-${tone}`}>
  <div className="metric-top"><span>{title}</span>{trend && <small>{trend}</small>}</div><strong>{value}</strong><p>{detail}</p>
</article>;
export default MetricCard;
