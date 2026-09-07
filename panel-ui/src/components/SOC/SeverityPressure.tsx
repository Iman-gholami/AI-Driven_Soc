import React from 'react';

const severityRows = [
  { key: 'critical', label: 'Critical', color: '#FF4D5A' },
  { key: 'high', label: 'High', color: '#FF8A3D' },
  { key: 'medium', label: 'Medium', color: '#FFD43B' },
  { key: 'low', label: 'Low', color: '#52D273' },
  { key: 'info', label: 'Info', color: '#4F89D8' },
  { key: 'unknown', label: 'Unknown', color: '#718096' },
];

const SeverityPressure:React.FC<{counts:Record<string,number>}> = ({counts}) => {
  const max = Math.max(1,...severityRows.map((row)=>counts[row.key]||0));
  const elevated = (counts.critical||0) + (counts.high||0);
  return <section className="soc-panel analytics-panel">
    <div className="panel-heading"><div><span className="eyebrow">Risk distribution</span><h2>Severity Pressure</h2></div></div>
    <div className="severity-list">{severityRows.map(({key,label,color})=><div className="severity-row" key={key}><div><span><i style={{background:color}} />{label}</span><strong>{counts[key]||0}</strong></div><div className="bar-track"><i style={{width:`${((counts[key]||0)/max)*100}%`,background:color}} /></div></div>)}</div>
    <div className="pressure-note"><span>Critical + high</span><strong>{elevated}</strong></div>
  </section>;
};

export default SeverityPressure;
