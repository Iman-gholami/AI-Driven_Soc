import React from 'react';

export interface SourceSignal { name: string; count: number; }

const DetectionSourcePanel: React.FC<{sources:SourceSignal[]}> = ({sources}) => {
  const total = sources.reduce((sum, source) => sum + source.count, 0);
  return <section className="soc-panel analytics-panel">
    <div className="panel-heading"><div><span className="eyebrow">Telemetry</span><h2>Detection Source Signals</h2></div><span className="panel-total">{total} total</span></div>
    <div className="source-list">
      {sources.length ? sources.map((source) => {
        const pct = total ? Math.round(source.count / total * 100) : 0;
        return <div className="source-row" key={source.name}>
          <div><strong>{source.name}</strong><span>{pct}%</span></div>
          <div className="bar-track"><i style={{width:`${pct}%`}} /></div>
          <b>{source.count}</b>
        </div>;
      }) : <div className="queue-empty"><span>No source data in this time window.</span></div>}
    </div>
  </section>;
};

export default DetectionSourcePanel;
