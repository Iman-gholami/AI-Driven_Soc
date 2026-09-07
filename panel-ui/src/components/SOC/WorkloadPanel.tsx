import React from 'react';

const WorkloadPanel:React.FC<{states:{label:string;value:number}[]}> = ({states}) => {
  const total = states.reduce((sum, state) => sum + state.value, 0);
  return <section className="soc-panel analytics-panel">
    <div className="panel-heading"><div><span className="eyebrow">AI lifecycle</span><h2>AI Triage Workload</h2></div><span className="panel-total">{total} alerts</span></div>
    <div className="workload-bar">{states.map((state,index)=><i key={state.label} className={`workload-${index}`} style={{width:`${total ? state.value/total*100 : 0}%`}} />)}</div>
    <div className="workload-list">{states.map((state,index)=><div key={state.label}><span><i className={`workload-${index}`} />{state.label}</span><strong>{state.value}</strong><small>{total ? Math.round(state.value/total*100) : 0}%</small></div>)}</div>
  </section>;
};

export default WorkloadPanel;
