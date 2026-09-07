import React from 'react';

interface Event {
  time: string;
  title: string;
  detail: string;
  state: 'critical'|'high'|'medium'|'low'|'neutral';
}

const ThreatTimeline:React.FC<{events:Event[];onViewAll?:()=>void}> = ({events,onViewAll}) => <section className="soc-panel timeline-panel">
  <div className="panel-heading">
    <div><span className="eyebrow">Recent stored detections</span><h2>Threat Activity Timeline</h2></div>
    {onViewAll && <button className="text-button" onClick={onViewAll}>View all activity →</button>}
  </div>
  {events.length ? <div className="timeline">{events.map((event,index)=>{const cssState={critical:'critical',high:'response',medium:'review',low:'ai',neutral:'review'}[event.state];return <div className={`timeline-event ${cssState}`} key={`${event.time}-${index}`}><time>{event.time}</time><i /><div><strong>{event.title}</strong><span>{event.detail}</span></div></div>})}</div> : <div className="queue-empty"><span>No detections in this time window.</span></div>}
</section>;

export default ThreatTimeline;
