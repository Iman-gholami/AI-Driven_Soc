import React from 'react';
interface Event {time:string;title:string;detail:string;state:'critical'|'ai'|'review'|'response'}
const ThreatTimeline:React.FC<{events:Event[]}> = ({events}) => <section className="soc-panel timeline-panel"><div className="panel-heading"><div><span className="eyebrow">Latest incident flow</span><h2>Threat Activity Timeline</h2></div><button className="text-button">View all activity →</button></div><div className="timeline">{events.map((e,i)=><div className={`timeline-event ${e.state}`} key={`${e.time}-${i}`}><time>{e.time}</time><i /><div><strong>{e.title}</strong><span>{e.detail}</span></div></div>)}</div></section>;
export default ThreatTimeline;
