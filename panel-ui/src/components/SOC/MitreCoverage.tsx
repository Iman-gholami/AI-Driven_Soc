import React from 'react';

interface Props {
  techniques: number;
  mappedAlerts: number;
  analyzedAlerts: number;
  coverage: number;
}

const MitreCoverage:React.FC<Props> = ({techniques,mappedAlerts,analyzedAlerts,coverage}) => <section className="soc-panel mitre-panel">
  <div className="panel-heading"><div><span className="eyebrow">AI analysis mappings</span><h2>MITRE ATT&amp;CK Mapping</h2></div></div>
  <div className="coverage-ring" style={{'--coverage':`${coverage*3.6}deg`} as React.CSSProperties}><div><strong>{coverage}%</strong><span>mapped analyses</span></div></div>
  <div className="mitre-stats"><div><strong>{techniques}</strong><span>Unique techniques</span></div><div><strong>{mappedAlerts}</strong><span>Mapped alerts</span></div></div>
  <div className="coverage-foot"><span>Analyzed alerts</span><strong>{analyzedAlerts}</strong></div>
</section>;

export default MitreCoverage;
