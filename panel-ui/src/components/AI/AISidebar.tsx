import React from 'react';
import { Drawer, Button, Space, Typography, Card, Spin, message, Tag, Divider, Timeline, Progress, Collapse } from 'antd';
import { CloseOutlined, CopyOutlined, RobotOutlined, CheckCircleOutlined } from '@ant-design/icons';
import { Alert as AlertType } from '../../types';

const { Title, Text, Paragraph } = Typography;
interface AISidebarProps { open:boolean; onClose:()=>void; alert:AlertType|null; loading?:boolean; }

const AISidebar:React.FC<AISidebarProps>=({open,onClose,alert,loading=false})=>{
 const analysis:any=alert?.fullAnalysis||{};
 const risk=analysis.risk_assessment||{};
 const decision=analysis.analyst_decision||{};
 const rule:any=alert?.detectionRule?.rule||{};
 const list=(v:any)=>Array.isArray(v)?v:[];
 const evidence=list(analysis.observed_evidence);
 const steps=list(analysis.recommended_investigation_steps);
 const story=list(analysis.attack_story).length?analysis.attack_story:[`Host ${alert?.host||'unknown'} generated suspicious activity`,alert?.signature||'Rule matched','Further investigation required'];
 const copy=async()=>{await navigator.clipboard.writeText(JSON.stringify(alert,null,2));message.success('Incident copied')};
 return <Drawer title={<Space><RobotOutlined/>SOC Investigation Workspace</Space>} width={820} open={open} onClose={onClose} closeIcon={<CloseOutlined/>} extra={alert?<Button icon={<CopyOutlined/>} onClick={copy}>Copy</Button>:null}>
 {!alert?<Text>Select an alert</Text>:loading?<Spin/>:<div className="space-y-4">
 <Card><Title level={3}>🚨 {alert.signature||'Security Alert'}</Title><Space wrap><Tag color="green"><CheckCircleOutlined/> AI {alert.aiStatus}</Tag><Tag>Rule: {String(rule.metadata||alert.severity||'UNKNOWN').toUpperCase()}</Tag><Tag color="orange">AI Risk: {String(risk.severity||'UNKNOWN').toUpperCase()}</Tag>{risk.confidence!==undefined&&<Tag>Confidence {risk.confidence}%</Tag>}</Space></Card>
 <Card title="Risk Overview"><Progress percent={Number(risk.confidence||0)} /><Text>Confidence based on rule context and evidence.</Text></Card>
 <Card title="SOC Decision"><Tag color="blue">{decision.action||'REVIEW'}</Tag><Paragraph>{decision.reason||analysis.final_soc_note||'No decision available'}</Paragraph></Card>
 <Card title="Executive Summary"><Paragraph>{analysis.one_line_summary||analysis.incident_summary?.description||analysis.behavior_analysis?.description||'No summary available'}</Paragraph></Card>
 <Card title="Attack Story"><Timeline items={story.map((x:any)=>({children:String(x)}))}/></Card>
 <Card title="Evidence Board">{evidence.length?evidence.map((x:any,i:number)=><Card size="small" key={i}>✓ {typeof x==='string'?x:JSON.stringify(x)}</Card>):<Text>No evidence available</Text>}</Card>
 <Card title="Detection Logic"><Paragraph>{alert.signature}</Paragraph>{analysis.detection_analysis?.matched_conditions?.map((x:string,i:number)=><div key={i}>✓ {x}</div>)}</Card>
 <Card title="MITRE ATT&CK"><Paragraph>{typeof analysis.attack_mapping==='string'?analysis.attack_mapping:JSON.stringify(analysis.attack_mapping||'No mapping available',null,2)}</Paragraph></Card>
 <Card title="Recommended Actions">{steps.length?steps.map((x:any,i:number)=><div key={i}>{i+1}. {typeof x==='string'?x:JSON.stringify(x)}</div>):<Text>No actions available</Text>}</Card>
 <Collapse items={[{key:'1',label:'AI Reasoning',children:<Paragraph>{analysis.final_soc_note||'No additional reasoning available'}</Paragraph>}]}/>
 <Divider/><Card title="Final SOC Note"><Paragraph>{analysis.final_soc_note||'—'}</Paragraph></Card>
 </div>}
 </Drawer>;
};
export default AISidebar;
