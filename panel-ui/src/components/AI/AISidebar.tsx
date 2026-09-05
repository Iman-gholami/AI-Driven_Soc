import React from 'react';
import { Drawer, Button, Space, Typography, Card, Spin, message, Tag, Divider, Timeline } from 'antd';
import { CloseOutlined, CopyOutlined, RobotOutlined, CheckCircleOutlined } from '@ant-design/icons';
import { Alert as AlertType } from '../../types';

const { Title, Text, Paragraph } = Typography;

interface AISidebarProps { open:boolean; onClose:()=>void; alert:AlertType|null; loading?:boolean; }

const AISidebar:React.FC<AISidebarProps>=({open,onClose,alert,loading=false})=>{
 const analysis:any=alert?.fullAnalysis||{};
 const risk=analysis.risk_assessment||{};
 const rule:any=alert?.detectionRule?.rule||{};
 const decision=analysis.analyst_decision||{};

 const pretty=(value:any)=>typeof value==='string'?value:JSON.stringify(value,null,2);
 const safeList=(value:any):any[]=>Array.isArray(value)?value:[];

 const evidence=safeList(analysis.observed_evidence);
 const steps=safeList(analysis.recommended_investigation_steps);
 const attackStory=analysis.attack_story?.length?analysis.attack_story:[
  alert?.host ? `Host ${alert.host} generated suspicious activity` : 'Suspicious activity detected',
  alert?.signature || 'Detection rule matched',
  'Further investigation required'
 ];

 const mitre=analysis.attack_mapping;
 const copy=async()=>{await navigator.clipboard.writeText(JSON.stringify(alert,null,2));message.success('Incident copied')};

 return <Drawer title={<Space><RobotOutlined/>SOC AI Assessment</Space>} width={760} open={open} onClose={onClose} closeIcon={<CloseOutlined/>} extra={alert?<Button icon={<CopyOutlined/>} onClick={copy}>Copy</Button>:null}>
 {!alert?<Text>Select an alert</Text>:loading?<Spin/>:<div className="space-y-4">
 <Card>
  <Title level={3}>{alert.signature||'Security Alert'}</Title>
  <Space wrap>
   <Tag color="green"><CheckCircleOutlined/> AI {alert.aiStatus}</Tag>
   <Tag>Rule Severity: {String(rule.metadata||alert.severity||'UNKNOWN').toUpperCase()}</Tag>
   <Tag color="orange">AI Risk: {String(risk.severity||'UNKNOWN').toUpperCase()}</Tag>
   {risk.confidence!==undefined&&<Tag>Confidence: {risk.confidence}%</Tag>}
  </Space>
 </Card>
 <Card title="SOC Decision"><Tag color="blue">{decision.action||'REVIEW'}</Tag><Paragraph>{decision.reason||analysis.final_soc_note||'No decision available'}</Paragraph></Card>
 <Card title="Executive Summary"><Paragraph>{analysis.one_line_summary || analysis.incident_summary?.description || analysis.behavior_analysis?.description || 'No summary available'}</Paragraph></Card>
 <Card title="Attack Story"><Timeline items={attackStory.map((x:any)=>({children:String(x)}))}/></Card>
 <Card title="Observed Evidence">{evidence.length?<ul>{evidence.map((x:any,i:number)=><li key={i}>{typeof x==='string'?x:pretty(x)}</li>)}</ul>:<Text type="secondary">No data available</Text>}</Card>
 <Card title="Detection Analysis">
  {analysis.detection_analysis?.matched_conditions && <><Text strong>Matched Conditions</Text><ul>{analysis.detection_analysis.matched_conditions.map((x:string,i:number)=><li key={i}>✓ {x}</li>)}</ul></>}
  {analysis.detection_analysis?.unmatched_conditions && <><Text strong>Review Points</Text><ul>{analysis.detection_analysis.unmatched_conditions.map((x:string,i:number)=><li key={i}>⚠ {x}</li>)}</ul></>}
 </Card>
 <Card title="MITRE ATT&CK"><Paragraph>{pretty(mitre)||'No MITRE mapping available'}</Paragraph></Card>
 <Card title="False Positive Analysis">{pretty(analysis.false_positive_analysis?.plausible_explanations||'No data available')}</Card>
 <Card title="Recommended Investigation Steps">{steps.length?<ol>{steps.map((x:any,i:number)=><li key={i}>{i+1}. {typeof x==='string'?x:pretty(x)}</li>)}</ol>:<Text type="secondary">No data available</Text>}</Card>
 <Divider/>
 <Card title="Final SOC Note"><Paragraph>{analysis.final_soc_note||'—'}</Paragraph></Card>
 </div>}
 </Drawer>
};

export default AISidebar;
