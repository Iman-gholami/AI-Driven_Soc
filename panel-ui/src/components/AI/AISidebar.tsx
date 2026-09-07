import React from 'react';
import { Drawer, Button, Space, Typography, Card, Spin, message, Tag, Divider, Timeline, Progress, Collapse } from 'antd';
import { CloseOutlined, CopyOutlined, RobotOutlined, CheckCircleOutlined, ReloadOutlined } from '@ant-design/icons';
import { Alert as AlertType } from '../../types';

const { Title, Text, Paragraph } = Typography;

interface AISidebarProps {
  open: boolean;
  onClose: () => void;
  alert: AlertType | null;
  loading?: boolean;
  onReanalyze?: (alert: AlertType) => Promise<void> | void;
}

const AISidebar:React.FC<AISidebarProps>=({open,onClose,alert,loading=false,onReanalyze})=>{
  const analysis:any = alert?.fullAnalysis || {};
  const risk = analysis.risk_assessment || {};
  const decision = analysis.analyst_decision || {};
  const rule:any = alert?.detectionRule?.rule || {};
  const list = (value:any) => Array.isArray(value) ? value : [];
  const evidence = list(analysis.observed_evidence);
  const steps = list(analysis.recommended_investigation_steps);
  const story = list(analysis.attack_story);
  const falsePositives = list(analysis.false_positive_analysis);
  const mapping = list(analysis.attack_mapping);
  const triggerEvidence = list(analysis.why_alert_triggered?.evidence);
  const copy = async () => {
    if (!alert) return;
    await navigator.clipboard.writeText(JSON.stringify(alert,null,2));
    message.success('Incident copied');
  };

  return <Drawer
    title={<Space><RobotOutlined/>SOC Investigation Workspace</Space>}
    width={820}
    open={open}
    onClose={onClose}
    closeIcon={<CloseOutlined/>}
    extra={alert?<Space><Button icon={<CopyOutlined/>} onClick={copy}>Copy</Button>{alert.aiStatus==='analyzed' && alert.aiEligibility?.eligible && onReanalyze && <Button icon={<ReloadOutlined/>} onClick={()=>onReanalyze(alert)}>Re-run AI</Button>}</Space>:null}
  >
    {!alert ? <Text>Select an alert</Text> : loading ? <Spin/> : <div className="space-y-4">
      <Card>
        <Title level={3}>🚨 {alert.signature||'Security Alert'}</Title>
        <Space wrap>
          <Tag color={alert.aiStatus==='analyzed'?'green':alert.aiStatus==='failed'?'red':'default'}><CheckCircleOutlined/> AI {alert.aiStatus}</Tag>
          <Tag>Rule: {rule.rule_id || alert.ruleMatch?.ruleId || 'UNRESOLVED'}</Tag>
          <Tag color="orange">AI Risk: {String(risk.severity||'UNKNOWN').toUpperCase()}</Tag>
          {risk.confidence!==undefined && <Tag>Confidence {Number(risk.confidence)}%</Tag>}
          {alert.analysisCount!==undefined && <Tag>Analyses {alert.analysisCount}</Tag>}
        </Space>
      </Card>

      <Card title="Observed Evidence">
        {evidence.length ? evidence.map((item:any,index:number)=><Card size="small" key={index}>✓ {typeof item==='string'?item:JSON.stringify(item)}</Card>) : <Text type="secondary">No observed evidence was returned by the model.</Text>}
      </Card>

      <Card title="Detection Logic">
        <Paragraph><Text strong>Matched rule:</Text> {rule.title || alert.signature || 'Unavailable'}</Paragraph>
        {rule.rule_id && <Paragraph><Text strong>Rule ID / revision:</Text> {rule.rule_id}{rule.revision!==undefined?` / ${rule.revision}`:''}</Paragraph>}
        {analysis.detection_analysis?.rule_logic && <Paragraph><Text strong>Rule logic:</Text> {analysis.detection_analysis.rule_logic}</Paragraph>}
        {analysis.detection_analysis?.limitations && <Paragraph><Text strong>Limitations:</Text> {analysis.detection_analysis.limitations}</Paragraph>}
        {triggerEvidence.length > 0 && <><Divider/><Text strong>Trigger evidence</Text>{triggerEvidence.map((item:any,index:number)=><div key={index}>✓ {String(item)}</div>)}</>}
        {rule.raw_rule && <Collapse items={[{key:'raw-rule',label:'Raw detection rule',children:<Paragraph code copyable>{rule.raw_rule}</Paragraph>}]}/>}      
      </Card>

      <Card title="AI Assessment">
        <Paragraph><Text strong>Verdict:</Text> {analysis.verdict || 'UNKNOWN'}</Paragraph>
        <Paragraph><Text strong>Summary:</Text> {analysis.one_line_summary || analysis.final_soc_note || 'No summary available'}</Paragraph>
        <Paragraph><Text strong>Behavior:</Text> {analysis.behavior_analysis || 'No behavior analysis available'}</Paragraph>
      </Card>

      <Card title="Risk Overview">
        <Progress percent={Number(risk.confidence||0)} />
        <Paragraph>{risk.reasoning || 'No risk reasoning available.'}</Paragraph>
      </Card>

      <Card title="SOC Decision">
        <Tag color="blue">{decision.action||'UNKNOWN'}</Tag>
        <Paragraph>{decision.reason||'No analyst decision returned by the model.'}</Paragraph>
      </Card>

      <Card title="Attack Story">
        {story.length ? <Timeline items={story.map((item:any)=>({children:String(item)}))}/> : <Text type="secondary">No evidence-backed attack story is available.</Text>}
      </Card>

      <Card title="MITRE ATT&CK">
        {mapping.length ? mapping.map((item:any,index:number)=><div key={index}><Text code>{item.technique || item.id || 'Unknown'}</Text>{item.name ? ` — ${item.name}` : ''}</div>) : <Text type="secondary">No MITRE technique was mapped from the supplied evidence.</Text>}
      </Card>

      <Card title="False-positive Analysis">
        {falsePositives.length ? falsePositives.map((item:any,index:number)=><div key={index}>• {String(item)}</div>) : <Text type="secondary">No false-positive scenarios were returned.</Text>}
      </Card>

      <Card title="Recommended Investigation Steps">
        {steps.length ? steps.map((item:any,index:number)=><div key={index}>{index+1}. {typeof item==='string'?item:JSON.stringify(item)}</div>) : <Text type="secondary">No investigation steps available.</Text>}
      </Card>

      <Divider/>
      <Card title="Final SOC Note"><Paragraph>{analysis.final_soc_note||'—'}</Paragraph></Card>
    </div>}
  </Drawer>;
};

export default AISidebar;
