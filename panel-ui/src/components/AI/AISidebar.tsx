import React from 'react';
import { Drawer, Button, Space, Typography, Card, Spin, message, Tag, Divider, Timeline, Progress, Collapse } from 'antd';
import { CloseOutlined, CopyOutlined, RobotOutlined, CheckCircleOutlined, ReloadOutlined } from '@ant-design/icons';
import { Alert as AlertType } from '../../types';

const { Title, Text, Paragraph } = Typography;

function renderValue(value:any, fallback='—') {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value);
  try { return JSON.stringify(value, null, 2); } catch { return String(value); }
}

function confidencePercent(value:any) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? Math.min(100, Math.max(0, numeric)) : 0;
}

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
  const networkIntel:any = alert?.soc?.networkIntelligence || {};
  const networkIps:any[] = Array.isArray(networkIntel.ips) ? networkIntel.ips : [];
  const networkCorrelations:any[] = Array.isArray(networkIntel.correlations) ? networkIntel.correlations : [];
  const rule:any = alert?.detectionRule?.rule || {};
  const list = (value:any) => Array.isArray(value) ? value : [];
  const evidence = list(analysis.observed_evidence);
  const steps = list(analysis.recommended_investigation_steps);
  const story = list(analysis.attack_story);
  const falsePositives = list(analysis.false_positive_analysis).length
    ? list(analysis.false_positive_analysis)
    : list(analysis.false_positive_analysis?.conditions);
  const mapping = list(analysis.attack_mapping).length
    ? list(analysis.attack_mapping)
    : list(analysis.attack_mapping?.mitre_techniques);
  const triggerEvidence = list(analysis.why_alert_triggered?.evidence).length
    ? list(analysis.why_alert_triggered?.evidence)
    : list(analysis.detection_analysis?.evidence);
  const summary = analysis.one_line_summary
    || analysis.incident_summary?.what_happened
    || analysis.incident_summary?.summary
    || analysis.final_soc_note
    || 'No summary available';
  const behavior = analysis.behavior_analysis || 'No behavior analysis available';
  const ruleLogic = analysis.detection_analysis?.rule_logic || analysis.detection_analysis?.trigger_reason;
  const limitations = analysis.detection_analysis?.limitations || analysis.detection_analysis?.gaps;
  const riskReasoning = risk.reasoning || risk.rationale || 'No risk reasoning available.';
  const confidence = confidencePercent(risk.confidence);
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
          {risk.confidence!==undefined && <Tag>Confidence {confidence}%</Tag>}
          {alert.analysisCount!==undefined && <Tag>Analyses {alert.analysisCount}</Tag>}
        </Space>
      </Card>

      <Card title="Observed Evidence">
        {evidence.length ? evidence.map((item:any,index:number)=><Card size="small" key={index}>✓ {typeof item==='string'?item:JSON.stringify(item)}</Card>) : <Text type="secondary">No observed evidence was returned by the model.</Text>}
      </Card>

      <Card title="Network Intelligence">
        {networkIps.length ? <div className="space-y-3">
          {networkIps.map((item:any) => <Card size="small" key={item.ip}>
            <Space wrap>
              <Text code>{item.ip}</Text>
              {(item.roles || []).map((role:string) => <Tag key={role}>{role}</Tag>)}
              {item.nationalNetwork && <Tag>National network</Tag>}
              {item.asset?.owned && <Tag>Organizational asset</Tag>}
              {item.threat?.directMatch && <Tag color="error">Direct threat evidence</Tag>}
              {!item.threat?.directMatch && item.threat?.relationshipMatch && <Tag color="warning">Threat relationship</Tag>}
            </Space>
            {item.asset?.owned && <Paragraph className="mt-2 mb-1">
              <Text strong>Organization:</Text> {renderValue(item.asset?.organization)}
              {item.asset?.category ? ` · ${renderValue(item.asset.category)}` : ''}
              {item.asset?.province ? ` · ${renderValue(item.asset.province)}` : ''}
            </Paragraph>}
            {item.ipMetadata?.matched && <Paragraph className="mb-1">
              <Text strong>IP metadata:</Text> {[item.ipMetadata.asName, item.ipMetadata.organization, item.ipMetadata.countryCode, item.ipMetadata.city].filter(Boolean).join(' · ') || 'Available'}
            </Paragraph>}
            {item.threat?.directMatch && <Paragraph className="mb-1">
              <Text strong>Direct feed evidence:</Text> {(item.threat.direct?.malware || []).join(', ') || (item.threat.direct?.classifications || []).map((entry:any)=>entry.identifier).filter(Boolean).join(', ') || 'Matched'}
              {item.threat.direct?.latestObservedAt ? ` · last observed ${new Date(item.threat.direct.latestObservedAt).toLocaleString()}` : ''}
            </Paragraph>}
            {item.threat?.relationshipMatch && <Paragraph className="mb-0">
              <Text strong>Relationship evidence:</Text> {(item.threat.relationship?.malware || []).join(', ') || 'Matched in feed destination telemetry'}
              {item.threat.relationship?.latestObservedAt ? ` · last observed ${new Date(item.threat.relationship.latestObservedAt).toLocaleString()}` : ''}
            </Paragraph>}
          </Card>)}
          {(networkIntel.sources?.threatDataset || networkIntel.sources?.assetDataset) && <Paragraph className="mb-0">
            <Text type="secondary">
              Intelligence snapshot
              {networkIntel.sources?.threatDataset?.sourceFile ? ` · TI: ${networkIntel.sources.threatDataset.sourceFile}` : ''}
              {networkIntel.sources?.threatDataset?.importedAt ? ` · imported ${new Date(networkIntel.sources.threatDataset.importedAt).toLocaleString()}` : ''}
            </Text>
          </Paragraph>}
          {networkCorrelations.length > 0 && <>
            <Divider/>
            <Text strong>Deterministic correlations</Text>
            {networkCorrelations.map((item:any,index:number) => <div key={index} className="mt-2">
              <Tag color={item.strength==='very_high'||item.strength==='high'?'error':item.strength==='moderate'?'warning':'default'}>{String(item.strength || 'unknown').replace('_',' ').toUpperCase()}</Tag>
              <Text>{String(item.type || 'network correlation').replaceAll('_',' ')}</Text>
              {Array.isArray(item.matchedFields) && item.matchedFields.length > 0 && <Text type="secondary"> · {item.matchedFields.join(' + ')}</Text>}
            </div>)}
          </>}
        </div> : <Text type="secondary">
          {networkIntel.status === 'not_applicable' ? 'No IPv4 indicators were found in this alert.' : 'Network intelligence is not available for this analysis.'}
        </Text>}
      </Card>

      <Card title="Detection Logic">
        <Paragraph><Text strong>Matched rule:</Text> {rule.title || alert.signature || 'Unavailable'}</Paragraph>
        {rule.rule_id && <Paragraph><Text strong>Rule ID / revision:</Text> {rule.rule_id}{rule.revision!==undefined?` / ${rule.revision}`:''}</Paragraph>}
        {ruleLogic && <Paragraph><Text strong>Rule logic:</Text> {renderValue(ruleLogic)}</Paragraph>}
        {limitations && <Paragraph><Text strong>Limitations:</Text> {renderValue(limitations)}</Paragraph>}
        {triggerEvidence.length > 0 && <><Divider/><Text strong>Trigger evidence</Text>{triggerEvidence.map((item:any,index:number)=><div key={index}>✓ {String(item)}</div>)}</>}
        {rule.raw_rule && <Collapse items={[{key:'raw-rule',label:'Raw detection rule',children:<Paragraph code copyable>{rule.raw_rule}</Paragraph>}]}/>}      
      </Card>

      <Card title="AI Assessment">
        <Paragraph><Text strong>Verdict:</Text> {renderValue(analysis.verdict, 'UNKNOWN')}</Paragraph>
        <Paragraph><Text strong>Summary:</Text> {renderValue(summary)}</Paragraph>
        <Paragraph style={{ whiteSpace: 'pre-wrap' }}><Text strong>Behavior:</Text> {renderValue(behavior)}</Paragraph>
      </Card>

      <Card title="Risk Overview">
        <Progress percent={confidence} />
        <Paragraph style={{ whiteSpace: 'pre-wrap' }}>{renderValue(riskReasoning)}</Paragraph>
      </Card>

      <Card title="SOC Decision">
        <Tag color="blue">{renderValue(decision.action, 'UNKNOWN')}</Tag>
        <Paragraph style={{ whiteSpace: 'pre-wrap' }}>{renderValue(decision.reason, 'No analyst decision returned by the model.')}</Paragraph>
      </Card>

      <Card title="Attack Story">
        {story.length ? <Timeline items={story.map((item:any)=>({children:String(item)}))}/> : <Text type="secondary">No evidence-backed attack story is available.</Text>}
      </Card>

      <Card title="MITRE ATT&CK">
        {mapping.length ? mapping.map((item:any,index:number)=><div key={index}><Text code>{renderValue(item?.technique || item?.id || item, 'Unknown')}</Text>{item?.name ? ` — ${renderValue(item.name)}` : ''}</div>) : <Text type="secondary">No MITRE technique was mapped from the supplied evidence.</Text>}
      </Card>

      <Card title="False-positive Analysis">
        {falsePositives.length ? falsePositives.map((item:any,index:number)=><div key={index}>• {renderValue(item)}</div>) : <Text type="secondary">No false-positive scenarios were returned.</Text>}
      </Card>

      <Card title="Recommended Investigation Steps">
        {steps.length ? steps.map((item:any,index:number)=><div key={index}>{index+1}. {typeof item==='string'?item:JSON.stringify(item)}</div>) : <Text type="secondary">No investigation steps available.</Text>}
      </Card>

      <Divider/>
      <Card title="Final SOC Note"><Paragraph style={{ whiteSpace: 'pre-wrap' }}>{renderValue(analysis.final_soc_note)}</Paragraph></Card>
    </div>}
  </Drawer>;
};

export default AISidebar;
