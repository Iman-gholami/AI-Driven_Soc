import React from 'react';
import { Drawer, Button, Space, Typography, Card, Spin, message, Divider, Tag, Collapse } from 'antd';
import { CloseOutlined, CopyOutlined, RobotOutlined, ClockCircleOutlined, CheckCircleOutlined, InfoCircleOutlined } from '@ant-design/icons';
import { Alert as AlertType } from '../../types';

const { Title, Text, Paragraph } = Typography;

interface AISidebarProps { open: boolean; onClose: () => void; alert: AlertType | null; loading?: boolean; }

const AISidebar: React.FC<AISidebarProps> = ({ open, onClose, alert, loading = false }) => {
  const formatDate = (dateString?: string) => dateString ? new Date(dateString).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' }) : '—';
  const formatValue = (value: unknown): string => {
    if (value === null || value === undefined || value === '') return '—';
    if (typeof value === 'string') return value;
    return JSON.stringify(value, null, 2);
  };

  const copyIncident = async () => {
    if (!alert) return;
    await navigator.clipboard.writeText(JSON.stringify({
      alertId: alert.alertId, source: alert.source, signature: alert.signature,
      eventType: alert.eventType, host: alert.host, severity: alert.severity,
      aiStatus: alert.aiStatus, aiEligibility: alert.aiEligibility,
      ruleMatch: alert.ruleMatch, detectionRule: alert.detectionRule,
      analysis: alert.fullAnalysis, rawEvent: alert.rawEvent,
    }, null, 2));
    message.success('Incident context copied');
  };

  const analysis = alert?.fullAnalysis;
  const risk = analysis?.risk_assessment || {};
  const confidence = typeof risk.confidence === 'number' ? risk.confidence : null;
  const evidence = Array.isArray(analysis?.observed_evidence) ? analysis.observed_evidence : [];
  const recommendations = Array.isArray(analysis?.recommended_investigation_steps) ? analysis.recommended_investigation_steps : [];
  const renderList = (items: unknown[], empty = 'No data available') => items.length ? (
    <ul className="space-y-2">{items.map((item, index) => <li key={index} className="rounded-lg bg-gray-50 dark:bg-gray-800 p-2"><Text>{formatValue(item)}</Text></li>)}</ul>
  ) : <Text type="secondary">{empty}</Text>;

  return (
    <Drawer
      title={<Space><RobotOutlined /><span>AI Incident Assessment</span></Space>}
      placement="right" width={620} open={open} onClose={onClose}
      extra={alert ? <Button icon={<CopyOutlined />} onClick={copyIncident}>Copy</Button> : null}
      closeIcon={<CloseOutlined />}
    >
      {!alert ? <div className="text-center py-12"><InfoCircleOutlined style={{ fontSize: 42 }} /><Text type="secondary" className="block mt-4">Select an alert to inspect it.</Text></div> : loading ? (
        <div className="flex flex-col items-center justify-center py-16"><Spin size="large" /><Text type="secondary" className="mt-4">Running deterministic rule resolution and AI triage…</Text></div>
      ) : (
        <div className="space-y-4">
          <Card size="small">
            <div className="flex items-center justify-between mb-3"><Title level={4} className="!mb-0">{alert.signature || 'Security Alert'}</Title><Tag>{alert.aiStatus.replace('_', ' ').toUpperCase()}</Tag></div>
            <Space wrap><Tag color="blue">{alert.source}</Tag><Tag color="gold">{alert.severity.toUpperCase()}</Tag>{alert.eventType && <Tag color="purple">{alert.eventType}</Tag>}{alert.host && <Tag color="cyan">{alert.host}</Tag>}</Space>
            <Divider className="my-3" />
            <div className="grid grid-cols-2 gap-2 text-sm"><Text type="secondary">Alert ID</Text><Text code>{alert.alertId}</Text><Text type="secondary">Created</Text><Text>{formatDate(alert.createdAt)}</Text><Text type="secondary">Updated</Text><Text>{formatDate(alert.updatedAt)}</Text><Text type="secondary">AI scenario</Text><Text>{alert.aiEligibility?.scenario || '—'}</Text></div>
          </Card>

          {!alert.signature || !alert.aiEligibility?.eligible ? <Card size="small" title="AI unavailable in V1"><Text>{alert.aiEligibility?.reason === 'missing_signature' ? 'This alert has no Signature. The current V1 workflow does not send such alerts to the LLM.' : `AI requires a deterministic Signature → detection-rule match. Reason: ${alert.aiEligibility?.reason || 'rule_not_matched'}.`}</Text></Card> : null}

          <Card title="Observed Evidence" size="small">
            <div className="space-y-2 text-sm"><div><Text strong>Signature: </Text><Text>{alert.signature || '—'}</Text></div><div><Text strong>Event type: </Text><Text>{alert.eventType || '—'}</Text></div><div><Text strong>Host: </Text><Text>{alert.host || '—'}</Text></div><div><Text strong>Event hash: </Text><Text code>{alert.eventHash || '—'}</Text></div></div>
            {alert.rawEvent && <Collapse className="mt-3" items={[{ key: 'raw', label: 'Raw incident fields', children: <pre className="whitespace-pre-wrap text-xs overflow-auto">{JSON.stringify(alert.rawEvent, null, 2)}</pre> }]} />}
          </Card>

          <Card title="Detection Logic" size="small">
            {alert.ruleMatch?.status === 'matched' && alert.detectionRule ? <div className="space-y-2 text-sm">
              <div><Text strong>Rule ID: </Text><Text code>{alert.detectionRule.rule_id}</Text></div><div><Text strong>Revision: </Text><Text>{alert.detectionRule.revision ?? '—'}</Text></div><div><Text strong>Title: </Text><Text>{alert.detectionRule.title || '—'}</Text></div><div><Text strong>Class type: </Text><Text>{alert.detectionRule.classtype || '—'}</Text></div><div><Text strong>Protocol: </Text><Text>{alert.detectionRule.protocol || '—'}</Text></div>
              <Collapse className="mt-3" items={[{ key: 'logic', label: 'Rule content / PCRE', children: <pre className="whitespace-pre-wrap text-xs overflow-auto">{formatValue({ contents: alert.detectionRule.contents, pcre: alert.detectionRule.pcre, flow: alert.detectionRule.flow })}</pre> }, { key: 'raw-rule', label: 'Raw rule', children: <pre className="whitespace-pre-wrap text-xs overflow-auto">{alert.detectionRule.raw_rule || '—'}</pre> }]} />
            </div> : <Text type="secondary">Rule resolution status: {alert.ruleMatch?.status || 'unresolved'}</Text>}
          </Card>

          {analysis ? <Card title="AI Assessment" size="small">
            <Space wrap className="mb-3"><Tag color="green"><CheckCircleOutlined /> AI completed</Tag>{risk.severity && <Tag color="red">Risk: {String(risk.severity).toUpperCase()}</Tag>}{confidence !== null && <Tag>Confidence: {confidence}%</Tag>}<Tag icon={<ClockCircleOutlined />}>{formatDate(alert.updatedAt)}</Tag></Space>
            <Title level={5}>Incident Summary</Title><Paragraph>{formatValue(analysis.incident_summary)}</Paragraph>
            <Title level={5}>Why Alert Triggered</Title><Paragraph>{formatValue(analysis.why_alert_triggered)}</Paragraph>
            <Title level={5}>Observed Evidence</Title>{renderList(evidence)}
            <Title level={5} className="mt-4">Detection Analysis</Title><Paragraph>{formatValue(analysis.detection_analysis)}</Paragraph>
            <Title level={5}>Behavior Analysis</Title><Paragraph>{formatValue(analysis.behavior_analysis)}</Paragraph>
            <Title level={5}>Attack Mapping</Title><Paragraph>{formatValue(analysis.attack_mapping)}</Paragraph>
            <Title level={5}>Risk Assessment</Title><Paragraph>{formatValue(analysis.risk_assessment)}</Paragraph>
            <Title level={5}>False Positive Analysis</Title><Paragraph>{formatValue(analysis.false_positive_analysis)}</Paragraph>
            <Title level={5}>Recommended Investigation Steps</Title>{renderList(recommendations)}
            <Title level={5} className="mt-4">Analyst Note</Title><Paragraph>{formatValue(analysis.analyst_note)}</Paragraph>
            <Divider /><Title level={5}>Final SOC Note</Title><Paragraph>{formatValue(analysis.final_soc_note)}</Paragraph>
          </Card> : <Card title="AI Assessment" size="small"><Text type="secondary">No AI assessment has been persisted for this alert.</Text></Card>}
        </div>
      )}
    </Drawer>
  );
};

export default AISidebar;
