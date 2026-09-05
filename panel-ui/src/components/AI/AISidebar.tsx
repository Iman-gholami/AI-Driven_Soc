import React from 'react';
import { Drawer, Button, Space, Typography, Card, Spin, message, Tag, Divider } from 'antd';
import { CloseOutlined, CopyOutlined, RobotOutlined, CheckCircleOutlined } from '@ant-design/icons';
import { Alert as AlertType } from '../../types';

const { Title, Text, Paragraph } = Typography;

interface AISidebarProps { open: boolean; onClose: () => void; alert: AlertType | null; loading?: boolean; }

const AISidebar: React.FC<AISidebarProps> = ({ open, onClose, alert, loading = false }) => {
  const analysis: any = alert?.fullAnalysis || {};
  const risk = analysis.risk_assessment || {};
  const decision = analysis.analyst_decision || {};

  const list = (items: any[]) => (
    <ul className="space-y-2">{(items || []).map((x, i) => <li key={i} className="rounded bg-gray-50 dark:bg-gray-800 p-2">{typeof x === 'string' ? x : JSON.stringify(x)}</li>)}</ul>
  );

  const copy = async () => {
    await navigator.clipboard.writeText(JSON.stringify(alert, null, 2));
    message.success('Incident copied');
  };

  return (
    <Drawer
      title={<Space><RobotOutlined /> SOC AI Assessment</Space>}
      placement="right"
      width={700}
      open={open}
      onClose={onClose}
      closeIcon={<CloseOutlined />}
      extra={alert ? <Button icon={<CopyOutlined />} onClick={copy}>Copy</Button> : null}
    >
      {!alert ? <Text>Select an alert</Text> : loading ? <Spin /> : <div className="space-y-4">
        <Card>
          <Title level={4}>{alert.signature || 'Security Alert'}</Title>
          <Space wrap>
            <Tag color="green"><CheckCircleOutlined /> {alert.aiStatus}</Tag>
            <Tag color="red">Risk: {(risk.severity || alert.severity || 'unknown').toUpperCase()}</Tag>
            {risk.confidence !== undefined && <Tag>Confidence: {risk.confidence}%</Tag>}
          </Space>
        </Card>

        <Card title="Executive Summary">
          <Paragraph>{analysis.one_line_summary || analysis.incident_summary?.signature || 'No summary available'}</Paragraph>
        </Card>

        <Card title="Analyst Decision">
          <Tag color="orange">{decision.action || 'REVIEW'}</Tag>
          <Paragraph>{decision.reason || analysis.final_soc_note}</Paragraph>
        </Card>

        <Card title="Attack Story">
          {list(analysis.attack_story || [])}
        </Card>

        <Card title="Observed Evidence">
          {list(analysis.observed_evidence || [])}
        </Card>

        <Card title="Detection Analysis">
          <Paragraph>{typeof analysis.detection_analysis === 'string' ? analysis.detection_analysis : JSON.stringify(analysis.detection_analysis || {}, null, 2)}</Paragraph>
        </Card>

        <Card title="MITRE Mapping">
          {list(analysis.attack_mapping || [])}
        </Card>

        <Card title="False Positive Analysis">
          {list(analysis.false_positive_analysis || [])}
        </Card>

        <Card title="Recommended Investigation Steps">
          {list(analysis.recommended_investigation_steps || [])}
        </Card>

        <Divider />
        <Text type="secondary">AI generated assessment. Validate before final incident closure.</Text>
      </div>}
    </Drawer>
  );
};

export default AISidebar;
