import React from 'react';
import { Card, Col, Row, Statistic, Typography, Tag, Table } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { AlertOutlined, RobotOutlined, WarningOutlined, CheckCircleOutlined } from '@ant-design/icons';
import { api } from '../../api/client';
import { Alert } from '../../types';

const { Title, Text } = Typography;

const Dashboard: React.FC = () => {
  const { data: alerts = [], isLoading } = useQuery({ queryKey: ['alerts'], queryFn: api.getAlerts });
  const critical = alerts.filter(a => a.severity === 'critical').length;
  const high = alerts.filter(a => a.severity === 'high').length;
  const analyzed = alerts.filter(a => a.aiStatus === 'analyzed').length;
  const eligible = alerts.filter(a => a.aiEligibility?.eligible).length;

  const columns = [
    { title: 'Alert', dataIndex: 'signature', key: 'signature', render: (v: string | null, r: Alert) => <div><Text strong>{v || 'No Signature'}</Text><div><Text type="secondary" className="text-xs">{r.alertId}</Text></div></div> },
    { title: 'Severity', dataIndex: 'severity', key: 'severity', render: (v: string) => <Tag color={v === 'critical' ? 'red' : v === 'high' ? 'orange' : 'default'}>{v.toUpperCase()}</Tag> },
    { title: 'AI', dataIndex: 'aiStatus', key: 'aiStatus', render: (v: string) => <Tag>{v.replace('_', ' ')}</Tag> },
    { title: 'Created', dataIndex: 'createdAt', key: 'createdAt', render: (v: string) => new Date(v).toLocaleString() },
  ];

  return <div className="space-y-6">
    <div><Title level={2} className="!mb-1">SOC Dashboard</Title><Text type="secondary">Operational view of ingested security alerts and analyst-triggered AI triage.</Text></div>
    <Row gutter={[16, 16]}>
      <Col xs={24} sm={12} lg={6}><Card><Statistic title="Total Alerts" value={alerts.length} prefix={<AlertOutlined />} /></Card></Col>
      <Col xs={24} sm={12} lg={6}><Card><Statistic title="Critical" value={critical} prefix={<WarningOutlined />} /></Card></Col>
      <Col xs={24} sm={12} lg={6}><Card><Statistic title="AI Eligible" value={eligible} prefix={<RobotOutlined />} /></Card></Col>
      <Col xs={24} sm={12} lg={6}><Card><Statistic title="AI Analyzed" value={analyzed} prefix={<CheckCircleOutlined />} /></Card></Col>
    </Row>
    <Card title="Recent Alerts" loading={isLoading} extra={<Tag color="orange">High: {high}</Tag>}><Table<Alert> rowKey="alertId" dataSource={alerts.slice(0, 10)} columns={columns} pagination={false} size="small" /></Card>
  </div>;
};

export default Dashboard;
