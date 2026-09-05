import React from 'react';
import { Card, Col, Row, Statistic, Typography, Tag, Table, Progress, Space } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { AlertOutlined, RobotOutlined, WarningOutlined, CheckCircleOutlined, RiseOutlined } from '@ant-design/icons';
import { api } from '../../api/client';
import { Alert } from '../../types';

const { Title, Text } = Typography;

const riskColor = (value:string) => {
  if (value === 'critical') return 'red';
  if (value === 'high') return 'orange';
  if (value === 'medium') return 'gold';
  return 'blue';
};

const Dashboard: React.FC = () => {
  const { data: alerts = [], isLoading } = useQuery({ queryKey: ['alerts'], queryFn: api.getAlerts });

  const critical = alerts.filter(a => a.severity === 'critical').length;
  const high = alerts.filter(a => a.severity === 'high').length;
  const medium = alerts.filter(a => a.severity === 'medium').length;
  const analyzed = alerts.filter(a => a.aiStatus === 'analyzed').length;
  const eligible = alerts.filter(a => a.aiEligibility?.eligible).length;
  const analysisRate = alerts.length ? Math.round((analyzed / alerts.length) * 100) : 0;
  const riskScore = Math.min(100, critical * 15 + high * 5 + medium * 2);

  const columns = [
    { title: 'Incident', dataIndex: 'signature', key: 'signature', render: (v:string|null, r:Alert) => <div><Text strong>{v || 'Unknown Detection'}</Text><div><Text type="secondary">{r.host || r.alertId}</Text></div></div> },
    { title: 'Risk', dataIndex: 'severity', key:'severity', render:(v:string)=><Tag color={riskColor(v)}>{(v || 'unknown').toUpperCase()}</Tag> },
    { title:'AI State', dataIndex:'aiStatus', key:'aiStatus', render:(v:string)=><Tag color="cyan">{(v || 'pending').replace('_',' ')}</Tag> },
    { title:'Time', dataIndex:'createdAt', key:'createdAt', render:(v:string)=>new Date(v).toLocaleString() }
  ];

  return <div className="space-y-6">
    <div>
      <Title level={2} className="!mb-1">SOC Command Center</Title>
      <Text type="secondary">Real-time threat visibility, AI triage and analyst decision support.</Text>
    </div>

    <Row gutter={[16,16]}>
      <Col xs={24} sm={12} lg={6}><Card><Statistic title="Active Incidents" value={alerts.length} prefix={<AlertOutlined/>}/></Card></Col>
      <Col xs={24} sm={12} lg={6}><Card><Statistic title="Critical Threats" value={critical} prefix={<WarningOutlined/>}/></Card></Col>
      <Col xs={24} sm={12} lg={6}><Card><Statistic title="AI Coverage" value={analysisRate} suffix="%" prefix={<RobotOutlined/>}/></Card></Col>
      <Col xs={24} sm={12} lg={6}><Card><Statistic title="Threat Pressure" value={riskScore} suffix="/100" prefix={<RiseOutlined/>}/></Card></Col>
    </Row>

    <Row gutter={[16,16]}>
      <Col xs={24} lg={12}>
        <Card title="Threat Severity Distribution">
          <Space direction="vertical" style={{width:'100%'}}>
            <Text>Critical</Text><Progress percent={alerts.length ? Math.round(critical/alerts.length*100) : 0} status="exception"/>
            <Text>High</Text><Progress percent={alerts.length ? Math.round(high/alerts.length*100) : 0}/>
            <Text>Medium</Text><Progress percent={alerts.length ? Math.round(medium/alerts.length*100) : 0}/>
          </Space>
        </Card>
      </Col>
      <Col xs={24} lg={12}>
        <Card title="AI Security Posture">
          <Statistic title="AI Eligible Alerts" value={eligible}/>
          <Progress percent={analysisRate}/>
          <Text type="secondary">AI assisted triage coverage</Text>
        </Card>
      </Col>
    </Row>

    <Card title="Active Investigation Queue" loading={isLoading} extra={<Tag color="orange">High: {high}</Tag>}>
      <Table<Alert> rowKey="alertId" dataSource={alerts.slice(0,10)} columns={columns} pagination={false} size="middle"/>
    </Card>

    <Card title="SOC Health">
      <Row gutter={16}>
        <Col span={12}><Statistic title="AI Analyzed" value={analyzed} prefix={<CheckCircleOutlined/>}/></Col>
        <Col span={12}><Statistic title="Pending Analysis" value={alerts.length-analyzed}/></Col>
      </Row>
    </Card>
  </div>;
};

export default Dashboard;
