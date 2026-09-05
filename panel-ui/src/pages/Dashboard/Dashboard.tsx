import React from 'react';
import { Card, Col, Row, Statistic, Typography, Tag, Table, Progress, Space } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { SafetyOutlined } from '@ant-design/icons';
import { api } from '../../api/client';
import { Alert } from '../../types';

const { Title, Text } = Typography;

const theme = {
  bg: '#090B0F',
  surface: '#14171C',
  border: 'rgba(255,255,255,.08)',
  text: '#F5F7FA',
  muted: '#8B95A7',
  critical: '#FF4D5A',
  high: '#FF8A3D',
  medium: '#FFD43B',
  ai: '#20D8FF',
  primary: '#1677FF',
  success: '#52D273'
};

const Metric = ({title,value,color}:{title:string;value:string|number;color:string}) => (
<Card style={{background:theme.surface,border:`1px solid ${theme.border}`,borderRadius:14}}>
<Text style={{color:theme.muted}}>{title}</Text>
<Statistic value={value} valueStyle={{color,fontSize:28}} />
</Card>
);

const Dashboard:React.FC = () => {
 const {data:alerts=[],isLoading}=useQuery({queryKey:['alerts'],queryFn:api.getAlerts});
 const critical=alerts.filter((a:Alert)=>a.severity==='critical').length;
 const high=alerts.filter((a:Alert)=>a.severity==='high').length;
 const analyzed=alerts.filter((a:Alert)=>a.aiStatus==='analyzed').length;
 const coverage=alerts.length?Math.round(analyzed/alerts.length*100):0;
 const risk=Math.min(100,critical*30+high*12);

 const columns=[
 {title:'Incident',dataIndex:'signature',render:(v:string,r:Alert)=><Space direction="vertical"><Text strong style={{color:theme.text}}>{v||'Unknown Detection'}</Text><Text style={{color:theme.muted}}>{r.host||r.alertId}</Text></Space>},
 {title:'Risk',dataIndex:'severity',render:(v:string)=><Tag color={v==='critical'?'red':v==='high'?'orange':'gold'}>{v?.toUpperCase()}</Tag>},
 {title:'AI Decision',dataIndex:'aiStatus',render:(v:string)=><Tag color="cyan">{v||'pending'}</Tag>},
 {title:'Last Seen',dataIndex:'createdAt'}
 ];

 return <div style={{background:theme.bg,minHeight:'100%',padding:32}}>
 <Title style={{color:theme.text,marginBottom:4}}>Cyber Command Center</Title>
 <Text style={{color:theme.muted}}>AI-driven security posture and analyst intelligence</Text>

 <Row gutter={[16,16]} style={{marginTop:28}}>
 <Col lg={8} xs={24}><Card title="Active Risk Index" style={{background:theme.surface,border:`1px solid ${theme.border}`}}><Progress type="dashboard" percent={risk} strokeColor={theme.ai}/><p style={{color:theme.muted}}>Open cases: {alerts.length}</p><p style={{color:theme.muted}}>Critical cases: {critical}</p></Card></Col>
 <Col lg={16} xs={24}><Row gutter={[16,16]}><Col span={8}><Metric title="Open Cases" value={alerts.length} color={theme.ai}/></Col><Col span={8}><Metric title="Critical Alerts" value={critical} color={theme.critical}/></Col><Col span={8}><Metric title="AI Coverage" value={`${coverage}%`} color={theme.primary}/></Col><Col span={8}><Metric title="Threat Pressure" value={`${risk}/100`} color={theme.high}/></Col><Col span={8}><Metric title="AI Engine" value="ONLINE" color={theme.success}/></Col><Col span={8}><Metric title="Signals" value={alerts.length} color={theme.ai}/></Col></Row></Col>
 </Row>

 <Row gutter={[16,16]} style={{marginTop:20}}>
 <Col lg={8} xs={24}><Card title="Severity Pressure" style={{background:theme.surface}}><Progress percent={critical?85:0} strokeColor={theme.critical}/><Text style={{color:theme.text}}>Critical</Text><Progress percent={high?45:0} strokeColor={theme.high}/><Text style={{color:theme.text}}>High</Text><Progress percent={30} strokeColor={theme.medium}/><Text style={{color:theme.text}}>Medium</Text></Card></Col>
 <Col lg={8} xs={24}><Card title="AI Intelligence" style={{background:theme.surface}}><Progress type="circle" percent={coverage} strokeColor={theme.ai}/><p style={{color:theme.muted}}>Automated triage coverage</p></Card></Col>
 <Col lg={8} xs={24}><Card title="SOC Operations" style={{background:theme.surface}}><Tag color="green">AI ONLINE</Tag><Tag color="blue">PIPELINE ACTIVE</Tag><Tag color="orange">INVESTIGATION</Tag><p style={{color:theme.muted}}><SafetyOutlined/> Detection system healthy</p></Card></Col>
 </Row>

 <Card title="Active Investigation Queue" loading={isLoading} style={{marginTop:20,background:theme.surface,border:`1px solid ${theme.border}`}}><Table rowKey="alertId" dataSource={alerts.slice(0,10)} columns={columns} pagination={false}/></Card>
 </div>;
};

export default Dashboard;
