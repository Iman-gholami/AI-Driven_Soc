import React from 'react';
import { Card, Col, Row, Statistic, Typography, Tag, Table, Progress, Space, Badge } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { AlertOutlined, RobotOutlined, WarningOutlined, RiseOutlined } from '@ant-design/icons';
import { api } from '../../api/client';
import { Alert } from '../../types';

const { Title, Text } = Typography;

const colors = {
  bg:'#07111F',
  card:'#0F172A',
  border:'#22314D',
  text:'#E5EEF9',
  muted:'#93A4BF',
  cyan:'#22D3EE',
  blue:'#3B82F6',
  red:'#EF4444',
  orange:'#F97316'
};

const riskColor=(v:string)=>v==='critical'?'red':v==='high'?'orange':v==='medium'?'gold':'blue';

const Dashboard:React.FC=()=>{
 const {data:alerts=[],isLoading}=useQuery({queryKey:['alerts'],queryFn:api.getAlerts});
 const critical=alerts.filter(a=>a.severity==='critical').length;
 const high=alerts.filter(a=>a.severity==='high').length;
 const medium=alerts.filter(a=>a.severity==='medium').length;
 const analyzed=alerts.filter(a=>a.aiStatus==='analyzed').length;
 const eligible=alerts.filter(a=>a.aiEligibility?.eligible).length;
 const coverage=alerts.length?Math.round(analyzed/alerts.length*100):0;
 const pressure=Math.min(100,critical*20+high*8+medium*3);

 const columns=[
  {title:'Incident',dataIndex:'signature',render:(v:string|null,r:Alert)=><div><Text strong style={{color:colors.text}}>{v||'Unknown Detection'}</Text><br/><Text style={{color:colors.muted}}>{r.host||r.alertId}</Text></div>},
  {title:'Risk',dataIndex:'severity',render:(v:string)=><Tag color={riskColor(v)}>{(v||'unknown').toUpperCase()}</Tag>},
  {title:'AI Decision',dataIndex:'aiStatus',render:(v:string)=><Tag color='cyan'>{v||'pending'}</Tag>},
  {title:'Time',dataIndex:'createdAt',render:(v:string)=>new Date(v).toLocaleString()}
 ];

 return <div style={{background:colors.bg,minHeight:'100%',padding:24}}>
  <Title level={2} style={{color:colors.text}}>SOC Command Center</Title>
  <Text style={{color:colors.muted}}>Threat visibility, AI triage and analyst decision intelligence</Text>

  <Row gutter={[16,16]} style={{marginTop:24}}>
   {[
    ['Active Incidents',alerts.length,<AlertOutlined style={{color:colors.cyan}}/>],
    ['Critical Threats',critical,<WarningOutlined style={{color:colors.red}}/>],
    ['AI Coverage',coverage+'%',<RobotOutlined style={{color:colors.blue}}/>],
    ['Threat Pressure',pressure+'/100',<RiseOutlined style={{color:colors.orange}}/>]
   ].map((x:any)=><Col xs={24} lg={6} key={x[0]}><Card style={{background:colors.card,border:`1px solid ${colors.border}`}}><Statistic title={<Text style={{color:colors.muted}}>{x[0]}</Text>} value={x[1]} prefix={x[2]} valueStyle={{color:colors.text}}/></Card></Col>)}
  </Row>

  <Row gutter={[16,16]} style={{marginTop:16}}>
   <Col xs={24} lg={8}><Card title='Threat Severity' style={{background:colors.card}}><Space direction='vertical' style={{width:'100%'}}><Text>Critical</Text><Progress percent={alerts.length?critical/alerts.length*100:0} status='exception'/><Text>High</Text><Progress percent={alerts.length?high/alerts.length*100:0}/><Text>Medium</Text><Progress percent={alerts.length?medium/alerts.length*100:0}/></Space></Card></Col>
   <Col xs={24} lg={8}><Card title='AI Security Posture' style={{background:colors.card}}><Progress type='circle' percent={coverage}/><p style={{color:colors.muted}}>Eligible alerts: {eligible}</p></Card></Col>
   <Col xs={24} lg={8}><Card title='SOC Status' style={{background:colors.card}}><Badge status='processing' text='AI Engine Online'/><br/><Badge status='success' text='Detection Pipeline Active'/><br/><Badge status='warning' text='Investigation Queue Open'/></Card></Col>
  </Row>

  <Card title='Active Investigation Queue' loading={isLoading} style={{marginTop:16,background:colors.card}}>
   <Table<Alert> rowKey='alertId' dataSource={alerts.slice(0,10)} columns={columns} pagination={false}/>
  </Card>
 </div>;
};

export default Dashboard;
