import React from 'react';
import { Card, Col, Row, Statistic, Typography, Tag, Table, Progress, Space } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { AlertOutlined, RobotOutlined, WarningOutlined, RiseOutlined, SafetyOutlined } from '@ant-design/icons';
import { api } from '../../api/client';
import { Alert } from '../../types';

const {Title, Text}=Typography;

const colors={bg:'#050b16',card:'#0b1424',border:'#1e3658',text:'#eef6ff',muted:'#8ea4c4',blue:'#3b82f6',cyan:'#22d3ee',red:'#ff4d6d',orange:'#ff9f43',green:'#35d07f'};

const Metric=({title,value,color}:{title:string,value:string|number,color:string})=><Card style={{background:colors.card,border:`1px solid ${colors.border}`,borderRadius:12}}><Text style={{color:colors.muted}}>{title}</Text><Statistic value={value} valueStyle={{color}}/></Card>;

const Dashboard:React.FC=()=>{
 const {data:alerts=[],isLoading}=useQuery({queryKey:['alerts'],queryFn:api.getAlerts});
 const critical=alerts.filter(a=>a.severity==='critical').length;
 const high=alerts.filter(a=>a.severity==='high').length;
 const analyzed=alerts.filter(a=>a.aiStatus==='analyzed').length;
 const coverage=alerts.length?Math.round(analyzed/alerts.length*100):0;
 const risk=Math.min(100,critical*30+high*12);

 const columns=[
  {title:'Incident',dataIndex:'signature',render:(v:string,r:Alert)=><Space direction="vertical"><Text strong>{v||'Unknown Detection'}</Text><Text type="secondary">{r.host||r.alertId}</Text></Space>},
  {title:'Risk',dataIndex:'severity',render:(v:string)=><Tag color={v==='critical'?'red':v==='high'?'orange':'gold'}>{v?.toUpperCase()}</Tag>},
  {title:'AI Decision',dataIndex:'aiStatus',render:(v:string)=><Tag color="cyan">{v||'pending'}</Tag>},
  {title:'Time',dataIndex:'createdAt',render:(v:string)=>new Date(v).toLocaleString()}
 ];

 return <div style={{background:colors.bg,minHeight:'100%',padding:30}}>
  <Title level={1} style={{color:colors.text,marginBottom:0}}>Cyber Command Center</Title>
  <Text style={{color:colors.muted}}>AI driven security posture and analyst intelligence</Text>

  <Row gutter={[16,16]} style={{marginTop:24}}>
   <Col span={24} lg={8}><Card style={{background:colors.card,border:`1px solid ${colors.border}`}}><Text>Active Risk Index</Text><Progress type="dashboard" percent={risk}/><div>Open cases {alerts.length}</div><div>Critical cases {critical}</div></Card></Col>
   <Col span={24} lg={16}><Row gutter={[12,12]}><Col span={8}><Metric title="Open Cases" value={alerts.length} color={colors.cyan}/></Col><Col span={8}><Metric title="Critical Alerts" value={critical} color={colors.red}/></Col><Col span={8}><Metric title="AI Coverage" value={`${coverage}%`} color={colors.blue}/></Col><Col span={8}><Metric title="Threat Pressure" value={`${risk}/100`} color={colors.orange}/></Col><Col span={8}><Metric title="AI Engine" value="ONLINE" color={colors.green}/></Col><Col span={8}><Metric title="Signals" value={alerts.length} color={colors.cyan}/></Col></Row></Col>
  </Row>

  <Row gutter={[16,16]} style={{marginTop:20}}>
   <Col span={24} lg={8}><Card title="Severity Pressure" style={{background:colors.card,border:`1px solid ${colors.border}`}}><Progress percent={critical?85:0} status="exception"/><p>Critical</p><Progress percent={high?45:0}/><p>High</p><Progress percent={30}/><p>Medium</p></Card></Col>
   <Col span={24} lg={8}><Card title="AI Intelligence" style={{background:colors.card,border:`1px solid ${colors.border}`}}><Progress type="circle" percent={coverage}/><p>Automated triage coverage</p></Card></Col>
   <Col span={24} lg={8}><Card title="SOC Operations" style={{background:colors.card,border:`1px solid ${colors.border}`}}><Tag color="green">AI ONLINE</Tag><Tag color="blue">PIPELINE ACTIVE</Tag><Tag color="orange">INVESTIGATION</Tag><p><SafetyOutlined/> Detection system healthy</p></Card></Col>
  </Row>

  <Card title="Active Investigation Queue" loading={isLoading} style={{marginTop:20,background:colors.card,border:`1px solid ${colors.border}`}}><Table rowKey="alertId" dataSource={alerts.slice(0,10)} columns={columns} pagination={false}/></Card>
 </div>;
};

export default Dashboard;
