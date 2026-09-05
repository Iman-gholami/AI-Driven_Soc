import React from 'react';
import { Card, Col, Row, Statistic, Typography, Tag, Table, Progress, Space } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { AlertOutlined, RobotOutlined, WarningOutlined, RiseOutlined } from '@ant-design/icons';
import { api } from '../../api/client';
import { Alert } from '../../types';

const {Title, Text}=Typography;

const theme={
 bg:'#07111f',
 panel:'#0b1628',
 border:'#203452',
 text:'#e5eef9',
 muted:'#8fa3bf',
 cyan:'#22d3ee',
 blue:'#3b82f6',
 red:'#ef4444',
 orange:'#f97316'
};

const Dashboard:React.FC=()=>{
 const {data:alerts=[],isLoading}=useQuery({queryKey:['alerts'],queryFn:api.getAlerts});
 const critical=alerts.filter(a=>a.severity==='critical').length;
 const high=alerts.filter(a=>a.severity==='high').length;
 const analyzed=alerts.filter(a=>a.aiStatus==='analyzed').length;
 const coverage=alerts.length?Math.round(analyzed/alerts.length*100):0;
 const pressure=Math.min(100,critical*25+high*10);

 const columns=[
  {title:'Incident',dataIndex:'signature',render:(v:string,r:Alert)=><Space direction='vertical'><Text strong style={{color:theme.text}}>{v||'Unknown Detection'}</Text><Text style={{color:theme.muted}}>{r.host||r.alertId}</Text></Space>},
  {title:'Risk',dataIndex:'severity',render:(v:string)=><Tag color={v==='critical'?'red':v==='high'?'orange':'gold'}>{(v||'unknown').toUpperCase()}</Tag>},
  {title:'AI',dataIndex:'aiStatus',render:(v:string)=><Tag color='cyan'>{v||'pending'}</Tag>},
  {title:'Last Seen',dataIndex:'createdAt',render:(v:string)=>new Date(v).toLocaleString()}
 ];

 return <div style={{background:theme.bg,minHeight:'100%',padding:32}}>
  <Title level={2} style={{color:theme.text,marginBottom:4}}>SOC Command Center</Title>
  <Text style={{color:theme.muted}}>Real-time threat monitoring and AI assisted investigation</Text>

  <Row gutter={[20,20]} style={{marginTop:28}}>
   {[
    ['Active Incidents',alerts.length,<AlertOutlined style={{color:theme.cyan}}/>],
    ['Critical Threats',critical,<WarningOutlined style={{color:theme.red}}/>],
    ['AI Coverage',coverage+'%',<RobotOutlined style={{color:theme.blue}}/>],
    ['Threat Pressure',pressure+'/100',<RiseOutlined style={{color:theme.orange}}/>]
   ].map((item:any)=><Col xs={24} lg={6} key={item[0]}><Card style={{background:theme.panel,border:`1px solid ${theme.border}`,borderRadius:16}}><Statistic title={<Text style={{color:theme.muted}}>{item[0]}</Text>} value={item[1]} prefix={item[2]} valueStyle={{color:theme.text,fontSize:30}}/></Card></Col>)}
  </Row>

  <Row gutter={[20,20]} style={{marginTop:20}}>
   <Col xs={24} lg={8}><Card title='Threat Landscape' style={{background:theme.panel,border:`1px solid ${theme.border}`}}><Progress percent={critical?80:0} status='exception'/><Text style={{color:theme.muted}}>Critical exposure</Text><Progress percent={high?60:0}/><Text style={{color:theme.muted}}>High risk activity</Text></Card></Col>
   <Col xs={24} lg={8}><Card title='AI Intelligence Engine' style={{background:theme.panel,border:`1px solid ${theme.border}`}}><Progress type='circle' percent={coverage}/><p style={{color:theme.muted}}>Automated triage coverage</p></Card></Col>
   <Col xs={24} lg={8}><Card title='SOC Operations' style={{background:theme.panel,border:`1px solid ${theme.border}`}}><Tag color='green'>AI ONLINE</Tag><br/><Tag color='blue'>PIPELINE ACTIVE</Tag><br/><Tag color='orange'>INVESTIGATIONS</Tag></Card></Col>
  </Row>

  <Card title='Active Investigations' loading={isLoading} style={{marginTop:20,background:theme.panel,border:`1px solid ${theme.border}`}}>
   <Table<Alert> rowKey='alertId' dataSource={alerts.slice(0,10)} columns={columns} pagination={false}/>
  </Card>
 </div>
};

export default Dashboard;
