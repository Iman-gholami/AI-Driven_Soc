import React, { useState } from 'react';
import { Table, Card, Typography, Button, Space, Tag, message, Modal, Tooltip, Badge, Collapse } from 'antd';
import { PlusOutlined, RobotOutlined, FilterOutlined, DownloadOutlined, CheckCircleOutlined, CloseCircleOutlined, SyncOutlined, InfoCircleOutlined, AlertOutlined, ClockCircleOutlined, FileTextOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../../api/client';
import { Alert } from '../../types';
import AISidebar from '../../components/AI/AISidebar';

const { Title, Text } = Typography;
const { Panel } = Collapse;

const Alerts: React.FC = () => {
  const [isModalVisible, setIsModalVisible] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState<string | null>(null);
  const [filterStatus, setFilterStatus] = useState<string | null>(null);
  const [filterAiStatus, setFilterAiStatus] = useState<string | null>(null);
  const [filterSource, setFilterSource] = useState<string | null>(null);
  const [aiSidebarOpen, setAiSidebarOpen] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [expandedRowKeys, setExpandedRowKeys] = useState<string[]>([]);
  const [sidebarLoading, setSidebarLoading] = useState(false);
  const queryClient = useQueryClient();

  const { data: alerts, isLoading } = useQuery({
    queryKey: ['alerts'],
    queryFn: api.getAlerts,
    select: data => data.filter(alert =>
      (!filterSeverity || alert.severity === filterSeverity) &&
      (!filterStatus || alert.status === filterStatus) &&
      (!filterAiStatus || alert.aiStatus === filterAiStatus) &&
      (!filterSource || alert.source === filterSource)
    ),
  });

  const handleAIAnalysis = async (alert: Alert) => {
    setSelectedAlert(alert);
    setAiSidebarOpen(true);
    if (alert.aiStatus === 'analyzed') return;

    try {
      setSidebarLoading(true);
      await api.generateAIAnalysis(alert.alertId);
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      setSelectedAlert(await api.getAlertById(alert.alertId));
      message.success('AI analysis completed');
    } catch (error: any) {
      const detail = error?.response?.data?.detail || error?.message || 'Failed to start AI analysis';
      message.error(detail);
      try { setSelectedAlert(await api.getAlertById(alert.alertId)); } catch { /* keep current alert */ }
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
    } finally {
      setSidebarLoading(false);
    }
  };

  const exportToCSV = () => {
    if (!alerts?.length) return;
    const csvData = alerts.map(alert => ({
      'Alert ID': alert.alertId, Source: alert.source, Signature: alert.signature || '',
      'Event Type': alert.eventType || '', Host: alert.host || '', Status: alert.status,
      'AI Status': alert.aiStatus, 'AI Eligible': alert.aiEligibility.eligible,
      'AI Reason': alert.aiEligibility.reason || '', Severity: alert.severity,
      Created: new Date(alert.createdAt).toLocaleString(), Updated: new Date(alert.updatedAt).toLocaleString(),
      'Event Hash': alert.eventHash, 'Rule Match Status': alert.ruleMatch?.status || '',
      'Rule Match Type': alert.ruleMatch?.matchType || '', Candidates: alert.ruleMatch?.candidateCount || 0,
    }));
    const csvString = [Object.keys(csvData[0]).join(','), ...csvData.map(item => Object.values(item).map(v => `"${v}"`).join(','))].join('\n');
    const url = URL.createObjectURL(new Blob([csvString], { type: 'text/csv' }));
    const a = document.createElement('a'); a.href = url; a.download = `alerts-${new Date().toISOString()}.csv`; a.click(); URL.revokeObjectURL(url);
    message.success('Alerts exported successfully');
  };

  const getSeverityIcon = (severity: string) => ({ critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', unknown: '⚪' }[severity] || '⚪');
  const getSeverityBadge = (severity: string) => ({ critical: 'error', high: 'warning', medium: 'warning', low: 'success', unknown: 'default' }[severity] || 'default');
  const getStatusIcon = (status: string) => ({ new: <AlertOutlined className="text-blue-500" />, investigating: <SyncOutlined className="text-orange-500" />, resolved: <CheckCircleOutlined className="text-green-500" />, closed: <CloseCircleOutlined className="text-gray-500" />, analyzed: <CheckCircleOutlined className="text-green-500" /> }[status] || null);
  const getStatusColor = (status: string) => ({ new: 'blue', investigating: 'orange', resolved: 'green', closed: 'default', analyzed: 'green' }[status] || 'default');
  const getAiStatusColor = (status: string) => ({ not_analyzed: 'default', analyzing: 'processing', analyzed: 'success', failed: 'error' }[status] || 'default');
  const getAiStatusIcon = (status: string) => ({ not_analyzed: <InfoCircleOutlined />, analyzing: <SyncOutlined spin />, analyzed: <CheckCircleOutlined />, failed: <CloseCircleOutlined /> }[status] || null);

  const expandedRowRender = (record: Alert) => {
    const ruleMatch = record.ruleMatch;
    return <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div><Text strong>Alert ID:</Text><Text code className="ml-2 text-xs">{record.alertId}</Text></div>
        <div><Text strong>Event Hash:</Text><Text code className="ml-2 text-xs">{record.eventHash}</Text></div>
        <div><Text strong>Source:</Text><Tag color="blue" className="ml-2">{record.source}</Tag></div>
        <div><Text strong>Host:</Text><Text className="ml-2">{record.host || 'N/A'}</Text></div>
        <div className="col-span-2"><Text strong>Signature:</Text><Text className="ml-2">{record.signature || 'No signature'}</Text></div>
      </div>
      <Collapse className="mb-4" ghost>
        <Panel header={<Text strong>AI Eligibility Details</Text>} key="1"><div className="space-y-2"><div><Text strong>Eligible:</Text><Tag color={record.aiEligibility.eligible ? 'success' : 'error'} className="ml-2">{record.aiEligibility.eligible ? 'Yes' : 'No'}</Tag></div><div><Text strong>Scenario:</Text><Text className="ml-2">{record.aiEligibility.scenario || 'N/A'}</Text></div><div><Text strong>Reason:</Text><Text type="secondary" className="ml-2">{record.aiEligibility.reason || 'N/A'}</Text></div></div></Panel>
      </Collapse>
      <Collapse className="mb-4" ghost>
        <Panel header={<Text strong>Rule Match Details</Text>} key="2"><div className="space-y-2"><div><Text strong>Status:</Text><Tag color={ruleMatch?.status === 'matched' ? 'success' : 'warning'} className="ml-2">{ruleMatch?.status?.toUpperCase() || 'UNRESOLVED'}</Tag></div><div><Text strong>Match Type:</Text><Text className="ml-2">{ruleMatch?.matchType || 'N/A'}</Text></div><div><Text strong>Candidate Count:</Text><Badge count={ruleMatch?.candidateCount || 0} className="ml-2" /></div>{ruleMatch?.reason && <div><Text strong>Reason:</Text><Text type="secondary" className="ml-2">{ruleMatch.reason}</Text></div>}</div></Panel>
      </Collapse>
      <div className="grid grid-cols-2 gap-4 mt-2 text-sm text-gray-500"><div><ClockCircleOutlined className="mr-1" />Created: {new Date(record.createdAt).toLocaleString()}</div><div><ClockCircleOutlined className="mr-1" />Updated: {new Date(record.updatedAt).toLocaleString()}</div></div>
    </div>;
  };

  const columns = [
    { title: 'Alert ID', dataIndex: 'alertId', key: 'alertId', render: (text: string) => <Text code className="text-xs">{text.substring(0, 12)}…</Text>, sorter: (a: Alert, b: Alert) => a.alertId.localeCompare(b.alertId) },
    { title: 'Signature / Event', dataIndex: 'signature', key: 'signature', render: (signature: string | null, record: Alert) => <div><div className="font-medium">{signature || 'No Signature'}</div>{record.eventType && <Tag color="purple" className="text-xs mt-1">{record.eventType}</Tag>}{record.host && <Tag color="cyan" className="text-xs mt-1">{record.host}</Tag>}</div> },
    { title: 'Source', dataIndex: 'source', key: 'source', render: (source: string) => <Tag color="blue">{source}</Tag> },
    { title: 'Severity', dataIndex: 'severity', key: 'severity', render: (severity: string) => <Badge status={getSeverityBadge(severity) as any} text={`${getSeverityIcon(severity)} ${severity.toUpperCase()}`} /> },
    { title: 'Status', dataIndex: 'status', key: 'status', render: (status: string) => <Tag color={getStatusColor(status)} className="px-3 py-1">{getStatusIcon(status)} {status.toUpperCase()}</Tag> },
    { title: 'AI Status', dataIndex: 'aiStatus', key: 'aiStatus', render: (status: string, record: Alert) => <Tooltip title={record.aiEligibility.eligible ? 'Eligible for AI analysis' : `AI unavailable in V1: ${record.aiEligibility.reason || 'rule match required'}`}><Tag color={getAiStatusColor(status)}>{getAiStatusIcon(status)} {status.replace('_', ' ').toUpperCase()}</Tag>{!record.aiEligibility.eligible && <InfoCircleOutlined className="text-gray-400 ml-1" />}</Tooltip> },
    { title: 'AI Action', key: 'aiAction', render: (_: unknown, record: Alert) => <Tooltip title={record.aiEligibility.eligible ? 'Run deterministic rule resolution and AI triage' : `AI unavailable in V1: ${record.aiEligibility.reason || 'rule match required'}`}><Button type="primary" icon={<RobotOutlined />} onClick={() => handleAIAnalysis(record)} size="middle">AI Analyze</Button></Tooltip> },
  ];

  return <div>
    <div className="flex justify-between items-center mb-6 flex-wrap gap-4"><div><Title level={2} className="mb-1">Security Alerts</Title><Text type="secondary">Monitor and analyze security alerts from SIEM/Splunk</Text></div><Space><Button icon={<FilterOutlined />} onClick={() => { setFilterSeverity(null); setFilterStatus(null); setFilterAiStatus(null); setFilterSource(null); }}>Clear Filters</Button><Button icon={<DownloadOutlined />} onClick={exportToCSV}>Export CSV</Button><Button type="primary" icon={<PlusOutlined />} onClick={() => setIsModalVisible(true)}>Ingestion Info</Button></Space></div>
    <Card><Table columns={columns} dataSource={alerts} loading={isLoading} rowKey="alertId" expandable={{ expandedRowRender, expandedRowKeys, onExpandedRowsChange: keys => setExpandedRowKeys(keys as string[]), expandIcon: ({ expanded, onExpand, record }) => <Button type="text" icon={expanded ? <CloseCircleOutlined /> : <FileTextOutlined />} onClick={e => onExpand(record, e)} /> }} pagination={{ pageSize: 10, showSizeChanger: true, showQuickJumper: true, showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} alerts`, pageSizeOptions: ['10', '20', '50'] }} /></Card>
    <Modal title="Alert ingestion" open={isModalVisible} onCancel={() => setIsModalVisible(false)} footer={[<Button key="close" type="primary" onClick={() => setIsModalVisible(false)}>Close</Button>]} width={600}><Text>Alerts are ingested from Splunk through <Text code>/webhook-alert</Text>. This panel intentionally does not create or delete alerts.</Text></Modal>
    <AISidebar open={aiSidebarOpen} onClose={() => { setAiSidebarOpen(false); setSelectedAlert(null); }} alert={selectedAlert} loading={sidebarLoading} />
  </div>;
};

export default Alerts;
