import React, { useEffect, useMemo, useState } from 'react';
import { Table, Card, Typography, Button, Space, Tag, message, Modal, Tooltip, Badge, Collapse, Select, Input } from 'antd';
import { PlusOutlined, RobotOutlined, FilterOutlined, DownloadOutlined, CheckCircleOutlined, CloseCircleOutlined, SyncOutlined, InfoCircleOutlined, AlertOutlined, ClockCircleOutlined, FileTextOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { api } from '../../api/client';
import { Alert, AlertListParams } from '../../types';
import AISidebar from '../../components/AI/AISidebar';
import './Alerts.css';

const { Title, Text } = Typography;
const { Panel } = Collapse;

const Alerts: React.FC = () => {
  const [searchParams] = useSearchParams();
  const deepLinkedAlertId = searchParams.get('alert');
  const [isModalVisible, setIsModalVisible] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [filterSeverity, setFilterSeverity] = useState<Alert['severity'] | ''>('');
  const [filterStatus, setFilterStatus] = useState<Alert['status'] | ''>('');
  const [filterAiStatus, setFilterAiStatus] = useState<Alert['aiStatus'] | ''>('');
  const [filterSource, setFilterSource] = useState('');
  const [search, setSearch] = useState('');
  const [aiSidebarOpen, setAiSidebarOpen] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [expandedRowKeys, setExpandedRowKeys] = useState<string[]>([]);
  const [sidebarLoading, setSidebarLoading] = useState(false);
  const [exporting, setExporting] = useState(false);
  const queryClient = useQueryClient();

  const queryParams: AlertListParams = useMemo(() => ({
    page,
    limit: pageSize,
    severity: filterSeverity,
    status: filterStatus,
    aiStatus: filterAiStatus,
    source: filterSource,
    search,
    sortBy: 'createdAt',
    sortDirection: 'desc',
  }), [page,pageSize,filterSeverity,filterStatus,filterAiStatus,filterSource,search]);

  const { data, isLoading } = useQuery({
    queryKey: ['alerts', queryParams],
    queryFn: () => api.getAlertsPage(queryParams),
    placeholderData: (previous) => previous,
  });

  const alerts = data?.alerts || [];
  const pagination = data?.pagination || { page, limit: pageSize, total: 0, pages: 0 };

  useEffect(() => {
    const alertId = deepLinkedAlertId;
    if (!alertId) return;
    let active = true;
    setAiSidebarOpen(true);
    setSidebarLoading(true);
    api.getAlertById(alertId)
      .then((alert) => { if (active) setSelectedAlert(alert); })
      .catch(() => { if (active) message.error('Alert could not be loaded'); })
      .finally(() => { if (active) setSidebarLoading(false); });
    return () => { active = false; };
  }, [deepLinkedAlertId]);

  const resetPage = () => setPage(1);

  const handleAIAnalysis = async (alert: Alert) => {
    setAiSidebarOpen(true);
    setSelectedAlert(alert);

    try {
      setSidebarLoading(true);
      if (alert.aiStatus !== 'analyzed') {
        await api.generateAIAnalysis(alert.alertId);
        message.success('AI analysis completed');
      }
      setSelectedAlert(await api.getAlertById(alert.alertId));
      await invalidateAlertData();
    } catch (error: any) {
      const detail = error?.response?.data?.detail || error?.message || 'Failed to run AI analysis';
      message.error(detail);
      try { setSelectedAlert(await api.getAlertById(alert.alertId)); } catch { /* keep current alert */ }
      await invalidateAlertData();
    } finally {
      setSidebarLoading(false);
    }
  };

  const handleReanalysis = async (alert: Alert) => {
    try {
      setSidebarLoading(true);
      await api.regenerateAIAnalysis(alert.alertId);
      setSelectedAlert(await api.getAlertById(alert.alertId));
      message.success('AI analysis re-run completed');
      await invalidateAlertData();
    } catch (error: any) {
      message.error(error?.response?.data?.detail || error?.message || 'Failed to re-run AI analysis');
    } finally {
      setSidebarLoading(false);
    }
  };

  const invalidateAlertData = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['alerts'] }),
      queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] }),
    ]);
  };

  const exportToCSV = async () => {
    try {
      setExporting(true);
      const baseParams = { ...queryParams, page: 1, limit: 100 };
      const first = await api.getAlertsPage(baseParams);
      const allAlerts = [...first.alerts];
      for (let currentPage = 2; currentPage <= first.pagination.pages; currentPage += 1) {
        const next = await api.getAlertsPage({ ...baseParams, page: currentPage });
        allAlerts.push(...next.alerts);
      }
      if (!allAlerts.length) {
        message.info('No alerts to export');
        return;
      }

      const csvData = allAlerts.map(alert => ({
        'Alert ID': alert.alertId,
        Source: alert.source,
        Signature: alert.signature || '',
        'Event Type': alert.eventType || '',
        Host: alert.host || '',
        Status: alert.status,
        'AI Status': alert.aiStatus,
        'AI Eligible': alert.aiEligibility.eligible,
        'AI Reason': alert.aiEligibility.reason || '',
        Severity: alert.severity,
        Created: new Date(alert.createdAt).toISOString(),
        Updated: new Date(alert.updatedAt).toISOString(),
        'Event Hash': alert.eventHash,
        'Rule ID': alert.ruleMatch?.ruleId || '',
        'Rule Match Status': alert.ruleMatch?.status || '',
        'Rule Match Type': alert.ruleMatch?.matchType || '',
        Candidates: alert.ruleMatch?.candidateCount || 0,
      }));
      const headers = Object.keys(csvData[0]);
      const csvString = [
        headers.map(escapeCsv).join(','),
        ...csvData.map(item => headers.map((header) => escapeCsv((item as any)[header])).join(',')),
      ].join('\n');
      const url = URL.createObjectURL(new Blob([csvString], { type: 'text/csv;charset=utf-8' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `alerts-${new Date().toISOString()}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      message.success(`${allAlerts.length} alerts exported`);
    } catch (error: any) {
      message.error(error?.message || 'Failed to export alerts');
    } finally {
      setExporting(false);
    }
  };

  const clearFilters = () => {
    setFilterSeverity('');
    setFilterStatus('');
    setFilterAiStatus('');
    setFilterSource('');
    setSearch('');
    setPage(1);
  };

  const getSeverityBadge = (severity: string) => ({ critical: 'error', high: 'warning', medium: 'warning', low: 'success', info: 'processing', unknown: 'default' }[severity] || 'default');
  const getStatusIcon = (status: string) => ({ new: <AlertOutlined className="text-blue-500" />, analyzed: <CheckCircleOutlined className="text-green-500" /> }[status] || null);
  const getStatusColor = (status: string) => ({ new: 'blue', analyzed: 'green' }[status] || 'default');
  const getAiStatusColor = (status: string) => ({ not_analyzed: 'default', analyzing: 'processing', analyzed: 'success', failed: 'error' }[status] || 'default');
  const getAiStatusIcon = (status: string) => ({ not_analyzed: <InfoCircleOutlined />, analyzing: <SyncOutlined spin />, analyzed: <CheckCircleOutlined />, failed: <CloseCircleOutlined /> }[status] || null);

  const expandedRowRender = (record: Alert) => {
    const ruleMatch = record.ruleMatch;
    return <div className="alerts-expanded p-4 rounded-lg">
      <div className="alerts-expanded-grid grid grid-cols-2 gap-4 mb-4">
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
        <Panel header={<Text strong>Rule Match Details</Text>} key="2"><div className="space-y-2"><div><Text strong>Status:</Text><Tag color={ruleMatch?.status === 'matched' ? 'success' : 'warning'} className="ml-2">{ruleMatch?.status?.toUpperCase() || 'UNRESOLVED'}</Tag></div><div><Text strong>Rule ID:</Text><Text className="ml-2">{ruleMatch?.ruleId || 'N/A'}</Text></div><div><Text strong>Match Type:</Text><Text className="ml-2">{ruleMatch?.matchType || 'N/A'}</Text></div><div><Text strong>Candidate Count:</Text><Badge count={ruleMatch?.candidateCount || 0} className="ml-2" /></div>{ruleMatch?.reason && <div><Text strong>Reason:</Text><Text type="secondary" className="ml-2">{ruleMatch.reason}</Text></div>}</div></Panel>
      </Collapse>
      <div className="grid grid-cols-2 gap-4 mt-2 text-sm text-gray-500"><div><ClockCircleOutlined className="mr-1" />Created: {new Date(record.createdAt).toLocaleString()}</div><div><ClockCircleOutlined className="mr-1" />Updated: {new Date(record.updatedAt).toLocaleString()}</div></div>
    </div>;
  };

  const columns = [
    { title: 'Alert ID', dataIndex: 'alertId', key: 'alertId', render: (text: string) => <Text code className="text-xs">{text.length > 14 ? `${text.substring(0, 14)}…` : text}</Text> },
    { title: 'Signature / Event', dataIndex: 'signature', key: 'signature', render: (signature: string | null, record: Alert) => <div><div className="font-medium">{signature || 'No Signature'}</div>{record.eventType && <Tag color="purple" className="text-xs mt-1">{record.eventType}</Tag>}{record.host && <Tag color="cyan" className="text-xs mt-1">{record.host}</Tag>}</div> },
    { title: 'Source', dataIndex: 'source', key: 'source', render: (source: string) => <Tag color="blue">{source}</Tag> },
    { title: 'Severity', dataIndex: 'severity', key: 'severity', render: (severity: string) => <Badge status={getSeverityBadge(severity) as any} text={severity.toUpperCase()} /> },
    { title: 'Status', dataIndex: 'status', key: 'status', render: (status: string) => <Tag color={getStatusColor(status)} className="px-3 py-1">{getStatusIcon(status)} {status.toUpperCase()}</Tag> },
    { title: 'AI Status', dataIndex: 'aiStatus', key: 'aiStatus', render: (status: string, record: Alert) => <Tooltip title={record.aiEligibility.eligible ? 'Eligible for AI analysis' : `AI unavailable in V1: ${record.aiEligibility.reason || 'rule match required'}`}><Tag color={getAiStatusColor(status)}>{getAiStatusIcon(status)} {status.replace('_', ' ').toUpperCase()}</Tag>{!record.aiEligibility.eligible && <InfoCircleOutlined className="text-gray-400 ml-1" />}</Tooltip> },
    { title: 'AI Action', key: 'aiAction', render: (_: unknown, record: Alert) => <Tooltip title={record.aiStatus === 'analyzed' ? 'View persisted AI analysis' : record.aiEligibility.eligible ? 'Run deterministic rule resolution and AI triage' : `AI unavailable in V1: ${record.aiEligibility.reason || 'rule match required'}`}><Button type="primary" icon={<RobotOutlined />} onClick={() => handleAIAnalysis(record)} disabled={record.aiStatus !== 'analyzed' && !record.aiEligibility.eligible} size="middle">{record.aiStatus === 'analyzed' ? 'View AI Analysis' : 'AI Analyze'}</Button></Tooltip> },
  ];

  return <main className="alerts-page">
    <header className="alerts-page-heading">
      <div>
        <div className="alerts-eyebrow"><AlertOutlined /> DETECTION QUEUE / STORED TELEMETRY</div>
        <Title level={2}>Security Alerts</Title>
        <Text type="secondary">Server-side investigation queue backed by persisted SIEM/Splunk alerts.</Text>
      </div>
      <Space wrap className="alerts-actions">
        <Button icon={<FilterOutlined />} onClick={clearFilters}>Clear filters</Button>
        <Button icon={<DownloadOutlined />} loading={exporting} onClick={exportToCSV}>Export CSV</Button>
        <Button icon={<PlusOutlined />} onClick={() => setIsModalVisible(true)}>Ingestion info</Button>
      </Space>
    </header>

    <Card className="alerts-filter-card">
      <Space wrap>
        <Input.Search placeholder="Search alert, signature, host, source" allowClear value={search} onChange={(event)=>{setSearch(event.target.value);resetPage();}} style={{width:320}} />
        <Select allowClear placeholder="Severity" value={filterSeverity || undefined} style={{width:140}} onChange={(value)=>{setFilterSeverity(value || '');resetPage();}} options={['critical','high','medium','low','info','unknown'].map(value=>({value,label:value.toUpperCase()}))}/>
        <Select allowClear placeholder="Status" value={filterStatus || undefined} style={{width:130}} onChange={(value)=>{setFilterStatus(value || '');resetPage();}} options={['new','analyzed'].map(value=>({value,label:value.toUpperCase()}))}/>
        <Select allowClear placeholder="AI status" value={filterAiStatus || undefined} style={{width:160}} onChange={(value)=>{setFilterAiStatus(value || '');resetPage();}} options={['not_analyzed','analyzing','analyzed','failed'].map(value=>({value,label:value.replace('_',' ').toUpperCase()}))}/>
        <Input placeholder="Source" allowClear value={filterSource} onChange={(event)=>{setFilterSource(event.target.value);resetPage();}} style={{width:160}} />
        <div className="alerts-result-count"><strong>{pagination.total.toLocaleString()}</strong><span>matching alerts</span></div>
      </Space>
    </Card>

    <Card className="alerts-table-card"><Table scroll={{ x: 1120 }} columns={columns} dataSource={alerts} loading={isLoading} rowKey="alertId" expandable={{ expandedRowRender, expandedRowKeys, onExpandedRowsChange: keys => setExpandedRowKeys(keys as string[]), expandIcon: ({ expanded, onExpand, record }) => <Button type="text" icon={expanded ? <CloseCircleOutlined /> : <FileTextOutlined />} onClick={e => onExpand(record, e)} /> }} pagination={{ current:pagination.page, pageSize:pagination.limit, total:pagination.total, showSizeChanger:true, showQuickJumper:true, showTotal:(total,range)=>`${range[0]}-${range[1]} of ${total} alerts`, pageSizeOptions:['10','20','50','100'], onChange:(nextPage,nextPageSize)=>{setPage(nextPageSize!==pageSize?1:nextPage);setPageSize(nextPageSize);} }} /></Card>

    <Modal title="Alert ingestion" open={isModalVisible} onCancel={() => setIsModalVisible(false)} footer={[<Button key="close" type="primary" onClick={() => setIsModalVisible(false)}>Close</Button>]} width={600}><Text>Alerts are ingested from Splunk through <Text code>/webhook-alert</Text>. This panel intentionally does not create or delete alerts.</Text></Modal>
    <AISidebar open={aiSidebarOpen} onClose={() => { setAiSidebarOpen(false); setSelectedAlert(null); }} alert={selectedAlert} loading={sidebarLoading} onReanalyze={handleReanalysis} />
  </main>;
};

function escapeCsv(value: unknown) {
  const text = String(value ?? '');
  return `"${text.replace(/"/g, '""')}"`;
}

export default Alerts;
