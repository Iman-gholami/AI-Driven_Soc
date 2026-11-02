import React, { useEffect, useMemo, useState } from 'react';
import { Table, Card, Typography, Button, Space, Tag, message, Modal, Tooltip, Badge, Collapse, Select, Input } from 'antd';
import { PlusOutlined, RobotOutlined, FilterOutlined, DownloadOutlined, CheckCircleOutlined, CloseCircleOutlined, SyncOutlined, InfoCircleOutlined, AlertOutlined, ClockCircleOutlined, FileTextOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { api, getErrorMessage } from '../../api/client';
import { Alert, AlertListParams } from '../../types';
import AISidebar from '../../components/AI/AISidebar';
import { ExperimentOutlined, SearchOutlined, ReloadOutlined, DatabaseOutlined, ThunderboltOutlined, WarningOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { useDemoMode, getDemoAlertsPage } from '../../demo/demoData';
import './Alerts.css';

const { Title, Text } = Typography;
const { Panel } = Collapse;

const Alerts: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [demoMode, setDemoMode] = useDemoMode();
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

  const { data: liveData, isLoading, isError, refetch } = useQuery({
    queryKey: ['alerts', queryParams],
    queryFn: () => api.getAlertsPage(queryParams),
    placeholderData: (previous) => previous,
    enabled: !demoMode,
  });
  const sampleData = useMemo(() => getDemoAlertsPage(queryParams), [queryParams]);
  const data = demoMode ? sampleData : liveData;

  const alerts = data?.alerts || [];
  const pagination = data?.pagination || { page, limit: pageSize, total: 0, pages: 0 };

  // Open the sidebar as soon as a deep link arrives; the effect below only fetches the alert.
  const [handledDeepLink, setHandledDeepLink] = useState<string | null>(null);
  if (!demoMode && !deepLinkedAlertId?.startsWith('DEMO-') && deepLinkedAlertId !== handledDeepLink) {
    setHandledDeepLink(deepLinkedAlertId);
    if (deepLinkedAlertId) {
      setAiSidebarOpen(true);
      setSidebarLoading(true);
    }
  }

  useEffect(() => {
    const alertId = deepLinkedAlertId;
    if (!alertId || demoMode || alertId.startsWith('DEMO-')) return;
    let active = true;
    api.getAlertById(alertId)
      .then((alert) => { if (active) setSelectedAlert(alert); })
      .catch(() => { if (active) message.error('Alert could not be loaded'); })
      .finally(() => { if (active) setSidebarLoading(false); });
    return () => { active = false; };
  }, [deepLinkedAlertId, demoMode]);

  const resetPage = () => setPage(1);
  const changeDemoMode = () => {
    setDemoMode(!demoMode);
    setAiSidebarOpen(false);
    setSelectedAlert(null);
    setExpandedRowKeys([]);
    resetPage();
  };

  const handleAIAnalysis = async (alert: Alert) => {
    if (demoMode) { message.info('Demo alerts cannot be submitted for AI analysis'); return; }
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
    } catch (error) {
      const detail = getErrorMessage(error, 'Failed to run AI analysis');
      message.error(detail);
      try { setSelectedAlert(await api.getAlertById(alert.alertId)); } catch { /* keep current alert */ }
      await invalidateAlertData();
    } finally {
      setSidebarLoading(false);
    }
  };

  const handleReanalysis = async (alert: Alert) => {
    if (demoMode) return;
    try {
      setSidebarLoading(true);
      await api.regenerateAIAnalysis(alert.alertId);
      setSelectedAlert(await api.getAlertById(alert.alertId));
      message.success('AI analysis re-run completed');
      await invalidateAlertData();
    } catch (error) {
      message.error(getErrorMessage(error, 'Failed to re-run AI analysis'));
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
    if (demoMode) { message.info('Sample data export is disabled'); return; }
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
        ...csvData.map(item => headers.map((header) => escapeCsv(item[header as keyof typeof item])).join(',')),
      ].join('\n');
      const url = URL.createObjectURL(new Blob([csvString], { type: 'text/csv;charset=utf-8' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `alerts-${new Date().toISOString()}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      message.success(`${allAlerts.length} alerts exported`);
    } catch (error) {
      message.error(getErrorMessage(error, 'Failed to export alerts'));
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

  const getAiStatusColor = (status: string) => ({ not_analyzed: 'default', analyzing: 'processing', analyzed: 'success', failed: 'error' }[status] || 'default');
  const getAiStatusIcon = (status: string) => ({ not_analyzed: <InfoCircleOutlined />, analyzing: <SyncOutlined spin />, analyzed: <CheckCircleOutlined />, failed: <CloseCircleOutlined /> }[status] || null);

  const expandedRowRender = (record: Alert) => {
    const ruleMatch = record.ruleMatch;
    return <div className="alerts-expanded p-4 rounded-lg">
      <div className="alerts-expanded-grid grid grid-cols-2 gap-4 mb-4">
        <div><Text strong>Alert ID:</Text><Text code className="ml-2 text-xs">{record.alertId}</Text></div>
        <div><Text strong>Event Hash:</Text><Text code className="ml-2 text-xs">{record.eventHash}</Text></div>
        <div><Text strong>Source:</Text><Tag className="alerts-meta-tag ml-2">{record.source}</Tag></div>
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

  const visibleCritical = alerts.filter(alert => alert.severity === 'critical').length;
  const visibleNeedsAI = alerts.filter(alert => alert.aiStatus === 'not_analyzed' || alert.aiStatus === 'failed').length;
  const visibleEligible = alerts.filter(alert => alert.aiEligibility.eligible).length;
  const hasFilters = !!(filterSeverity || filterStatus || filterAiStatus || filterSource || search);
  const columns = [
    { title: 'Detection / Alert ID', key: 'detection', render: (_: unknown, record: Alert) => <div className="alerts-detection-cell">
        <strong>{record.signature || record.eventType || 'Unclassified detection'}</strong>
        <span>{record.alertId} {record.host ? '· ' + record.host : ''}</span>
      </div> },
    { title: 'Severity', dataIndex: 'severity', key: 'severity', render: (severity: string) =>
      <span className={'alerts-severity-pill severity-' + severity}><span className="alerts-pill-dot"/>{severity.toUpperCase()}</span> },
    { title: 'Source', dataIndex: 'source', key: 'source', render: (source: string) => <Tag className="alerts-meta-tag">{source}</Tag> },
    { title: 'Received', dataIndex: 'createdAt', key: 'createdAt', render: (createdAt: string) =>
      <span className="alerts-date-cell">{new Date(createdAt).toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'})}</span> },
    { title: 'AI status', dataIndex: 'aiStatus', key: 'aiStatus', render: (status: string, record: Alert) =>
      <Tooltip title={demoMode ? 'Demo alert: preview only' : record.aiEligibility.eligible ? 'Eligible for AI analysis' : 'Not eligible: ' + (record.aiEligibility.reason || 'rule match required')}>
        <Tag color={getAiStatusColor(status)} className="alerts-ai-tag">{getAiStatusIcon(status)} {status.replace('_',' ').toUpperCase()}</Tag>
      </Tooltip> },
    { title: 'Action', key: 'aiAction', render: (_: unknown, record: Alert) =>
      <Tooltip title={demoMode ? 'AI actions are disabled for sample data' : record.aiStatus === 'analyzed' ? 'View saved analysis' : record.aiEligibility.eligible ? 'Run AI triage' : record.aiEligibility.reason || 'Matched rule required'}>
        <Button type={record.aiStatus === 'analyzed' ? 'default' : 'primary'} icon={<RobotOutlined />}
          onClick={() => void handleAIAnalysis(record)}
          disabled={demoMode || (record.aiStatus !== 'analyzed' && !record.aiEligibility.eligible)}
          className="alerts-ai-action" size="middle">
          {record.aiStatus === 'analyzed' ? 'View analysis' : 'Analyze'}
        </Button>
      </Tooltip> },
  ];

  return <main className="alerts-page alerts-redesign">
    <header className="alerts-page-heading">
      <div>
        <div className="alerts-eyebrow"><span className="alerts-live-dot"/> SECURITY OPERATIONS / DETECTION QUEUE</div>
        <Title level={2}>Alerts <span className="alerts-heading-accent">&amp; Investigations</span></Title>
        <Text type="secondary">Prioritize findings, filter detections, and review AI analysis from Splunk / SIEM.</Text>
      </div>
      <Space wrap className="alerts-actions">
        <button type="button" aria-pressed={demoMode} className={'soc-demo-switch' + (demoMode ? ' is-on' : '')}
          onClick={changeDemoMode} title="Enable browser-only sample data">
          <ExperimentOutlined /> Demo data <strong>{demoMode ? 'ON' : 'OFF'}</strong>
        </button>
        <Button icon={<ReloadOutlined />} onClick={() => void refetch()} disabled={demoMode}>Refresh</Button>
        <Button icon={<DownloadOutlined />} loading={exporting} onClick={exportToCSV} disabled={demoMode}>Export CSV</Button>
        <Button icon={<PlusOutlined />} onClick={() => setIsModalVisible(true)}>Ingestion info</Button>
      </Space>
    </header>

    {demoMode && <div className="soc-demo-banner" role="status">
      <ExperimentOutlined />
      <div><strong>DEMO MODE — SYNTHETIC ALERTS</strong><span>Preview data only. AI actions, exports, and API requests are disabled. Nothing is written to MongoDB.</span></div>
      <button type="button" onClick={changeDemoMode}>Return to live data</button>
    </div>}

    {!demoMode && isError && <div className="alerts-query-error" role="alert">
      <WarningOutlined /> Alert data could not be refreshed.
      <Button size="small" onClick={() => void refetch()}>Retry</Button>
    </div>}

    <section className="alerts-summary-grid" aria-label="Queue summary">
      <article className="alerts-summary-card">
        <span className="alerts-summary-icon alerts-summary-purple"><DatabaseOutlined /></span>
        <div><span>MATCHING ALERTS</span><strong>{pagination.total.toLocaleString()}</strong><small>{hasFilters ? 'Current search & filters' : 'Current queue'}</small></div>
      </article>
      <article className="alerts-summary-card">
        <span className="alerts-summary-icon alerts-summary-red"><WarningOutlined /></span>
        <div><span>CRITICAL</span><strong>{visibleCritical.toLocaleString()}</strong><small>On current page</small></div>
      </article>
      <article className="alerts-summary-card">
        <span className="alerts-summary-icon alerts-summary-yellow"><ThunderboltOutlined /></span>
        <div><span>NEEDS AI REVIEW</span><strong>{visibleNeedsAI.toLocaleString()}</strong><small>On current page</small></div>
      </article>
      <article className="alerts-summary-card">
        <span className="alerts-summary-icon alerts-summary-green"><SafetyCertificateOutlined /></span>
        <div><span>RULE-MATCH ELIGIBLE</span><strong>{visibleEligible.toLocaleString()}</strong><small>On current page</small></div>
      </article>
    </section>

    <section className="alerts-queue-section" aria-label="Investigation queue">
      <div className="alerts-workspace-title">
        <div><span className="alerts-mini-eyebrow">INVESTIGATION WORKSPACE</span><h2>Detection queue</h2><p>Quick filters apply server-side for live alerts, or locally in Demo mode.</p></div>
        <span className="alerts-workspace-count">{pagination.total.toLocaleString()} results</span>
      </div>

      <Card className="alerts-filter-card">
        <div className="alerts-filter-topline"><span><FilterOutlined /> FILTER DETECTIONS</span>
          <Button size="small" type="text" disabled={!hasFilters} onClick={clearFilters}>Clear all filters</Button>
        </div>
        <Space wrap className="alerts-filter-controls">
          <Input.Search prefix={<SearchOutlined />} placeholder="Search alert, signature, host, source" allowClear
            value={search} onChange={event => { setSearch(event.target.value); resetPage(); }} style={{width:300}} />
          <Select allowClear placeholder="Severity" value={filterSeverity || undefined} style={{width:135}}
            onChange={value => {setFilterSeverity(value || '');resetPage();}}
            options={['critical','high','medium','low','info','unknown'].map(value=>({value,label:value.toUpperCase()}))}/>
          <Select allowClear placeholder="Status" value={filterStatus || undefined} style={{width:120}}
            onChange={value=>{setFilterStatus(value || '');resetPage();}}
            options={['new','analyzed'].map(value=>({value,label:value.toUpperCase()}))}/>
          <Select allowClear placeholder="AI status" value={filterAiStatus || undefined} style={{width:150}}
            onChange={value=>{setFilterAiStatus(value || '');resetPage();}}
            options={['not_analyzed','analyzing','analyzed','failed'].map(value=>({value,label:value.replace('_',' ').toUpperCase()}))}/>
          <Input placeholder="Detection source" allowClear value={filterSource} onChange={event=>{setFilterSource(event.target.value);resetPage();}} style={{width:158}}/>
        </Space>
        <div className="alerts-quick-filters">
          <span>QUICK FILTERS</span>
          <button type="button" className={!hasFilters ? 'is-active' : ''} onClick={clearFilters}>All alerts</button>
          <button type="button" className={filterSeverity === 'critical' ? 'is-active' : ''} onClick={()=>{clearFilters();setFilterSeverity('critical');}}>Critical only</button>
          <button type="button" className={filterAiStatus === 'not_analyzed' ? 'is-active' : ''} onClick={()=>{clearFilters();setFilterAiStatus('not_analyzed');}}>Not analyzed</button>
          <button type="button" className={filterAiStatus === 'failed' ? 'is-active' : ''} onClick={()=>{clearFilters();setFilterAiStatus('failed');}}>AI failed</button>
        </div>
      </Card>

      <Card className="alerts-table-card">
        <div className="alerts-table-header"><div><strong>Stored detections</strong><span>Newest first · Expand a row for rule match and AI eligibility</span></div>
          <span>{demoMode ? 'SAMPLE DATA' : 'LIVE DATA'}</span></div>
        <Table scroll={{x:1000}} columns={columns} dataSource={alerts} loading={!demoMode && isLoading} rowKey="alertId"
          locale={{emptyText:<div className="alerts-empty-state"><AlertOutlined /><strong>No alerts match these filters</strong><span>{demoMode ? 'Try clearing filters or turning off demo data.' : 'Try clearing filters or check the incoming SIEM telemetry.'}</span><Button size="small" onClick={clearFilters}>Clear filters</Button></div>}}
          expandable={{expandedRowRender,expandedRowKeys:demoMode && deepLinkedAlertId && alerts.some(a=>a.alertId===deepLinkedAlertId) ? [...new Set([...expandedRowKeys,deepLinkedAlertId])] : expandedRowKeys,
            onExpandedRowsChange:keys=>setExpandedRowKeys(keys as string[]),
            expandIcon:({expanded,onExpand,record})=><Button type="text" aria-label={expanded?'Collapse details':'Expand details'} icon={expanded?<CloseCircleOutlined />:<FileTextOutlined />} onClick={e=>onExpand(record,e)}/>}}
          pagination={{current:pagination.page,pageSize:pagination.limit,total:pagination.total,showSizeChanger:true,showQuickJumper:!demoMode,showTotal:(total,range)=>total ? range[0]+'–'+range[1]+' of '+total+' alerts':'0 alerts',pageSizeOptions:['10','20','50','100'],
            onChange:(nextPage,nextPageSize)=>{setPage(nextPageSize!==pageSize?1:nextPage);setPageSize(nextPageSize);}}}/>
      </Card>
    </section>
    <Modal title="Alert ingestion" open={isModalVisible} onCancel={()=>setIsModalVisible(false)}
      footer={[<Button key="close" type="primary" onClick={()=>setIsModalVisible(false)}>Close</Button>]} width={600}>
      <Text>Alerts are ingested from Splunk through <Text code>/webhook-alert</Text>. This panel intentionally does not create or delete alerts.</Text>
    </Modal>
    {!demoMode && <AISidebar open={aiSidebarOpen} onClose={()=>{setAiSidebarOpen(false);setSelectedAlert(null);}}
      alert={selectedAlert} loading={sidebarLoading} onReanalyze={handleReanalysis}/>}
  </main>;
};

function escapeCsv(value: unknown) {
  const text = String(value ?? '');
  return `"${text.replace(/"/g, '""')}"`;
}

export default Alerts;
