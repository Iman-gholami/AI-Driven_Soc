import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  Drawer,
  Empty,
  Input,
  List,
  Row,
  Select,
  Space,
  Statistic,
  Table,
  Tabs,
  Tag,
  Typography,
  message as antMessage,
} from 'antd';
import {
  AlertOutlined,
  BarChartOutlined,
  CheckCircleOutlined,
  DatabaseOutlined,
  FileSearchOutlined,
  FireOutlined,
  FolderOpenOutlined,
  ImportOutlined,
  MessageOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
  ThunderboltOutlined,
  TrophyOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Chart as ChartJS,
  BarElement,
  CategoryScale,
  Legend,
  LinearScale,
  Tooltip,
} from 'chart.js';
import { Bar } from 'react-chartjs-2';
import { api } from '../../api/client';
import type { HistoricalReport, ReportCopilotResult, ReportImportResult } from '../../types/reports';
import ReportUploadReview from './ReportUploadReview';
import './Reports.css';

ChartJS.register(BarElement, CategoryScale, LinearScale, Legend, Tooltip);

const { Text, Title, Paragraph } = Typography;
const JALALI_MONTHS = ['فروردین', 'اردیبهشت', 'خرداد', 'تیر', 'مرداد', 'شهریور', 'مهر', 'آبان', 'آذر', 'دی', 'بهمن', 'اسفند'];
const CHART = {
  primary: '#3b82f6',
  cyan: '#06b6d4',
  green: '#22c55e',
  amber: '#f59e0b',
  orange: '#f97316',
  red: '#ef4444',
  purple: '#8b5cf6',
  slate: '#64748b',
  tick: '#94a3b8',
  grid: 'rgba(148, 163, 184, 0.10)',
};

const severityTag: Record<string, string> = {
  critical: 'red',
  high: 'volcano',
  medium: 'gold',
  low: 'blue',
  info: 'cyan',
  none: 'default',
  unknown: 'default',
};

const severityColor: Record<string, string> = {
  critical: CHART.red,
  high: CHART.orange,
  medium: CHART.amber,
  low: CHART.primary,
  info: CHART.cyan,
  unknown: CHART.slate,
  none: CHART.slate,
};

const reportTypeLabel: Record<string, string> = {
  misconfiguration: 'Misconfiguration',
  vulnerability: 'Vulnerability',
  incident: 'Incident',
  malware: 'Malware',
  unknown: 'Unknown',
};

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  result?: ReportCopilotResult;
}

const Reports: React.FC = () => {
  const queryClient = useQueryClient();
  const [year, setYear] = useState<number>(1404);
  const [activeTab, setActiveTab] = useState('overview');
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState<string | undefined>();
  const [urgency, setUrgency] = useState<string | undefined>();
  const [selectedReport, setSelectedReport] = useState<HistoricalReport | null>(null);
  const [copilotInput, setCopilotInput] = useState('');
  const [chat, setChat] = useState<ChatMessage[]>([]);
  const [lastImport, setLastImport] = useState<ReportImportResult | null>(null);

  const yearsQuery = useQuery({ queryKey: ['report-years'], queryFn: api.getReportYears });

  useEffect(() => {
    if (yearsQuery.data?.length && !yearsQuery.data.some((item) => item.year === year)) {
      setYear(yearsQuery.data[0].year);
    }
  }, [yearsQuery.data, year]);

  const statsQuery = useQuery({
    queryKey: ['report-stats', year],
    queryFn: () => api.getReportStats(year),
    enabled: Boolean(year) && Boolean(yearsQuery.data?.some((item) => item.year === year)),
  });

  const reportsQuery = useQuery({
    queryKey: ['historical-reports', year, page, search, severity, urgency],
    queryFn: () => api.getHistoricalReports({ year, page, limit: 20, search, severity, urgency }),
    enabled: Boolean(year) && Boolean(yearsQuery.data?.some((item) => item.year === year)),
  });

  const scanQuery = useQuery({
    queryKey: ['report-import-scan', year],
    queryFn: () => api.scanHistoricalReports(year),
    enabled: false,
  });

  const importMutation = useMutation({
    mutationFn: ({ dryRun }: { dryRun: boolean }) => api.importHistoricalReports(year, dryRun),
    onSuccess: async (result) => {
      setLastImport(result);
      if (!result.dryRun) {
        await Promise.all([
          queryClient.invalidateQueries({ queryKey: ['report-years'] }),
          queryClient.invalidateQueries({ queryKey: ['report-stats'] }),
          queryClient.invalidateQueries({ queryKey: ['historical-reports'] }),
        ]);
        antMessage.success(`Import complete: ${result.imported} new, ${result.updated} updated`);
      }
    },
    onError: (error: any) => antMessage.error(error?.response?.data?.detail || error?.message || 'Import failed'),
  });

  const copilotMutation = useMutation({
    mutationFn: api.queryReportCopilot,
    onSuccess: (result) => {
      setChat((current) => [...current, { role: 'assistant', content: result.answer, result }]);
    },
    onError: (error: any) => {
      setChat((current) => [...current, {
        role: 'assistant',
        content: error?.response?.data?.detail || error?.message || 'Report query failed.',
      }]);
    },
  });

  const stats = statsQuery.data;
  const years = useMemo(() => {
    const fromData = yearsQuery.data?.map((item) => item.year) || [];
    return [...new Set([1404, ...fromData])].sort((a, b) => b - a);
  }, [yearsQuery.data]);

  const dashboard = useMemo(() => {
    if (!stats) return null;

    const activeMonths = stats.byMonth
      .filter((item) => item.month && item.count > 0)
      .sort((a, b) => Number(a.month) - Number(b.month));
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
    const severityRows = severityOrder
      .map((key) => ({
        key,
        count: stats.bySeverity.find((item) => item.severity === key)?.count || 0,
      }))
      .filter((item) => item.count > 0);

    return {
      activeMonths,
      severityRows,
      topFinding: stats.byFinding[0] || null,
      topOrganization: stats.topOrganizations[0] || null,
      dominantType: stats.byReportType[0] || null,
      maxFindingCount: Math.max(1, ...stats.byFinding.map((item) => item.count)),
      maxOrganizationCount: Math.max(1, ...stats.topOrganizations.map((item) => item.count)),
      maxPortCount: Math.max(1, ...stats.topPorts.map((item) => item.count)),
    };
  }, [stats]);

  const askCopilot = (value?: string) => {
    const text = String(value ?? copilotInput).trim();
    if (!text || copilotMutation.isPending) return;
    setChat((current) => [...current, { role: 'user', content: text }]);
    setCopilotInput('');
    copilotMutation.mutate(text);
  };

  const openReportSearch = (value?: string) => {
    if (!value) return;
    setSearch(value);
    setSeverity(undefined);
    setUrgency(undefined);
    setPage(1);
    setActiveTab('reports');
  };

  const refreshReportData = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['report-years'] }),
      queryClient.invalidateQueries({ queryKey: ['report-stats'] }),
      queryClient.invalidateQueries({ queryKey: ['historical-reports'] }),
    ]);
  };

  const overview = (
    <div className="report-tab-stack">
      {!stats && !statsQuery.isLoading ? (
        <Empty description={`No imported report data for ${year}. Use Import & Review to load DOCX files.`} />
      ) : null}

      {stats && dashboard ? (
        <>
          <div className="report-kpi-grid">
            <MetricCard title="Total reports" value={stats.summary.total} note={`${stats.summary.uniqueOrganizations} organizations in the local dataset`} icon={<DatabaseOutlined />} tone="primary" />
            <MetricCard title="High / Critical" value={stats.summary.highCritical} suffix={`${stats.summary.highCriticalPercent}%`} note="Reports with elevated security severity" icon={<FireOutlined />} tone="danger" />
            <MetricCard title="Immediate action" value={stats.summary.immediate} suffix={`${stats.summary.immediatePercent}%`} note="Reports explicitly requiring immediate response" icon={<ThunderboltOutlined />} tone="warning" />
            <MetricCard title="Observed target IPs" value={stats.summary.uniqueIps} note={`${stats.summary.qualityWarnings} reports retain review flags`} icon={<SafetyCertificateOutlined />} tone="cyan" />
          </div>

          <div className="report-section-heading">
            <div><span className="report-section-kicker">PRIORITY SIGNALS</span><Title level={4}>What deserves analyst attention</Title></div>
            <Text type="secondary">Derived deterministically from the imported report dataset.</Text>
          </div>

          <div className="report-insight-grid">
            <InsightCard icon={<TrophyOutlined />} eyebrow="Dominant finding" title={dashboard.topFinding?.name || dashboard.topFinding?.key || 'No finding data'} value={dashboard.topFinding ? `${dashboard.topFinding.count} reports` : '—'} detail={dashboard.topFinding?.category || 'No category available'} tone="primary" onClick={dashboard.topFinding ? () => openReportSearch(dashboard.topFinding?.name || dashboard.topFinding?.key) : undefined} />
            <InsightCard icon={<BarChartOutlined />} eyebrow="Dominant report type" title={dashboard.dominantType ? reportTypeLabel[dashboard.dominantType.reportType] || dashboard.dominantType.reportType : 'No type data'} value={dashboard.dominantType ? `${dashboard.dominantType.count} reports` : '—'} detail={dashboard.dominantType && stats.summary.total ? `${Math.round((dashboard.dominantType.count / stats.summary.total) * 100)}% of imported reports` : 'No distribution available'} tone="purple" />
            <InsightCard icon={<AlertOutlined />} eyebrow="Repeated exposure" title={`${stats.repeated.repeatedGroups} repeated patterns`} value={`${stats.repeated.reportsInRepeatedGroups} reports`} detail="Organization + finding combinations seen more than once" tone="warning" />
            <InsightCard icon={<WarningOutlined />} eyebrow="Data quality" title={stats.summary.qualityWarnings ? `${stats.summary.qualityWarnings} need review` : 'No review flags'} value={stats.summary.qualityWarnings ? 'Review retained' : 'Clean'} detail="Quality flags remain visible instead of being silently normalized" tone={stats.summary.qualityWarnings ? 'danger' : 'success'} />
          </div>

          <Row gutter={[14, 14]}>
            <Col xs={24} xl={14}>
              {dashboard.activeMonths.length <= 1 ? (
                <Card className="report-panel-card report-coverage-card" title="Coverage snapshot">
                  <div className="report-coverage-spotlight">
                    <div className="report-coverage-main">
                      <span className="report-section-kicker">ACTIVE PERIOD</span>
                      <strong>{dashboard.activeMonths[0]?.month ? JALALI_MONTHS[Number(dashboard.activeMonths[0].month) - 1] : 'No dated month'} {year}</strong>
                      <p>{dashboard.activeMonths[0]?.count || stats.summary.total} reports are concentrated in the currently imported period, so a 12-month chart would add visual noise rather than signal.</p>
                    </div>
                    <div className="report-coverage-stats">
                      <MiniStat label="Reports" value={dashboard.activeMonths[0]?.count || stats.summary.total} />
                      <MiniStat label="High / Critical" value={`${stats.summary.highCriticalPercent}%`} />
                      <MiniStat label="Immediate" value={`${stats.summary.immediatePercent}%`} />
                      <MiniStat label="Organizations" value={stats.summary.uniqueOrganizations} />
                    </div>
                  </div>
                </Card>
              ) : (
                <Card className="report-panel-card report-chart-card" title="Reports by active month">
                  <Bar
                    data={{ labels: dashboard.activeMonths.map((item) => item.month ? JALALI_MONTHS[Number(item.month) - 1] : 'Unknown'), datasets: [{ label: 'Reports', data: dashboard.activeMonths.map((item) => item.count), backgroundColor: CHART.primary, borderRadius: 7, maxBarThickness: 46 }] }}
                    options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { grid: { display: false }, ticks: { color: CHART.tick } }, y: { beginAtZero: true, grid: { color: CHART.grid }, ticks: { color: CHART.tick, precision: 0 } } } }}
                  />
                </Card>
              )}
            </Col>
            <Col xs={24} xl={10}>
              <Card className="report-panel-card report-chart-card" title="Severity posture">
                <Bar
                  data={{ labels: dashboard.severityRows.map((item) => item.key), datasets: [{ label: 'Reports', data: dashboard.severityRows.map((item) => item.count), backgroundColor: dashboard.severityRows.map((item) => severityColor[item.key] || CHART.slate), borderRadius: 7, maxBarThickness: 30 }] }}
                  options={{ indexAxis: 'y' as const, responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, grid: { color: CHART.grid }, ticks: { color: CHART.tick, precision: 0 } }, y: { grid: { display: false }, ticks: { color: CHART.tick } } } }}
                />
              </Card>
            </Col>
          </Row>

          <Row gutter={[14, 14]}>
            <Col xs={24} xl={14}>
              <Card className="report-panel-card report-findings-card" title="Top findings">
                <div className="report-chart-tall">
                  <Bar
                    data={{ labels: stats.byFinding.slice(0, 8).map((item) => item.name || item.key), datasets: [{ label: 'Reports', data: stats.byFinding.slice(0, 8).map((item) => item.count), backgroundColor: stats.byFinding.slice(0, 8).map((_, index) => index === 0 ? CHART.primary : 'rgba(59, 130, 246, 0.45)'), borderRadius: 7, maxBarThickness: 26 }] }}
                    options={{ indexAxis: 'y' as const, responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, grid: { color: CHART.grid }, ticks: { color: CHART.tick, precision: 0 } }, y: { grid: { display: false }, ticks: { color: CHART.tick, autoSkip: false } } } }}
                  />
                </div>
                <div className="report-findings-tags">
                  {stats.byFinding.slice(0, 6).map((item) => <button key={item.key} type="button" onClick={() => openReportSearch(item.name || item.key)}><span>{item.category || 'uncategorized'}</span><strong>{item.count}</strong></button>)}
                </div>
              </Card>
            </Col>
            <Col xs={24} xl={10}>
              <Card className="report-panel-card" title="Report type mix">
                <div className="report-type-list">
                  {stats.byReportType.map((item, index) => {
                    const percent = stats.summary.total ? Math.round((item.count / stats.summary.total) * 100) : 0;
                    return (
                      <div className="report-type-row" key={item.reportType}>
                        <div className="report-type-label"><span className={`report-type-dot tone-${index % 4}`} /><strong>{reportTypeLabel[item.reportType] || item.reportType}</strong><span>{item.count}</span></div>
                        <div className="report-progress-track"><span className={`report-progress-fill tone-${index % 4}`} style={{ width: `${percent}%` }} /></div>
                        <small>{percent}% of reports</small>
                      </div>
                    );
                  })}
                </div>
                <Divider />
                <div className="report-mini-summary"><MiniStat label="Action required" value={stats.summary.actionRequired} /><MiniStat label="Informational" value={stats.summary.informational} /><MiniStat label="Review flags" value={stats.summary.qualityWarnings} /></div>
              </Card>
            </Col>
          </Row>

          <Row gutter={[14, 14]}>
            <Col xs={24} xl={14}>
              <Card className="report-panel-card" title="Organizations with most report history">
                <div className="report-rank-list">
                  {stats.topOrganizations.slice(0, 8).map((item, index) => (
                    <button className="report-rank-row" type="button" key={item.organization} onClick={() => openReportSearch(item.organization)}>
                      <span className="report-rank-number">{String(index + 1).padStart(2, '0')}</span>
                      <span className="report-rank-content"><strong>{item.organization}</strong><span className="report-rank-track"><i style={{ width: `${(item.count / dashboard.maxOrganizationCount) * 100}%` }} /></span></span>
                      <span className="report-rank-value">{item.count}<small>reports</small></span>
                    </button>
                  ))}
                </div>
              </Card>
            </Col>
            <Col xs={24} xl={10}>
              <Card className="report-panel-card" title="Observed service ports">
                <div className="report-port-grid">
                  {stats.topPorts.length ? stats.topPorts.slice(0, 10).map((item) => (
                    <div className="report-port-chip" key={item.port}><div><Text code>{item.port}</Text><span>observed port</span></div><strong>{item.count}</strong><span className="report-port-meter"><i style={{ width: `${(item.count / dashboard.maxPortCount) * 100}%` }} /></span></div>
                  )) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No port data extracted" />}
                </div>
              </Card>
            </Col>
          </Row>
        </>
      ) : null}
    </div>
  );

  const reportsTable = (
    <div className="report-tab-stack">
      <Card>
        <div className="report-filter-bar">
          <Input allowClear prefix={<SearchOutlined />} placeholder="Search title, organization, IP, report number, finding, CVE, domain..." value={search} onChange={(event) => { setSearch(event.target.value); setPage(1); }} />
          <Select allowClear placeholder="Severity" value={severity} onChange={(value) => { setSeverity(value); setPage(1); }} options={['critical', 'high', 'medium', 'low', 'unknown'].map((value) => ({ value, label: value }))} />
          <Select allowClear placeholder="Urgency" value={urgency} onChange={(value) => { setUrgency(value); setPage(1); }} options={['immediate', 'action_required', 'informational', 'high', 'normal', 'low', 'unknown'].map((value) => ({ value, label: value }))} />
        </div>
      </Card>

      <Card>
        <Table
          rowKey="_id"
          loading={reportsQuery.isLoading}
          dataSource={reportsQuery.data?.reports || []}
          onRow={(record) => ({ onClick: () => setSelectedReport(record), className: 'report-clickable-row' })}
          pagination={{ current: page, pageSize: 20, total: reportsQuery.data?.pagination.total || 0, showSizeChanger: false, onChange: setPage }}
          scroll={{ x: 1180 }}
          columns={[
            { title: 'Date', dataIndex: 'reportDateRaw', width: 110 },
            { title: 'Report No', dataIndex: 'reportNumber', width: 165, render: (value) => value || '—' },
            { title: 'Type', dataIndex: 'reportType', width: 130 },
            { title: 'Organization', dataIndex: ['target', 'organization'], width: 250, ellipsis: true },
            { title: 'IP', dataIndex: ['target', 'ip'], width: 135, render: (value) => <Text code>{value || '—'}</Text> },
            { title: 'Finding', dataIndex: ['finding', 'name'], width: 210, render: (value, row) => value || row.finding?.type || 'unknown' },
            { title: 'Severity', dataIndex: ['severity', 'level'], width: 100, render: (value, row) => <Tag color={severityTag[value] || 'default'}>{value} {row.severity.score ?? ''}</Tag> },
            { title: 'Urgency', dataIndex: ['urgency', 'normalized'], width: 130, render: (value) => <Tag color={value === 'immediate' ? 'red' : value === 'informational' ? 'blue' : 'default'}>{value}</Tag> },
          ]}
        />
      </Card>
    </div>
  );

  const reportCopilot = (
    <Row gutter={[14, 14]}>
      <Col xs={24} xl={8}>
        <Card title={<><MessageOutlined /> Report Copilot</>}>
          <Paragraph type="secondary">Statistical questions are answered directly from MongoDB. No RAG and no LLM arithmetic are used in this version.</Paragraph>
          <Text strong>Examples</Text>
          <div className="report-question-chips">
            {[`در سال ${year} چند گزارش حادثه داشتیم؟`, `بیشترین Finding سال ${year} چه بوده؟`, `کدام سازمان بیشترین گزارش UDP Amplification داشته؟`, `چند درصد گزارش‌های ${year} نیازمند اقدام فوری بوده‌اند؟`, `روند ماهانه گزارش‌های ${year} را نشان بده`, 'روی پورت 443 چند گزارش ثبت شده؟', 'برای IP 62.60.167.73 چه گزارش‌هایی داریم؟'].map((question) => <button key={question} type="button" onClick={() => askCopilot(question)}>{question}</button>)}
          </div>
        </Card>
      </Col>
      <Col xs={24} xl={16}>
        <Card className="report-chat-card">
          <div className="report-chat-log">
            {!chat.length ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="Ask a question about imported reports" /> : chat.map((item, index) => <div key={`${item.role}-${index}`} className={`report-chat-message is-${item.role}`}><span>{item.role === 'user' ? 'YOU' : 'REPORT DATA'}</span><pre>{item.content}</pre></div>)}
            {copilotMutation.isPending ? <div className="report-chat-thinking">Querying historical report dataset…</div> : null}
          </div>
          <Divider />
          <Space.Compact block>
            <Input.TextArea autoSize={{ minRows: 2, maxRows: 4 }} value={copilotInput} placeholder="مثلاً: در سال ۱۴۰۴ چند گزارش UDP Amplification داشتیم؟" onChange={(event) => setCopilotInput(event.target.value)} onPressEnter={(event) => { if (!event.shiftKey) { event.preventDefault(); askCopilot(); } }} />
            <Button type="primary" loading={copilotMutation.isPending} onClick={() => askCopilot()}>Ask</Button>
          </Space.Compact>
        </Card>
      </Col>
    </Row>
  );

  const importPanel = (
    <div className="report-tab-stack">
      <ReportUploadReview year={year} onCommitted={refreshReportData} />

      <Divider orientation="start">Advanced: server folder workflow</Divider>
      <Row gutter={[14, 14]}>
        <Col xs={24} xl={10}>
          <Card title={<><FolderOpenOutlined /> Existing local DOCX folder</>}>
            <Paragraph>
              For bulk/admin workflows, files already present under <Text code>REPORTS_ROOT/{year}/</Text> can still be scanned and dry-run locally. The upload workflow above is the recommended path when an analyst wants to inspect every extraction before saving.
            </Paragraph>
            <Space wrap>
              <Button icon={<SearchOutlined />} loading={scanQuery.isFetching} onClick={() => scanQuery.refetch()}>Scan {year}</Button>
              <Button icon={<CheckCircleOutlined />} loading={importMutation.isPending} onClick={() => importMutation.mutate({ dryRun: true })}>Dry Run folder</Button>
            </Space>

            {scanQuery.data ? (
              <Descriptions className="report-import-descriptions" column={1} size="small" bordered>
                <Descriptions.Item label="Local root"><Text code>{scanQuery.data.root}</Text></Descriptions.Item>
                <Descriptions.Item label="Year folder"><Text code>{scanQuery.data.directory}</Text></Descriptions.Item>
                <Descriptions.Item label="DOCX discovered">{scanQuery.data.count}</Descriptions.Item>
                <Descriptions.Item label="Eligible">{scanQuery.data.eligibleCount}</Descriptions.Item>
                <Descriptions.Item label="Oversized">{scanQuery.data.oversizedCount}</Descriptions.Item>
              </Descriptions>
            ) : null}
          </Card>
        </Col>
        <Col xs={24} xl={14}>
          <Card title={<><DatabaseOutlined /> Folder dry-run result</>}>
            {!lastImport ? <Empty description="Run a folder Dry Run to see validation results" /> : (
              <>
                <Row gutter={[10, 10]}>
                  <Col span={8}><Statistic title="Would import" value={lastImport.imported} /></Col>
                  <Col span={8}><Statistic title="Would update" value={lastImport.updated} /></Col>
                  <Col span={8}><Statistic title="Unchanged" value={lastImport.skipped} /></Col>
                </Row>
                <Divider />
                <Alert type={lastImport.failed ? 'warning' : 'success'} showIcon message="Folder dry run completed; database was not changed." description={`${lastImport.discovered} files discovered · ${lastImport.failed} failed`} />
                {lastImport.errors.length ? <List size="small" dataSource={lastImport.errors.slice(0, 20)} renderItem={(item) => <List.Item><Text type="danger">{item.file}: {item.error}</Text></List.Item>} /> : null}
              </>
            )}
          </Card>
        </Col>
      </Row>
    </div>
  );

  return (
    <section className="report-page">
      <div className="report-page-heading">
        <div>
          <span className="report-eyebrow">HISTORICAL REPORT INTELLIGENCE</span>
          <Title level={2}>Security Reports</Title>
          <Paragraph type="secondary">Local security reports transformed into prior-exposure intelligence for analysts, alert triage, and SOC Copilot.</Paragraph>
        </div>
        <Space>
          <Text type="secondary">Jalali year</Text>
          <Select value={year} onChange={(value) => { setYear(value); setPage(1); }} options={years.map((value) => ({ value, label: String(value) }))} style={{ minWidth: 110 }} />
          <Button icon={<ReloadOutlined />} onClick={refreshReportData} />
        </Space>
      </div>

      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          { key: 'overview', label: <span><DatabaseOutlined /> Overview</span>, children: overview },
          { key: 'reports', label: <span><FileSearchOutlined /> Reports</span>, children: reportsTable },
          { key: 'copilot', label: <span><MessageOutlined /> Ask Reports</span>, children: reportCopilot },
          { key: 'import', label: <span><ImportOutlined /> Import & Review</span>, children: importPanel },
        ]}
      />

      <Drawer width={800} title={selectedReport?.reportNumber || selectedReport?.title || 'Report detail'} open={Boolean(selectedReport)} onClose={() => setSelectedReport(null)}>
        {selectedReport ? <ReportDetail report={selectedReport} /> : null}
      </Drawer>
    </section>
  );
};

const MetricCard: React.FC<{ title: string; value: number; suffix?: string; note: string; icon: React.ReactNode; tone: string; }> = ({ title, value, suffix, note, icon, tone }) => (
  <Card className={`report-metric-card tone-${tone}`}><div className="report-metric-head"><span className="report-metric-icon">{icon}</span><span className="report-metric-label">{title}</span></div><Statistic value={value} suffix={suffix ? <span className="report-metric-suffix">{suffix}</span> : undefined} /><div className="report-metric-note">{note}</div></Card>
);

const InsightCard: React.FC<{ icon: React.ReactNode; eyebrow: string; title: string; value: string; detail: string; tone: string; onClick?: () => void; }> = ({ icon, eyebrow, title, value, detail, tone, onClick }) => (
  <button className={`report-insight-card tone-${tone}${onClick ? ' is-clickable' : ''}`} type="button" onClick={onClick} disabled={!onClick}><span className="report-insight-icon">{icon}</span><span className="report-insight-copy"><small>{eyebrow}</small><strong>{title}</strong><span>{detail}</span></span><b>{value}</b></button>
);

const MiniStat: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => <div className="report-mini-stat"><span>{label}</span><strong>{value}</strong></div>;

const ReportDetail: React.FC<{ report: HistoricalReport }> = ({ report }) => (
  <div className="report-detail">
    <Descriptions bordered column={1} size="small">
      <Descriptions.Item label="Title">{report.title}</Descriptions.Item>
      <Descriptions.Item label="Date">{report.reportDateRaw || '—'}</Descriptions.Item>
      <Descriptions.Item label="Report type"><Tag>{report.reportType}</Tag></Descriptions.Item>
      <Descriptions.Item label="Organization">{report.target.organization || '—'}</Descriptions.Item>
      <Descriptions.Item label="IP"><Text code>{report.target.ip || report.target.rawIp || '—'}</Text></Descriptions.Item>
      <Descriptions.Item label="Finding">{report.finding?.name || report.finding?.type || 'unknown'}</Descriptions.Item>
      <Descriptions.Item label="Category">{report.finding?.category || '—'}</Descriptions.Item>
      <Descriptions.Item label="CWE">{report.finding?.cwe || report.vulnerability?.cwe || '—'}</Descriptions.Item>
      <Descriptions.Item label="CVEs">{report.cves?.length ? report.cves.map((cve) => <Tag key={cve}>{cve}</Tag>) : '—'}</Descriptions.Item>
      <Descriptions.Item label="Severity"><Tag color={severityTag[report.severity.level] || 'default'}>{report.severity.level} {report.severity.score ?? ''}</Tag></Descriptions.Item>
      <Descriptions.Item label="Urgency">{report.urgency.raw || report.urgency.normalized}</Descriptions.Item>
      <Descriptions.Item label="Effect">{report.effect || '—'}</Descriptions.Item>
      <Descriptions.Item label="Source"><Text code>{report.source.relativePath}</Text></Descriptions.Item>
    </Descriptions>

    {report.extraction.warnings?.length ? <Alert className="report-detail-alert" type="warning" showIcon icon={<WarningOutlined />} message="Extraction review recommended" description={report.extraction.warnings.join(' · ')} /> : null}

    <Title level={5}>Description</Title>
    <Paragraph className="report-preserve-lines">{report.description || 'No description extracted.'}</Paragraph>
    {report.conclusion ? <><Title level={5}>Conclusion</Title><Paragraph className="report-preserve-lines">{report.conclusion}</Paragraph></> : null}

    <Title level={5}>Affected Systems / Event Details</Title>
    <Table size="small" pagination={false} rowKey={(_, index) => String(index)} dataSource={report.affectedSystems || []} scroll={{ x: 1250 }} columns={[
      { title: 'Organization', dataIndex: 'organization', width: 220, ellipsis: true },
      { title: 'IP', dataIndex: 'ip', width: 130 },
      { title: 'Domain', dataIndex: 'domain', width: 160 },
      { title: 'Service', dataIndex: 'service', width: 170, ellipsis: true },
      { title: 'Port', dataIndex: 'port', width: 80 },
      { title: 'Method', dataIndex: 'method', width: 80 },
      { title: 'Parameter', dataIndex: 'parameter', width: 120 },
      { title: 'URL / Path', dataIndex: 'url', width: 250, ellipsis: true },
      { title: 'Packets', dataIndex: 'packetCount', width: 120 },
      { title: 'Participant IPs', dataIndex: 'participantIpCount', width: 120 },
      { title: 'Traffic', dataIndex: 'trafficVolumeRaw', width: 110 },
      { title: 'Event date', dataIndex: 'eventDateRaw', width: 110 },
      { title: 'Time', dataIndex: 'timeRange', width: 130 },
      { title: 'Version', dataIndex: 'softwareVersion', width: 100 },
      { title: 'Reported finding', dataIndex: 'reportedFinding', width: 220, ellipsis: true },
    ]} />

    <Title level={5}>Recommendations</Title>
    <List size="small" dataSource={report.recommendations || []} locale={{ emptyText: 'No recommendations extracted.' }} renderItem={(item) => <List.Item>{item}</List.Item>} />
  </div>
);

export default Reports;
