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
  CheckCircleOutlined,
  DatabaseOutlined,
  FileSearchOutlined,
  FolderOpenOutlined,
  ImportOutlined,
  MessageOutlined,
  ReloadOutlined,
  SearchOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Chart as ChartJS,
  ArcElement,
  BarElement,
  CategoryScale,
  Legend,
  LinearScale,
  Tooltip,
} from 'chart.js';
import { Bar, Doughnut } from 'react-chartjs-2';
import { api } from '../../api/client';
import type { HistoricalReport, ReportCopilotResult, ReportImportResult } from '../../types/reports';
import './Reports.css';

ChartJS.register(ArcElement, BarElement, CategoryScale, LinearScale, Legend, Tooltip);

const { Text, Title, Paragraph } = Typography;
const JALALI_MONTHS = ['فروردین', 'اردیبهشت', 'خرداد', 'تیر', 'مرداد', 'شهریور', 'مهر', 'آبان', 'آذر', 'دی', 'بهمن', 'اسفند'];

const severityTag: Record<string, string> = {
  critical: 'red',
  high: 'volcano',
  medium: 'gold',
  low: 'blue',
  none: 'default',
  unknown: 'default',
};

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  result?: ReportCopilotResult;
}

const Reports: React.FC = () => {
  const queryClient = useQueryClient();
  const [year, setYear] = useState<number>(1404);
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

  const askCopilot = (value?: string) => {
    const text = String(value ?? copilotInput).trim();
    if (!text || copilotMutation.isPending) return;
    setChat((current) => [...current, { role: 'user', content: text }]);
    setCopilotInput('');
    copilotMutation.mutate(text);
  };

  const overview = (
    <div className="report-tab-stack">
      {!stats && !statsQuery.isLoading ? (
        <Empty description={`No imported report data for ${year}. Use Local Import to load DOCX files.`} />
      ) : null}

      {stats ? (
        <>
          <Row gutter={[12, 12]}>
            <Col xs={12} md={8} xl={4}><MetricCard title="Reports" value={stats.summary.total} /></Col>
            <Col xs={12} md={8} xl={4}><MetricCard title="Organizations" value={stats.summary.uniqueOrganizations} /></Col>
            <Col xs={12} md={8} xl={4}><MetricCard title="Unique IPs" value={stats.summary.uniqueIps} /></Col>
            <Col xs={12} md={8} xl={4}><MetricCard title="High / Critical" value={stats.summary.highCritical} suffix={`${stats.summary.highCriticalPercent}%`} /></Col>
            <Col xs={12} md={8} xl={4}><MetricCard title="Immediate Action" value={stats.summary.immediate} suffix={`${stats.summary.immediatePercent}%`} /></Col>
            <Col xs={12} md={8} xl={4}><MetricCard title="Needs Review" value={stats.summary.qualityWarnings} /></Col>
          </Row>

          <Row gutter={[14, 14]}>
            <Col xs={24} xl={14}>
              <Card title="Reports by Month" className="report-chart-card">
                <Bar
                  data={{
                    labels: JALALI_MONTHS,
                    datasets: [{
                      label: 'Reports',
                      data: JALALI_MONTHS.map((_, index) => stats.byMonth.find((item) => item.month === index + 1)?.count || 0),
                    }],
                  }}
                  options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }}
                />
              </Card>
            </Col>
            <Col xs={24} xl={10}>
              <Card title="Severity Distribution" className="report-chart-card">
                <Doughnut
                  data={{
                    labels: stats.bySeverity.map((item) => item.severity),
                    datasets: [{ data: stats.bySeverity.map((item) => item.count) }],
                  }}
                  options={{ responsive: true, maintainAspectRatio: false }}
                />
              </Card>
            </Col>
          </Row>

          <Row gutter={[14, 14]}>
            <Col xs={24} xl={12}>
              <Card title="Top Findings">
                <Table
                  rowKey={(row) => row.key}
                  pagination={false}
                  size="small"
                  dataSource={stats.byFinding}
                  columns={[
                    { title: 'Finding', dataIndex: 'name', render: (value, row) => value || row.key },
                    { title: 'Category', dataIndex: 'category', width: 150, render: (value) => value || '—' },
                    { title: 'Count', dataIndex: 'count', width: 80, align: 'right' as const },
                  ]}
                />
              </Card>
            </Col>
            <Col xs={24} xl={12}>
              <Card title="Top Organizations">
                <Table
                  rowKey="organization"
                  pagination={false}
                  size="small"
                  dataSource={stats.topOrganizations}
                  columns={[
                    { title: 'Organization', dataIndex: 'organization', ellipsis: true },
                    { title: 'Reports', dataIndex: 'count', width: 90, align: 'right' as const },
                  ]}
                />
              </Card>
            </Col>
          </Row>

          <Row gutter={[14, 14]}>
            <Col xs={24} xl={12}>
              <Card title="Report Types">
                <Table
                  rowKey="reportType"
                  pagination={false}
                  size="small"
                  dataSource={stats.byReportType}
                  columns={[
                    { title: 'Type', dataIndex: 'reportType' },
                    { title: 'Reports', dataIndex: 'count', width: 90, align: 'right' as const },
                  ]}
                />
              </Card>
            </Col>
            <Col xs={24} xl={12}>
              <Card title="Observed Ports">
                <Table
                  rowKey={(row) => String(row.port)}
                  pagination={false}
                  size="small"
                  dataSource={stats.topPorts}
                  columns={[
                    { title: 'Port', dataIndex: 'port' },
                    { title: 'Reports / systems', dataIndex: 'count', width: 130, align: 'right' as const },
                  ]}
                />
              </Card>
            </Col>
          </Row>

          <Card title="Repeated Finding Signal">
            <div className="report-repeat-strip">
              <div><strong>{stats.repeated.repeatedGroups}</strong><span>organization + finding combinations appeared more than once</span></div>
              <div><strong>{stats.repeated.reportsInRepeatedGroups}</strong><span>reports belong to repeated groups</span></div>
            </div>
          </Card>
        </>
      ) : null}
    </div>
  );

  const reportsTable = (
    <div className="report-tab-stack">
      <Card>
        <div className="report-filter-bar">
          <Input
            allowClear
            prefix={<SearchOutlined />}
            placeholder="Search title, organization, IP, report number, finding, CVE, domain..."
            value={search}
            onChange={(event) => { setSearch(event.target.value); setPage(1); }}
          />
          <Select
            allowClear
            placeholder="Severity"
            value={severity}
            onChange={(value) => { setSeverity(value); setPage(1); }}
            options={['critical', 'high', 'medium', 'low', 'unknown'].map((value) => ({ value, label: value }))}
          />
          <Select
            allowClear
            placeholder="Urgency"
            value={urgency}
            onChange={(value) => { setUrgency(value); setPage(1); }}
            options={['immediate', 'action_required', 'informational', 'high', 'normal', 'low', 'unknown'].map((value) => ({ value, label: value }))}
          />
        </div>
      </Card>

      <Card>
        <Table
          rowKey="_id"
          loading={reportsQuery.isLoading}
          dataSource={reportsQuery.data?.reports || []}
          onRow={(record) => ({ onClick: () => setSelectedReport(record), className: 'report-clickable-row' })}
          pagination={{
            current: page,
            pageSize: 20,
            total: reportsQuery.data?.pagination.total || 0,
            showSizeChanger: false,
            onChange: setPage,
          }}
          scroll={{ x: 1180 }}
          columns={[
            { title: 'Date', dataIndex: 'reportDateRaw', width: 110 },
            { title: 'Report No', dataIndex: 'reportNumber', width: 165, render: (value) => value || '—' },
            { title: 'Type', dataIndex: 'reportType', width: 130 },
            { title: 'Organization', dataIndex: ['target', 'organization'], width: 250, ellipsis: true },
            { title: 'IP', dataIndex: ['target', 'ip'], width: 135, render: (value) => <Text code>{value || '—'}</Text> },
            { title: 'Finding', dataIndex: ['finding', 'name'], width: 210, render: (value, row) => value || row.finding?.type || 'unknown' },
            {
              title: 'Severity',
              dataIndex: ['severity', 'level'],
              width: 100,
              render: (value, row) => <Tag color={severityTag[value] || 'default'}>{value} {row.severity.score ?? ''}</Tag>,
            },
            {
              title: 'Urgency',
              dataIndex: ['urgency', 'normalized'],
              width: 130,
              render: (value) => <Tag color={value === 'immediate' ? 'red' : value === 'informational' ? 'blue' : 'default'}>{value}</Tag>,
            },
          ]}
        />
      </Card>
    </div>
  );

  const reportCopilot = (
    <Row gutter={[14, 14]}>
      <Col xs={24} xl={8}>
        <Card title={<><MessageOutlined /> Report Copilot</>}>
          <Paragraph type="secondary">
            Statistical questions are answered directly from MongoDB. No RAG and no LLM arithmetic are used in this version.
          </Paragraph>
          <Text strong>Examples</Text>
          <div className="report-question-chips">
            {[
              `در سال ${year} چند گزارش حادثه داشتیم؟`,
              `بیشترین Finding سال ${year} چه بوده؟`,
              `کدام سازمان بیشترین گزارش UDP Amplification داشته؟`,
              `چند درصد گزارش‌های ${year} نیازمند اقدام فوری بوده‌اند؟`,
              `روند ماهانه گزارش‌های ${year} را نشان بده`,
              'روی پورت 443 چند گزارش ثبت شده؟',
              'برای IP 62.60.167.73 چه گزارش‌هایی داریم؟',
            ].map((question) => (
              <button key={question} type="button" onClick={() => askCopilot(question)}>{question}</button>
            ))}
          </div>
        </Card>
      </Col>
      <Col xs={24} xl={16}>
        <Card className="report-chat-card">
          <div className="report-chat-log">
            {!chat.length ? (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="Ask a question about imported reports" />
            ) : chat.map((item, index) => (
              <div key={`${item.role}-${index}`} className={`report-chat-message is-${item.role}`}>
                <span>{item.role === 'user' ? 'YOU' : 'REPORT DATA'}</span>
                <pre>{item.content}</pre>
              </div>
            ))}
            {copilotMutation.isPending ? <div className="report-chat-thinking">Querying historical report dataset…</div> : null}
          </div>
          <Divider />
          <Space.Compact block>
            <Input.TextArea
              autoSize={{ minRows: 2, maxRows: 4 }}
              value={copilotInput}
              placeholder="مثلاً: در سال ۱۴۰۴ چند گزارش UDP Amplification داشتیم؟"
              onChange={(event) => setCopilotInput(event.target.value)}
              onPressEnter={(event) => {
                if (!event.shiftKey) {
                  event.preventDefault();
                  askCopilot();
                }
              }}
            />
            <Button type="primary" loading={copilotMutation.isPending} onClick={() => askCopilot()}>Ask</Button>
          </Space.Compact>
        </Card>
      </Col>
    </Row>
  );

  const importPanel = (
    <Row gutter={[14, 14]}>
      <Col xs={24} xl={10}>
        <Card title={<><FolderOpenOutlined /> Local DOCX Source</>}>
          <Paragraph>
            Files stay on the SOC server. Configure <Text code>REPORTS_ROOT</Text>, then place reports under a year folder such as <Text code>1404/</Text>.
          </Paragraph>
          <Space wrap>
            <Button icon={<SearchOutlined />} loading={scanQuery.isFetching} onClick={() => scanQuery.refetch()}>Scan {year}</Button>
            <Button icon={<CheckCircleOutlined />} loading={importMutation.isPending} onClick={() => importMutation.mutate({ dryRun: true })}>Dry Run</Button>
            <Button type="primary" icon={<ImportOutlined />} loading={importMutation.isPending} onClick={() => importMutation.mutate({ dryRun: false })}>Import DOCX</Button>
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
        <Card title={<><DatabaseOutlined /> Import Result</>}>
          {!lastImport ? <Empty description="Run Dry Run or Import to see the result" /> : (
            <>
              <Row gutter={[10, 10]}>
                <Col span={8}><Statistic title="Imported" value={lastImport.imported} /></Col>
                <Col span={8}><Statistic title="Updated" value={lastImport.updated} /></Col>
                <Col span={8}><Statistic title="Skipped" value={lastImport.skipped} /></Col>
              </Row>
              <Divider />
              <Alert
                type={lastImport.failed ? 'warning' : 'success'}
                showIcon
                message={lastImport.dryRun ? 'Dry run completed; database was not changed.' : 'Import completed.'}
                description={`${lastImport.discovered} files discovered · ${lastImport.failed} failed`}
              />
              {lastImport.errors.length ? (
                <List
                  size="small"
                  dataSource={lastImport.errors.slice(0, 20)}
                  renderItem={(item) => <List.Item><Text type="danger">{item.file}: {item.error}</Text></List.Item>}
                />
              ) : null}
            </>
          )}
        </Card>
      </Col>
    </Row>
  );

  return (
    <section className="report-page">
      <div className="report-page-heading">
        <div>
          <span className="report-eyebrow">HISTORICAL REPORT INTELLIGENCE</span>
          <Title level={2}>Security Reports</Title>
          <Paragraph type="secondary">Local DOCX reports converted into a structured, queryable security dataset.</Paragraph>
        </div>
        <Space>
          <Text type="secondary">Jalali year</Text>
          <Select
            value={year}
            onChange={(value) => { setYear(value); setPage(1); }}
            options={years.map((value) => ({ value, label: String(value) }))}
            style={{ minWidth: 110 }}
          />
          <Button icon={<ReloadOutlined />} onClick={() => {
            queryClient.invalidateQueries({ queryKey: ['report-years'] });
            queryClient.invalidateQueries({ queryKey: ['report-stats'] });
            queryClient.invalidateQueries({ queryKey: ['historical-reports'] });
          }} />
        </Space>
      </div>

      <Tabs
        defaultActiveKey="overview"
        items={[
          { key: 'overview', label: <span><DatabaseOutlined /> Overview</span>, children: overview },
          { key: 'reports', label: <span><FileSearchOutlined /> Reports</span>, children: reportsTable },
          { key: 'copilot', label: <span><MessageOutlined /> Ask Reports</span>, children: reportCopilot },
          { key: 'import', label: <span><ImportOutlined /> Local Import</span>, children: importPanel },
        ]}
      />

      <Drawer
        width={800}
        title={selectedReport?.reportNumber || selectedReport?.title || 'Report detail'}
        open={Boolean(selectedReport)}
        onClose={() => setSelectedReport(null)}
      >
        {selectedReport ? <ReportDetail report={selectedReport} /> : null}
      </Drawer>
    </section>
  );
};

const MetricCard: React.FC<{ title: string; value: number; suffix?: string }> = ({ title, value, suffix }) => (
  <Card className="report-metric-card"><Statistic title={title} value={value} suffix={suffix ? <span className="report-metric-suffix">{suffix}</span> : undefined} /></Card>
);

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

    {report.extraction.warnings?.length ? (
      <Alert className="report-detail-alert" type="warning" showIcon icon={<WarningOutlined />} message="Extraction review recommended" description={report.extraction.warnings.join(' · ')} />
    ) : null}

    <Title level={5}>Description</Title>
    <Paragraph className="report-preserve-lines">{report.description || 'No description extracted.'}</Paragraph>

    {report.conclusion ? (
      <>
        <Title level={5}>Conclusion</Title>
        <Paragraph className="report-preserve-lines">{report.conclusion}</Paragraph>
      </>
    ) : null}

    <Title level={5}>Affected Systems / Event Details</Title>
    <Table
      size="small"
      pagination={false}
      rowKey={(_, index) => String(index)}
      dataSource={report.affectedSystems || []}
      scroll={{ x: 1250 }}
      columns={[
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
      ]}
    />

    <Title level={5}>Recommendations</Title>
    <List
      size="small"
      dataSource={report.recommendations || []}
      locale={{ emptyText: 'No recommendations extracted.' }}
      renderItem={(item) => <List.Item>{item}</List.Item>}
    />
  </div>
);

export default Reports;
