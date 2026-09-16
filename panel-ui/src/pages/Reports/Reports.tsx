import React, { useMemo, useState } from 'react';
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
import type {
  HistoricalReport,
  ReportCopilotResult,
  ReportFilterParams,
  ReportImportResult,
} from '../../types/reports';
import ReportUploadReview from './ReportUploadReview';
import './Reports.css';

ChartJS.register(BarElement, CategoryScale, LinearScale, Legend, Tooltip);

const { Text, Title, Paragraph } = Typography;
const JALALI_MONTHS = ['فروردین', 'اردیبهشت', 'خرداد', 'تیر', 'مرداد', 'شهریور', 'مهر', 'آبان', 'آذر', 'دی', 'بهمن', 'اسفند'];
const CHART = {
  primary: '#3b82f6',
  cyan: '#06b6d4',
  amber: '#f59e0b',
  orange: '#f97316',
  red: '#ef4444',
  purple: '#8b5cf6',
  slate: '#64748b',
  tick: '#94a3b8',
  grid: 'rgba(148, 163, 184, 0.10)',
};

const severityTag: Record<string, string> = {
  critical: 'red', high: 'volcano', medium: 'gold', low: 'blue', info: 'cyan', none: 'default', unknown: 'default',
};

const severityColor: Record<string, string> = {
  critical: CHART.red, high: CHART.orange, medium: CHART.amber, low: CHART.primary,
  info: CHART.cyan, unknown: CHART.slate, none: CHART.slate,
};

const reportTypeLabel: Record<string, string> = {
  misconfiguration: 'Misconfiguration', vulnerability: 'Vulnerability', incident: 'Incident', malware: 'Malware', unknown: 'Unknown',
};

type ReportFilterState = Omit<ReportFilterParams, 'year'>;

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  result?: ReportCopilotResult;
}

type FilterOption = { value: string | number; label: string };

const Reports: React.FC = () => {
  const queryClient = useQueryClient();
  const [year, setYear] = useState<number>(1404);
  const [activeTab, setActiveTab] = useState('overview');
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState<ReportFilterState>({});
  const [selectedReport, setSelectedReport] = useState<HistoricalReport | null>(null);
  const [copilotInput, setCopilotInput] = useState('');
  const [chat, setChat] = useState<ChatMessage[]>([]);
  const [lastImport, setLastImport] = useState<ReportImportResult | null>(null);
  const [organizationSearch, setOrganizationSearch] = useState('');
  const [organizationSuggestionsOpen, setOrganizationSuggestionsOpen] = useState(false);

  const yearsQuery = useQuery({ queryKey: ['report-years'], queryFn: api.getReportYears });

  const filterParams = useMemo<ReportFilterParams>(() => ({ year, ...filters }), [year, filters]);

  const statsQuery = useQuery({
    queryKey: ['report-stats', filterParams],
    queryFn: () => api.getReportStats(filterParams),
    enabled: Boolean(year),
  });

  const reportsQuery = useQuery({
    queryKey: ['historical-reports', filterParams, page],
    queryFn: () => api.getHistoricalReports({ ...filterParams, page, limit: 20 }),
    enabled: Boolean(year),
  });

  const organizationCatalogParams = useMemo(() => {
    const { organization: _organization, ...rest } = filters;
    return { year, ...rest };
  }, [year, filters]);

  const organizationCatalogQuery = useQuery({
    queryKey: ['report-organization-catalog', organizationCatalogParams],
    queryFn: async () => {
      const first = await api.getHistoricalReports({ ...organizationCatalogParams, page: 1, limit: 100 });
      const reports = [...first.reports];
      const pages = Math.min(Number(first.pagination.pages || 1), 20);
      if (pages > 1) {
        const remaining = await Promise.all(
          Array.from({ length: pages - 1 }, (_, index) => index + 2)
            .map((catalogPage) => api.getHistoricalReports({ ...organizationCatalogParams, page: catalogPage, limit: 100 })),
        );
        remaining.forEach((result) => reports.push(...result.reports));
      }
      return reports;
    },
    enabled: Boolean(year),
    staleTime: 60_000,
  });

  const organizationOptions = useMemo(() => {
    const counts = new Map<string, number>();
    for (const report of organizationCatalogQuery.data || []) {
      const organization = String(report.target?.organization || '').trim();
      if (!organization) continue;
      counts.set(organization, (counts.get(organization) || 0) + 1);
    }

    const needle = normalizePersianSearch(organizationSearch);
    return [...counts.entries()]
      .filter(([organization]) => !needle || normalizePersianSearch(organization).includes(needle))
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], 'fa'))
      .slice(0, needle ? 20 : 12)
      .map(([organization, count]) => ({ organization, count }));
  }, [organizationCatalogQuery.data, organizationSearch]);

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
        await refreshReportData();
        antMessage.success(`Import complete: ${result.imported} new, ${result.updated} updated`);
      }
    },
    onError: (error: any) => antMessage.error(error?.response?.data?.detail || error?.message || 'Import failed'),
  });

  const copilotMutation = useMutation({
    mutationFn: api.queryReportCopilot,
    onSuccess: (result) => setChat((current) => [...current, { role: 'assistant', content: result.answer, result }]),
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

  const activeFilterCount = useMemo(
    () => Object.values(filters).filter((value) => value !== undefined && value !== null && value !== '').length,
    [filters],
  );

  const scopeLabel = useMemo(() => {
    const month = filters.month ? JALALI_MONTHS[Number(filters.month) - 1] : null;
    if (month && filters.day) return `${filters.day} ${month} ${year}`;
    if (month) return `${month} ${year}`;
    return `سال ${year}`;
  }, [filters.day, filters.month, year]);

  const dashboard = useMemo(() => {
    if (!stats) return null;
    const activeMonths = stats.byMonth
      .filter((item) => item.month && item.count > 0)
      .sort((a, b) => Number(a.month) - Number(b.month));
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
    const severityRows = severityOrder
      .map((key) => ({ key, count: stats.bySeverity.find((item) => item.severity === key)?.count || 0 }))
      .filter((item) => item.count > 0);

    return {
      activeMonths,
      severityRows,
      topFinding: stats.byFinding[0] || null,
      dominantType: stats.byReportType[0] || null,
      maxOrganizationCount: Math.max(1, ...stats.topOrganizations.map((item) => item.count)),
      maxPortCount: Math.max(1, ...stats.topPorts.map((item) => item.count)),
    };
  }, [stats]);

  function setFilter<K extends keyof ReportFilterState>(key: K, value: ReportFilterState[K]) {
    setFilters((current) => ({ ...current, [key]: value === '' || value === null ? undefined : value }));
    setPage(1);
  }

  function clearFilters() {
    setFilters({});
    setOrganizationSearch('');
    setOrganizationSuggestionsOpen(false);
    setPage(1);
  }

  function commitOrganization(organization?: string) {
    const value = String(organization || '').trim();
    setOrganizationSearch(value);
    setOrganizationSuggestionsOpen(false);
    setFilter('organization', value || undefined);
  }

  function openFinding(finding?: string) {
    if (!finding) return;
    setFilter('finding', finding);
    setActiveTab('reports');
  }

  function openOrganization(organization?: string) {
    if (!organization) return;
    commitOrganization(organization);
    setActiveTab('reports');
  }

  const askCopilot = (value?: string) => {
    const text = String(value ?? copilotInput).trim();
    if (!text || copilotMutation.isPending) return;
    setChat((current) => [...current, { role: 'user', content: text }]);
    setCopilotInput('');
    copilotMutation.mutate(text);
  };

  const refreshReportData = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['report-years'] }),
      queryClient.invalidateQueries({ queryKey: ['report-stats'] }),
      queryClient.invalidateQueries({ queryKey: ['historical-reports'] }),
      queryClient.invalidateQueries({ queryKey: ['report-organization-catalog'] }),
    ]);
  };

  const filterPanel = (
    <Card
      size="small"
      style={{ overflow: 'visible' }}
      title={<Space><SearchOutlined /><span>Analytics scope</span><Tag color={activeFilterCount ? 'blue' : 'default'}>{activeFilterCount ? `${activeFilterCount} filters` : 'Full year'}</Tag></Space>}
      extra={<Button size="small" disabled={!activeFilterCount} onClick={clearFilters}>Reset filters</Button>}
    >
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'flex-start' }}>
        <NativeFilterSelect
          value={filters.month}
          placeholder="همه ماه‌ها"
          options={JALALI_MONTHS.map((label, index) => ({ value: index + 1, label }))}
          width={155}
          onChange={(value) => {
            const month = value ? Number(value) : undefined;
            setFilters((current) => ({ ...current, month, day: undefined }));
            setPage(1);
          }}
        />
        <NativeFilterSelect
          value={filters.day}
          placeholder="روز"
          disabled={!filters.month}
          options={Array.from({ length: 31 }, (_, index) => ({ value: index + 1, label: String(index + 1) }))}
          width={90}
          onChange={(value) => setFilter('day', value ? Number(value) : undefined)}
        />
        <NativeFilterSelect
          value={filters.reportType}
          placeholder="Report type"
          options={['misconfiguration', 'vulnerability', 'incident', 'malware', 'unknown'].map((value) => ({ value, label: reportTypeLabel[value] || value }))}
          width={155}
          onChange={(value) => setFilter('reportType', value || undefined)}
        />
        <NativeFilterSelect
          value={filters.severity}
          placeholder="Severity"
          options={['critical', 'high', 'medium', 'low', 'info', 'unknown'].map((value) => ({ value, label: value }))}
          width={125}
          onChange={(value) => setFilter('severity', value || undefined)}
        />
        <NativeFilterSelect
          value={filters.urgency}
          placeholder="Urgency"
          options={['immediate', 'action_required', 'informational', 'unknown'].map((value) => ({ value, label: value }))}
          width={150}
          onChange={(value) => setFilter('urgency', value || undefined)}
        />

        <div style={{ position: 'relative', width: 290, zIndex: organizationSuggestionsOpen ? 2000 : 1 }}>
          <Input
            allowClear
            prefix={<SearchOutlined />}
            value={organizationSearch}
            placeholder="سازمان؛ مثلاً دانشگاه علوم"
            onFocus={() => setOrganizationSuggestionsOpen(true)}
            onBlur={() => window.setTimeout(() => setOrganizationSuggestionsOpen(false), 140)}
            onChange={(event) => {
              const value = event.target.value;
              setOrganizationSearch(value);
              setOrganizationSuggestionsOpen(true);
              if (!value.trim()) setFilter('organization', undefined);
            }}
            onPressEnter={() => commitOrganization(organizationSearch)}
          />
          {organizationSuggestionsOpen ? (
            <div
              style={{
                position: 'absolute',
                top: 'calc(100% + 6px)',
                left: 0,
                right: 0,
                zIndex: 2500,
                maxHeight: 280,
                overflowY: 'auto',
                padding: 6,
                border: '1px solid var(--panel-border-strong)',
                borderRadius: 10,
                background: 'var(--panel-surface-raised)',
                boxShadow: '0 18px 46px rgba(0,0,0,.24)',
              }}
              onMouseDown={(event) => event.preventDefault()}
            >
              {organizationCatalogQuery.isLoading ? (
                <div style={{ padding: '10px 11px', color: 'var(--panel-muted)', fontSize: 11 }}>در حال بارگذاری سازمان‌ها…</div>
              ) : organizationOptions.length ? organizationOptions.map((item) => (
                <button
                  key={item.organization}
                  type="button"
                  onMouseDown={(event) => event.preventDefault()}
                  onClick={() => commitOrganization(item.organization)}
                  style={{
                    width: '100%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 12,
                    padding: '9px 10px',
                    border: 0,
                    borderRadius: 8,
                    background: 'transparent',
                    color: 'var(--panel-text)',
                    cursor: 'pointer',
                    textAlign: 'right',
                  }}
                >
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.organization}</span>
                  <span style={{ flex: '0 0 auto', color: 'var(--panel-muted)', fontSize: 10 }}>{item.count} گزارش</span>
                </button>
              )) : (
                <div style={{ padding: '10px 11px', color: 'var(--panel-muted)', fontSize: 11 }}>
                  سازمانی با این عبارت پیدا نشد.
                </div>
              )}
            </div>
          ) : null}
        </div>

        <Input allowClear placeholder="Finding type e.g. xss" value={String(filters.finding || '')} onChange={(event) => setFilter('finding', event.target.value)} style={{ width: 180 }} />
        <Input allowClear placeholder="IP" value={String(filters.ip || '')} onChange={(event) => setFilter('ip', event.target.value)} style={{ width: 150 }} />
        <Input allowClear placeholder="Port" value={String(filters.port || '')} onChange={(event) => setFilter('port', event.target.value)} style={{ width: 90 }} />
        <Input allowClear placeholder="CVE" value={String(filters.cve || '')} onChange={(event) => setFilter('cve', event.target.value)} style={{ width: 150 }} />
        <Input allowClear placeholder="Service" value={String(filters.service || '')} onChange={(event) => setFilter('service', event.target.value)} style={{ width: 140 }} />
        <Input allowClear placeholder="Domain" value={String(filters.domain || '')} onChange={(event) => setFilter('domain', event.target.value)} style={{ width: 165 }} />
        <Input allowClear placeholder="Provider" value={String(filters.provider || '')} onChange={(event) => setFilter('provider', event.target.value)} style={{ width: 160 }} />
        <Input
          allowClear
          prefix={<SearchOutlined />}
          placeholder="Free-text search across report content"
          value={String(filters.search || '')}
          onChange={(event) => setFilter('search', event.target.value)}
          style={{ width: 310 }}
        />
      </div>
      <div style={{ marginTop: 10 }}>
        <Text type="secondary">
          Scope: <Text strong>{scopeLabel}</Text>. The KPIs, charts and Reports table below all use this exact same filter set.
        </Text>
      </div>
    </Card>
  );

  const overview = (
    <div className="report-tab-stack">
      {!stats && !statsQuery.isLoading ? <Empty description={`No report data for ${scopeLabel}.`} /> : null}
      {stats && dashboard ? (
        <>
          {stats.summary.total === 0 ? <Alert showIcon type="info" message="No reports match the current filter scope" description="Change or reset filters to widen the result set." /> : null}
          <div className="report-kpi-grid">
            <MetricCard title="Reports in scope" value={stats.summary.total} note={`${stats.summary.uniqueOrganizations} organizations · ${scopeLabel}`} icon={<DatabaseOutlined />} tone="primary" />
            <MetricCard title="High / Critical" value={stats.summary.highCritical} suffix={`${stats.summary.highCriticalPercent}%`} note="Elevated-severity reports in the current scope" icon={<FireOutlined />} tone="danger" />
            <MetricCard title="Immediate action" value={stats.summary.immediate} suffix={`${stats.summary.immediatePercent}%`} note="Immediate-response reports in the current scope" icon={<ThunderboltOutlined />} tone="warning" />
            <MetricCard title="Observed target IPs" value={stats.summary.uniqueIps} note={`${stats.summary.qualityWarnings} reports retain review flags`} icon={<SafetyCertificateOutlined />} tone="cyan" />
          </div>

          <div className="report-section-heading">
            <div><span className="report-section-kicker">FILTERED INTELLIGENCE</span><Title level={4}>What stands out in {scopeLabel}</Title></div>
            <Text type="secondary">Every visualization is recalculated from the same filtered MongoDB result set.</Text>
          </div>

          <div className="report-insight-grid">
            <InsightCard icon={<TrophyOutlined />} eyebrow="Dominant finding" title={dashboard.topFinding?.name || dashboard.topFinding?.key || 'No finding data'} value={dashboard.topFinding ? `${dashboard.topFinding.count} reports` : '—'} detail={dashboard.topFinding?.category || 'No category available'} tone="primary" onClick={dashboard.topFinding ? () => openFinding(dashboard.topFinding?.key) : undefined} />
            <InsightCard icon={<BarChartOutlined />} eyebrow="Dominant report type" title={dashboard.dominantType ? reportTypeLabel[dashboard.dominantType.reportType] || dashboard.dominantType.reportType : 'No type data'} value={dashboard.dominantType ? `${dashboard.dominantType.count} reports` : '—'} detail={dashboard.dominantType && stats.summary.total ? `${Math.round((dashboard.dominantType.count / stats.summary.total) * 100)}% of filtered reports` : 'No distribution available'} tone="purple" />
            <InsightCard icon={<AlertOutlined />} eyebrow="Repeated exposure" title={`${stats.repeated.repeatedGroups} repeated patterns`} value={`${stats.repeated.reportsInRepeatedGroups} reports`} detail="Organization + finding combinations repeated inside this scope" tone="warning" />
            <InsightCard icon={<WarningOutlined />} eyebrow="Data quality" title={stats.summary.qualityWarnings ? `${stats.summary.qualityWarnings} need review` : 'No review flags'} value={stats.summary.qualityWarnings ? 'Review retained' : 'Clean'} detail="Extraction review flags in the current scope" tone={stats.summary.qualityWarnings ? 'danger' : 'success'} />
          </div>

          <Row gutter={[14, 14]}>
            <Col xs={24} xl={14}>
              {filters.month || dashboard.activeMonths.length <= 1 ? (
                <Card className="report-panel-card report-coverage-card" title="Time-scope snapshot">
                  <div className="report-coverage-spotlight">
                    <div className="report-coverage-main">
                      <span className="report-section-kicker">CURRENT SCOPE</span>
                      <strong>{scopeLabel}</strong>
                      <p>{stats.summary.total} report(s) match the current filter scope. Clear the month filter to return to the annual trend.</p>
                    </div>
                    <div className="report-coverage-stats">
                      <MiniStat label="Reports" value={stats.summary.total} />
                      <MiniStat label="High / Critical" value={`${stats.summary.highCriticalPercent}%`} />
                      <MiniStat label="Immediate" value={`${stats.summary.immediatePercent}%`} />
                      <MiniStat label="Organizations" value={stats.summary.uniqueOrganizations} />
                    </div>
                  </div>
                </Card>
              ) : (
                <Card className="report-panel-card report-chart-card" title={`Monthly trend · ${year}`}>
                  <Bar
                    data={{ labels: dashboard.activeMonths.map((item) => item.month ? JALALI_MONTHS[Number(item.month) - 1] : 'Unknown'), datasets: [{ label: 'Reports', data: dashboard.activeMonths.map((item) => item.count), backgroundColor: CHART.primary, borderRadius: 7, maxBarThickness: 46 }] }}
                    options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { grid: { display: false }, ticks: { color: CHART.tick } }, y: { beginAtZero: true, grid: { color: CHART.grid }, ticks: { color: CHART.tick, precision: 0 } } } }}
                  />
                </Card>
              )}
            </Col>
            <Col xs={24} xl={10}>
              <Card className="report-panel-card report-chart-card" title="Severity posture">
                {dashboard.severityRows.length ? (
                  <Bar
                    data={{ labels: dashboard.severityRows.map((item) => item.key), datasets: [{ label: 'Reports', data: dashboard.severityRows.map((item) => item.count), backgroundColor: dashboard.severityRows.map((item) => severityColor[item.key] || CHART.slate), borderRadius: 7, maxBarThickness: 30 }] }}
                    options={{ indexAxis: 'y' as const, responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, grid: { color: CHART.grid }, ticks: { color: CHART.tick, precision: 0 } }, y: { grid: { display: false }, ticks: { color: CHART.tick } } } }}
                  />
                ) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No severity data in scope" />}
              </Card>
            </Col>
          </Row>

          <Row gutter={[14, 14]}>
            <Col xs={24} xl={14}>
              <Card className="report-panel-card report-findings-card" title="Top findings">
                <div className="report-chart-tall">
                  {stats.byFinding.length ? (
                    <Bar
                      data={{ labels: stats.byFinding.slice(0, 8).map((item) => item.name || item.key), datasets: [{ label: 'Reports', data: stats.byFinding.slice(0, 8).map((item) => item.count), backgroundColor: stats.byFinding.slice(0, 8).map((_, index) => index === 0 ? CHART.primary : 'rgba(59, 130, 246, 0.45)'), borderRadius: 7, maxBarThickness: 26 }] }}
                      options={{ indexAxis: 'y' as const, responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, grid: { color: CHART.grid }, ticks: { color: CHART.tick, precision: 0 } }, y: { grid: { display: false }, ticks: { color: CHART.tick, autoSkip: false } } } }}
                    />
                  ) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No findings in scope" />}
                </div>
                <div className="report-findings-tags">
                  {stats.byFinding.slice(0, 6).map((item) => <button key={item.key} type="button" onClick={() => openFinding(item.key)}><span>{item.category || 'uncategorized'}</span><strong>{item.count}</strong></button>)}
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
                        <small>{percent}% of filtered reports</small>
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
                    <button className="report-rank-row" type="button" key={item.organization} onClick={() => openOrganization(item.organization)}>
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
                    <button type="button" className="report-port-chip" key={item.port} onClick={() => { setFilter('port', item.port); setActiveTab('reports'); }}><div><Text code>{item.port}</Text><span>observed port</span></div><strong>{item.count}</strong><span className="report-port-meter"><i style={{ width: `${(item.count / dashboard.maxPortCount) * 100}%` }} /></span></button>
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
      <Card title={`Reports · ${scopeLabel}`} extra={<Text type="secondary">{reportsQuery.data?.pagination.total ?? 0} matching records</Text>}>
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
          <Paragraph type="secondary">Statistical questions are answered directly from MongoDB. You can ask about a year, month, organization, finding, IP, port, severity or report type.</Paragraph>
          <Text strong>Examples</Text>
          <div className="report-question-chips">
            {[`در اردیبهشت ${year} چند گزارش داشتیم؟`, `در سال ${year} چند گزارش حادثه داشتیم؟`, `بیشترین Finding سال ${year} چه بوده؟`, `کدام سازمان بیشترین گزارش آسیب پذیری داشته؟`, `چند درصد گزارش‌های ${year} نیازمند اقدام فوری بوده‌اند؟`, `روند ماهانه گزارش‌های ${year} را نشان بده`, 'روی پورت 443 چند گزارش ثبت شده؟'].map((question) => <button key={question} type="button" onClick={() => askCopilot(question)}>{question}</button>)}
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
            <Input.TextArea autoSize={{ minRows: 2, maxRows: 4 }} value={copilotInput} placeholder={`مثلاً: در اردیبهشت ${year} چند گزارش آسیب‌پذیری داشتیم؟`} onChange={(event) => setCopilotInput(event.target.value)} onPressEnter={(event) => { if (!event.shiftKey) { event.preventDefault(); askCopilot(); } }} />
            <Button type="primary" loading={copilotMutation.isPending} onClick={() => askCopilot()}>Ask</Button>
          </Space.Compact>
        </Card>
      </Col>
    </Row>
  );

  const importPanel = (
    <div className="report-tab-stack">
      <ReportUploadReview year={year} onCommitted={refreshReportData} />
      <Divider>Advanced: server folder workflow</Divider>
      <Row gutter={[14, 14]}>
        <Col xs={24} xl={10}>
          <Card title={<><FolderOpenOutlined /> Existing local DOCX folder</>}>
            <Paragraph>For bulk/admin workflows, files already present under <Text code>REPORTS_ROOT/{year}/</Text> can still be scanned and dry-run locally.</Paragraph>
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
          <Paragraph type="secondary">Monthly, annual and multidimensional report intelligence from the local historical dataset.</Paragraph>
        </div>
        <Space>
          <Text type="secondary">Jalali year</Text>
          <NativeFilterSelect
            value={year}
            placeholder="سال"
            options={years.map((value) => ({ value, label: String(value) }))}
            width={110}
            onChange={(value) => {
              if (!value) return;
              setYear(Number(value));
              setPage(1);
            }}
          />
          <Button icon={<ReloadOutlined />} onClick={refreshReportData} />
        </Space>
      </div>

      {filterPanel}

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

const NativeFilterSelect: React.FC<{
  value?: string | number | null;
  placeholder: string;
  options: FilterOption[];
  width: number;
  disabled?: boolean;
  onChange: (value?: string) => void;
}> = ({ value, placeholder, options, width, disabled = false, onChange }) => (
  <select
    aria-label={placeholder}
    disabled={disabled}
    value={value === undefined || value === null ? '' : String(value)}
    onChange={(event) => onChange(event.target.value || undefined)}
    style={{
      width,
      height: 36,
      padding: '0 10px',
      border: '1px solid var(--panel-border)',
      borderRadius: 10,
      background: disabled ? 'var(--panel-surface-soft)' : 'var(--panel-surface)',
      color: value === undefined || value === null || value === '' ? 'var(--panel-muted)' : 'var(--panel-text)',
      cursor: disabled ? 'not-allowed' : 'pointer',
      outline: 'none',
      opacity: disabled ? 0.55 : 1,
    }}
  >
    <option value="">{placeholder}</option>
    {options.map((option) => <option key={String(option.value)} value={String(option.value)}>{option.label}</option>)}
  </select>
);

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

function normalizePersianSearch(value: string) {
  return String(value || '')
    .replace(/ي/g, 'ی')
    .replace(/ك/g, 'ک')
    .replace(/\u200c/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .toLocaleLowerCase('fa');
}

export default Reports;
