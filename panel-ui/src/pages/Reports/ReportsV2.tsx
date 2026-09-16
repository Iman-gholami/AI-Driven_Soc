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
  Segmented,
  Select,
  Space,
  Statistic,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
  message as antMessage,
} from 'antd';
import {
  ApartmentOutlined,
  BarChartOutlined,
  CheckCircleOutlined,
  CloudDownloadOutlined,
  DatabaseOutlined,
  FileSearchOutlined,
  FireOutlined,
  FolderOpenOutlined,
  ImportOutlined,
  LineChartOutlined,
  LinkOutlined,
  MessageOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SaveOutlined,
  SearchOutlined,
  ThunderboltOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Legend,
  LinearScale,
  Tooltip as ChartTooltip,
} from 'chart.js';
import { Bar } from 'react-chartjs-2';
import { api } from '../../api/client';
import type {
  HistoricalReport,
  ReportCopilotResult,
  ReportEntitySummary,
  ReportFacetItem,
  ReportFilterParams,
  ReportImportResult,
  ReportStats,
} from '../../types/reports';
import ReportUploadReview from './ReportUploadReview';
import './ReportsV2.css';

ChartJS.register(BarElement, CategoryScale, LinearScale, Legend, ChartTooltip);

const { Paragraph, Text, Title } = Typography;
const JALALI_MONTHS = ['فروردین', 'اردیبهشت', 'خرداد', 'تیر', 'مرداد', 'شهریور', 'مهر', 'آبان', 'آذر', 'دی', 'بهمن', 'اسفند'];
const TARGET_LABEL: Record<string, string> = { single: 'تک‌هدف', multi_target: 'چندهدف', scope: 'حوزه‌ای', unknown: 'نامشخص' };
const TARGET_COLOR: Record<string, string> = { single: 'blue', multi_target: 'orange', scope: 'purple', unknown: 'default' };
const REPORT_TYPE_LABEL: Record<string, string> = { misconfiguration: 'Misconfiguration', vulnerability: 'Vulnerability', incident: 'Incident', malware: 'Malware', unknown: 'Unknown' };
const SEVERITY_COLOR: Record<string, string> = { critical: 'red', high: 'volcano', medium: 'gold', low: 'blue', info: 'cyan', unknown: 'default', none: 'default' };
const FILTER_LABELS: Record<string, string> = {
  month: 'ماه', day: 'روز', reportType: 'نوع گزارش', targetMode: 'نوع هدف', scopeName: 'حوزه', severity: 'شدت', urgency: 'فوریت', finding: 'Finding', organization: 'سازمان', ip: 'IP', port: 'Port', service: 'Service', domain: 'Domain', cve: 'CVE', provider: 'Provider', search: 'جستجو',
};
const SAVED_VIEW_KEY = 'report-intelligence-saved-views-v2';

type ReportFilterState = Omit<ReportFilterParams, 'year'>;
type EntitySelection = { type: 'organization' | 'scope' | 'ip' | 'finding'; value: string };
type SavedView = { id: string; name: string; year: number; filters: ReportFilterState };
type Density = 'compact' | 'comfortable';
type ChatMessage = { role: 'user' | 'assistant'; content: string; result?: ReportCopilotResult };
type ChangeItem = { label: string; value: string; direction: 'up' | 'down' | 'flat'; detail: string };

const ReportsV2: React.FC = () => {
  const queryClient = useQueryClient();
  const initialUrlState = useMemo(() => readReportUrlState(), []);
  const [year, setYear] = useState(initialUrlState.year);
  const [filters, setFilters] = useState<ReportFilterState>(initialUrlState.filters);
  const [activeTab, setActiveTab] = useState('intelligence');
  const [page, setPage] = useState(1);
  const [density, setDensity] = useState<Density>('comfortable');
  const [selectedReport, setSelectedReport] = useState<HistoricalReport | null>(null);
  const [entity, setEntity] = useState<EntitySelection | null>(null);
  const [savedViews, setSavedViews] = useState<SavedView[]>(() => loadSavedViews());
  const [copilotInput, setCopilotInput] = useState('');
  const [chat, setChat] = useState<ChatMessage[]>([]);
  const [lastImport, setLastImport] = useState<ReportImportResult | null>(null);
  const [exporting, setExporting] = useState(false);
  const [organizationPickerOpen, setOrganizationPickerOpen] = useState(false);
  const [organizationActiveIndex, setOrganizationActiveIndex] = useState(-1);

  const yearsQuery = useQuery({ queryKey: ['report-years'], queryFn: api.getReportYears });
  const params = useMemo<ReportFilterParams>(() => ({ year, ...filters }), [year, filters]);
  const facetParams = useMemo<ReportFilterParams>(() => ({ year, month: filters.month, day: filters.day }), [year, filters.month, filters.day]);
  const previousParams = useMemo(() => previousPeriodParams(params), [params]);

  const statsQuery = useQuery({ queryKey: ['report-stats-v2', params], queryFn: () => api.getReportStats(params) });
  const previousStatsQuery = useQuery({ queryKey: ['report-stats-previous-v2', previousParams], queryFn: () => api.getReportStats(previousParams) });
  const facetsQuery = useQuery({ queryKey: ['report-facets-v2', facetParams], queryFn: () => api.getReportFacets(facetParams) });
  const reportsQuery = useQuery({
    queryKey: ['historical-reports-v2', params, page],
    queryFn: () => api.getHistoricalReports({ ...params, page, limit: 20 }),
  });
  const entityQuery = useQuery({
    queryKey: ['report-entity-v2', entity, year, filters.month, filters.day],
    queryFn: () => api.getReportEntitySummary(entity!.type, entity!.value, { year, month: filters.month, day: filters.day }),
    enabled: Boolean(entity),
  });

  const scanQuery = useQuery({ queryKey: ['report-import-scan-v2', year], queryFn: () => api.scanHistoricalReports(year), enabled: false });
  const importMutation = useMutation({
    mutationFn: ({ dryRun }: { dryRun: boolean }) => api.importHistoricalReports(year, dryRun),
    onSuccess: async (result) => {
      setLastImport(result);
      if (!result.dryRun) {
        await refresh();
        antMessage.success(`Import complete: ${result.imported} new, ${result.updated} updated`);
      }
    },
    onError: (error: any) => antMessage.error(error?.response?.data?.detail || error?.message || 'Import failed'),
  });
  const copilotMutation = useMutation({
    mutationFn: api.queryReportCopilot,
    onSuccess: (result) => setChat((current) => [...current, { role: 'assistant', content: result.answer, result }]),
    onError: (error: any) => setChat((current) => [...current, { role: 'assistant', content: error?.response?.data?.detail || error?.message || 'Report query failed.' }]),
  });

  const stats = statsQuery.data;
  const facets = facetsQuery.data;
  const previousStats = previousStatsQuery.data;
  const years = useMemo(
    () => [...new Set([1404, 1403, ...(yearsQuery.data || []).map((item) => item.year)])].sort((a, b) => b - a),
    [yearsQuery.data],
  );
  const scopeLabel = useMemo(() => formatScopeLabel(year, filters), [year, filters]);
  const activeFilters = useMemo(() => Object.entries(filters).filter(([, value]) => value !== undefined && value !== null && value !== ''), [filters]);
  const comparison = useMemo(() => buildComparison(stats, previousStats, params, previousParams), [stats, previousStats, params, previousParams]);

  const scopeLoading =
    statsQuery.isFetching ||
    facetsQuery.isFetching ||
    reportsQuery.isFetching;

  useEffect(() => {
    syncReportUrl(year, filters);
  }, [year, filters]);


  const organizationOptions = useMemo(() => {
    const values = new Map<string, number>();

    const add = (value: unknown, count = 0) => {
      const key = String(value ?? '').trim();
      if (!key) return;
      values.set(key, Math.max(values.get(key) || 0, Number(count) || 0));
    };

    for (const item of facets?.organizations || []) {
      add(item.value, item.count);
    }

    for (const item of stats?.topOrganizations || []) {
      add(item.organization, item.count);
    }

    for (const report of reportsQuery.data?.reports || []) {
      add(report.target?.organization);

      for (const asset of report.affectedSystems || []) {
        add(asset.organization);
      }
    }

    return [...values.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], 'fa'))
      .slice(0, 100)
      .map(([value, count]) => ({
        value,
        label: count ? `${value} · ${count}` : value,
      }));
  }, [
    facets?.organizations,
    stats?.topOrganizations,
    reportsQuery.data?.reports,
  ]);


  const filteredOrganizationOptions = useMemo(() => {
    const query = normalizeFa(String(filters.organization || ''));
    const options = query
      ? organizationOptions.filter((item) => normalizeFa(item.value).includes(query))
      : organizationOptions;

    return options.slice(0, 12);
  }, [organizationOptions, filters.organization]);

  useEffect(() => {
    setOrganizationActiveIndex(-1);
  }, [filters.organization, organizationPickerOpen]);


  function selectOrganization(value: string) {
    setFilter('organization', value);
    setOrganizationPickerOpen(false);
    setOrganizationActiveIndex(-1);
  }

  function setFilter(key: keyof ReportFilterState, value: any) {
    setFilters((current) => ({ ...current, [key]: value === '' || value === null ? undefined : value }));
    setPage(1);
  }

  function toggleFacet(key: 'reportType' | 'targetMode' | 'severity' | 'urgency' | 'finding', value: string) {
    const current = csvValues(String(filters[key] || ''));
    const next = current.includes(value) ? current.filter((item) => item !== value) : [...current, value];
    setFilter(key, next.length ? next.join(',') : undefined);
  }

  function clearFilters() {
    setFilters({});
    setPage(1);
  }

  function saveView() {
    const name = window.prompt('نام این View را وارد کنید:');
    if (!name?.trim()) return;
    const next = [...savedViews, { id: `${Date.now()}`, name: name.trim(), year, filters }];
    setSavedViews(next);
    localStorage.setItem(SAVED_VIEW_KEY, JSON.stringify(next));
    antMessage.success('View ذخیره شد');
  }

  function applySavedView(id: string) {
    const view = savedViews.find((item) => item.id === id);
    if (!view) return;
    setYear(view.year);
    setFilters(view.filters || {});
    setPage(1);
  }

  function removeSavedView(id: string) {
    const next = savedViews.filter((item) => item.id !== id);
    setSavedViews(next);
    localStorage.setItem(SAVED_VIEW_KEY, JSON.stringify(next));
  }

  async function copyShareUrl() {
    try {
      const url = buildReportUrl(year, filters);
      await navigator.clipboard.writeText(url);
      antMessage.success('لینک فیلترهای فعلی کپی شد');
    } catch {
      antMessage.error('کپی لینک انجام نشد');
    }
  }

  async function refresh() {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['report-years'] }),
      queryClient.invalidateQueries({ queryKey: ['report-stats-v2'] }),
      queryClient.invalidateQueries({ queryKey: ['report-stats-previous-v2'] }),
      queryClient.invalidateQueries({ queryKey: ['report-facets-v2'] }),
      queryClient.invalidateQueries({ queryKey: ['historical-reports-v2'] }),
      queryClient.invalidateQueries({ queryKey: ['report-entity-v2'] }),
    ]);
  }

  async function exportCsv() {
    setExporting(true);
    try {
      const first = await api.getHistoricalReports({ ...params, page: 1, limit: 100 });
      const rows = [...first.reports];
      for (let current = 2; current <= first.pagination.pages; current += 1) {
        const batch = await api.getHistoricalReports({ ...params, page: current, limit: 100 });
        rows.push(...batch.reports);
      }
      const csv = toCsv(rows);
      const blob = new Blob([`\ufeff${csv}`], { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `historical-reports-${year}.csv`;
      link.click();
      URL.revokeObjectURL(url);
      antMessage.success(`${rows.length} گزارش export شد`);
    } catch (error: any) {
      antMessage.error(error?.message || 'Export failed');
    } finally {
      setExporting(false);
    }
  }

  function askCopilot(value?: string) {
    const text = String(value ?? copilotInput).trim();
    if (!text || copilotMutation.isPending) return;
    setChat((current) => [...current, { role: 'user', content: text }]);
    setCopilotInput('');
    copilotMutation.mutate(text);
  }

  const filterRail = (
    <aside className="report-v2-filter-rail">
      <div className="report-v2-filter-head">
        <div><span>FACETED SEARCH</span><strong>فیلترهای تحلیلی</strong></div>
        <Button size="small" type="text" disabled={!activeFilters.length} onClick={clearFilters}>پاک‌کردن</Button>
      </div>

      <FacetGroup title="Report type" items={facets?.reportTypes} selected={csvValues(String(filters.reportType || ''))} onToggle={(value) => toggleFacet('reportType', value)} labels={REPORT_TYPE_LABEL} />
      <FacetGroup title="Target mode" items={facets?.targetModes} selected={csvValues(String(filters.targetMode || ''))} onToggle={(value) => toggleFacet('targetMode', value)} labels={TARGET_LABEL} />
      <FacetGroup title="Severity" items={facets?.severities} selected={csvValues(String(filters.severity || ''))} onToggle={(value) => toggleFacet('severity', value)} />
      <FacetGroup title="Urgency" items={facets?.urgencies} selected={csvValues(String(filters.urgency || ''))} onToggle={(value) => toggleFacet('urgency', value)} />
      <FacetGroup title="Top findings" items={facets?.findings?.slice(0, 8)} selected={csvValues(String(filters.finding || ''))} onToggle={(value) => toggleFacet('finding', value)} useLabel />

      <div className="report-v2-filter-group">
        <div className="report-v2-filter-title"><span>Scope</span><small>{facets?.scopes?.length || 0}</small></div>
        <Select
          allowClear
          showSearch
          value={filters.scopeName}
          placeholder="انتخاب حوزه"
          optionFilterProp="label"
          options={(facets?.scopes || []).map((item) => ({ value: String(item.value), label: `${item.value} · ${item.count}` }))}
          onChange={(value) => {
            setFilters((current) => ({ ...current, scopeName: value || undefined, targetMode: value ? 'scope' : current.targetMode }));
            setPage(1);
          }}
        />
      </div>

      <div className="report-v2-filter-group">
        <div className="report-v2-filter-title"><span>Organization</span></div>
        <div className="report-v2-org-picker">
          <Input
            allowClear
            value={filters.organization}
            placeholder="نام سازمان"
            onFocus={() => setOrganizationPickerOpen(true)}
            onBlur={() => setOrganizationPickerOpen(false)}
            onChange={(event) => {
              setFilter('organization', event.target.value || undefined);
              setOrganizationPickerOpen(true);
              setOrganizationActiveIndex(-1);
            }}
            onKeyDown={(event) => {
              if (event.key === 'ArrowDown') {
                event.preventDefault();
                setOrganizationPickerOpen(true);
                setOrganizationActiveIndex((current) =>
                  Math.min(current + 1, filteredOrganizationOptions.length - 1),
                );
                return;
              }

              if (event.key === 'ArrowUp') {
                event.preventDefault();
                setOrganizationActiveIndex((current) => Math.max(current - 1, 0));
                return;
              }

              if (
                event.key === 'Enter' &&
                organizationPickerOpen &&
                organizationActiveIndex >= 0
              ) {
                event.preventDefault();
                const selected = filteredOrganizationOptions[organizationActiveIndex];
                if (selected) selectOrganization(selected.value);
                return;
              }

              if (event.key === 'Escape') {
                setOrganizationPickerOpen(false);
                setOrganizationActiveIndex(-1);
              }
            }}
          />

          {organizationPickerOpen && filteredOrganizationOptions.length ? (
            <div className="report-v2-org-suggestions">
              {filteredOrganizationOptions.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  className={
                    filteredOrganizationOptions[organizationActiveIndex]?.value === option.value
                      ? 'is-active'
                      : ''
                  }
                  onMouseEnter={() =>
                    setOrganizationActiveIndex(
                      filteredOrganizationOptions.findIndex((item) => item.value === option.value),
                    )
                  }
                  onMouseDown={(event) => event.preventDefault()}
                  onClick={() => selectOrganization(option.value)}
                >
                  <span>{option.value}</span>
                  {option.label !== option.value ? <small>{option.label}</small> : null}
                </button>
              ))}
            </div>
          ) : null}
        </div>
      </div>

      <div className="report-v2-filter-group report-v2-advanced-filters">
        <div className="report-v2-filter-title"><span>Technical</span></div>
        <Input allowClear placeholder="IP" value={filters.ip} onChange={(event) => setFilter('ip', event.target.value)} />
        <Input allowClear placeholder="Port" value={String(filters.port || '')} onChange={(event) => setFilter('port', event.target.value)} />
        <Input allowClear placeholder="CVE" value={filters.cve} onChange={(event) => setFilter('cve', event.target.value)} />
        <Input allowClear placeholder="Domain" value={filters.domain} onChange={(event) => setFilter('domain', event.target.value)} />
      </div>

      <div className="report-v2-filter-group">
        <div className="report-v2-filter-title"><span>Saved views</span><Button type="text" size="small" icon={<SaveOutlined />} onClick={saveView}>Save</Button></div>
        {!savedViews.length ? <Text type="secondary" className="report-v2-empty-note">View ذخیره‌شده‌ای ندارید.</Text> : (
          <div className="report-v2-saved-list">
            {savedViews.slice(-6).reverse().map((view) => (
              <div key={view.id}><button type="button" onClick={() => applySavedView(view.id)}>{view.name}</button><button type="button" onClick={() => removeSavedView(view.id)}>×</button></div>
            ))}
          </div>
        )}
      </div>
    </aside>
  );

  const intelligence = (
    <div className="report-v2-workspace-grid">
      {filterRail}
      <main className="report-v2-main">
        {statsQuery.isLoading ? <Card loading /> : stats ? (
          <>
            <section className="report-v2-command-strip">
              <CommandMetric label="Reports" value={stats.summary.total} sub={scopeLabel} icon={<DatabaseOutlined />} />
              <CommandMetric label="Organizations" value={stats.summary.uniqueOrganizations} sub="observed entities" icon={<ApartmentOutlined />} />
              <CommandMetric label="High / Critical" value={stats.summary.highCritical} sub={`${stats.summary.highCriticalPercent}% of scope`} icon={<FireOutlined />} tone="danger" />
              <CommandMetric label="Immediate" value={stats.summary.immediate} sub={`${stats.summary.immediatePercent}% of scope`} icon={<ThunderboltOutlined />} tone="warning" />
              <CommandMetric label="Target IPs" value={stats.summary.uniqueIps} sub={`${stats.summary.qualityWarnings} review flags`} icon={<SafetyCertificateOutlined />} tone="cyan" />
            </section>

            <section className="report-v2-insight-banner">
              <div className="report-v2-insight-title"><LineChartOutlined /><div><span>WHAT CHANGED?</span><strong>{comparison.label}</strong></div></div>
              <div className="report-v2-change-grid">
                {comparison.items.map((item) => <ChangeChip key={item.label} {...item} />)}
              </div>
            </section>

            <Row gutter={[14, 14]}>
              <Col xs={24} xl={14}>
                <Card className="report-v2-card report-v2-chart-card" title="Trend intelligence" extra={<Text type="secondary">{scopeLabel}</Text>}>
                  <Bar
                    data={{
                      labels: stats.byMonth.filter((item) => item.month).map((item) => JALALI_MONTHS[Number(item.month) - 1]),
                      datasets: [{ label: 'Reports', data: stats.byMonth.filter((item) => item.month).map((item) => item.count), backgroundColor: '#3b82f6', borderRadius: 7, maxBarThickness: 42 }],
                    }}
                    options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { grid: { display: false } }, y: { beginAtZero: true, ticks: { precision: 0 } } } }}
                  />
                </Card>
              </Col>
              <Col xs={24} xl={10}>
                <Card className="report-v2-card" title="Target intelligence" extra={<Text type="secondary">report → target model</Text>}>
                  <div className="report-v2-target-stack">
                    {stats.byTargetMode.map((item) => (
                      <button type="button" key={item.mode} onClick={() => { setFilter('targetMode', item.mode); setActiveTab('reports'); }}>
                        <span><Tag color={TARGET_COLOR[item.mode] || 'default'}>{TARGET_LABEL[item.mode] || item.mode}</Tag><small>{targetModeDescription(item.mode)}</small></span>
                        <strong>{item.count}</strong>
                        <i style={{ width: `${stats.summary.total ? (item.count / stats.summary.total) * 100 : 0}%` }} />
                      </button>
                    ))}
                  </div>
                </Card>
              </Col>
            </Row>

            <Row gutter={[14, 14]}>
              <Col xs={24} xxl={15}>
                <Card className="report-v2-card" title="Finding × Month heatmap" extra={<Text type="secondary">تکرار الگوها در طول سال</Text>}>
                  <FindingHeatmap stats={stats} onFinding={(finding) => { setFilter('finding', finding); setActiveTab('reports'); }} />
                </Card>
              </Col>
              <Col xs={24} xxl={9}>
                <Card className="report-v2-card" title="Top scopes" extra={<Tag color="purple">حوزه‌ای</Tag>}>
                  <RankList
                    items={stats.topScopes.slice(0, 8).map((item) => ({ label: item.scope, value: item.count }))}
                    onClick={(value) => setEntity({ type: 'scope', value })}
                  />
                </Card>
              </Col>
            </Row>

            <Row gutter={[14, 14]}>
              <Col xs={24} xl={12}>
                <Card className="report-v2-card" title="Persistent / repeated exposure" extra={<Text type="secondary">organization + finding</Text>}>
                  {!stats.repeatedPatterns.length ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No repeated patterns" /> : (
                    <div className="report-v2-repeat-list">
                      {stats.repeatedPatterns.slice(0, 8).map((item) => (
                        <button type="button" key={`${item.organization}-${item.finding}`} onClick={() => setEntity({ type: 'organization', value: item.organization })}>
                          <span><strong>{item.organization}</strong><small>{item.finding}</small></span><b>{item.count}<small> reports</small></b>
                        </button>
                      ))}
                    </div>
                  )}
                </Card>
              </Col>
              <Col xs={24} xl={12}>
                <Card className="report-v2-card" title="Organizations with most history" extra={<Text type="secondary">click to investigate</Text>}>
                  <RankList
                    items={stats.topOrganizations.slice(0, 8).map((item) => ({ label: item.organization, value: item.count }))}
                    onClick={(value) => setEntity({ type: 'organization', value })}
                  />
                </Card>
              </Col>
            </Row>

            <Row gutter={[14, 14]}>
              <Col xs={24} xl={14}>
                <Card className="report-v2-card" title="Largest multi-asset reports">
                  <div className="report-v2-large-targets">
                    {stats.largestTargets.slice(0, 8).map((item) => (
                      <div key={`${item.reportNumber}-${item.title}`}>
                        <span><Tag color={TARGET_COLOR[item.mode] || 'default'}>{TARGET_LABEL[item.mode] || item.mode}</Tag><strong>{item.scopeName || item.organization || item.reportNumber || item.title}</strong></span>
                        <b>{item.assetCount}<small> assets</small></b>
                      </div>
                    ))}
                  </div>
                </Card>
              </Col>
              <Col xs={24} xl={10}>
                <Card className="report-v2-card" title="Observed IP intelligence">
                  <div className="report-v2-ip-cloud">
                    {stats.topIps.slice(0, 12).map((item) => <button key={item.ip} type="button" onClick={() => setEntity({ type: 'ip', value: item.ip })}><Text code>{item.ip}</Text><span>{item.count}</span></button>)}
                  </div>
                </Card>
              </Col>
            </Row>
          </>
        ) : <Empty description="No report intelligence available" />}
      </main>
    </div>
  );

  const reportsTable = (
    <div className="report-v2-workspace-grid">
      {filterRail}
      <main className="report-v2-main">
        <Card className="report-v2-card report-v2-table-card" title={<Space><FileSearchOutlined /><span>Analyst report explorer</span></Space>} extra={<Space><Segmented size="small" value={density} options={[{ value: 'compact', label: 'Compact' }, { value: 'comfortable', label: 'Comfortable' }]} onChange={(value) => setDensity(value as Density)} /><Button icon={<CloudDownloadOutlined />} loading={exporting} onClick={exportCsv}>CSV</Button></Space>}>
          <Table
            rowKey="_id"
            size={density === 'compact' ? 'small' : 'middle'}
            loading={reportsQuery.isLoading}
            dataSource={reportsQuery.data?.reports || []}
            sticky
            scroll={{ x: 1380 }}
            onRow={(record) => ({ onClick: () => setSelectedReport(record), className: 'report-v2-click-row' })}
            pagination={{ current: page, pageSize: 20, total: reportsQuery.data?.pagination.total || 0, showSizeChanger: false, onChange: setPage, showTotal: (total) => `${total} reports` }}
            columns={[
              { title: 'Date', dataIndex: 'reportDateRaw', width: 105, fixed: 'left' },
              { title: 'Report', dataIndex: 'reportNumber', width: 165, fixed: 'left', render: (value) => <Text code>{value || '—'}</Text> },
              { title: 'Target', width: 210, render: (_, row) => <TargetCell report={row} onEntity={setEntity} /> },
              { title: 'Assets', width: 90, align: 'right' as const, render: (_, row) => <strong>{row.affectedSystems?.length || 0}</strong> },
              { title: 'Finding', width: 220, render: (_, row) => <button className="report-v2-link-button" type="button" onClick={(event) => { event.stopPropagation(); setEntity({ type: 'finding', value: row.finding?.type || 'unknown' }); }}>{row.finding?.name || row.finding?.type || 'unknown'}</button> },
              { title: 'Severity', width: 110, render: (_, row) => <Tag color={SEVERITY_COLOR[row.severity.level] || 'default'}>{row.severity.level} {row.severity.score ?? ''}</Tag> },
              { title: 'Urgency', width: 135, render: (_, row) => <Tag color={row.urgency.normalized === 'immediate' ? 'red' : row.urgency.normalized === 'informational' ? 'blue' : 'default'}>{row.urgency.normalized}</Tag> },
              { title: 'Quality', width: 120, render: (_, row) => <QualityBadge report={row} /> },
              { title: 'Type', dataIndex: 'reportType', width: 145, render: (value) => REPORT_TYPE_LABEL[value] || value },
              { title: 'Title', dataIndex: 'title', width: 320, ellipsis: true },
            ]}
          />
        </Card>
      </main>
    </div>
  );

  const askReports = (
    <Row gutter={[14, 14]}>
      <Col xs={24} xl={8}>
        <Card className="report-v2-card" title={<Space><MessageOutlined /><span>Ask Reports</span></Space>}>
          <Paragraph type="secondary">پرسش‌های آماری مستقیماً روی دیتاست تاریخی MongoDB اجرا می‌شوند. برای تحلیل‌های تکرارشونده از Saved Viewها استفاده کن.</Paragraph>
          <div className="report-v2-question-list">
            {[`در اردیبهشت ${year} چند گزارش داشتیم؟`, `کدام سازمان بیشترین گزارش آسیب پذیری داشته؟`, `چند گزارش حوزه‌ای در سال ${year} داریم؟`, `بیشترین Finding سال ${year} چه بوده؟`, `روی پورت 443 چند گزارش ثبت شده؟`].map((question) => <button key={question} type="button" onClick={() => askCopilot(question)}>{question}</button>)}
          </div>
        </Card>
      </Col>
      <Col xs={24} xl={16}>
        <Card className="report-v2-card report-v2-chat-card">
          <div className="report-v2-chat-log">
            {!chat.length ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="Ask a question about historical reports" /> : chat.map((item, index) => <div key={`${item.role}-${index}`} className={`report-v2-chat-message is-${item.role}`}><span>{item.role === 'user' ? 'YOU' : 'REPORT DATA'}</span><pre>{item.content}</pre></div>)}
            {copilotMutation.isPending ? <div className="report-v2-chat-thinking">Querying historical report dataset…</div> : null}
          </div>
          <Divider />
          <Space.Compact block>
            <Input.TextArea autoSize={{ minRows: 2, maxRows: 5 }} value={copilotInput} onChange={(event) => setCopilotInput(event.target.value)} onPressEnter={(event) => { if (!event.shiftKey) { event.preventDefault(); askCopilot(); } }} placeholder="مثلاً: گزارش‌های حوزه اقتصادی در اردیبهشت چه Findingهایی داشتند؟" />
            <Button type="primary" loading={copilotMutation.isPending} onClick={() => askCopilot()}>Ask</Button>
          </Space.Compact>
        </Card>
      </Col>
    </Row>
  );

  const importPanel = (
    <div className="report-v2-import-stack">
      <ReportUploadReview year={year} onCommitted={refresh} />
      <Divider>Advanced · Server folder</Divider>
      <Row gutter={[14, 14]}>
        <Col xs={24} xl={10}>
          <Card className="report-v2-card" title={<Space><FolderOpenOutlined /><span>Local DOCX folder</span></Space>}>
            <Paragraph type="secondary">برای bulk/admin workflow فایل‌های موجود در REPORTS_ROOT/{year}/ را scan یا dry-run کن.</Paragraph>
            <Space><Button icon={<SearchOutlined />} loading={scanQuery.isFetching} onClick={() => scanQuery.refetch()}>Scan {year}</Button><Button icon={<CheckCircleOutlined />} loading={importMutation.isPending} onClick={() => importMutation.mutate({ dryRun: true })}>Dry run</Button></Space>
            {scanQuery.data ? <Descriptions column={1} size="small" bordered className="report-v2-scan-description"><Descriptions.Item label="Discovered">{scanQuery.data.count}</Descriptions.Item><Descriptions.Item label="Eligible">{scanQuery.data.eligibleCount}</Descriptions.Item><Descriptions.Item label="Oversized">{scanQuery.data.oversizedCount}</Descriptions.Item></Descriptions> : null}
          </Card>
        </Col>
        <Col xs={24} xl={14}>
          <Card className="report-v2-card" title="Folder validation result">
            {!lastImport ? <Empty description="Run a dry run to validate the folder" /> : <><Row gutter={10}><Col span={8}><Statistic title="Would import" value={lastImport.imported} /></Col><Col span={8}><Statistic title="Would update" value={lastImport.updated} /></Col><Col span={8}><Statistic title="Unchanged" value={lastImport.skipped} /></Col></Row><Divider /><Alert showIcon type={lastImport.failed ? 'warning' : 'success'} message={`${lastImport.discovered} files · ${lastImport.failed} failed`} /></>}
          </Card>
        </Col>
      </Row>
    </div>
  );

  return (
    <section className="report-v2-page">
      <header className="report-v2-hero">
        <div className="report-v2-hero-copy">
          <span className="report-v2-eyebrow">HISTORICAL THREAT INTELLIGENCE</span>
          <Title level={2}>Report Intelligence Workspace</Title>
        </div>
        <div className="report-v2-hero-actions">
          <select
            className="report-v2-native-select report-v2-year-select"
            value={year}
            aria-label="سال گزارش"
            onChange={(event) => {
              setYear(Number(event.target.value));
              setFilters({});
              setPage(1);
            }}
          >
            {years.map((value) => (
              <option key={value} value={value}>{value}</option>
            ))}
          </select>

          <select
            className="report-v2-native-select report-v2-month-select"
            value={filters.month ?? ''}
            aria-label="ماه گزارش"
            onChange={(event) => {
              const value = event.target.value ? Number(event.target.value) : undefined;
              setFilters((current) => ({
                ...current,
                month: value,
                day: undefined,
              }));
              setPage(1);
            }}
          >
            <option value="">همه ماه‌ها</option>
            {JALALI_MONTHS.map((label, index) => (
              <option key={label} value={index + 1}>{label}</option>
            ))}
          </select>

          <select
            className="report-v2-native-select report-v2-day-select"
            value={filters.day ?? ''}
            disabled={!filters.month}
            aria-label="روز گزارش"
            onChange={(event) => {
              setFilter('day', event.target.value ? Number(event.target.value) : undefined);
            }}
          >
            <option value="">روز</option>
            {Array.from({ length: 31 }, (_, index) => (
              <option key={index + 1} value={index + 1}>{index + 1}</option>
            ))}
          </select>

          <div
            className={`report-v2-filter-status ${scopeLoading ? 'is-loading' : ''}`}
            aria-live="polite"
          >
            {scopeLoading ? (
              <>
                <i />
                <span>در حال به‌روزرسانی</span>
              </>
            ) : (
              <>
                <strong>{stats?.summary.total ?? reportsQuery.data?.pagination.total ?? 0}</strong>
                <span>گزارش</span>
              </>
            )}
          </div>

          <Tooltip title="کپی لینک همین فیلترها">
            <Button icon={<LinkOutlined />} onClick={copyShareUrl} />
          </Tooltip>

          <Tooltip title="Refresh intelligence">
            <Button
              icon={<ReloadOutlined />}
              loading={scopeLoading}
              onClick={refresh}
            />
          </Tooltip>
        </div>
      </header>

      <div className="report-v2-searchbar">
        <Input allowClear size="large" prefix={<SearchOutlined />} placeholder="جستجو در عنوان، سازمان، حوزه، Finding، توضیحات، CVE، IP، Domain و Service…" value={filters.search} onChange={(event) => setFilter('search', event.target.value)} />
        <div className="report-v2-search-meta"><span>{scopeLabel}</span><span>{stats?.summary.total ?? '—'} matching reports</span></div>
      </div>

      <div className="report-v2-filter-chips">
        {activeFilters.map(([key, value]) => <Tag key={key} closable onClose={() => setFilter(key as keyof ReportFilterState, undefined)}>{FILTER_LABELS[key] || key}: {humanFilterValue(key, value)}</Tag>)}
        {activeFilters.length ? <Button type="link" size="small" onClick={clearFilters}>Clear all</Button> : <Tag>Full dataset scope</Tag>}
      </div>

      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          { key: 'intelligence', label: <span><BarChartOutlined /> Intelligence</span>, children: intelligence },
          { key: 'reports', label: <span><FileSearchOutlined /> Explorer</span>, children: reportsTable },
          { key: 'copilot', label: <span><MessageOutlined /> Ask Reports</span>, children: askReports },
          { key: 'import', label: <span><ImportOutlined /> Import & Review</span>, children: importPanel },
        ]}
      />

      <Drawer width={900} open={Boolean(selectedReport)} onClose={() => setSelectedReport(null)} title={selectedReport?.reportNumber || selectedReport?.title || 'Report detail'}>
        {selectedReport ? <ReportDetail report={selectedReport} onEntity={setEntity} /> : null}
      </Drawer>

      <Drawer width={720} open={Boolean(entity)} onClose={() => setEntity(null)} title={entity ? `${entityTitle(entity.type)} · ${entity.value}` : 'Entity intelligence'}>
        <EntityDrawer entity={entity} data={entityQuery.data} loading={entityQuery.isLoading} onReport={setSelectedReport} onEntity={setEntity} />
      </Drawer>
    </section>
  );
};

const FacetGroup: React.FC<{ title: string; items?: ReportFacetItem[]; selected: string[]; onToggle: (value: string) => void; labels?: Record<string, string>; useLabel?: boolean }> = ({ title, items = [], selected, onToggle, labels = {}, useLabel = false }) => (
  <div className="report-v2-filter-group">
    <div className="report-v2-filter-title"><span>{title}</span><small>{items.length}</small></div>
    <div className="report-v2-facet-list">
      {items.map((item) => {
        const value = String(item.value);
        const active = selected.includes(value);
        return <button key={value} type="button" className={active ? 'is-active' : ''} onClick={() => onToggle(value)}><span><i />{useLabel ? (item.label || value) : (labels[value] || value)}</span><b>{item.count}</b></button>;
      })}
    </div>
  </div>
);

const CommandMetric: React.FC<{ label: string; value: React.ReactNode; sub: string; icon: React.ReactNode; tone?: string }> = ({ label, value, sub, icon, tone = 'primary' }) => (
  <div className={`report-v2-command-metric tone-${tone}`}><span className="report-v2-command-icon">{icon}</span><div><small>{label}</small><strong>{value}</strong><span>{sub}</span></div></div>
);

const ChangeChip: React.FC<ChangeItem> = ({ label, value, direction, detail }) => (
  <div className={`report-v2-change-chip is-${direction}`}><small>{label}</small><strong>{value}</strong><span>{detail}</span></div>
);

const RankList: React.FC<{ items: Array<{ label: string; value: number }>; onClick?: (label: string) => void }> = ({ items, onClick }) => {
  const max = Math.max(1, ...items.map((item) => item.value));
  if (!items.length) return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />;
  return <div className="report-v2-rank-list">{items.map((item, index) => <button type="button" key={item.label} onClick={() => onClick?.(item.label)}><span className="report-v2-rank-index">{String(index + 1).padStart(2, '0')}</span><span className="report-v2-rank-name"><strong>{item.label}</strong><i><b style={{ width: `${(item.value / max) * 100}%` }} /></i></span><span className="report-v2-rank-count">{item.value}</span></button>)}</div>;
};

const FindingHeatmap: React.FC<{ stats: ReportStats; onFinding: (finding: string) => void }> = ({ stats, onFinding }) => {
  const findings = stats.byFinding.slice(0, 6);
  const map = new Map(stats.findingMonthHeatmap.map((item) => [`${item.finding}:${item.month}`, item.count]));
  const max = Math.max(1, ...stats.findingMonthHeatmap.map((item) => item.count));
  if (!findings.length) return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />;
  return (
    <div className="report-v2-heatmap">
      <div className="report-v2-heatmap-head"><span>Finding</span>{JALALI_MONTHS.map((month) => <b key={month}>{month.slice(0, 3)}</b>)}</div>
      {findings.map((finding) => <div className="report-v2-heatmap-row" key={finding.key}><button type="button" onClick={() => onFinding(finding.key)}>{finding.name || finding.key}</button>{JALALI_MONTHS.map((_, index) => { const count = map.get(`${finding.key}:${index + 1}`) || 0; const level = count ? Math.max(0.16, count / max) : 0; return <Tooltip key={index} title={`${count} report(s)`}><span className={count ? 'has-value' : ''} style={{ '--heat': level } as React.CSSProperties}>{count || ''}</span></Tooltip>; })}</div>)}
    </div>
  );
};

const TargetCell: React.FC<{ report: HistoricalReport; onEntity: (value: EntitySelection) => void }> = ({ report, onEntity }) => {
  const mode = report.target?.mode || 'unknown';
  const label = mode === 'scope' ? report.target.scopeName : report.target.organization;
  return <div className="report-v2-target-cell"><Tag color={TARGET_COLOR[mode] || 'default'}>{TARGET_LABEL[mode] || mode}</Tag>{label ? <button type="button" onClick={(event) => { event.stopPropagation(); onEntity({ type: mode === 'scope' ? 'scope' : 'organization', value: label }); }}>{label}</button> : <Text type="secondary">—</Text>}</div>;
};

const QualityBadge: React.FC<{ report: HistoricalReport }> = ({ report }) => {
  const warnings = report.extraction?.warnings || [];
  const recovered = warnings.some((item) => /recovered|resolved_from_table/.test(item));
  if (!warnings.length) return <Tag color="green">Clean</Tag>;
  if (recovered && !report.extraction.organizationMismatch && !report.extraction.ipMismatch) return <Tag color="cyan">Recovered</Tag>;
  return <Tag color="gold">Review</Tag>;
};

const EntityDrawer: React.FC<{ entity: EntitySelection | null; data?: ReportEntitySummary; loading: boolean; onReport: (report: HistoricalReport) => void; onEntity: (value: EntitySelection) => void }> = ({ entity, data, loading, onReport, onEntity }) => {
  if (loading) return <Card loading />;
  if (!entity || !data) return <Empty description="No entity data" />;
  const stats = data.stats;
  return <div className="report-v2-entity-drawer">
    <div className="report-v2-entity-hero"><span>{entityTitle(entity.type).toUpperCase()}</span><Title level={3}>{entity.value}</Title><Text type="secondary">Historical evidence across the selected time scope</Text></div>
    <div className="report-v2-entity-metrics"><Statistic title="Reports" value={data.totalReports} /><Statistic title="Organizations" value={stats.summary.uniqueOrganizations} /><Statistic title="IPs" value={stats.summary.uniqueIps} /><Statistic title="High / Critical" value={stats.summary.highCritical} /></div>
    <Divider />
    <Title level={5}>Top findings</Title>
    <div className="report-v2-entity-tags">{stats.byFinding.slice(0, 8).map((item) => <button type="button" key={item.key} onClick={() => onEntity({ type: 'finding', value: item.key })}><span>{item.name || item.key}</span><b>{item.count}</b></button>)}</div>
    <Title level={5}>Target modes</Title>
    <Space wrap>{stats.byTargetMode.map((item) => <Tag key={item.mode} color={TARGET_COLOR[item.mode] || 'default'}>{TARGET_LABEL[item.mode] || item.mode}: {item.count}</Tag>)}</Space>
    <Divider />
    <Title level={5}>Report timeline</Title>
    <List dataSource={data.recentReports} renderItem={(report) => <List.Item className="report-v2-entity-report" onClick={() => onReport(report)}><List.Item.Meta title={<Space><Text code>{report.reportDateRaw || '—'}</Text><span>{report.title}</span></Space>} description={`${report.finding?.name || report.finding?.type || 'unknown'} · ${report.severity.level}`} /></List.Item>} />
  </div>;
};

const ReportDetail: React.FC<{ report: HistoricalReport; onEntity: (value: EntitySelection) => void }> = ({ report, onEntity }) => {
  const mode = report.target?.mode || 'unknown';
  const organizations = [...new Set((report.affectedSystems || []).map((item) => String(item.organization || '').trim()).filter(Boolean))];
  return <div className="report-v2-detail">
    <div className="report-v2-detail-hero"><div><Tag color={TARGET_COLOR[mode] || 'default'}>{TARGET_LABEL[mode] || mode}</Tag><span>{report.reportType}</span></div><Title level={4}>{report.title}</Title><div className="report-v2-detail-metrics"><span><b>{report.affectedSystems?.length || 0}</b> assets</span><span><b>{organizations.length}</b> organizations</span><span><b>{report.cves?.length || 0}</b> CVEs</span></div></div>
    <Descriptions bordered column={1} size="small">
      <Descriptions.Item label="Date">{report.reportDateRaw || '—'}</Descriptions.Item>
      <Descriptions.Item label="Report number"><Text code>{report.reportNumber || '—'}</Text></Descriptions.Item>
      {mode === 'scope' ? <Descriptions.Item label="Scope"><button className="report-v2-link-button" type="button" onClick={() => report.target.scopeName && onEntity({ type: 'scope', value: report.target.scopeName })}>{report.target.scopeName || report.target.rawOrganization || '—'}</button></Descriptions.Item> : <Descriptions.Item label="Organization"><button className="report-v2-link-button" type="button" onClick={() => report.target.organization && onEntity({ type: 'organization', value: report.target.organization })}>{report.target.organization || '—'}</button></Descriptions.Item>}
      <Descriptions.Item label="IP">{report.target.ip ? <button className="report-v2-link-button" type="button" onClick={() => onEntity({ type: 'ip', value: report.target.ip! })}><Text code>{report.target.ip}</Text></button> : <Text code>{report.target.rawIp || '—'}</Text>}</Descriptions.Item>
      <Descriptions.Item label="Finding"><button className="report-v2-link-button" type="button" onClick={() => onEntity({ type: 'finding', value: report.finding?.type || 'unknown' })}>{report.finding?.name || report.finding?.type || 'unknown'}</button></Descriptions.Item>
      <Descriptions.Item label="Severity"><Tag color={SEVERITY_COLOR[report.severity.level] || 'default'}>{report.severity.level} {report.severity.score ?? ''}</Tag></Descriptions.Item>
      <Descriptions.Item label="Urgency">{report.urgency.raw || report.urgency.normalized}</Descriptions.Item>
      <Descriptions.Item label="Source"><Text code>{report.source.relativePath}</Text></Descriptions.Item>
    </Descriptions>
    {report.extraction.warnings?.length ? <Alert className="report-v2-detail-alert" type="warning" showIcon icon={<WarningOutlined />} message="Extraction review metadata" description={report.extraction.warnings.join(' · ')} /> : null}
    <Title level={5}>Description</Title><Paragraph className="report-v2-preserve">{report.description || 'No description extracted.'}</Paragraph>
    {report.conclusion ? <><Title level={5}>Conclusion</Title><Paragraph className="report-v2-preserve">{report.conclusion}</Paragraph></> : null}
    <Title level={5}>Affected systems</Title>
    <Table size="small" pagination={{ pageSize: 20 }} rowKey={(_, index) => String(index)} dataSource={report.affectedSystems || []} scroll={{ x: 1000 }} columns={[
      { title: 'Organization', dataIndex: 'organization', width: 220, ellipsis: true }, { title: 'IP', dataIndex: 'ip', width: 135 }, { title: 'Domain', dataIndex: 'domain', width: 180 }, { title: 'Port', dataIndex: 'port', width: 80 }, { title: 'Service', dataIndex: 'service', width: 150 }, { title: 'URL / Path', dataIndex: 'url', width: 260, ellipsis: true }, { title: 'Version', dataIndex: 'softwareVersion', width: 110 }, { title: 'Finding', dataIndex: 'reportedFinding', width: 220, ellipsis: true },
    ]} />
    <Title level={5}>Recommendations</Title><List size="small" dataSource={report.recommendations || []} locale={{ emptyText: 'No recommendations extracted.' }} renderItem={(item) => <List.Item>{item}</List.Item>} />
  </div>;
};


const URL_FILTER_KEYS: Array<keyof ReportFilterState> = [
  'month',
  'day',
  'reportType',
  'targetMode',
  'scopeType',
  'scopeName',
  'severity',
  'urgency',
  'finding',
  'organization',
  'ip',
  'port',
  'service',
  'domain',
  'cve',
  'provider',
  'search',
];

function readReportUrlState(): { year: number; filters: ReportFilterState } {
  if (typeof window === 'undefined') return { year: 1404, filters: {} };

  const search = new URLSearchParams(window.location.search);
  const parsedYear = Number(search.get('year'));
  const year = Number.isInteger(parsedYear) && parsedYear > 0 ? parsedYear : 1404;

  const filters: ReportFilterState = {};

  for (const key of URL_FILTER_KEYS) {
    const raw = search.get(key);
    if (raw === null || raw === '') continue;

    if (key === 'month' || key === 'day' || key === 'port') {
      const numeric = Number(raw);
      if (Number.isFinite(numeric)) {
        (filters as Record<string, unknown>)[key] = numeric;
      }
      continue;
    }

    (filters as Record<string, unknown>)[key] = raw;
  }

  return { year, filters };
}

function buildReportUrl(year: number, filters: ReportFilterState) {
  const url = new URL(window.location.href);
  const next = new URLSearchParams();

  next.set('year', String(year));

  for (const key of URL_FILTER_KEYS) {
    const value = filters[key];
    if (value === undefined || value === null || value === '') continue;
    next.set(key, String(value));
  }

  url.search = next.toString();
  return url.toString();
}

function syncReportUrl(year: number, filters: ReportFilterState) {
  if (typeof window === 'undefined') return;

  const next = buildReportUrl(year, filters);
  if (next !== window.location.href) {
    window.history.replaceState(null, '', next);
  }
}

function previousPeriodParams(params: ReportFilterParams): ReportFilterParams {
  const next: ReportFilterParams = { ...params, day: undefined };
  if (params.month) {
    if (params.month > 1) next.month = params.month - 1;
    else { next.year = params.year - 1; next.month = 12; }
  } else {
    next.year = params.year - 1;
  }
  return next;
}

function buildComparison(current?: ReportStats, previous?: ReportStats, params?: ReportFilterParams, previousParams?: ReportFilterParams) {
  const label = params?.month ? `مقایسه با ${JALALI_MONTHS[Number(previousParams?.month || 1) - 1]} ${previousParams?.year}` : `مقایسه با سال ${previousParams?.year}`;
  if (!current || !previous) return { label, items: [] as ChangeItem[] };
  const metrics: Array<[string, number, number]> = [
    ['Reports', current.summary.total, previous.summary.total],
    ['Organizations', current.summary.uniqueOrganizations, previous.summary.uniqueOrganizations],
    ['High / Critical', current.summary.highCritical, previous.summary.highCritical],
    ['Scope-wide', current.byTargetMode.find((item) => item.mode === 'scope')?.count || 0, previous.byTargetMode.find((item) => item.mode === 'scope')?.count || 0],
  ];
  const items: ChangeItem[] = metrics.map(([name, now, before]) => {
    const delta = now - before;
    const pct = before ? Math.round((delta / before) * 100) : (now ? 100 : 0);
    return { label: name, value: `${delta > 0 ? '+' : ''}${delta}`, direction: delta > 0 ? 'up' : delta < 0 ? 'down' : 'flat', detail: `${pct > 0 ? '+' : ''}${pct}%` };
  });
  const currentTop = current.byFinding[0];
  const previousTop = previous.byFinding[0];
  if (currentTop) items.push({ label: 'Top finding', value: currentTop.name || currentTop.key, direction: currentTop.key === previousTop?.key ? 'flat' : 'up', detail: currentTop.key === previousTop?.key ? 'unchanged' : 'changed' });
  return { label, items };
}

function targetModeDescription(mode: string) {
  if (mode === 'scope') return 'حوزه/گروه هدف';
  if (mode === 'multi_target') return 'چند سازمان یا دارایی';
  if (mode === 'single') return 'یک هدف مشخص';
  return 'نیازمند بررسی';
}

function formatScopeLabel(year: number, filters: ReportFilterState) {
  if (filters.month && filters.day) return `${filters.day} ${JALALI_MONTHS[filters.month - 1]} ${year}`;
  if (filters.month) return `${JALALI_MONTHS[filters.month - 1]} ${year}`;
  return `سال ${year}`;
}

function csvValues(value: string) { return value.split(',').map((item) => item.trim()).filter(Boolean); }
function normalizeFa(value: string) { return String(value || '').replace(/ي/g, 'ی').replace(/ك/g, 'ک').replace(/\u200c/g, ' ').replace(/\s+/g, ' ').trim().toLocaleLowerCase('fa'); }
function entityTitle(type: EntitySelection['type']) { return type === 'organization' ? 'Organization' : type === 'scope' ? 'Scope' : type === 'ip' ? 'IP' : 'Finding'; }
function humanFilterValue(key: string, value: unknown) { if (key === 'month') return JALALI_MONTHS[Number(value) - 1] || String(value); if (key === 'targetMode') return csvValues(String(value)).map((item) => TARGET_LABEL[item] || item).join('، '); if (key === 'reportType') return csvValues(String(value)).map((item) => REPORT_TYPE_LABEL[item] || item).join('، '); return String(value); }
function loadSavedViews(): SavedView[] { try { const raw = localStorage.getItem(SAVED_VIEW_KEY); const parsed = raw ? JSON.parse(raw) : []; return Array.isArray(parsed) ? parsed : []; } catch { return []; } }

function toCsv(reports: HistoricalReport[]) {
  const headers = ['date', 'reportNumber', 'reportType', 'targetMode', 'scope', 'organization', 'ip', 'assets', 'finding', 'severity', 'score', 'urgency', 'quality'];
  const lines = reports.map((report) => [report.reportDateRaw, report.reportNumber, report.reportType, report.target?.mode, report.target?.scopeName, report.target?.organization, report.target?.ip, report.affectedSystems?.length || 0, report.finding?.name || report.finding?.type, report.severity?.level, report.severity?.score, report.urgency?.normalized, report.extraction?.warnings?.length ? 'review' : 'clean'].map(csvEscape).join(','));
  return [headers.join(','), ...lines].join('\n');
}
function csvEscape(value: unknown) { const text = String(value ?? ''); return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text; }

export default ReportsV2;
