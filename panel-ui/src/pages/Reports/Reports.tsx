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
  BarChartOutlined,
  CheckCircleOutlined,
  CloudDownloadOutlined,
  FileSearchOutlined,
  FolderOpenOutlined,
  ImportOutlined,
  LinkOutlined,
  MessageOutlined,
  ReloadOutlined,
  SaveOutlined,
  SearchOutlined,
} from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { } from 'react-chartjs-2';
import { api, getErrorMessage } from '../../api/client';
import type {
  HistoricalReport,
  ReportFilterParams,
  ReportImportResult,
} from '../../types/reports';
import ReportUploadReview from './ReportUploadReview';


import {
  JALALI_MONTHS,
  TARGET_LABEL,
  REPORT_TYPE_LABEL,
  SEVERITY_COLOR,
  FILTER_LABELS,
  SAVED_VIEW_KEY,
  type ReportYear,
  type ReportFilterState,
  type EntitySelection,
  type SavedView,
  type Density,
  type ChatMessage,
  readReportUrlState,
  buildReportUrl,
  syncReportUrl,
  previousPeriodParams,
  buildComparison,
  formatScopeLabel,
  csvValues,
  normalizeFa,
  entityTitle,
  humanFilterValue,
  loadSavedViews,
  toCsv,
} from './reportsModel';
import {
  FacetGroup,
  TargetCell,
  QualityBadge,
  EntityDrawer,
  ReportDetail,
} from './ReportWidgets';
import ReportIntelligenceOverview from './ReportIntelligenceOverview';
import './Reports.css';

const { Paragraph, Text, Title } = Typography;

const Reports: React.FC = () => {
  const queryClient = useQueryClient();
  const initialUrlState = useMemo(() => readReportUrlState(), []);
  const [year, setYear] = useState<ReportYear>(initialUrlState.year);
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
  const params = useMemo<ReportFilterParams>(
    () => ({
      ...(year === 'all' ? {} : { year }),
      ...filters,
    }),
    [year, filters],
  );
  const facetParams = useMemo<ReportFilterParams>(
    () => ({
      ...(year === 'all' ? {} : { year }),
      month: filters.month,
      day: filters.day,
    }),
    [year, filters.month, filters.day],
  );
  const previousParams = useMemo(
    () => year === 'all' ? undefined : previousPeriodParams(params),
    [year, params],
  );

  const statsQuery = useQuery({ queryKey: ['report-stats-v2', params], queryFn: () => api.getReportStats(params) });
  const previousStatsQuery = useQuery({
    queryKey: ['report-stats-previous-v2', previousParams],
    queryFn: () => api.getReportStats(previousParams!),
    enabled: Boolean(previousParams),
  });
  const facetsQuery = useQuery({ queryKey: ['report-facets-v2', facetParams], queryFn: () => api.getReportFacets(facetParams) });
  const reportsQuery = useQuery({
    queryKey: ['historical-reports-v2', params, page],
    queryFn: () => api.getHistoricalReports({ ...params, page, limit: 20 }),
  });
  const entityQuery = useQuery({
    queryKey: ['report-entity-v2', entity, year, filters.month, filters.day],
    queryFn: () => api.getReportEntitySummary(entity!.type, entity!.value, {
      ...(year === 'all' ? {} : { year }),
      month: filters.month,
      day: filters.day,
    }),
    enabled: Boolean(entity),
  });

  const scanQuery = useQuery({
    queryKey: ['report-import-scan-v2', year],
    queryFn: () => {
      if (year === 'all') {
        throw new Error('برای Scan باید یک سال مشخص انتخاب شود');
      }
      return api.scanHistoricalReports(year);
    },
    enabled: false,
  });
  const importMutation = useMutation({
    mutationFn: ({ dryRun }: { dryRun: boolean }) => {
      if (year === 'all') {
        throw new Error('برای Import باید یک سال مشخص انتخاب شود');
      }
      return api.importHistoricalReports(year, dryRun);
    },
    onSuccess: async (result) => {
      setLastImport(result);
      if (!result.dryRun) {
        await refresh();
        antMessage.success(`Import complete: ${result.imported} new, ${result.updated} updated`);
      }
    },
    onError: (error) => antMessage.error(getErrorMessage(error, 'Import failed')),
  });
  const copilotMutation = useMutation({
    mutationFn: api.queryReportCopilot,
    onSuccess: (result) => setChat((current) => [...current, { role: 'assistant', content: result.answer, result }]),
    onError: (error) => setChat((current) => [...current, { role: 'assistant', content: getErrorMessage(error, 'Report query failed.') }]),
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


  function selectOrganization(value: string) {
    setFilter('organization', value);
    setOrganizationPickerOpen(false);
    setOrganizationActiveIndex(-1);
  }

  function setFilter<K extends keyof ReportFilterState>(key: K, value: ReportFilterState[K] | '' | null) {
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
    } catch (error) {
      antMessage.error(getErrorMessage(error, 'Export failed'));
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
            onFocus={() => {
              setOrganizationPickerOpen(true);
              setOrganizationActiveIndex(-1);
            }}
            onBlur={() => {
              setOrganizationPickerOpen(false);
              setOrganizationActiveIndex(-1);
            }}
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
          <ReportIntelligenceOverview
            stats={stats}
            scopeLabel={scopeLabel}
            comparison={comparison}
            onTargetMode={(mode) => { setFilter('targetMode', mode); setActiveTab('reports'); }}
            onFinding={(finding) => { setFilter('finding', finding); setActiveTab('reports'); }}
            onEntity={setEntity}
          />
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
      {year === 'all' ? (
        <Alert
          type="info"
          showIcon
          message="برای بررسی و ورود فایل، یک سال مشخص انتخاب کنید"
        />
      ) : (
      <ReportUploadReview year={year} onCommitted={refresh} />
      )}
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
              setYear(
                event.target.value === 'all'
                  ? 'all'
                  : Number(event.target.value),
              );
              setFilters({});
              setPage(1);
            }}
          >
            <option value="all">همه سال‌ها</option>
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

export default Reports;
