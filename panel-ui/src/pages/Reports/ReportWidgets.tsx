import React from 'react';
import {
  Alert,
  Card,
  Descriptions,
  Divider,
  Empty,
  List,
  Space,
  Statistic,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import {
  WarningOutlined,
} from '@ant-design/icons';
import type {
  HistoricalReport,
  ReportEntitySummary,
  ReportFacetItem,
  ReportStats,
} from '../../types/reports';
import {
  JALALI_MONTHS,
  TARGET_LABEL,
  TARGET_COLOR,
  SEVERITY_COLOR,
  type EntitySelection,
  type ChangeItem,
  entityTitle,
} from './reportsModel';

const { Paragraph, Text, Title } = Typography;

export const FacetGroup: React.FC<{ title: string; items?: ReportFacetItem[]; selected: string[]; onToggle: (value: string) => void; labels?: Record<string, string>; useLabel?: boolean }> = ({ title, items = [], selected, onToggle, labels = {}, useLabel = false }) => (
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

export const CommandMetric: React.FC<{ label: string; value: React.ReactNode; sub: string; icon: React.ReactNode; tone?: string }> = ({ label, value, sub, icon, tone = 'primary' }) => (
  <div className={`report-v2-command-metric tone-${tone}`}><span className="report-v2-command-icon">{icon}</span><div><small>{label}</small><strong>{value}</strong><span>{sub}</span></div></div>
);

export const ChangeChip: React.FC<ChangeItem> = ({ label, value, direction, detail }) => (
  <div className={`report-v2-change-chip is-${direction}`}><small>{label}</small><strong>{value}</strong><span>{detail}</span></div>
);

export const RankList: React.FC<{ items: Array<{ label: string; value: number }>; onClick?: (label: string) => void }> = ({ items, onClick }) => {
  const max = Math.max(1, ...items.map((item) => item.value));
  if (!items.length) return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />;
  return <div className="report-v2-rank-list">{items.map((item, index) => <button type="button" key={item.label} onClick={() => onClick?.(item.label)}><span className="report-v2-rank-index">{String(index + 1).padStart(2, '0')}</span><span className="report-v2-rank-name"><strong>{item.label}</strong><i><b style={{ width: `${(item.value / max) * 100}%` }} /></i></span><span className="report-v2-rank-count">{item.value}</span></button>)}</div>;
};

export const FindingHeatmap: React.FC<{ stats: ReportStats; onFinding: (finding: string) => void }> = ({ stats, onFinding }) => {
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

export const TargetCell: React.FC<{ report: HistoricalReport; onEntity: (value: EntitySelection) => void }> = ({ report, onEntity }) => {
  const mode = report.target?.mode || 'unknown';
  const label = mode === 'scope' ? report.target.scopeName : report.target.organization;
  return <div className="report-v2-target-cell"><Tag color={TARGET_COLOR[mode] || 'default'}>{TARGET_LABEL[mode] || mode}</Tag>{label ? <button type="button" onClick={(event) => { event.stopPropagation(); onEntity({ type: mode === 'scope' ? 'scope' : 'organization', value: label }); }}>{label}</button> : <Text type="secondary">—</Text>}</div>;
};

export const QualityBadge: React.FC<{ report: HistoricalReport }> = ({ report }) => {
  const warnings = report.extraction?.warnings || [];
  const recovered = warnings.some((item) => /recovered|resolved_from_table/.test(item));
  if (!warnings.length) return <Tag color="green">Clean</Tag>;
  if (recovered && !report.extraction.organizationMismatch && !report.extraction.ipMismatch) return <Tag color="cyan">Recovered</Tag>;
  return <Tag color="gold">Review</Tag>;
};

export const EntityDrawer: React.FC<{ entity: EntitySelection | null; data?: ReportEntitySummary; loading: boolean; onReport: (report: HistoricalReport) => void; onEntity: (value: EntitySelection) => void }> = ({ entity, data, loading, onReport, onEntity }) => {
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

export const ReportDetail: React.FC<{ report: HistoricalReport; onEntity: (value: EntitySelection) => void }> = ({ report, onEntity }) => {
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
