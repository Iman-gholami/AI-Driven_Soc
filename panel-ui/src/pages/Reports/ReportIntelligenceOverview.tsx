import React from 'react';
import { Card, Col, Empty, Row, Tag, Typography } from 'antd';
import {
  ApartmentOutlined,
  DatabaseOutlined,
  FireOutlined,
  LineChartOutlined,
  SafetyCertificateOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import {
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Legend,
  LinearScale,
  Tooltip as ChartTooltip,
} from 'chart.js';
import { Bar } from 'react-chartjs-2';
import type { ReportStats } from '../../types/reports';
import {
  JALALI_MONTHS,
  TARGET_COLOR,
  TARGET_LABEL,
  targetModeDescription,
  type ChangeItem,
  type EntitySelection,
} from './reportsModel';
import { ChangeChip, CommandMetric, FindingHeatmap, RankList } from './ReportWidgets';

ChartJS.register(BarElement, CategoryScale, LinearScale, Legend, ChartTooltip);

const { Text } = Typography;

interface ReportIntelligenceOverviewProps {
  stats: ReportStats;
  scopeLabel: string;
  comparison: { label: string; items: ChangeItem[] };
  onTargetMode: (mode: string) => void;
  onFinding: (finding: string) => void;
  onEntity: (entity: EntitySelection) => void;
}

// Aggregate report intelligence for the current scope: KPIs, period-over-period change and drill-down panels.
const ReportIntelligenceOverview: React.FC<ReportIntelligenceOverviewProps> = ({
  stats,
  scopeLabel,
  comparison,
  onTargetMode,
  onFinding,
  onEntity,
}) => (
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
                <button type="button" key={item.mode} onClick={() => onTargetMode(item.mode)}>
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
            <FindingHeatmap stats={stats} onFinding={onFinding} />
          </Card>
        </Col>
        <Col xs={24} xxl={9}>
          <Card className="report-v2-card" title="Top scopes" extra={<Tag color="purple">حوزه‌ای</Tag>}>
            <RankList
              items={stats.topScopes.slice(0, 8).map((item) => ({ label: item.scope, value: item.count }))}
              onClick={(value) => onEntity({ type: 'scope', value })}
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
                  <button type="button" key={`${item.organization}-${item.finding}`} onClick={() => onEntity({ type: 'organization', value: item.organization })}>
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
              onClick={(value) => onEntity({ type: 'organization', value })}
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
              {stats.topIps.slice(0, 12).map((item) => <button key={item.ip} type="button" onClick={() => onEntity({ type: 'ip', value: item.ip })}><Text code>{item.ip}</Text><span>{item.count}</span></button>)}
            </div>
          </Card>
        </Col>
      </Row>
  </>
);

export default ReportIntelligenceOverview;
