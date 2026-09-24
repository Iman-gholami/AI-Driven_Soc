import React, { useState } from 'react';
import { Alert, Card, Empty, Segmented, Spin, Table, Tag, Tooltip, Typography } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { api, getErrorMessage } from '../../api/client';
import MetricCard from '../../components/SOC/MetricCard';
import { REVIEW_SECTIONS, outcomeLabel } from '../../components/Investigation/investigationFormat';
import type { AgreementGroup, AnalystFeedbackReport, SectionAgreement } from '../../types/investigation';
import '../Dashboard/Dashboard.css';
import './AnalystFeedback.css';

const { Text, Paragraph } = Typography;
const DAY_MS = 24 * 60 * 60 * 1000;
const RANGES = [
  { value: 7, label: '7 days' },
  { value: 30, label: '30 days' },
  { value: 90, label: '90 days' },
];

function percent(value: number | null | undefined) {
  return value === null || value === undefined ? 'No data' : `${Math.round(value * 1000) / 10}%`;
}

function duration(ms: number | null) {
  if (ms === null) return 'No data';
  const hours = ms / (60 * 60 * 1000);
  if (hours < 1) return `${Math.round(ms / 60000)} min`;
  if (hours < 48) return `${Math.round(hours * 10) / 10} h`;
  return `${Math.round((hours / 24) * 10) / 10} d`;
}

function agreementCell(stats: SectionAgreement) {
  if (!stats.reviewed) return <Text type="secondary">No data</Text>;
  return (
    <Tooltip
      title={`${stats.agree} agree · ${stats.partiallyAgree} partial · ${stats.disagree} disagree · ${stats.notReviewed} not reviewed`}
    >
      <span>
        {percent(stats.strictAgreementRate)} <Text type="secondary">(n={stats.reviewed})</Text>
      </span>
    </Tooltip>
  );
}

function groupColumns(title: string) {
  return [
    {
      title,
      dataIndex: 'key',
      key: 'key',
      render: (key: string) => (key === 'unknown' ? <Tag>unknown</Tag> : <Text code>{key}</Text>),
    },
    { title: 'Reviews', dataIndex: 'reviews', key: 'reviews', width: 90 },
    ...REVIEW_SECTIONS.map((section) => ({
      title: `${section.label} agreement`,
      key: section.id,
      render: (_: unknown, group: AgreementGroup) => agreementCell(group.sections[section.id]),
    })),
  ];
}

// Analyst Feedback: how analysts judged AI output in a reviewed sample. Not calibrated accuracy.
const AnalystFeedback: React.FC = () => {
  const [range, setRange] = useState(() => ({ days: 30, to: new Date().toISOString() }));
  const from = new Date(Date.parse(range.to) - range.days * DAY_MS).toISOString();
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['analyst-feedback', range.days, range.to],
    queryFn: () => api.getAnalystFeedback({ from, to: range.to }),
  });
  const { data: vocabulary } = useQuery({
    queryKey: ['investigation-reasons'],
    queryFn: api.getDispositionVocabulary,
    staleTime: 60 * 60 * 1000,
  });

  return (
    <main className="command-center analyst-feedback">
      <header className="command-header">
        <div>
          <div className="eyebrow">ANALYTICS / HUMAN REVIEW OF AI</div>
          <h1 className="analyst-feedback-title">Analyst Feedback</h1>
          <Paragraph type="secondary" className="analyst-feedback-lead">
            These metrics describe alerts analysts reviewed or dispositioned. They are not calibrated accuracy
            on all SOC traffic: reviewed alerts are a selected sample.
          </Paragraph>
        </div>
        <Segmented
          value={range.days}
          options={RANGES}
          onChange={(value) => setRange({ days: Number(value), to: new Date().toISOString() })}
        />
      </header>

      {isLoading && <Spin />}
      {isError && (
        <Alert
          type="error"
          showIcon
          message={getErrorMessage(error, 'Analyst feedback could not be loaded')}
        />
      )}
      {data && <Report report={data} vocabulary={vocabulary} />}
    </main>
  );
};

function Report({
  report,
  vocabulary,
}: {
  report: AnalystFeedbackReport;
  vocabulary: Parameters<typeof outcomeLabel>[0];
}) {
  const { coverage, agreement, verdictOutcome, falsePositiveShareByRule, timeToDisposition, cohorts } =
    report;
  const cellCount = (verdict: string, outcome: string) =>
    verdictOutcome.cells.find((cell) => cell.verdict === verdict && cell.outcome === outcome)?.count || 0;

  return (
    <>
      <Text type="secondary">
        Window {report.window.from} – {report.window.to} (UTC, half-open interval {report.window.interval})
      </Text>

      <section className="kpi-grid analyst-feedback-kpis">
        <MetricCard
          title="Review coverage"
          value={percent(coverage.coverageRate)}
          detail={`${coverage.reviewedAlerts} of ${coverage.analyzedAlerts} alerts analyzed in the window have a human review`}
          tone="ai"
        />
        <MetricCard
          title="Verdict agreement"
          value={percent(agreement.sections.verdict.strictAgreementRate)}
          detail={`Strict agree over ${agreement.sections.verdict.reviewed} reviewed verdicts; partial ${percent(agreement.sections.verdict.partialAgreementRate)}`}
          tone="success"
        />
        <MetricCard
          title="Median time to disposition"
          value={duration(timeToDisposition.medianMs)}
          detail={`From referenced AI analysis; ${timeToDisposition.eligible} eligible dispositions`}
        />
      </section>

      <Paragraph type="secondary" className="analyst-feedback-note">
        Latest AI run per analyzed alert: {coverage.latestRunReviewed} reviewed,{' '}
        {coverage.latestRunUnreviewed} not reviewed
        {coverage.latestRunUnestablished
          ? `, ${coverage.latestRunUnestablished} cannot be established from stored references`
          : ''}
        . Coverage is alert-level, not per analysis run.
      </Paragraph>

      <Card title="Agreement by section" className="analyst-feedback-card">
        <Paragraph type="secondary">
          Cohort: {cohorts.reviews.description} ({cohorts.reviews.alerts} alerts). Strict agreement = agree /
          (agree + partially agree + disagree); “not reviewed” is excluded.
        </Paragraph>
        <Table
          size="small"
          pagination={false}
          rowKey="section"
          dataSource={REVIEW_SECTIONS.map((section) => ({
            section: section.label,
            ...agreement.sections[section.id],
          }))}
          columns={[
            { title: 'Section', dataIndex: 'section', key: 'section' },
            {
              title: 'Strict agreement',
              key: 'strict',
              render: (_: unknown, row: SectionAgreement) => percent(row.strictAgreementRate),
            },
            {
              title: 'Partial',
              key: 'partial',
              render: (_: unknown, row: SectionAgreement) => percent(row.partialAgreementRate),
            },
            {
              title: 'Disagree',
              key: 'disagree',
              render: (_: unknown, row: SectionAgreement) => percent(row.disagreementRate),
            },
            { title: 'Reviewed (n)', dataIndex: 'reviewed', key: 'reviewed' },
            { title: 'Not reviewed', dataIndex: 'notReviewed', key: 'notReviewed' },
          ]}
        />
      </Card>

      <Card title="AI verdict × analyst outcome" className="analyst-feedback-card">
        <Paragraph type="secondary">
          Uses the AI verdict captured with each effective disposition. Categories are kept as recorded; no
          accuracy is computed across the different label sets. {verdictOutcome.excludedWithoutAnalysis}{' '}
          disposition(s) without an AI snapshot excluded.
        </Paragraph>
        {verdictOutcome.included === 0 ? (
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No data" />
        ) : (
          <Table
            size="small"
            pagination={false}
            rowKey="verdict"
            dataSource={verdictOutcome.verdicts.map((verdict) => ({ verdict }))}
            columns={[
              {
                title: 'AI verdict',
                dataIndex: 'verdict',
                key: 'verdict',
                render: (verdict: string) => <Text code>{verdict}</Text>,
              },
              ...verdictOutcome.outcomes.map((outcome) => ({
                title: outcomeLabel(vocabulary, outcome),
                key: outcome,
                render: (_: unknown, row: { verdict: string }) => cellCount(row.verdict, outcome),
              })),
            ]}
          />
        )}
      </Card>

      <Card title="Top false-positive rules" className="analyst-feedback-card">
        <Paragraph type="secondary">{falsePositiveShareByRule.definition}</Paragraph>
        <Table
          size="small"
          pagination={false}
          rowKey="key"
          locale={{ emptyText: 'No data' }}
          dataSource={falsePositiveShareByRule.rules}
          columns={[
            {
              title: 'Rule',
              dataIndex: 'key',
              key: 'key',
              render: (key: string) => (key === 'unknown' ? <Tag>unknown</Tag> : <Text code>{key}</Text>),
            },
            {
              title: 'FP share',
              key: 'share',
              render: (_: unknown, row: { falsePositiveShare: number | null }) =>
                percent(row.falsePositiveShare),
            },
            { title: 'False positive', dataIndex: 'falsePositive', key: 'fp' },
            { title: 'Determinate (n)', dataIndex: 'determinate', key: 'determinate' },
            { title: 'Inconclusive', dataIndex: 'inconclusive', key: 'inconclusive' },
          ]}
        />
      </Card>

      <Card title="Agreement by provider / model" className="analyst-feedback-card">
        <Paragraph type="secondary">
          Grouped by the model recorded with each reviewed analysis, not the current model.
        </Paragraph>
        <Table
          size="small"
          pagination={false}
          rowKey="key"
          locale={{ emptyText: 'No data' }}
          dataSource={agreement.byModel}
          columns={groupColumns('Provider / model')}
          scroll={{ x: 900 }}
        />
      </Card>

      <Card title="Agreement by detection rule" className="analyst-feedback-card">
        <Table
          size="small"
          rowKey="key"
          locale={{ emptyText: 'No data' }}
          dataSource={agreement.byRule}
          columns={groupColumns('Rule @ revision')}
          scroll={{ x: 900 }}
          pagination={{ pageSize: 10, hideOnSinglePage: true }}
        />
      </Card>
    </>
  );
}

export default AnalystFeedback;
