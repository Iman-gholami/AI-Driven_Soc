import React, { useState } from 'react';
import { Alert, Button, Input, Segmented, Select, Space, Tag, Typography } from 'antd';
import type { InvestigationView, ReviewSection, ReviewStatus } from '../../types/investigation';
import {
  REVIEW_SECTIONS,
  REVIEW_STATUS_OPTIONS,
  SEVERITIES,
  VERDICTS,
  analysisRunLabel,
  formatTime,
} from './investigationFormat';
import SaveStatusNotice from './SaveStatusNotice';
import { useInvestigationSubmission } from './useSubmission';

const { Text } = Typography;

interface Props {
  alertId: string;
  investigation: InvestigationView;
  onRefresh: () => void;
}

const EMPTY_SECTIONS: Record<ReviewSection, ReviewStatus> = {
  verdict: 'not_reviewed',
  severity: 'not_reviewed',
  mitre: 'not_reviewed',
  recommendations: 'not_reviewed',
};

const UNAVAILABLE_REASON: Record<string, string> = {
  no_analysis: 'This alert has no AI analysis to review. You can still record a disposition or a note.',
  analysis_in_progress: 'AI analysis is running. Refresh when it completes to review it.',
  legacy_analysis_without_reference:
    'This alert only has a legacy AI result without a stored run reference, so it cannot be reviewed.',
};

// Review of the latest persisted AI analysis. Every section starts as "Not reviewed"; nothing is preselected.
const AnalystReviewForm: React.FC<Props> = ({ alertId, investigation, onRefresh }) => {
  const [sections, setSections] = useState<Record<ReviewSection, ReviewStatus>>(EMPTY_SECTIONS);
  const [correctedVerdict, setCorrectedVerdict] = useState<string>();
  const [correctedSeverity, setCorrectedSeverity] = useState<string>();
  const [comment, setComment] = useState('');
  const { status, submit } = useInvestigationSubmission(alertId, 'review');

  const { reviewableAnalysis, latestAnalysisReviewed } = investigation;
  if (
    reviewableAnalysis.status !== 'available' ||
    !reviewableAnalysis.analysisRef ||
    !reviewableAnalysis.snapshot
  ) {
    return (
      <Alert
        type="info"
        showIcon
        message="AI review unavailable"
        description={UNAVAILABLE_REASON[reviewableAnalysis.reason || ''] || 'No reviewable AI analysis.'}
        action={
          reviewableAnalysis.status === 'in_progress' ? (
            <Button size="small" onClick={onRefresh}>
              Refresh
            </Button>
          ) : undefined
        }
      />
    );
  }

  const ref = reviewableAnalysis.analysisRef;
  const snapshot = reviewableAnalysis.snapshot;
  const anyReviewed = Object.values(sections).some((value) => value !== 'not_reviewed');
  const verdictMissing = sections.verdict === 'disagree' && !correctedVerdict;
  const severityMissing = sections.severity === 'disagree' && !correctedSeverity;

  const setSection = (section: ReviewSection, value: ReviewStatus) => {
    setSections((current) => ({ ...current, [section]: value }));
    if (section === 'verdict' && value !== 'disagree') setCorrectedVerdict(undefined);
    if (section === 'severity' && value !== 'disagree') setCorrectedSeverity(undefined);
  };

  const save = async () => {
    const result = await submit({
      expectedVersion: investigation.version,
      analysisRef: ref,
      payload: {
        sections,
        corrections: {
          ...(correctedVerdict ? { verdict: correctedVerdict } : {}),
          ...(correctedSeverity ? { severity: correctedSeverity } : {}),
        },
        ...(comment.trim() ? { comment: comment.trim() } : {}),
      },
    });
    if (result) {
      setSections(EMPTY_SECTIONS);
      setCorrectedVerdict(undefined);
      setCorrectedSeverity(undefined);
      setComment('');
    }
  };

  const aiValue: Record<ReviewSection, React.ReactNode> = {
    verdict: <Text code>{snapshot.verdict || 'unknown'}</Text>,
    severity: <Text code>{snapshot.severity || 'unknown'}</Text>,
    mitre: snapshot.attackMapping?.length ? (
      snapshot.attackMapping.map((item) => <Tag key={item.technique}>{item.technique}</Tag>)
    ) : (
      <Text type="secondary">{snapshot.attackMapping ? 'none mapped' : 'unknown'}</Text>
    ),
    recommendations: (
      <Text type="secondary">
        {snapshot.recommendations ? `${snapshot.recommendations.length} step(s)` : 'unknown'}
      </Text>
    ),
  };

  return (
    <div className="investigation-form">
      <Space wrap className="investigation-form-meta">
        <Text strong>Reviewing {analysisRunLabel(ref.analysisIndex)}</Text>
        <Text type="secondary">analyzed {formatTime(ref.analyzedAt)}</Text>
        <Text type="secondary">
          model {snapshot.provider || 'unknown'}/{snapshot.model || 'unknown'}
        </Text>
        {latestAnalysisReviewed === false && <Tag color="warning">Latest analysis not reviewed</Tag>}
        {latestAnalysisReviewed && <Tag color="success">Latest analysis reviewed</Tag>}
      </Space>

      {REVIEW_SECTIONS.map((section) => (
        <div className="investigation-review-row" key={section.id}>
          <div className="investigation-review-label">
            <Text strong>{section.label}</Text>
            <div className="investigation-ai-value">AI: {aiValue[section.id]}</div>
          </div>
          <Segmented
            size="small"
            value={sections[section.id]}
            options={REVIEW_STATUS_OPTIONS}
            onChange={(value) => setSection(section.id, value as ReviewStatus)}
          />
          {section.id === 'verdict' && sections.verdict === 'disagree' && (
            <Select
              size="small"
              placeholder="Corrected verdict"
              value={correctedVerdict}
              onChange={setCorrectedVerdict}
              options={VERDICTS.filter((value) => value !== snapshot.verdict).map((value) => ({
                value,
                label: value,
              }))}
              status={verdictMissing ? 'error' : undefined}
              style={{ minWidth: 160 }}
            />
          )}
          {section.id === 'severity' && sections.severity === 'disagree' && (
            <Select
              size="small"
              placeholder="Corrected severity"
              value={correctedSeverity}
              onChange={setCorrectedSeverity}
              options={SEVERITIES.filter((value) => value !== snapshot.severity).map((value) => ({
                value,
                label: value,
              }))}
              status={severityMissing ? 'error' : undefined}
              style={{ minWidth: 160 }}
            />
          )}
        </div>
      ))}

      <Input.TextArea
        rows={2}
        maxLength={2000}
        showCount
        placeholder="Optional comment on the AI analysis"
        value={comment}
        onChange={(event) => setComment(event.target.value)}
      />
      <SaveStatusNotice status={status} onRefresh={onRefresh} />
      <Button
        type="primary"
        onClick={save}
        loading={status.state === 'saving'}
        disabled={!anyReviewed || verdictMissing || severityMissing}
      >
        Save review
      </Button>
      {!anyReviewed && <Text type="secondary"> Review at least one section to save.</Text>}
    </div>
  );
};

export default AnalystReviewForm;
