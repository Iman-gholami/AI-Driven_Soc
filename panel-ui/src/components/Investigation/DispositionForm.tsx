import React, { useState } from 'react';
import { Button, Input, Radio, Select, Space, Typography } from 'antd';
import type {
  DispositionAction,
  DispositionOutcome,
  DispositionVocabulary,
  InvestigationView,
} from '../../types/investigation';
import { analysisRunLabel, formatTime } from './investigationFormat';
import SaveStatusNotice from './SaveStatusNotice';
import { useInvestigationSubmission } from './useSubmission';

const { Text } = Typography;

interface Props {
  alertId: string;
  investigation: InvestigationView;
  vocabulary: DispositionVocabulary;
  onRefresh: () => void;
}

// Human disposition. No outcome or action is preselected; options come from the reasons API.
const DispositionForm: React.FC<Props> = ({ alertId, investigation, vocabulary, onRefresh }) => {
  const [outcome, setOutcome] = useState<DispositionOutcome>();
  const [action, setAction] = useState<DispositionAction>();
  const [reasonCodes, setReasonCodes] = useState<string[]>([]);
  const [reasonText, setReasonText] = useState('');
  const [ticketNumber, setTicketNumber] = useState('');
  const { status, submit } = useInvestigationSubmission(alertId, 'disposition');

  const { reviewableAnalysis } = investigation;
  const blockedByAnalysis = reviewableAnalysis.status === 'in_progress';
  const analysisRef = reviewableAnalysis.status === 'available' ? reviewableAnalysis.analysisRef : null;
  const availableReasons = vocabulary.reasons.filter(
    (reason) => !reason.retired && (!outcome || reason.outcomes.includes(outcome)),
  );
  const needsText = reasonCodes.some(
    (code) => vocabulary.reasons.find((reason) => reason.id === code)?.requiresText,
  );
  const textMissing = needsText && !reasonText.trim();
  const ready = Boolean(outcome && action && reasonCodes.length > 0 && !textMissing && !blockedByAnalysis);

  const chooseOutcome = (next: DispositionOutcome) => {
    setOutcome(next);
    // Drop reasons that do not apply to the new outcome instead of silently submitting them.
    setReasonCodes((current) =>
      current.filter((code) =>
        vocabulary.reasons.find((reason) => reason.id === code)?.outcomes.includes(next),
      ),
    );
  };

  const save = async () => {
    if (!outcome || !action) return;
    const result = await submit({
      expectedVersion: investigation.version,
      analysisRef,
      payload: {
        outcome,
        action,
        reasonCodes,
        ...(reasonText.trim() ? { reasonText: reasonText.trim() } : {}),
        ...(ticketNumber.trim() ? { ticketNumber: ticketNumber.trim() } : {}),
      },
    });
    if (result) {
      setOutcome(undefined);
      setAction(undefined);
      setReasonCodes([]);
      setReasonText('');
      setTicketNumber('');
    }
  };

  return (
    <div className="investigation-form">
      <Text type="secondary" className="investigation-form-meta">
        {blockedByAnalysis
          ? 'AI analysis is running; refresh when it completes to record a disposition.'
          : analysisRef
            ? `Linked to ${analysisRunLabel(analysisRef.analysisIndex)} (${formatTime(analysisRef.analyzedAt)}). Saved separately from the AI review.`
            : 'No AI analysis: this disposition will not reference one.'}
      </Text>

      <Text strong>Outcome</Text>
      <Radio.Group
        value={outcome}
        onChange={(event) => chooseOutcome(event.target.value)}
        className="investigation-choice-list"
      >
        {vocabulary.outcomes.map((item) => (
          <Radio key={item.id} value={item.id}>
            <span className="investigation-choice-label">{item.label}</span>
            <span className="investigation-choice-help">{item.description}</span>
          </Radio>
        ))}
      </Radio.Group>

      <Text strong>Action</Text>
      <Radio.Group
        value={action}
        onChange={(event) => setAction(event.target.value)}
        optionType="button"
        buttonStyle="solid"
        size="small"
        options={vocabulary.actions.map((item) => ({
          value: item.id,
          label: item.label,
          title: item.description,
        }))}
      />
      {action && (
        <Text type="secondary">{vocabulary.actions.find((item) => item.id === action)?.description}</Text>
      )}

      <Text strong>Reasons</Text>
      <Select
        mode="multiple"
        placeholder={outcome ? 'Select one or more reasons' : 'Choose an outcome first'}
        disabled={!outcome}
        value={reasonCodes}
        onChange={setReasonCodes}
        options={availableReasons.map((reason) => ({
          value: reason.id,
          label: (
            <span>
              {reason.labelEn} <span className="investigation-fa-label">{reason.labelFa}</span>
            </span>
          ),
        }))}
        optionFilterProp="value"
        style={{ width: '100%' }}
      />
      {needsText && (
        <Input.TextArea
          rows={2}
          maxLength={2000}
          showCount
          placeholder="Describe the reason (required for “Other”)"
          value={reasonText}
          status={textMissing ? 'error' : undefined}
          onChange={(event) => setReasonText(event.target.value)}
        />
      )}
      {!needsText && (
        <Input.TextArea
          rows={1}
          maxLength={2000}
          placeholder="Optional reason details"
          value={reasonText}
          onChange={(event) => setReasonText(event.target.value)}
        />
      )}

      <Input
        maxLength={128}
        placeholder="External ticket number (optional)"
        value={ticketNumber}
        onChange={(event) => setTicketNumber(event.target.value)}
      />
      <SaveStatusNotice status={status} onRefresh={onRefresh} />
      <Space>
        <Button type="primary" onClick={save} loading={status.state === 'saving'} disabled={!ready}>
          Save disposition
        </Button>
      </Space>
    </div>
  );
};

export default DispositionForm;
