import React, { useState } from 'react';
import { Button, Input, Typography } from 'antd';
import SaveStatusNotice from './SaveStatusNotice';
import { useInvestigationSubmission } from './useSubmission';

const { Text } = Typography;

interface Props {
  alertId: string;
  version: number;
  onRefresh: () => void;
}

// Reopening clears the current disposition; notes and AI reviews stay in the history.
const ReopenForm: React.FC<Props> = ({ alertId, version, onRefresh }) => {
  const [reason, setReason] = useState('');
  const { status, submit } = useInvestigationSubmission(alertId, 'reopen');

  const save = async () => {
    const result = await submit({ expectedVersion: version, payload: { reason: reason.trim() } });
    if (result) setReason('');
  };

  return (
    <div className="investigation-form">
      <Text type="secondary">
        Reopening clears the current disposition, outcome and ticket. Notes and AI reviews are kept.
      </Text>
      <Input.TextArea
        rows={2}
        maxLength={2000}
        showCount
        placeholder="Why is this alert being reopened?"
        value={reason}
        onChange={(event) => setReason(event.target.value)}
      />
      <SaveStatusNotice status={status} onRefresh={onRefresh} />
      <Button danger onClick={save} loading={status.state === 'saving'} disabled={!reason.trim()}>
        Reopen triage
      </Button>
    </div>
  );
};

export default ReopenForm;
