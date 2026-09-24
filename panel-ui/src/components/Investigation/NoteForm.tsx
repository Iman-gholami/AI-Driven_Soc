import React, { useState } from 'react';
import { Button, Input } from 'antd';
import SaveStatusNotice from './SaveStatusNotice';
import { useInvestigationSubmission } from './useSubmission';

interface Props {
  alertId: string;
  onRefresh: () => void;
}

// Notes never change triage state, so they do not send an expected version.
const NoteForm: React.FC<Props> = ({ alertId, onRefresh }) => {
  const [text, setText] = useState('');
  const { status, submit } = useInvestigationSubmission(alertId, 'notes');

  const save = async () => {
    const result = await submit({ payload: { text: text.trim() } });
    if (result) setText('');
  };

  return (
    <div className="investigation-form">
      <Input.TextArea
        rows={2}
        maxLength={4000}
        showCount
        placeholder="Add an investigation note"
        value={text}
        onChange={(event) => setText(event.target.value)}
      />
      <SaveStatusNotice status={status} onRefresh={onRefresh} />
      <Button onClick={save} loading={status.state === 'saving'} disabled={!text.trim()}>
        Add note
      </Button>
    </div>
  );
};

export default NoteForm;
