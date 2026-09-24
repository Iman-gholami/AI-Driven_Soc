import React from 'react';
import { Alert, Button } from 'antd';
import type { SaveStatus } from './useSubmission';

interface Props {
  status: SaveStatus;
  onRefresh: () => void;
}

// Explicit per-form save feedback. On conflicts the draft is kept; the analyst refreshes and re-submits.
const SaveStatusNotice: React.FC<Props> = ({ status, onRefresh }) => {
  if (status.state === 'idle') return null;
  if (status.state === 'saving')
    return <Alert className="investigation-save-status" type="info" showIcon message="Saving…" />;
  if (status.state === 'saved') {
    return (
      <Alert
        className="investigation-save-status"
        type="success"
        showIcon
        message={
          status.replayed
            ? `Already saved as event #${status.sequence}`
            : `Saved as event #${status.sequence}`
        }
      />
    );
  }

  const { error } = status;
  const conflict = error.status === 409;
  return (
    <Alert
      className="investigation-save-status"
      type={conflict ? 'warning' : 'error'}
      showIcon
      message={conflict ? 'Not saved: the investigation changed' : 'Not saved'}
      description={
        <>
          <div>{error.message}</div>
          {error.issues.length > 0 && (
            <ul className="investigation-issues">
              {error.issues.map((issue) => (
                <li key={`${issue.path}-${issue.message}`}>
                  {issue.path ? `${issue.path}: ` : ''}
                  {issue.message}
                </li>
              ))}
            </ul>
          )}
          {conflict && (
            <div>Your input is kept. Refresh to see the latest state, check it, then save again.</div>
          )}
        </>
      }
      action={
        conflict ? (
          <Button size="small" onClick={onRefresh}>
            Refresh
          </Button>
        ) : undefined
      }
    />
  );
};

export default SaveStatusNotice;
