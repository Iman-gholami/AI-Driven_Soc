import React from 'react';
import { Alert, Button, Space } from 'antd';

interface NoticeProps {
  description: string;
  onAccept: () => void;
  onDiscard: () => void;
}

const AnalysisChangedNotice: React.FC<NoticeProps> = ({ description, onAccept, onDiscard }) => (
  <Alert
    type="warning"
    showIcon
    message="The AI analysis changed since you started this draft"
    description={description}
    action={
      <Space direction="vertical">
        <Button size="small" type="primary" onClick={onAccept}>
          Keep for new analysis
        </Button>
        <Button size="small" onClick={onDiscard}>
          Discard draft
        </Button>
      </Space>
    }
  />
);

export default AnalysisChangedNotice;
