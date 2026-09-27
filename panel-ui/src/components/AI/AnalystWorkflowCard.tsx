import React, { useState } from 'react';
import { Alert, Button, Card, Input, Radio, Space, Spin, Tag, Typography, message } from 'antd';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, getErrorMessage } from '../../api/client';
import type { AnalystCase, AnalystOutcome } from '../../types/alertMemory';

const { Text, Paragraph } = Typography;

const LEGACY_FP_LABELS: Record<string, string> = {
  authorized_scanner: 'Authorized scanner',
  authorized_testing: 'Authorized testing / simulation',
  known_benign_service: 'Known benign service',
  rule_too_broad: 'Detection rule too broad',
  duplicate_alert: 'Duplicate alert',
  expected_behavior: 'Expected behavior',
  other: 'Other',
};

interface Props {
  alertId: string;
}

const AnalystWorkflowCard: React.FC<Props> = ({ alertId }) => {
  const query = useQuery({
    queryKey: ['alert-memory', alertId],
    queryFn: () => api.getAlertMemory(alertId),
  });

  if (query.isLoading) return <Card title="Analyst Decision"><Spin /></Card>;
  if (query.isError || !query.data) {
    return (
      <Card title="Analyst Decision">
        <Alert type="error" showIcon message={getErrorMessage(query.error, 'Analyst case could not be loaded')} />
      </Card>
    );
  }

  const { current } = query.data;
  const analystCase = current.analystCase;

  if (current.status === 'closed' || analystCase?.closedAt) {
    return <ClosedCase analystCase={analystCase} />;
  }

  return <DecisionEditor alertId={alertId} />;
};

function DecisionEditor({ alertId }: { alertId: string }) {
  const queryClient = useQueryClient();
  const [finalOutcome, setFinalOutcome] = useState<AnalystOutcome>();
  const [ticketNumber, setTicketNumber] = useState('');
  const [falsePositiveReason, setFalsePositiveReason] = useState('');

  const invalidate = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['alert-memory', alertId] }),
      queryClient.invalidateQueries({ queryKey: ['alerts'] }),
      queryClient.invalidateQueries({ queryKey: ['alert', alertId] }),
      queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] }),
    ]);
  };

  const closeMutation = useMutation({
    mutationFn: () => {
      if (!finalOutcome) throw new Error('Choose the final analyst decision');

      if (finalOutcome === 'true_positive') {
        return api.closeAlert(alertId, {
          finalOutcome,
          ticketNumber: ticketNumber.trim(),
        });
      }

      return api.closeAlert(alertId, {
        finalOutcome,
        // The backend keeps a stable reason code for historical compatibility.
        // The analyst only needs to provide the actual free-text explanation.
        falsePositiveReason: 'other',
        falsePositiveDetails: falsePositiveReason.trim(),
      });
    },
    onSuccess: async () => {
      message.success('Alert closed');
      await invalidate();
    },
    onError: (error) => message.error(getErrorMessage(error, 'Could not close alert')),
  });

  const missingTicket = finalOutcome === 'true_positive' && !ticketNumber.trim();
  const missingFalsePositiveReason = finalOutcome === 'false_positive' && !falsePositiveReason.trim();
  const canClose = Boolean(finalOutcome && !missingTicket && !missingFalsePositiveReason);

  return (
    <Card title="Analyst Decision">
      <Paragraph type="secondary">
        Confirm the final human decision for this alert. A real incident requires a ticket number; a false positive requires a reason.
      </Paragraph>

      <Radio.Group
        value={finalOutcome}
        onChange={(event) => setFinalOutcome(event.target.value)}
        style={{ display: 'flex', flexDirection: 'column', gap: 8 }}
      >
        <Radio value="true_positive">
          <Text strong>True positive</Text> — confirmed security incident
        </Radio>
        <Radio value="false_positive">
          <Text strong>False positive</Text> — alert was not a real security incident
        </Radio>
      </Radio.Group>

      {finalOutcome === 'true_positive' && (
        <div style={{ marginTop: 14 }}>
          <Text strong>Ticket number</Text>
          <Input
            value={ticketNumber}
            onChange={(event) => setTicketNumber(event.target.value)}
            maxLength={128}
            placeholder="Required, e.g. SOC-12345"
            status={missingTicket ? 'error' : undefined}
            style={{ marginTop: 6 }}
          />
          {missingTicket && (
            <Text type="danger" style={{ display: 'block', marginTop: 6 }}>
              Ticket number is required.
            </Text>
          )}
        </div>
      )}

      {finalOutcome === 'false_positive' && (
        <div style={{ marginTop: 14 }}>
          <Text strong>Reason</Text>
          <Input.TextArea
            value={falsePositiveReason}
            onChange={(event) => setFalsePositiveReason(event.target.value)}
            maxLength={2000}
            showCount
            rows={3}
            placeholder="Explain why this alert is a false positive"
            status={missingFalsePositiveReason ? 'error' : undefined}
            style={{ marginTop: 6 }}
          />
          {missingFalsePositiveReason && (
            <Text type="danger" style={{ display: 'block', marginTop: 6 }}>
              A reason is required.
            </Text>
          )}
        </div>
      )}

      <Button
        type="primary"
        danger
        disabled={!canClose}
        loading={closeMutation.isPending}
        onClick={() => closeMutation.mutate()}
        style={{ marginTop: 16 }}
      >
        Close alert
      </Button>
    </Card>
  );
}

function ClosedCase({ analystCase }: { analystCase: AnalystCase | null }) {
  const outcome = analystCase?.finalOutcome;
  const falsePositiveText =
    analystCase?.falsePositiveDetails ||
    (analystCase?.falsePositiveReason ? LEGACY_FP_LABELS[analystCase.falsePositiveReason] : null);

  return (
    <Card title="Analyst Decision" extra={<Tag color="success">CLOSED</Tag>}>
      {!analystCase ? (
        <Text type="secondary">This alert is closed, but no analyst decision details are available.</Text>
      ) : (
        <Space direction="vertical" style={{ width: '100%' }} size={8}>
          <div>
            <Text strong>Final decision: </Text>
            <Tag color={outcome === 'true_positive' ? 'red' : 'gold'}>
              {outcome === 'true_positive' ? 'TRUE POSITIVE' : 'FALSE POSITIVE'}
            </Tag>
          </div>

          {outcome === 'true_positive' && (
            <div>
              <Text strong>Ticket: </Text>
              <Text code>{analystCase.ticketNumber || 'missing'}</Text>
            </div>
          )}

          {outcome === 'false_positive' && (
            <div>
              <Text strong>Reason</Text>
              <Paragraph style={{ whiteSpace: 'pre-wrap', marginTop: 4, marginBottom: 0 }}>
                {falsePositiveText || 'No reason recorded'}
              </Paragraph>
            </div>
          )}

          <Text type="secondary">
            Closed by {analystCase.closedBy?.displayName || 'Analyst'}
            {analystCase.closedAt ? ` · ${formatTime(analystCase.closedAt)}` : ''}
          </Text>
        </Space>
      )}
    </Card>
  );
}

function formatTime(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default AnalystWorkflowCard;
