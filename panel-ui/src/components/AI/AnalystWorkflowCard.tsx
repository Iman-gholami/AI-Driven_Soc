import React, { useState } from 'react';
import { Alert, Button, Card, Divider, Input, Radio, Select, Space, Spin, Tag, Typography, message } from 'antd';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, getErrorMessage } from '../../api/client';
import type {
  AnalystCase,
  AnalystOutcome,
  FalsePositiveReason,
} from '../../types/alertMemory';

const { Text, Paragraph } = Typography;

const ACTION_OPTIONS = [
  'Reviewed previous occurrences',
  'Checked source IP',
  'Checked destination asset',
  'Reviewed firewall / network logs',
  'Checked endpoint / EDR',
  'Checked threat intelligence',
  'Contacted asset owner',
  'Escalated to IR',
].map((value) => ({ value, label: value }));

const FALSE_POSITIVE_OPTIONS: Array<{ value: FalsePositiveReason; label: string }> = [
  { value: 'authorized_scanner', label: 'Authorized scanner' },
  { value: 'authorized_testing', label: 'Authorized testing / simulation' },
  { value: 'known_benign_service', label: 'Known benign service' },
  { value: 'rule_too_broad', label: 'Detection rule too broad' },
  { value: 'duplicate_alert', label: 'Duplicate alert' },
  { value: 'expected_behavior', label: 'Expected behavior' },
  { value: 'other', label: 'Other' },
];

const FP_LABELS = Object.fromEntries(FALSE_POSITIVE_OPTIONS.map((item) => [item.value, item.label])) as Record<
  FalsePositiveReason,
  string
>;

// Ant Design renders Select menus in document.body by default. Inside the investigation
// Drawer that can put the popup outside the Drawer's stacking/scrolling context and make
// an otherwise populated Select look like it does not open. Keep each popup next to its
// trigger so both menus remain clickable and visible inside the Drawer.
function selectPopupContainer(trigger: HTMLElement): HTMLElement {
  return trigger.parentElement || document.body;
}

interface Props {
  alertId: string;
}

const AnalystWorkflowCard: React.FC<Props> = ({ alertId }) => {
  const query = useQuery({
    queryKey: ['alert-memory', alertId],
    queryFn: () => api.getAlertMemory(alertId),
  });

  if (query.isLoading) return <Card title="Analyst Investigation"><Spin /></Card>;
  if (query.isError || !query.data) {
    return (
      <Card title="Analyst Investigation">
        <Alert type="error" showIcon message={getErrorMessage(query.error, 'Analyst case could not be loaded')} />
      </Card>
    );
  }

  const { current } = query.data;
  const analystCase = current.analystCase;

  if (current.status === 'closed' || analystCase?.closedAt) {
    return <ClosedCase analystCase={analystCase} />;
  }

  return (
    <WorkflowEditor
      key={analystCase?.updatedAt || analystCase?.startedAt || 'new-case'}
      alertId={alertId}
      status={current.status}
      analystCase={analystCase}
    />
  );
};

function WorkflowEditor({
  alertId,
  status,
  analystCase,
}: {
  alertId: string;
  status: 'new' | 'analyzed' | 'investigating' | 'closed';
  analystCase: AnalystCase | null;
}) {
  const queryClient = useQueryClient();
  const [actionsTaken, setActionsTaken] = useState<string[]>(analystCase?.actionsTaken || []);
  const [note, setNote] = useState(analystCase?.note || '');
  const [finalOutcome, setFinalOutcome] = useState<AnalystOutcome>();
  const [ticketNumber, setTicketNumber] = useState('');
  const [falsePositiveReason, setFalsePositiveReason] = useState<FalsePositiveReason>();
  const [falsePositiveDetails, setFalsePositiveDetails] = useState('');

  const invalidate = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['alert-memory', alertId] }),
      queryClient.invalidateQueries({ queryKey: ['alerts'] }),
      queryClient.invalidateQueries({ queryKey: ['alert', alertId] }),
      queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] }),
    ]);
  };

  const saveMutation = useMutation({
    mutationFn: () => api.saveAlertInvestigation(alertId, {
      actionsTaken,
      ...(note.trim() ? { note: note.trim() } : {}),
    }),
    onSuccess: async () => {
      message.success('Investigation progress saved');
      await invalidate();
    },
    onError: (error) => message.error(getErrorMessage(error, 'Could not save investigation progress')),
  });

  const closeMutation = useMutation({
    mutationFn: () => {
      if (!finalOutcome) throw new Error('Choose the final analyst decision');
      return api.closeAlert(alertId, {
        finalOutcome,
        actionsTaken,
        ...(note.trim() ? { note: note.trim() } : {}),
        ...(ticketNumber.trim() ? { ticketNumber: ticketNumber.trim() } : {}),
        ...(falsePositiveReason ? { falsePositiveReason } : {}),
        ...(falsePositiveDetails.trim() ? { falsePositiveDetails: falsePositiveDetails.trim() } : {}),
      });
    },
    onSuccess: async () => {
      message.success('Alert closed');
      await invalidate();
    },
    onError: (error) => message.error(getErrorMessage(error, 'Could not close alert')),
  });

  const missingTicket = finalOutcome === 'true_positive' && !ticketNumber.trim();
  const missingFpReason = finalOutcome === 'false_positive' && !falsePositiveReason;
  const missingFpDetails =
    finalOutcome === 'false_positive' && falsePositiveReason === 'other' && !falsePositiveDetails.trim();
  const canClose = Boolean(finalOutcome && !missingTicket && !missingFpReason && !missingFpDetails);

  return (
    <Card
      title="Analyst Investigation"
      extra={<Tag color={status === 'investigating' ? 'processing' : 'default'}>{status.toUpperCase()}</Tag>}
    >
      <Paragraph type="secondary">
        Review the AI evidence, record what you checked, then make the final human decision. The AI does not close the alert.
      </Paragraph>

      <Text strong>Actions taken</Text>
      <Select
        mode="tags"
        value={actionsTaken}
        onChange={setActionsTaken}
        options={ACTION_OPTIONS}
        placeholder="Select or type investigation actions"
        tokenSeparators={[',']}
        optionFilterProp="label"
        getPopupContainer={selectPopupContainer}
        style={{ width: '100%', marginTop: 6 }}
        maxTagCount="responsive"
      />

      <Input.TextArea
        value={note}
        onChange={(event) => setNote(event.target.value)}
        maxLength={4000}
        showCount
        rows={3}
        placeholder="Analyst notes: what you checked, evidence found, and investigation context"
        style={{ marginTop: 10 }}
      />

      <Button
        onClick={() => saveMutation.mutate()}
        loading={saveMutation.isPending}
        style={{ marginTop: 10 }}
      >
        {status === 'investigating' ? 'Save progress' : 'Start investigation / Save progress'}
      </Button>

      <Divider />
      <Text strong>Final decision</Text>
      <Radio.Group
        value={finalOutcome}
        onChange={(event) => setFinalOutcome(event.target.value)}
        style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}
      >
        <Radio value="true_positive">
          <Text strong>True positive</Text> — confirmed security incident
        </Radio>
        <Radio value="false_positive">
          <Text strong>False positive</Text> — alert was not a real security incident
        </Radio>
      </Radio.Group>

      {finalOutcome === 'true_positive' && (
        <div style={{ marginTop: 12 }}>
          <Text strong>Ticket number</Text>
          <Input
            value={ticketNumber}
            onChange={(event) => setTicketNumber(event.target.value)}
            maxLength={128}
            placeholder="Required, e.g. SOC-12345"
            status={missingTicket ? 'error' : undefined}
            style={{ marginTop: 6 }}
          />
          {missingTicket && <Text type="danger"> A ticket is required before closing a true positive.</Text>}
        </div>
      )}

      {finalOutcome === 'false_positive' && (
        <div style={{ marginTop: 12 }}>
          <Text strong>Why is this a false positive?</Text>
          <Select
            value={falsePositiveReason}
            onChange={setFalsePositiveReason}
            options={FALSE_POSITIVE_OPTIONS}
            placeholder="Required false-positive reason"
            status={missingFpReason ? 'error' : undefined}
            getPopupContainer={selectPopupContainer}
            style={{ width: '100%', marginTop: 6 }}
          />
          {falsePositiveReason === 'other' && (
            <Input.TextArea
              value={falsePositiveDetails}
              onChange={(event) => setFalsePositiveDetails(event.target.value)}
              maxLength={2000}
              rows={2}
              placeholder="Describe the false-positive reason (required)"
              status={missingFpDetails ? 'error' : undefined}
              style={{ marginTop: 8 }}
            />
          )}
        </div>
      )}

      <Alert
        type="info"
        showIcon
        style={{ marginTop: 14 }}
        message="Closing is the final analyst action"
        description="True positives require a ticket. False positives require a reason. The result becomes historical context for future similar alerts."
      />

      <Button
        type="primary"
        danger
        disabled={!canClose}
        loading={closeMutation.isPending}
        onClick={() => closeMutation.mutate()}
        style={{ marginTop: 12 }}
      >
        Close alert
      </Button>
    </Card>
  );
}

function ClosedCase({ analystCase }: { analystCase: AnalystCase | null }) {
  const outcome = analystCase?.finalOutcome;
  return (
    <Card title="Analyst Investigation" extra={<Tag color="success">CLOSED</Tag>}>
      {!analystCase ? (
        <Text type="secondary">This alert is closed, but no analyst case details are available.</Text>
      ) : (
        <Space direction="vertical" style={{ width: '100%' }} size={8}>
          <div>
            <Text strong>Final decision: </Text>
            <Tag color={outcome === 'true_positive' ? 'red' : 'gold'}>
              {outcome === 'true_positive' ? 'TRUE POSITIVE' : 'FALSE POSITIVE'}
            </Tag>
          </div>
          {outcome === 'true_positive' && (
            <div><Text strong>Ticket: </Text><Text code>{analystCase.ticketNumber || 'missing'}</Text></div>
          )}
          {outcome === 'false_positive' && analystCase.falsePositiveReason && (
            <div>
              <Text strong>False-positive reason: </Text>
              <Text>{FP_LABELS[analystCase.falsePositiveReason]}</Text>
              {analystCase.falsePositiveDetails && (
                <Paragraph style={{ whiteSpace: 'pre-wrap', marginTop: 4 }}>{analystCase.falsePositiveDetails}</Paragraph>
              )}
            </div>
          )}
          {analystCase.actionsTaken.length > 0 && (
            <div>
              <Text strong>Actions taken</Text>
              <div style={{ marginTop: 4 }}>
                {analystCase.actionsTaken.map((action) => <Tag key={action}>{action}</Tag>)}
              </div>
            </div>
          )}
          {analystCase.note && (
            <div>
              <Text strong>Analyst note</Text>
              <Paragraph style={{ whiteSpace: 'pre-wrap', marginTop: 4 }}>{analystCase.note}</Paragraph>
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
