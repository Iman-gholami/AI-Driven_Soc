import React, { useState } from 'react';
import { Alert, Button, Card, Collapse, Empty, Input, Select, Space, Spin, Tag, Typography, message } from 'antd';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, getErrorMessage } from '../../api/client';
import type { AlertResolution, AnalystOutcome } from '../../types/alertMemory';

const { Text, Paragraph } = Typography;

const OUTCOME_OPTIONS: Array<{ value: AnalystOutcome; label: string }> = [
  { value: 'true_positive', label: 'True positive' },
  { value: 'benign_true_positive', label: 'Benign true positive' },
  { value: 'false_positive', label: 'False positive' },
  { value: 'inconclusive', label: 'Inconclusive' },
];

const OUTCOME_LABELS: Record<AnalystOutcome, string> = Object.fromEntries(
  OUTCOME_OPTIONS.map((item) => [item.value, item.label]),
) as Record<AnalystOutcome, string>;

const OUTCOME_COLORS: Record<AnalystOutcome, string> = {
  true_positive: 'red',
  benign_true_positive: 'green',
  false_positive: 'gold',
  inconclusive: 'default',
};

const MATCH_LABELS: Record<string, string> = {
  same_detection_rule: 'same rule',
  same_signature: 'same signature',
  same_host: 'same host',
  same_event_type: 'same event type',
  same_source_ip: 'same source IP',
  same_destination_ip: 'same destination IP',
  same_network_peer: 'same network peer',
};

interface Props {
  alertId: string;
}

const AlertMemoryCard: React.FC<Props> = ({ alertId }) => {
  const query = useQuery({
    queryKey: ['alert-memory', alertId],
    queryFn: () => api.getAlertMemory(alertId),
  });

  if (query.isLoading) {
    return <Card title="Alert Memory"><Spin /></Card>;
  }

  if (query.isError || !query.data) {
    return (
      <Card title="Alert Memory">
        <Alert
          type="error"
          showIcon
          message={getErrorMessage(query.error, 'Previous alert history could not be loaded')}
        />
      </Card>
    );
  }

  const { summary, occurrences, current, pagination } = query.data;
  const outcomeEntries = Object.entries(summary.outcomeCounts).filter(([, count]) => count > 0);

  return (
    <Card
      title="Alert Memory"
      extra={
        summary.seenBefore
          ? <Tag color="processing">Seen {summary.count} time(s) before</Tag>
          : <Tag>First observed occurrence</Tag>
      }
    >
      <Space wrap size={[6, 6]}>
        {summary.sameRuleCount > 0 && <Tag>{summary.sameRuleCount} same rule</Tag>}
        {summary.sameHostCount > 0 && <Tag>{summary.sameHostCount} same host</Tag>}
        {summary.firstSeen && <Text type="secondary">First: {formatTime(summary.firstSeen)}</Text>}
        {summary.lastSeen && <Text type="secondary">Last: {formatTime(summary.lastSeen)}</Text>}
      </Space>

      {outcomeEntries.length > 0 && (
        <div style={{ marginTop: 10 }}>
          <Text strong>Previous analyst outcomes: </Text>
          <Space wrap size={[4, 4]}>
            {outcomeEntries.map(([key, count]) =>
              key === 'unresolved' ? (
                <Tag key={key}>{count} unresolved</Tag>
              ) : (
                <Tag key={key} color={OUTCOME_COLORS[key as AnalystOutcome]}>
                  {count} {OUTCOME_LABELS[key as AnalystOutcome]}
                </Tag>
              ),
            )}
          </Space>
        </div>
      )}

      <OutcomeEditor
        key={current.analystResult?.resolvedAt || 'new'}
        alertId={alertId}
        current={current.analystResult}
      />

      <div style={{ marginTop: 16 }}>
        <Text strong>Previous occurrences</Text>
        {!occurrences.length ? (
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No related earlier alerts found" />
        ) : (
          <Collapse
            style={{ marginTop: 8 }}
            items={occurrences.map((item) => ({
              key: item.alertId,
              label: (
                <Space wrap>
                  <Tag color={item.match.level === 'exact' ? 'blue' : item.match.level === 'strong' ? 'cyan' : 'default'}>
                    {item.match.level.toUpperCase()}
                  </Tag>
                  <Text>{formatTime(item.occurredAt)}</Text>
                  {item.analystResult?.outcome && (
                    <Tag color={OUTCOME_COLORS[item.analystResult.outcome]}>
                      {OUTCOME_LABELS[item.analystResult.outcome]}
                    </Tag>
                  )}
                  {!item.analystResult && item.aiResult.verdict && <Tag>AI: {item.aiResult.verdict}</Tag>}
                </Space>
              ),
              children: (
                <div>
                  <Space wrap size={[4, 4]}>
                    {item.match.reasons.map((reason) => (
                      <Tag key={reason}>{MATCH_LABELS[reason] || reason.replaceAll('_', ' ')}</Tag>
                    ))}
                  </Space>
                  <Paragraph style={{ marginTop: 8, marginBottom: 4 }}>
                    <Text strong>AI result: </Text>
                    {item.aiResult.verdict || 'unknown'}
                    {item.aiResult.severity ? ` · ${item.aiResult.severity}` : ''}
                  </Paragraph>
                  {item.aiResult.summary && (
                    <Paragraph type="secondary" ellipsis={{ rows: 3, expandable: true, symbol: 'more' }}>
                      {item.aiResult.summary}
                    </Paragraph>
                  )}
                  {item.analystResult ? (
                    <div>
                      <Text strong>Analyst result: </Text>
                      <Tag color={OUTCOME_COLORS[item.analystResult.outcome]}>
                        {OUTCOME_LABELS[item.analystResult.outcome]}
                      </Tag>
                      {item.analystResult.note && (
                        <Paragraph style={{ whiteSpace: 'pre-wrap', marginTop: 6 }}>
                          {item.analystResult.note}
                        </Paragraph>
                      )}
                      <Text type="secondary">
                        {item.analystResult.resolvedBy?.displayName || 'Analyst'}
                        {item.analystResult.resolvedAt ? ` · ${formatTime(item.analystResult.resolvedAt)}` : ''}
                        {item.analystResult.ticketNumber ? ` · ticket ${item.analystResult.ticketNumber}` : ''}
                      </Text>
                    </div>
                  ) : (
                    <Text type="secondary">No analyst outcome was recorded for this occurrence.</Text>
                  )}
                </div>
              ),
            }))}
          />
        )}
        {pagination.candidateLimitReached && (
          <Alert
            style={{ marginTop: 8 }}
            type="warning"
            showIcon
            message="The history candidate cap was reached; this is a ranked recent subset."
          />
        )}
      </div>
    </Card>
  );
};

function OutcomeEditor({
  alertId,
  current,
}: {
  alertId: string;
  current: AlertResolution | null;
}) {
  const queryClient = useQueryClient();
  const [outcome, setOutcome] = useState<AnalystOutcome | undefined>(current?.outcome);
  const [note, setNote] = useState(current?.note || '');
  const [ticketNumber, setTicketNumber] = useState(current?.ticketNumber || '');

  const mutation = useMutation({
    mutationFn: () => {
      if (!outcome) throw new Error('Choose an outcome first');
      return api.saveAlertOutcome(alertId, {
        outcome,
        ...(note.trim() ? { note: note.trim() } : {}),
        ...(ticketNumber.trim() ? { ticketNumber: ticketNumber.trim() } : {}),
      });
    },
    onSuccess: async () => {
      message.success(current ? 'Analyst outcome updated' : 'Analyst outcome saved');
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['alert-memory', alertId] }),
        queryClient.invalidateQueries({ queryKey: ['alerts'] }),
      ]);
    },
    onError: (error) => message.error(getErrorMessage(error, 'Could not save analyst outcome')),
  });

  return (
    <Card size="small" title={current ? 'Current analyst outcome' : 'Record analyst outcome'} style={{ marginTop: 14 }}>
      {current && (
        <Space wrap style={{ marginBottom: 10 }}>
          <Tag color={OUTCOME_COLORS[current.outcome]}>{OUTCOME_LABELS[current.outcome]}</Tag>
          <Text type="secondary">
            {current.resolvedBy?.displayName || 'Analyst'}
            {current.resolvedAt ? ` · ${formatTime(current.resolvedAt)}` : ''}
          </Text>
        </Space>
      )}
      <Space direction="vertical" style={{ width: '100%' }}>
        <Select
          value={outcome}
          onChange={setOutcome}
          placeholder="Final analyst outcome"
          options={OUTCOME_OPTIONS}
          style={{ width: '100%' }}
        />
        <Input.TextArea
          value={note}
          onChange={(event) => setNote(event.target.value)}
          maxLength={2000}
          rows={2}
          placeholder="Optional analyst note — what was concluded and why?"
        />
        <Input
          value={ticketNumber}
          onChange={(event) => setTicketNumber(event.target.value)}
          maxLength={128}
          placeholder="External ticket number (optional)"
        />
        <Button
          type="primary"
          disabled={!outcome}
          loading={mutation.isPending}
          onClick={() => mutation.mutate()}
        >
          {current ? 'Update outcome' : 'Save outcome'}
        </Button>
      </Space>
    </Card>
  );
}

function formatTime(value: string | null) {
  if (!value) return 'unknown time';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default AlertMemoryCard;
