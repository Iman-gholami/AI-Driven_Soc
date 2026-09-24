import React from 'react';
import { Alert, Card, Collapse, Empty, Space, Spin, Tag, Typography } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { api, getErrorMessage } from '../../api/client';
import type { AnalystOutcome } from '../../types/alertMemory';
import AnalystWorkflowCard from './AnalystWorkflowCard';

const { Text, Paragraph } = Typography;

const OUTCOME_LABELS: Record<AnalystOutcome, string> = {
  true_positive: 'True positive',
  false_positive: 'False positive',
};

const OUTCOME_COLORS: Record<AnalystOutcome, string> = {
  true_positive: 'red',
  false_positive: 'gold',
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

const FP_REASON_LABELS: Record<string, string> = {
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

  const { summary, occurrences, pagination } = query.data;

  return (
    <>
      <Card
        title="Alert Memory"
        extra={
          summary.seenBefore
            ? <Tag color="processing">Seen {summary.count} time(s) before</Tag>
            : <Tag>First observed occurrence</Tag>
        }
      >
        <Paragraph type="secondary">
          Previous similar alerts and their final human outcomes. Use this as investigation context, not as an automatic decision.
        </Paragraph>

        <Space wrap size={[6, 6]}>
          {summary.sameRuleCount > 0 && <Tag>{summary.sameRuleCount} same rule</Tag>}
          {summary.sameHostCount > 0 && <Tag>{summary.sameHostCount} same host</Tag>}
          {summary.firstSeen && <Text type="secondary">First: {formatTime(summary.firstSeen)}</Text>}
          {summary.lastSeen && <Text type="secondary">Last: {formatTime(summary.lastSeen)}</Text>}
        </Space>

        {summary.count > 0 && (
          <div style={{ marginTop: 10 }}>
            <Text strong>Previous final outcomes: </Text>
            <Space wrap size={[4, 4]}>
              {summary.outcomeCounts.true_positive > 0 && (
                <Tag color="red">{summary.outcomeCounts.true_positive} true positive</Tag>
              )}
              {summary.outcomeCounts.false_positive > 0 && (
                <Tag color="gold">{summary.outcomeCounts.false_positive} false positive</Tag>
              )}
              {summary.outcomeCounts.unresolved > 0 && (
                <Tag>{summary.outcomeCounts.unresolved} unresolved</Tag>
              )}
            </Space>
          </div>
        )}

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
                    {item.analystResult?.finalOutcome && (
                      <Tag color={OUTCOME_COLORS[item.analystResult.finalOutcome]}>
                        {OUTCOME_LABELS[item.analystResult.finalOutcome]}
                      </Tag>
                    )}
                    {!item.analystResult?.finalOutcome && item.aiResult.verdict && <Tag>AI: {item.aiResult.verdict}</Tag>}
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
                    {item.analystResult?.finalOutcome ? (
                      <div>
                        <Text strong>Final analyst decision: </Text>
                        <Tag color={OUTCOME_COLORS[item.analystResult.finalOutcome]}>
                          {OUTCOME_LABELS[item.analystResult.finalOutcome]}
                        </Tag>
                        {item.analystResult.finalOutcome === 'true_positive' && item.analystResult.ticketNumber && (
                          <Text> ticket {item.analystResult.ticketNumber}</Text>
                        )}
                        {item.analystResult.finalOutcome === 'false_positive' && item.analystResult.falsePositiveReason && (
                          <Paragraph style={{ marginTop: 6, marginBottom: 4 }}>
                            <Text strong>False-positive reason: </Text>
                            {FP_REASON_LABELS[item.analystResult.falsePositiveReason] || item.analystResult.falsePositiveReason}
                            {item.analystResult.falsePositiveDetails ? ` — ${item.analystResult.falsePositiveDetails}` : ''}
                          </Paragraph>
                        )}
                        {item.analystResult.actionsTaken.length > 0 && (
                          <div style={{ marginTop: 6 }}>
                            <Text strong>Actions: </Text>
                            {item.analystResult.actionsTaken.map((action) => <Tag key={action}>{action}</Tag>)}
                          </div>
                        )}
                        {item.analystResult.note && (
                          <Paragraph style={{ whiteSpace: 'pre-wrap', marginTop: 6 }}>
                            {item.analystResult.note}
                          </Paragraph>
                        )}
                        <Text type="secondary">
                          {item.analystResult.closedBy?.displayName || 'Analyst'}
                          {item.analystResult.closedAt ? ` · ${formatTime(item.analystResult.closedAt)}` : ''}
                        </Text>
                      </div>
                    ) : item.analystResult ? (
                      <Text type="secondary">A previous investigation exists, but it was not closed with a final decision.</Text>
                    ) : (
                      <Text type="secondary">No analyst investigation was recorded for this occurrence.</Text>
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
      <AnalystWorkflowCard alertId={alertId} />
    </>
  );
};

function formatTime(value: string | null) {
  if (!value) return 'unknown time';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default AlertMemoryCard;
