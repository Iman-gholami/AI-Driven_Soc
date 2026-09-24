import React from 'react';
import { Alert, Card, Descriptions, Spin, Tag } from 'antd';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { api, getErrorMessage } from '../../api/client';
import AnalystReviewForm from './AnalystReviewForm';
import DispositionForm from './DispositionForm';
import InvestigationTimeline from './InvestigationTimeline';
import NoteForm from './NoteForm';
import ReopenForm from './ReopenForm';
import { OUTCOME_COLORS, actionLabel, formatTime, outcomeLabel, reasonLabel } from './investigationFormat';
import './Investigation.css';

interface Props {
  alertId: string;
}

// Human investigation workspace for one alert. Opening it never runs AI analysis.
const InvestigationPanel: React.FC<Props> = ({ alertId }) => {
  const vocabularyQuery = useQuery({
    queryKey: ['investigation-reasons'],
    queryFn: api.getDispositionVocabulary,
    staleTime: 60 * 60 * 1000,
  });
  const investigationQuery = useInfiniteQuery({
    queryKey: ['investigation', alertId],
    queryFn: ({ pageParam }) => api.getInvestigation(alertId, pageParam),
    initialPageParam: null as number | null,
    getNextPageParam: (lastPage) => lastPage.pagination.nextBefore,
  });

  if (investigationQuery.isLoading) return <Spin />;
  if (investigationQuery.isError || !investigationQuery.data) {
    return (
      <Alert
        type="error"
        showIcon
        message={getErrorMessage(investigationQuery.error, 'Investigation could not be loaded')}
      />
    );
  }

  // The first page carries the current state; later pages only add older events.
  const [latest, ...older] = investigationQuery.data.pages;
  const investigation = latest;
  const events = [latest, ...older].flatMap((page) => page.events);
  const { state } = investigation;
  const vocabulary = vocabularyQuery.data;
  const refresh = () => {
    void investigationQuery.refetch();
  };

  return (
    <div className="investigation-panel">
      <Card size="small" title="Triage state">
        <Descriptions size="small" column={2}>
          <Descriptions.Item label="Status">
            <Tag color={state.status === 'closed' ? 'default' : 'processing'}>
              {state.status.toUpperCase()}
            </Tag>
          </Descriptions.Item>
          <Descriptions.Item label="Version">{investigation.version}</Descriptions.Item>
          <Descriptions.Item label="Outcome">
            {state.outcome ? (
              <Tag color={OUTCOME_COLORS[state.outcome]}>{outcomeLabel(vocabulary, state.outcome)}</Tag>
            ) : (
              'No disposition'
            )}
          </Descriptions.Item>
          <Descriptions.Item label="Action">{actionLabel(vocabulary, state.action)}</Descriptions.Item>
          <Descriptions.Item label="Reasons" span={2}>
            {state.reasonCodes.length
              ? state.reasonCodes.map((code) => <Tag key={code}>{reasonLabel(vocabulary, code)}</Tag>)
              : '—'}
          </Descriptions.Item>
          <Descriptions.Item label="Ticket">{state.ticketNumber || '—'}</Descriptions.Item>
          <Descriptions.Item label="Last change">
            {state.updatedBy ? `${state.updatedBy.displayName}, ${formatTime(state.updatedAt)}` : '—'}
          </Descriptions.Item>
        </Descriptions>
        {state.status === 'closed' && (
          <Alert
            type="info"
            showIcon
            message="Local triage is closed. This does not mean the underlying incident was remediated."
          />
        )}
      </Card>

      <Card size="small" title="Analyst review of AI">
        <AnalystReviewForm alertId={alertId} investigation={investigation} onRefresh={refresh} />
      </Card>

      <Card size="small" title="Disposition">
        {vocabulary ? (
          <DispositionForm
            alertId={alertId}
            investigation={investigation}
            vocabulary={vocabulary}
            onRefresh={refresh}
          />
        ) : vocabularyQuery.isError ? (
          <Alert type="error" showIcon message="Disposition reasons could not be loaded" />
        ) : (
          <Spin />
        )}
      </Card>

      <Card size="small" title="Note">
        <NoteForm alertId={alertId} onRefresh={refresh} />
      </Card>

      {state.status === 'closed' && (
        <Card size="small" title="Reopen">
          <ReopenForm alertId={alertId} version={investigation.version} onRefresh={refresh} />
        </Card>
      )}

      <Card size="small" title="Investigation timeline">
        <InvestigationTimeline
          analyses={investigation.analyses}
          events={events}
          vocabulary={vocabulary}
          hasMore={Boolean(investigationQuery.hasNextPage)}
          loadingMore={investigationQuery.isFetchingNextPage}
          onLoadMore={() => void investigationQuery.fetchNextPage()}
        />
      </Card>
    </div>
  );
};

export default InvestigationPanel;
