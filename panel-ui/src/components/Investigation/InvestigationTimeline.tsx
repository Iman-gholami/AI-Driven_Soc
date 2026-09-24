import React from 'react';
import { Button, Empty, Tag, Timeline, Typography } from 'antd';
import type {
  AnalysisSummaryEntry,
  DispositionVocabulary,
  InvestigationEvent,
  ReviewSection,
  ReviewStatus,
} from '../../types/investigation';
import {
  OUTCOME_COLORS,
  REVIEW_SECTIONS,
  actionLabel,
  analysisRunLabel,
  formatTime,
  outcomeLabel,
  reasonLabel,
} from './investigationFormat';

const { Text, Paragraph } = Typography;

interface Props {
  analyses: AnalysisSummaryEntry[];
  events: InvestigationEvent[];
  vocabulary?: DispositionVocabulary;
  hasMore: boolean;
  loadingMore: boolean;
  onLoadMore: () => void;
}

type Item =
  | { kind: 'analysis'; at: number; order: number; analysis: AnalysisSummaryEntry }
  | { kind: 'event'; at: number; order: number; event: InvestigationEvent };

const STATUS_COLORS: Record<ReviewStatus, string> = {
  agree: 'success',
  partially_agree: 'warning',
  disagree: 'error',
  not_reviewed: 'default',
};

function time(value: string | null) {
  const parsed = value ? Date.parse(value) : NaN;
  return Number.isNaN(parsed) ? 0 : parsed;
}

function EventBody({ event, vocabulary }: { event: InvestigationEvent; vocabulary?: DispositionVocabulary }) {
  const payload = event.payload as Record<string, unknown>;
  const ref = event.context.analysisRef;

  if (event.type === 'ai_review') {
    const sections = payload.sections as Record<ReviewSection, ReviewStatus>;
    const corrections = (payload.corrections || {}) as { verdict?: string; severity?: string };
    const snapshot = event.context.analysisSnapshot;
    return (
      <>
        <Text strong>Reviewed {analysisRunLabel(ref?.analysisIndex)}</Text>
        <Text type="secondary">
          {' '}
          (AI said {snapshot?.verdict || 'unknown'} / {snapshot?.severity || 'unknown'} ·{' '}
          {snapshot?.provider || 'unknown'}/{snapshot?.model || 'unknown'})
        </Text>
        <div className="investigation-timeline-tags">
          {REVIEW_SECTIONS.map((section) => (
            <Tag key={section.id} color={STATUS_COLORS[sections?.[section.id] || 'not_reviewed']}>
              {section.label}: {(sections?.[section.id] || 'not_reviewed').replace('_', ' ')}
            </Tag>
          ))}
        </div>
        {(corrections.verdict || corrections.severity) && (
          <Text>Corrected to {[corrections.verdict, corrections.severity].filter(Boolean).join(' / ')}</Text>
        )}
        {typeof payload.comment === 'string' && (
          <Paragraph className="investigation-timeline-text">{payload.comment}</Paragraph>
        )}
      </>
    );
  }

  if (event.type === 'disposition') {
    const reasons = Array.isArray(payload.reasonCodes) ? (payload.reasonCodes as string[]) : [];
    return (
      <>
        <Text strong>Disposition </Text>
        <Tag color={OUTCOME_COLORS[String(payload.outcome)] || 'default'}>
          {outcomeLabel(vocabulary, String(payload.outcome))}
        </Tag>
        <Tag>{actionLabel(vocabulary, String(payload.action))}</Tag>
        {typeof payload.ticketNumber === 'string' && <Tag color="blue">Ticket {payload.ticketNumber}</Tag>}
        <div className="investigation-timeline-tags">
          {reasons.map((code) => (
            <Tag key={code}>{reasonLabel(vocabulary, code)}</Tag>
          ))}
        </div>
        {typeof payload.reasonText === 'string' && (
          <Paragraph className="investigation-timeline-text">{payload.reasonText}</Paragraph>
        )}
        <Text type="secondary">
          {ref ? `Based on ${analysisRunLabel(ref.analysisIndex)}` : 'No AI analysis referenced'}
        </Text>
      </>
    );
  }

  if (event.type === 'note') {
    return (
      <>
        <Text strong>Note</Text>
        <Paragraph className="investigation-timeline-text">{String(payload.text || '')}</Paragraph>
      </>
    );
  }

  if (event.type === 'reopened') {
    return (
      <>
        <Text strong>Reopened</Text>
        <Paragraph className="investigation-timeline-text">{String(payload.reason || '')}</Paragraph>
      </>
    );
  }

  return <Text strong>{event.type.replace('_', ' ')}</Text>;
}

// Stored AI run summaries and investigation events, newest first. Order is by time, then event sequence /
// run index, so items sharing a timestamp keep a stable order.
const InvestigationTimeline: React.FC<Props> = ({
  analyses,
  events,
  vocabulary,
  hasMore,
  loadingMore,
  onLoadMore,
}) => {
  const oldestLoadedEvent = events.length
    ? Math.min(...events.map((event) => time(event.createdAt)))
    : -Infinity;
  const items: Item[] = [
    ...events.map((event) => ({
      kind: 'event' as const,
      at: time(event.createdAt),
      order: event.sequence,
      event,
    })),
    // While older events are still unloaded, only show runs inside the loaded time range.
    ...analyses
      .filter((analysis) => !hasMore || time(analysis.analyzedAt) >= oldestLoadedEvent)
      .map((analysis) => ({
        kind: 'analysis' as const,
        at: time(analysis.analyzedAt),
        order: analysis.analysisIndex,
        analysis,
      })),
  ].sort((a, b) => b.at - a.at || (a.kind === b.kind ? b.order - a.order : a.kind === 'event' ? -1 : 1));

  if (items.length === 0)
    return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No investigation history yet" />;

  return (
    <>
      <Timeline
        className="investigation-timeline"
        items={items.map((item) =>
          item.kind === 'analysis'
            ? {
                key: `analysis-${item.analysis.analysisIndex}`,
                color: 'purple',
                children: (
                  <div>
                    <Text strong>{analysisRunLabel(item.analysis.analysisIndex)}</Text>{' '}
                    <Tag>{item.analysis.verdict || 'unknown'}</Tag>
                    <Tag>{item.analysis.severity || 'unknown'}</Tag>
                    {item.analysis.isLatest && <Tag color="purple">latest</Tag>}
                    <Tag color={item.analysis.reviewCount ? 'success' : 'default'}>
                      {item.analysis.reviewCount ? `${item.analysis.reviewCount} review(s)` : 'not reviewed'}
                    </Tag>
                    {item.analysis.summary && (
                      <Paragraph className="investigation-timeline-text" type="secondary">
                        {item.analysis.summary}
                      </Paragraph>
                    )}
                    <Text type="secondary" className="investigation-timeline-meta">
                      AI summary · {formatTime(item.analysis.analyzedAt)}
                    </Text>
                  </div>
                ),
              }
            : {
                key: item.event.id,
                color:
                  item.event.type === 'disposition'
                    ? 'blue'
                    : item.event.type === 'reopened'
                      ? 'orange'
                      : 'gray',
                children: (
                  <div>
                    <EventBody event={item.event} vocabulary={vocabulary} />
                    <Text type="secondary" className="investigation-timeline-meta">
                      #{item.event.sequence} · {item.event.actor.displayName} ·{' '}
                      {formatTime(item.event.createdAt)}
                    </Text>
                  </div>
                ),
              },
        )}
      />
      {hasMore && (
        <Button size="small" onClick={onLoadMore} loading={loadingMore}>
          Load older events
        </Button>
      )}
    </>
  );
};

export default InvestigationTimeline;
