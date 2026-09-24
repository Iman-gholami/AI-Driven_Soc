import type { DispositionVocabulary, ReviewSection, ReviewStatus } from '../../types/investigation';

export const REVIEW_SECTIONS: Array<{ id: ReviewSection; label: string }> = [
  { id: 'verdict', label: 'Verdict' },
  { id: 'severity', label: 'Severity' },
  { id: 'mitre', label: 'MITRE mapping' },
  { id: 'recommendations', label: 'Recommendations' },
];

export const REVIEW_STATUS_OPTIONS: Array<{ value: ReviewStatus; label: string }> = [
  { value: 'not_reviewed', label: 'Not reviewed' },
  { value: 'agree', label: 'Agree' },
  { value: 'partially_agree', label: 'Partially' },
  { value: 'disagree', label: 'Disagree' },
];

export const VERDICTS = ['BENIGN', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN'];
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];

export const OUTCOME_COLORS: Record<string, string> = {
  true_positive: 'red',
  benign_true_positive: 'gold',
  false_positive: 'green',
  inconclusive: 'default',
};

export function outcomeLabel(vocabulary: DispositionVocabulary | undefined, id: string | null | undefined) {
  if (!id) return '—';
  return vocabulary?.outcomes.find((outcome) => outcome.id === id)?.label || id.replace(/_/g, ' ');
}

export function actionLabel(vocabulary: DispositionVocabulary | undefined, id: string | null | undefined) {
  if (!id) return '—';
  return vocabulary?.actions.find((action) => action.id === id)?.label || id.replace(/_/g, ' ');
}

export function reasonLabel(vocabulary: DispositionVocabulary | undefined, id: string) {
  const reason = vocabulary?.reasons.find((item) => item.id === id);
  return reason ? `${reason.labelEn} · ${reason.labelFa}` : id;
}

export function formatTime(value: string | null | undefined) {
  if (!value) return 'unknown time';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'unknown time' : date.toLocaleString();
}

// Analyses are stored zero-based; analysts see one-based run numbers.
export function analysisRunLabel(analysisIndex: number | null | undefined) {
  return analysisIndex === null || analysisIndex === undefined
    ? 'unknown run'
    : `AI run #${analysisIndex + 1}`;
}

export function newIdempotencyKey() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
