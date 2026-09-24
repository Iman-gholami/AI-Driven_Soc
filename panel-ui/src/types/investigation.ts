export type ReviewStatus = 'agree' | 'partially_agree' | 'disagree' | 'not_reviewed';
export type ReviewSection = 'verdict' | 'severity' | 'mitre' | 'recommendations';
export type TriageStatus = 'open' | 'closed';
export type DispositionOutcome = 'true_positive' | 'benign_true_positive' | 'false_positive' | 'inconclusive';
export type DispositionAction = 'ticket_created' | 'escalated' | 'closed_no_action' | 'monitoring';
export type InvestigationEventType =
  'ai_review' | 'disposition' | 'note' | 'reopened' | 'query_run' | 'evidence_marked';

export interface InvestigationActor {
  kind: 'human' | 'ai';
  id: string;
  displayName: string;
}

export interface AnalysisRef {
  analysisIndex: number;
  analyzedAt: string;
  fingerprint: string;
}

export interface AnalysisSnapshot {
  verdict: string | null;
  severity: string | null;
  attackMapping: Array<{ technique: string; name: string | null }> | null;
  recommendations: string[] | null;
  provider: string | null;
  model: string | null;
  rule: { ruleId: string; revision: number | null } | null;
}

export interface ReviewPayload {
  sections: Record<ReviewSection, ReviewStatus>;
  corrections: { verdict?: string; severity?: string };
  comment?: string;
}

export interface DispositionPayload {
  outcome: DispositionOutcome;
  action: DispositionAction;
  reasonCodes: string[];
  reasonText?: string;
  ticketNumber?: string;
}

export interface InvestigationEvent {
  id: string;
  alertId: string;
  sequence: number;
  type: InvestigationEventType;
  schemaVersion: number;
  createdAt: string;
  actor: InvestigationActor;
  payload: Record<string, unknown>;
  context: {
    analysisRef: (Omit<AnalysisRef, 'fingerprint'> & { fingerprint?: string }) | null;
    analysisSnapshot: AnalysisSnapshot | null;
    rule: { ruleId: string; revision: number | null } | null;
  };
}

export interface TriageState {
  status: TriageStatus;
  version: number;
  outcome: DispositionOutcome | null;
  action: DispositionAction | null;
  reasonCodes: string[];
  reasonText: string | null;
  ticketNumber: string | null;
  closedAt: string | null;
  disposition: { eventId: string; sequence: number; at: string; actor: InvestigationActor | null } | null;
  review: {
    eventId: string;
    sequence: number;
    at: string;
    actor: InvestigationActor | null;
    analysisRef: { analysisIndex: number; analyzedAt: string } | null;
    sections: Record<ReviewSection, ReviewStatus>;
  } | null;
  updatedAt: string | null;
  updatedBy: InvestigationActor | null;
}

export interface AnalysisSummaryEntry {
  analysisIndex: number;
  analyzedAt: string | null;
  verdict: string | null;
  severity: string | null;
  summary: string | null;
  isLatest: boolean;
  reviewCount: number;
}

export interface InvestigationView {
  alert: { alertId: string; alertRef: string; aiStatus: string | null };
  state: TriageState;
  version: number;
  projectionConsistent: boolean;
  reviewableAnalysis: {
    status: 'available' | 'none' | 'in_progress';
    reason: string | null;
    analysisRef: AnalysisRef | null;
    snapshot: AnalysisSnapshot | null;
  };
  latestAnalysisReviewed: boolean | null;
  analyses: AnalysisSummaryEntry[];
  events: InvestigationEvent[];
  pagination: { limit: number; total: number; nextBefore: number | null };
}

export interface InvestigationWriteResult {
  event: InvestigationEvent;
  state: TriageState;
  version: number;
  replayed: boolean;
}

export interface DispositionVocabulary {
  outcomes: Array<{ id: DispositionOutcome; label: string; description: string }>;
  actions: Array<{ id: DispositionAction; label: string; description: string; closesTriage: boolean }>;
  reasons: Array<{
    id: string;
    labelEn: string;
    labelFa: string;
    outcomes: DispositionOutcome[];
    requiresText: boolean;
    retired: boolean;
  }>;
}

export interface TriageSummary {
  status: TriageStatus;
  version: number;
  outcome: DispositionOutcome | null;
  action: DispositionAction | null;
  ticketNumber: string | null;
  closedAt: string | null;
  updatedAt: string | null;
  updatedBy: InvestigationActor | null;
  reviewedAnalysisRef: { analysisIndex: number; analyzedAt: string | null } | null;
  latestAnalysisReviewed: boolean | null;
}

export interface SectionAgreement {
  agree: number;
  partiallyAgree: number;
  disagree: number;
  notReviewed: number;
  reviewed: number;
  strictAgreementRate: number | null;
  partialAgreementRate: number | null;
  disagreementRate: number | null;
}

export interface AgreementGroup {
  key: string;
  ruleId?: string | null;
  revision?: number | null;
  provider?: string | null;
  model?: string | null;
  reviews: number;
  sections: Record<ReviewSection, SectionAgreement>;
}

export interface AnalystFeedbackReport {
  window: { from: string; to: string; interval: string; timezone: string };
  cohorts: {
    reviews: { alerts: number; description: string };
    dispositions: { alerts: number; description: string };
  };
  agreement: {
    sections: Record<ReviewSection, SectionAgreement>;
    byRule: AgreementGroup[];
    byModel: AgreementGroup[];
  };
  falsePositiveShareByRule: {
    definition: string;
    rules: Array<{
      key: string;
      ruleId: string | null;
      revision: number | null;
      falsePositive: number;
      truePositive: number;
      benignTruePositive: number;
      inconclusive: number;
      determinate: number;
      falsePositiveShare: number | null;
    }>;
  };
  verdictOutcome: {
    verdicts: string[];
    outcomes: DispositionOutcome[];
    cells: Array<{ verdict: string; outcome: DispositionOutcome; count: number }>;
    included: number;
    excludedWithoutAnalysis: number;
  };
  timeToDisposition: { medianMs: number | null; eligible: number; excluded: number; description: string };
  coverage: {
    analyzedAlerts: number;
    reviewedAlerts: number;
    coverageRate: number | null;
    latestRunReviewed: number;
    latestRunUnreviewed: number;
    latestRunUnestablished: number;
    description: string;
  };
}
