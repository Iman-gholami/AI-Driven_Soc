export type AnalystOutcome = 'true_positive' | 'false_positive';

export type FalsePositiveReason =
  | 'authorized_scanner'
  | 'authorized_testing'
  | 'known_benign_service'
  | 'rule_too_broad'
  | 'duplicate_alert'
  | 'expected_behavior'
  | 'other';

export interface AnalystActor {
  id: string | null;
  displayName: string | null;
}

export interface AnalystCase {
  actionsTaken: string[];
  note: string | null;
  startedAt: string | null;
  startedBy: AnalystActor | null;
  updatedAt: string | null;
  updatedBy: AnalystActor | null;
  finalOutcome: AnalystOutcome | null;
  falsePositiveReason: FalsePositiveReason | null;
  falsePositiveDetails: string | null;
  ticketNumber: string | null;
  closedAt: string | null;
  closedBy: AnalystActor | null;
}

export interface AlertMemoryOccurrence {
  alertId: string;
  occurredAt: string | null;
  source: string | null;
  signature: string | null;
  host: string | null;
  eventType: string | null;
  severity: string;
  aiStatus: string;
  status: 'new' | 'analyzed' | 'investigating' | 'closed';
  ruleId: string | null;
  match: {
    score: number;
    level: 'exact' | 'strong' | 'related';
    reasons: string[];
  };
  aiResult: {
    verdict: string | null;
    severity: string | null;
    summary: string | null;
    action: string | null;
    analyzedAt: string | null;
  };
  analystResult: AnalystCase | null;
}

export interface AlertMemoryResult {
  alertId: string;
  current: {
    status: 'new' | 'analyzed' | 'investigating' | 'closed';
    occurredAt: string | null;
    signature: string | null;
    host: string | null;
    ruleId: string | null;
    analystCase: AnalystCase | null;
  };
  summary: {
    seenBefore: boolean;
    count: number;
    firstSeen: string | null;
    lastSeen: string | null;
    sameRuleCount: number;
    sameHostCount: number;
    outcomeCounts: Record<AnalystOutcome | 'unresolved', number>;
  };
  occurrences: AlertMemoryOccurrence[];
  pagination: {
    returned: number;
    matched: number;
    candidateLimitReached: boolean;
  };
}

export interface SaveInvestigationInput {
  actionsTaken: string[];
  note?: string;
}

export interface CloseAlertInput extends SaveInvestigationInput {
  finalOutcome: AnalystOutcome;
  ticketNumber?: string;
  falsePositiveReason?: FalsePositiveReason;
  falsePositiveDetails?: string;
}

export interface AnalystCaseWriteResult {
  status: 'investigating' | 'closed';
  analystCase: AnalystCase;
}
