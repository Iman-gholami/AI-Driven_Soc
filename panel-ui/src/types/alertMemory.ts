export type AnalystOutcome =
  | 'true_positive'
  | 'benign_true_positive'
  | 'false_positive'
  | 'inconclusive';

export interface AlertResolution {
  outcome: AnalystOutcome;
  note: string | null;
  ticketNumber: string | null;
  resolvedAt: string | null;
  resolvedBy: { id: string | null; displayName: string | null } | null;
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
  analystResult: AlertResolution | null;
}

export interface AlertMemoryResult {
  alertId: string;
  current: {
    occurredAt: string | null;
    signature: string | null;
    host: string | null;
    ruleId: string | null;
    analystResult: AlertResolution | null;
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

export interface SaveAlertOutcomeInput {
  outcome: AnalystOutcome;
  note?: string;
  ticketNumber?: string;
}
