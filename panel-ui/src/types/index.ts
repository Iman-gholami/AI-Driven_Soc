import type React from 'react';

export interface ApiResponse<T = any> {
  success: boolean;
  data: T;
  message?: string;
  total?: number;
}

export interface User {
  id: string;
  name: string;
  email: string;
  role: string;
  avatar?: string;
}

export interface DetectionRule {
  rule_id?: string;
  revision?: number;
  title?: string;
  classtype?: string;
  protocol?: string;
  header?: Record<string, unknown>;
  flow?: string[];
  contents?: unknown[];
  pcre?: string[];
  references?: unknown[];
  metadata?: unknown;
  source_file?: string;
  raw_rule?: string;
  action?: string;
}

export interface DetectionRuleContext {
  status?: string;
  match_type?: string | null;
  candidate_count?: number;
  reason?: string | null;
  candidates?: unknown[];
  resolution_evidence?: any[];
  rule?: DetectionRule;
}

export interface RuleMatch {
  status: 'unresolved' | 'matched' | 'no_match' | 'ambiguous' | 'pending' | 'unavailable';
  matchType: string | null;
  signature: string | null;
  candidateCount: number;
  reason: string | null;
  resolutionEvidence: any[];
  ruleId?: string;
  revision?: number;
  title?: string;
  protocol?: string;
  classtype?: string;
  sourceFile?: string;
}

export interface AnalysisSummary {
  severity?: string;
  summary?: string;
  recommendations?: string[];
  verdict?: string;
  confidence?: number;
  action?: string;
  analyzedAt?: string;
}

export interface Alert {
  alertId: string;
  source: string;
  signature: string | null;
  eventType: string | null;
  host: string | null;
  status: 'new' | 'analyzed';
  aiStatus: 'not_analyzed' | 'analyzing' | 'analyzed' | 'failed';
  aiEligibility: { eligible: boolean; scenario: string | null; reason: string | null };
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
  eventTime?: string;
  createdAt: string;
  updatedAt: string;
  eventHash: string;
  processingTimeMs?: number | null;
  analysisCount?: number;
  ruleMatch?: RuleMatch;
  detectionRule?: DetectionRuleContext;
  rawEvent?: Record<string, any>;
  fullAnalysis?: any;
  analysis?: AnalysisSummary[];
  soc?: {
    mitreAttack?: any;
    iocs?: any[];
    correlation?: any;
    threatIntelligence?: any;
    networkIntelligence?: any;
    historicalReports?: any;
    providerMetadata?: any;
  };
  processing?: Record<string, any>;
}

export interface AlertListParams {
  page?: number;
  limit?: number;
  status?: Alert['status'] | '';
  aiStatus?: Alert['aiStatus'] | '';
  severity?: Alert['severity'] | '';
  source?: string;
  search?: string;
  createdAtFrom?: string;
  createdAtTo?: string;
  sortBy?: 'createdAt' | 'updatedAt' | 'alertId' | 'severity' | 'source';
  sortDirection?: 'asc' | 'desc';
}

export interface AlertListResult {
  alerts: Alert[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
  filters?: Record<string, unknown>;
  sort?: Record<string, string>;
}

export interface DashboardStats {
  window: { from: string | null; to: string | null };
  totals: {
    alerts: number;
    uniqueHosts: number;
    sources: number;
  };
  severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    unknown: number;
  };
  aiStatus: {
    analyzed: number;
    analyzing: number;
    failed: number;
    notAnalyzed: number;
  };
  sources: { name: string; count: number }[];
  performance: {
    aiCoveragePercent: number;
    ruleMatchCoveragePercent: number;
    avgProcessingTimeMs: number;
  };
  posture: {
    severityPressureIndex: number;
    matchedRules: number;
  };
  mitre: {
    techniqueCount: number;
    mappedAlertCount: number;
    analyzedAlertCount: number;
    coveragePercent: number;
  };
  recentAlerts: Alert[];
}

export interface MitreTechniqueCoverage {
  techniqueId: string;
  name: string;
  isSubTechnique: boolean;
  parentTechniqueId: string | null;
  ruleCount: number;
}

export interface MitreTacticCoverage {
  tacticId: string;
  name: string;
  shortName: string;
  totalTechniques: number;
  coveredTechniques: number;
  coveragePercent: number;
  techniques: MitreTechniqueCoverage[];
}

export interface MitreCoverageSnapshot {
  scopeTier: 'all' | 'native' | 'imported' | 'community';
  generatedAt: string;
  attackVersion?: string | null;
  summary: {
    rules: {
      total: number;
      withMitre: number;
      withActiveMitre: number;
      explicitReference: number;
      curated: number;
      gapCurated: number;
      legacyOnly: number;
      unmapped: number;
      quarantined: number;
    };
    techniques: {
      total: number;
      covered: number;
      coveragePercent: number;
    };
  };
  tactics: MitreTacticCoverage[];
  unmappedRules: Array<{
    ruleId: string;
    title: string;
    classtype?: string;
    sourceFile?: string;
  }>;
}

export interface MitreTechniqueRulesResult {
  technique: {
    techniqueId: string;
    name: string;
    description?: string;
  };
  rules: Array<{
    ruleId: string;
    revision?: number;
    title: string;
    classtype?: string;
    sourceFile?: string;
    tier?: string;
    mitre?: Record<string, any>;
  }>;
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}

export interface CopilotChatHistoryItem {
  role: 'user' | 'assistant';
  content: string;
}

export interface CopilotConversationState {
  focus?: { entityType: 'alert' | 'ip' | 'organization' | 'rule' | 'mitre_technique'; id: string } | null;
  relatedEntities?: {
    sourceIp?: string;
    destinationIp?: string;
    organization?: string;
    ruleId?: string;
    mitreTechniques?: string[];
  };
  lastTool?: string | null;
  lastQueryPlan?: any;
}

export interface CopilotResponse {
  supported: boolean;
  answer: string;
  tool?: string | null;
  queryPlan?: any;
  result?: any;
  metadata?: Record<string, any>;
  state?: CopilotConversationState;
}

export interface SidebarItem {
  key: string;
  label: string;
  icon?: React.ReactNode;
  path?: string;
  children?: SidebarItem[];
}