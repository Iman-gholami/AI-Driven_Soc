export interface ApiResponse<T = unknown> {
  success: boolean;
  data: T;
  message?: string;
  total?: number;
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
  resolution_evidence?: unknown[];
  rule?: DetectionRule;
}

export interface RuleMatch {
  status: 'unresolved' | 'matched' | 'no_match' | 'ambiguous' | 'pending' | 'unavailable';
  matchType: string | null;
  signature: string | null;
  candidateCount: number;
  reason: string | null;
  resolutionEvidence: unknown[];
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

// Persisted AI analysis. Fields are optional because older analyses predate the current schema
// (see src/models/incidentSchema.js); legacy aliases are kept so those records still render.
export interface RelationshipEndpoint {
  ip?: string;
  organization?: string;
  context?: string;
}

export interface AttackMappingEntry {
  technique?: string;
  id?: string;
  name?: string;
}

export interface IncidentAnalysis {
  verdict?: string;
  one_line_summary?: string;
  incident_summary?: { what_happened?: string; summary?: string };
  attack_story?: string[];
  why_alert_triggered?: { rule?: string; evidence?: string[] };
  observed_evidence?: unknown[];
  network_relationship_analysis?: {
    assessment?: string;
    summary?: string;
    source?: RelationshipEndpoint;
    destination?: RelationshipEndpoint;
    why_suspicious?: unknown[];
    current_alert_domains?: unknown[];
    current_alert_packet_evidence?: unknown[];
    threat_feed_context?: unknown[];
    limitations?: string;
  };
  detection_analysis?: {
    rule_logic?: string;
    trigger_reason?: string;
    limitations?: string;
    gaps?: string;
    evidence?: string[];
  };
  behavior_analysis?: string;
  attack_mapping?: Array<AttackMappingEntry | string> | { mitre_techniques?: Array<AttackMappingEntry | string> };
  risk_assessment?: {
    severity?: string;
    confidence?: number | string;
    reasoning?: string;
    rationale?: string;
  };
  analyst_decision?: { action?: string; reason?: string };
  false_positive_analysis?: unknown[] | { conditions?: unknown[] };
  recommended_investigation_steps?: unknown[];
  final_soc_note?: string;
}

interface ThreatMatchDetail {
  malware?: string[];
  classifications?: Array<{ identifier?: string }>;
  latestObservedAt?: string;
}

export interface NetworkIntelligenceIp {
  ip: string;
  roles?: string[];
  nationalNetwork?: boolean;
  asset?: { owned?: boolean; organization?: string; category?: string; province?: string };
  ipMetadata?: { matched?: boolean; asName?: string; organization?: string; countryCode?: string; city?: string };
  threat?: {
    directMatch?: boolean;
    relationshipMatch?: boolean;
    direct?: ThreatMatchDetail;
    relationship?: ThreatMatchDetail;
  };
}

export interface NetworkIntelligence {
  status?: string;
  ips?: NetworkIntelligenceIp[];
  correlations?: Array<{ type?: string; strength?: string; matchedFields?: string[] }>;
  sources?: {
    threatDataset?: { sourceFile?: string; importedAt?: string } | null;
    assetDataset?: { sourceFile?: string; importedAt?: string } | null;
  };
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
  rawEvent?: Record<string, unknown>;
  fullAnalysis?: IncidentAnalysis;
  analysis?: AnalysisSummary[];
  soc?: {
    mitreAttack?: unknown;
    iocs?: unknown[];
    correlation?: unknown;
    threatIntelligence?: unknown;
    networkIntelligence?: NetworkIntelligence;
    historicalReports?: unknown;
    providerMetadata?: unknown;
  };
  processing?: Record<string, unknown>;
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
      mappingCoveragePercent: number;
      activeMappingCoveragePercent: number;
      byTier: { native: number; imported: number; community: number };
    };
    techniques: {
      total: number;
      covered: number;
      uncovered: number;
      coveragePercent: number;
    };
  };
  tactics: MitreTacticCoverage[];
  techniqueStats: MitreTechniqueCoverage[];
}

export interface MitreTechniqueDetail {
  techniqueId: string;
  name: string;
  description?: string;
  tactics: { id: string; name: string; shortName: string }[];
  platforms: string[];
  isSubTechnique: boolean;
  parentTechniqueId?: string | null;
  attackVersion?: string;
}

export interface MitreRuleSummary {
  ruleId: string;
  revision: number;
  title: string;
  protocol?: string;
  classtype?: string;
  sourceFile?: string;
  tier?: 'native' | 'imported' | 'community';
  quarantined?: boolean;
  mitre?: {
    mapped?: boolean;
    techniqueIds?: string[];
    tacticIds?: string[];
    mappings?: {
      techniqueId?: string;
      source?: string;
      mappingRuleId?: string;
      confidence?: number;
      reviewed?: boolean;
      evidence?: string[];
    }[];
  };
}

export interface MitreTechniqueRulesResult {
  technique: MitreTechniqueDetail;
  rules: MitreRuleSummary[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}

export interface AIAlertResponse {
  id: string;
  alertId: string;
  content: string;
  timestamp: string;
  confidence: number;
  summary: string;
  insights: string[];
  recommendations: string[];
  severity: Alert['severity'];
  source: string;
  signature: string | null;
  eventType: string | null;
  host: string | null;
  status: Alert['aiStatus'];
  cached?: boolean;
  analysisCount?: number;
}

export type ThemeMode = 'light' | 'dark';


export interface CopilotQueryPlan {
  dataset: string;
  operation: 'count' | 'aggregate' | 'list' | 'distinct';
  timeRange?: {
    type: string;
    value?: number;
    from?: string;
    to?: string;
    field?: string;
  };
  filters?: Array<{ field: string; operator: string; value?: unknown }>;
  groupBy?: string[];
  metrics?: Array<{ type: string; field?: string; alias?: string }>;
  select?: string[];
  sort?: Array<{ field: string; direction: 'asc' | 'desc' }>;
  limit?: number;
}

export interface CopilotQueryResult {
  dataset: string;
  operation: string;
  timeRange?: {
    field?: string | null;
    from?: string | null;
    to?: string | null;
    timezone?: string;
    label?: string;
  };
  data?: {
    count?: number;
    rows?: Array<Record<string, unknown>>;
  };
  metadata?: Record<string, unknown>;
  queryPlan?: CopilotQueryPlan;
}

export interface CopilotBatchPlan {
  queries: CopilotQueryPlan[];
}

export interface CopilotBatchResult {
  count: number;
  results: CopilotQueryResult[];
  metadata?: Record<string, unknown>;
}

export interface CopilotEntityContextPlan {
  entityType: 'alert' | 'ip' | 'organization' | 'rule' | 'mitre_technique';
  id: string;
}

export interface CopilotEntityContextResult {
  entity: {
    type: 'alert' | 'ip' | 'organization' | 'rule' | 'mitre_technique';
    id: string;
  };
  contextType?: string;
  relatedEntities?: {
    sourceIp?: string;
    destinationIp?: string;
    organization?: string;
    ruleId?: string;
    mitreTechniques?: string[];
  };
  [key: string]: unknown;
}

export interface CopilotConversationState {
  focus?: {
    entityType: 'alert' | 'ip' | 'organization' | 'rule' | 'mitre_technique';
    id: string;
  } | null;
  relatedEntities?: {
    sourceIp?: string;
    destinationIp?: string;
    organization?: string;
    ruleId?: string;
    mitreTechniques?: string[];
  };
  lastTool?: string | null;
  lastQueryPlan?: unknown;
}

export interface CopilotMetricPlan {
  operation: 'compare' | 'percentage' | 'trend';
  [key: string]: unknown;
}

export interface CopilotCorrelationPlan {
  relationship:
    | 'alert_source_ip_to_threat_source'
    | 'alert_destination_ip_to_asset'
    | 'alert_rule_to_detection_rule'
    | 'detection_rule_to_mitre_technique'
    | 'alert_ip_to_organization';
  timeRange?: CopilotQueryPlan['timeRange'];
  limit?: number;
}

export type CopilotPlan =
  | CopilotQueryPlan
  | CopilotBatchPlan
  | CopilotEntityContextPlan
  | CopilotMetricPlan
  | CopilotCorrelationPlan;

export interface CopilotMetricResult {
  operation: 'compare' | 'percentage' | 'trend';
  left?: { label: string; count: number };
  right?: { label: string; count: number };
  numerator?: { label: string; count: number };
  denominator?: { label: string; count: number };
  difference?: number;
  changePercent?: number | null;
  percentage?: number | null;
  dataset?: string;
  bucket?: 'hour' | 'day';
  points?: Array<{ from: string; to: string; count: number }>;
  metadata?: Record<string, unknown>;
}

export interface CopilotCorrelationResult {
  operation: 'correlate';
  relationship: string;
  relationshipDescription?: string;
  timeRange?: {
    from?: string | null;
    to?: string | null;
    timezone?: string;
    label?: string;
  };
  rows: Array<Record<string, unknown>>;
  count: number;
  metadata?: Record<string, unknown>;
}

export interface CopilotChatHistoryItem {
  role: 'user' | 'assistant';
  content: string;
}

export interface CopilotResponse {
  supported: boolean;
  answer: string;
  tool: string | null;
  queryPlan: CopilotPlan | null;
  result:
    | CopilotQueryResult
    | CopilotBatchResult
    | CopilotEntityContextResult
    | CopilotMetricResult
    | CopilotCorrelationResult
    | null;
  metadata: {
    provider?: string;
    model?: string;
    readOnly?: boolean;
    mcp?: boolean;
    timezone?: string;
  };
  state?: CopilotConversationState;
}
