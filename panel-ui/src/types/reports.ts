export interface HistoricalAffectedSystem {
  method?: string | null;
  parameter?: string | null;
  url?: string | null;
  domain?: string | null;
  organization?: string | null;
  ip?: string | null;
  port?: number | null;
  service?: string | null;
  packetCount?: number | null;
  participantIpCount?: number | null;
  trafficVolumeRaw?: string | null;
  trafficVolumeBytes?: number | null;
  eventDateRaw?: string | null;
  eventYear?: number | null;
  eventMonth?: number | null;
  eventDay?: number | null;
  timeRange?: string | null;
  softwareVersion?: string | null;
  reportedFinding?: string | null;
  cves?: string[];
}

export interface HistoricalReport {
  _id: string;
  documentKey: string;
  reportNumber?: string | null;
  reportDateRaw?: string | null;
  year: number;
  month?: number | null;
  day?: number | null;
  title: string;
  reportType: string;
  provider?: string | null;
  contact?: string | null;
  effect?: string | null;
  target: {
    organization?: string | null;
    ip?: string | null;
    rawIp?: string | null;
  };
  severity: {
    score?: number | null;
    level: string;
  };
  urgency: {
    raw?: string | null;
    normalized: string;
  };
  finding: {
    type: string;
    name?: string | null;
    category: string;
    cwe?: string | null;
  };
  vulnerability: {
    name?: string | null;
    normalizedName: string;
    category: string;
    cwe?: string | null;
  };
  cves: string[];
  description: string;
  conclusion?: string;
  recommendations: string[];
  affectedSystems: HistoricalAffectedSystem[];
  source: {
    filename: string;
    relativePath: string;
    sha256: string;
    sizeBytes: number;
  };
  extraction: {
    parserVersion: string;
    warnings: string[];
    organizationMismatch?: boolean;
    ipMismatch?: boolean;
  };
}

export interface HistoricalReportListResult {
  reports: HistoricalReport[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}

export interface ReportStats {
  year: number;
  summary: {
    total: number;
    uniqueOrganizations: number;
    uniqueIps: number;
    highCritical: number;
    immediate: number;
    actionRequired: number;
    informational: number;
    qualityWarnings: number;
    immediatePercent: number;
    highCriticalPercent: number;
  };
  byMonth: Array<{ month: number | null; count: number }>;
  byFinding: Array<{ key: string; name: string; category?: string; count: number }>;
  byVulnerability: Array<{ key: string; name: string; count: number }>;
  byReportType: Array<{ reportType: string; count: number }>;
  bySeverity: Array<{ severity: string; count: number }>;
  byUrgency: Array<{ urgency: string; count: number }>;
  topOrganizations: Array<{ organization: string; count: number }>;
  topIps: Array<{ ip: string; count: number }>;
  topPorts: Array<{ port: number; count: number }>;
  repeated: {
    repeatedGroups: number;
    reportsInRepeatedGroups: number;
  };
}

export interface ReportImportScan {
  year: number;
  root: string;
  directory: string;
  count: number;
  eligibleCount: number;
  oversizedCount: number;
  files: Array<{
    filename: string;
    relativePath: string;
    sizeBytes: number;
    eligible: boolean;
  }>;
}

export interface ReportImportResult {
  year: number;
  discovered: number;
  eligible: number;
  imported: number;
  updated: number;
  skipped: number;
  failed: number;
  dryRun: boolean;
  errors: Array<{ file: string; error: string }>;
}

export interface ReportCopilotResult {
  supported: boolean;
  answer: string;
  plan: Record<string, unknown>;
  data: unknown;
  metadata?: {
    deterministic?: boolean;
    readOnly?: boolean;
  };
}
