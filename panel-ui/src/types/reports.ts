export interface HistoricalAffectedSystem {
  method?: string | null;
  parameter?: string | null;
  url?: string | null;
  additionalUrls?: string[];
  domain?: string | null;
  organization?: string | null;
  ip?: string | null;
  rawIp?: string | null;
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

export interface HistoricalPhishingInfrastructure {
  url?: string | null;
  domain?: string | null;
  ip?: string | null;
  rawIp?: string | null;
  pageTitle?: string | null;
}

export interface HistoricalIndicator {
  type: string;
  role?: string | null;
  value: string;
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
    raw?: string | null;
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
  affectedCves: string[];
  description: string;
  conclusion?: string;
  recommendations: string[];
  affectedSystems: HistoricalAffectedSystem[];
  phishingInfrastructure?: HistoricalPhishingInfrastructure[];
  indicators?: HistoricalIndicator[];
  source: {
    filename: string;
    relativePath: string;
    sha256: string;
    sizeBytes: number;
  };
  extraction: {
    parserVersion: string;
    paragraphCount?: number;
    tableCount?: number;
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

export interface ReportFilterParams {
  year: number;
  month?: number;
  day?: number;
  reportType?: string;
  severity?: string;
  urgency?: string;
  finding?: string;
  findingCategory?: string;
  vulnerability?: string;
  provider?: string;
  organization?: string;
  ip?: string;
  port?: number | string;
  service?: string;
  domain?: string;
  cve?: string;
  minScore?: number | string;
  maxScore?: number | string;
  search?: string;
}

export interface ReportStats {
  year: number;
  scope?: Partial<Omit<ReportFilterParams, 'year'>>;
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

export interface ReportImportQuality {
  unknownFindingCount: number;
  unknownFindingFiles: string[];
  findingCounts: Record<string, number>;
  reportTypeCounts: Record<string, number>;
  warningCounts: Record<string, number>;
}

export interface ReportUploadNormalizedRecord {
  reportNumber?: string | null;
  reportDateRaw?: string | null;
  year?: number | null;
  month?: number | null;
  day?: number | null;
  title?: string | null;
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
    raw?: string | null;
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
  affectedCves: string[];
  description: string;
  conclusion: string;
  recommendations: string[];
  affectedSystems: HistoricalAffectedSystem[];
  phishingInfrastructure: HistoricalPhishingInfrastructure[];
  indicators: HistoricalIndicator[];
  source: {
    filename?: string | null;
    relativePath: string;
    sha256?: string | null;
    sizeBytes: number;
  };
  extraction: {
    parserVersion?: string | null;
    paragraphCount: number;
    tableCount: number;
    warnings: string[];
    organizationMismatch: boolean;
    ipMismatch: boolean;
  };
}

export interface ReportUploadPreviewItem {
  id: string;
  action: 'new' | 'update' | 'unchanged';
  file: string;
  title?: string | null;
  reportNumber?: string | null;
  date?: string | null;
  reportType: string;
  provider?: string | null;
  organization?: string | null;
  ip?: string | null;
  rawIp?: string | null;
  severityScore?: number | null;
  severityLevel: string;
  urgency: string;
  effect?: string | null;
  finding: string;
  findingName?: string | null;
  vulnerability: string;
  cves: string[];
  affectedSystems: number;
  affectedSystemPreview: Array<{
    organization?: string | null;
    ip?: string | null;
    domain?: string | null;
    url?: string | null;
    service?: string | null;
    port?: number | null;
    packetCount?: number | null;
    participantIpCount?: number | null;
    trafficVolume?: string | null;
    eventDate?: string | null;
    timeRange?: string | null;
    softwareVersion?: string | null;
    cves?: string[];
  }>;
  phishingInfrastructure?: HistoricalPhishingInfrastructure[];
  recommendations: number;
  recommendationPreview?: string[];
  descriptionPreview?: string | null;
  conclusionPreview?: string | null;
  warnings: string[];
  record: ReportUploadNormalizedRecord;
}

export interface ReportUploadPreviewSession {
  sessionToken: string;
  year: number;
  createdAt: string;
  expiresAt: string;
  discovered: number;
  ready: number;
  failed: number;
  previews: ReportUploadPreviewItem[];
  errors: Array<{ file: string; error: string }>;
  quality: ReportImportQuality;
  storagePolicy: {
    databaseChanged: false;
    stagedLocally: true;
    stagedFilesExpireMinutes: number;
  };
}

export interface ReportUploadCommitResult {
  sessionToken: string;
  year: number;
  selected: number;
  imported: number;
  updated: number;
  skipped: number;
  failed: number;
  sessionRetained?: boolean;
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
