import axios from 'axios';
import {
  ApiResponse,
  Alert,
  DetectionRuleContext,
  IncidentAnalysis,
  AIAlertResponse,
  AlertListParams,
  AlertListResult,
  DashboardStats,
  MitreCoverageSnapshot,
  MitreTechniqueRulesResult,
  CopilotResponse,
  CopilotChatHistoryItem,
  CopilotConversationState,
} from '../types';
import type {
  HistoricalReport,
  HistoricalReportListResult,
  ReportCopilotResult,
  ReportEntitySummary,
  ReportFacets,
  ReportFilterParams,
  ReportImportResult,
  ReportImportScan,
  ReportStats,
  ReportUploadCommitResult,
  ReportUploadPreviewSession,
} from '../types/reports';

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '',
  timeout: 30000,
});

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

let unauthorizedHandler: (() => void) | null = null;

// Lets the auth layer drop an expired or revoked server session instead of leaving the panel half signed-in.
export function setUnauthorizedHandler(handler: (() => void) | null) {
  unauthorizedHandler = handler;
}

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) unauthorizedHandler?.();
    return Promise.reject(error);
  },
);

export const api = {
  getAlertsPage: async (params: AlertListParams = {}): Promise<AlertListResult> => {
    const response = await apiClient.get<ApiResponse<AlertListResult> & Partial<AlertListResult>>('/alerts', {
      params: cleanParams(params),
    });
    const payload = response.data;
    const data = payload.data || payload;
    return {
      alerts: data.alerts || [],
      pagination: data.pagination || { page: params.page || 1, limit: params.limit || 50, total: 0, pages: 0 },
      filters: data.filters,
      sort: data.sort,
    };
  },

  getAlerts: async (params: AlertListParams = {}): Promise<Alert[]> => {
    const result = await api.getAlertsPage(params);
    return result.alerts;
  },

  getAlertById: async (alertId: string): Promise<Alert> => {
    const response = await apiClient.get<Alert>(`/alerts/${encodeURIComponent(alertId)}`);
    return response.data;
  },

  getDashboardStats: async (params: { createdAtFrom?: string; createdAtTo?: string } = {}): Promise<DashboardStats> => {
    const response = await apiClient.get<ApiResponse<DashboardStats>>('/dashboard/stats', {
      params: cleanParams(params),
    });
    return response.data.data;
  },

  getMitreCoverage: async (tier: 'all' | 'native' | 'imported' | 'community' = 'all'): Promise<MitreCoverageSnapshot> => {
    const response = await apiClient.get<ApiResponse<MitreCoverageSnapshot>>('/mitre/coverage', {
      params: { tier },
    });
    return response.data.data;
  },

  getMitreTechniqueRules: async (
    techniqueId: string,
    params: { tier?: 'all' | 'native' | 'imported' | 'community'; page?: number; limit?: number } = {},
  ): Promise<MitreTechniqueRulesResult> => {
    const response = await apiClient.get<ApiResponse<MitreTechniqueRulesResult>>(
      `/mitre/techniques/${encodeURIComponent(techniqueId)}/rules`,
      { params: cleanParams(params) },
    );
    return response.data.data;
  },

  generateAIAnalysis: async (alertId: string, force = false): Promise<AIAlertResponse> => {
    const response = await apiClient.post<ApiResponse<{
      alertId: string;
      aiStatus: Alert['aiStatus'];
      analysis?: IncidentAnalysis;
      ruleMatch: Alert['ruleMatch'];
      detectionRule?: DetectionRuleContext;
      metadata?: { cached?: boolean; analysisCount?: number };
    }>>(`/alerts/${encodeURIComponent(alertId)}/analyze`, force ? { force: true } : {});

    const result = response.data.data;
    const summary = String(
      result.analysis?.one_line_summary ||
      result.analysis?.final_soc_note ||
      result.analysis?.incident_summary?.what_happened ||
      result.analysis?.incident_summary?.summary ||
      '',
    );
    return {
      id: `${result.alertId}-${Date.now()}`,
      alertId: result.alertId,
      content: result.analysis?.final_soc_note || summary,
      timestamp: new Date().toISOString(),
      confidence: Number(result.analysis?.risk_assessment?.confidence ?? 0),
      summary,
      insights: toStringList(result.analysis?.observed_evidence),
      recommendations: toStringList(result.analysis?.recommended_investigation_steps),
      severity: (result.analysis?.risk_assessment?.severity || 'unknown') as Alert['severity'],
      source: '',
      signature: null,
      eventType: null,
      host: null,
      status: result.aiStatus,
      cached: Boolean(result.metadata?.cached),
      analysisCount: Number(result.metadata?.analysisCount || 0),
    };
  },

  regenerateAIAnalysis: async (alertId: string): Promise<AIAlertResponse> => api.generateAIAnalysis(alertId, true),

  queryCopilot: async (
    message: string,
    history: CopilotChatHistoryItem[] = [],
    state: CopilotConversationState = {},
  ): Promise<CopilotResponse> => {
    const response = await apiClient.post<ApiResponse<CopilotResponse>>('/copilot/query', {
      message,
      history,
      state,
    });
    return response.data.data;
  },

  getReportYears: async (): Promise<Array<{ year: number; count: number }>> => {
    const response = await apiClient.get<ApiResponse<Array<{ year: number; count: number }>>>('/reports/years');
    return response.data.data || [];
  },

  getReportStats: async (params: ReportFilterParams): Promise<ReportStats> => {
    const response = await apiClient.get<ApiResponse<ReportStats>>('/reports/stats', {
      params: cleanParams(params),
    });
    return response.data.data;
  },

  getReportFacets: async (params: ReportFilterParams): Promise<ReportFacets> => {
    const response = await apiClient.get<ApiResponse<ReportFacets>>('/reports/facets', {
      params: cleanParams(params),
    });
    return response.data.data;
  },

  getReportEntitySummary: async (
    type: 'organization' | 'scope' | 'ip' | 'finding',
    value: string,
    params: Pick<ReportFilterParams, 'year' | 'month' | 'day'>,
  ): Promise<ReportEntitySummary> => {
    const response = await apiClient.get<ApiResponse<ReportEntitySummary>>(
      `/reports/entities/${encodeURIComponent(type)}`,
      { params: cleanParams({ ...params, value }) },
    );
    return response.data.data;
  },

  getHistoricalReports: async (params: Record<string, unknown> = {}): Promise<HistoricalReportListResult> => {
    const response = await apiClient.get<ApiResponse<HistoricalReportListResult>>('/reports', {
      params: cleanParams(params),
    });
    return response.data.data;
  },

  getHistoricalReport: async (id: string): Promise<HistoricalReport> => {
    const response = await apiClient.get<ApiResponse<HistoricalReport>>(`/reports/${encodeURIComponent(id)}`);
    return response.data.data;
  },

  scanHistoricalReports: async (year: number): Promise<ReportImportScan> => {
    const response = await apiClient.get<ApiResponse<ReportImportScan>>('/reports/import/scan', { params: { year } });
    return response.data.data;
  },

  importHistoricalReports: async (year: number, dryRun = false): Promise<ReportImportResult> => {
    const response = await apiClient.post<ApiResponse<ReportImportResult>>('/reports/import', { year, dryRun });
    return response.data.data;
  },

  previewHistoricalReportUpload: async (year: number, files: File[]): Promise<ReportUploadPreviewSession> => {
    const formData = new FormData();
    formData.append('year', String(year));
    files.forEach((file) => formData.append('reports', file, file.name));
    const response = await apiClient.post<ApiResponse<ReportUploadPreviewSession>>(
      '/reports/import/upload/preview',
      formData,
      { timeout: 120000 },
    );
    return response.data.data;
  },

  commitHistoricalReportUpload: async (
    sessionToken: string,
    selectedIds: string[],
  ): Promise<ReportUploadCommitResult> => {
    const response = await apiClient.post<ApiResponse<ReportUploadCommitResult>>(
      '/reports/import/upload/commit',
      { sessionToken, selectedIds },
      { timeout: 120000 },
    );
    return response.data.data;
  },

  cancelHistoricalReportUpload: async (sessionToken: string): Promise<{ cancelled: boolean; sessionToken: string }> => {
    const response = await apiClient.delete<ApiResponse<{ cancelled: boolean; sessionToken: string }>>(
      `/reports/import/upload/${encodeURIComponent(sessionToken)}`,
    );
    return response.data.data;
  },

  queryReportCopilot: async (message: string): Promise<ReportCopilotResult> => {
    const response = await apiClient.post<ApiResponse<ReportCopilotResult>>('/reports/copilot/query', { message });
    return response.data.data;
  },
};

function toStringList(value: unknown): string[] {
  return Array.isArray(value) ? value.map((item) => (typeof item === 'string' ? item : JSON.stringify(item))) : [];
}

function cleanParams<T extends object>(params: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(params).filter(([, value]) => value !== undefined && value !== null && value !== ''),
  ) as Partial<T>;
}

// Prefers the backend's `detail` message, then the transport error, then the caller's fallback.
export function getErrorMessage(error: unknown, fallback: string): string {
  if (axios.isAxiosError(error)) {
    const detail = (error.response?.data as { detail?: unknown } | undefined)?.detail;
    if (typeof detail === 'string' && detail) return detail;
  }
  if (error instanceof Error && error.message) return error.message;
  return fallback;
}

export default apiClient;
