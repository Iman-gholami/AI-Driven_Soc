import axios from 'axios';
import {
  ApiResponse,
  Alert,
  AIAlertResponse,
  AlertListParams,
  AlertListResult,
  DashboardStats,
  MitreCoverageSnapshot,
  MitreTechniqueRulesResult,
} from '../types';

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '',
  timeout: 30000,
});

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

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
      analysis: any;
      ruleMatch: Alert['ruleMatch'];
      detectionRule?: any;
      metadata?: any;
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
      insights: Array.isArray(result.analysis?.observed_evidence) ? result.analysis.observed_evidence : [],
      recommendations: Array.isArray(result.analysis?.recommended_investigation_steps)
        ? result.analysis.recommended_investigation_steps
        : [],
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
};

function cleanParams<T extends Record<string, any>>(params: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(params).filter(([, value]) => value !== undefined && value !== null && value !== ''),
  ) as Partial<T>;
}

export default apiClient;
