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
  CopilotResponse,
  CopilotChatHistoryItem,
  CopilotConversationState,
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

  streamThreatHunt: async ({
    goal,
    maxSteps = 6,
    signal,
    onEvent,
  }: {
    goal: string;
    maxSteps?: number;
    signal?: AbortSignal;
    onEvent: (event: any) => void;
  }): Promise<void> => {
    const token = localStorage.getItem('access_token');
    const response = await fetch(buildApiUrl('/hunting/stream'), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ goal, maxSteps }),
      signal,
    });

    if (!response.ok) {
      throw new Error(`Threat hunt request failed (${response.status})`);
    }
    if (!response.body) throw new Error('Threat hunt stream is unavailable');

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { value, done } = await reader.read();
      buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        const text = line.trim();
        if (!text) continue;
        onEvent(JSON.parse(text));
      }
      if (done) break;
    }

    if (buffer.trim()) onEvent(JSON.parse(buffer.trim()));
  },

  generateDetectionProposal: async ({
    goal,
    report,
    days = 30,
  }: {
    goal: string;
    report: any;
    days?: number;
  }): Promise<any> => {
    const response = await apiClient.post<ApiResponse<any>>('/hunting/detection-proposal', {
      goal,
      report,
      days,
    });
    return response.data.data;
  },

  getBehaviorAnomalies: async (params: {
    dimension?: 'signature' | 'host' | 'source' | 'rule';
    hours?: number;
    baselineDays?: number;
    limit?: number;
  } = {}): Promise<any> => {
    const response = await apiClient.get<ApiResponse<any>>('/hunting/behavior/anomalies', {
      params: cleanParams(params),
    });
    return response.data.data;
  },
};

function buildApiUrl(path: string): string {
  const base = String(import.meta.env.VITE_API_URL || '').replace(/\/$/, '');
  return `${base}${path}`;
}

function cleanParams<T extends Record<string, any>>(params: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(params).filter(([, value]) => value !== undefined && value !== null && value !== ''),
  ) as Partial<T>;
}

export default apiClient;