import axios from 'axios';
import { ApiResponse, DashboardStats, Alert, AIAlertResponse } from '../types';

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
  getAlerts: async (): Promise<Alert[]> => {
    const response = await apiClient.get<ApiResponse<{
      alerts: Alert[];
      pagination?: any;
      filters?: any;
      sort?: any;
    }>>('/alerts');
    return response.data.data.alerts;
  },

  getAlertById: async (alertId: string): Promise<Alert> => {
    const response = await apiClient.get<Alert>(`/alerts/${alertId}`);
    return response.data;
  },

  getDashboardStats: async (): Promise<DashboardStats> => {
    const alerts = await api.getAlerts();
    const total = alerts.length;
    const highRisk = alerts.filter(a => a.severity === 'critical' || a.severity === 'high').length;
    const analyzed = alerts.filter(a => a.aiStatus === 'analyzed').length;
    const pending = alerts.filter(a => a.aiStatus === 'not_analyzed' || a.aiStatus === 'analyzing').length;
    return {
      totalRevenue: total,
      totalUsers: highRisk,
      totalOrders: analyzed,
      conversionRate: total ? Math.round((analyzed / total) * 100) : 0,
      revenueData: [{ month: 'Alerts', revenue: total }],
      userGrowth: [
        { month: 'High/Critical', users: highRisk },
        { month: 'Pending AI', users: pending },
        { month: 'Analyzed', users: analyzed },
      ],
    };
  },

  generateAIAnalysis: async (alertId: string): Promise<AIAlertResponse> => {
    const response = await apiClient.post<ApiResponse<{
      alertId: string;
      aiStatus: Alert['aiStatus'];
      analysis: any;
      ruleMatch: Alert['ruleMatch'];
      detectionRule?: any;
      metadata?: any;
    }>>(`/alerts/${alertId}/analyze`);

    const result = response.data.data;
    return {
      id: `${result.alertId}-${Date.now()}`,
      alertId: result.alertId,
      content: result.analysis?.final_soc_note || result.analysis?.incident_summary || '',
      timestamp: new Date().toISOString(),
      confidence: Number(result.analysis?.risk_assessment?.confidence ?? 0),
      summary: result.analysis?.incident_summary || '',
      insights: result.analysis?.observed_evidence || [],
      recommendations: result.analysis?.recommended_investigation_steps || [],
      severity: (result.analysis?.risk_assessment?.severity || 'unknown') as any,
      source: '',
      signature: null,
      eventType: null,
      host: null,
      status: result.aiStatus,
    };
  },

  regenerateAIAnalysis: async (alertId: string): Promise<AIAlertResponse> => api.generateAIAnalysis(alertId),
};

export default apiClient;
