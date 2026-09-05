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

export interface DashboardStats {
  totalRevenue: number;
  totalUsers: number;
  totalOrders: number;
  conversionRate: number;
  revenueData: { month: string; revenue: number }[];
  userGrowth: { month: string; users: number }[];
}

export interface DetectionRuleContext {
  status?: string;
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
  metadata?: unknown[];
  source_file?: string;
  raw_rule?: string;
  action?: string;
}

export interface RuleMatch {
  status: 'unresolved' | 'matched' | 'no_match' | 'ambiguous' | 'pending';
  matchType: string | null;
  signature: string | null;
  candidateCount: number;
  reason: string | null;
  resolutionEvidence: any[];
}

export interface Alert {
  alertId: string;
  source: string;
  signature: string | null;
  eventType: string | null;
  host: string | null;
  status: 'new' | 'investigating' | 'resolved' | 'closed' | 'analyzed';
  aiStatus: 'not_analyzed' | 'analyzing' | 'analyzed' | 'failed';
  aiEligibility: { eligible: boolean; scenario: string | null; reason: string | null };
  severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  createdAt: string;
  updatedAt: string;
  eventHash: string;
  ruleMatch?: RuleMatch;
  detectionRule?: DetectionRuleContext;
  rawEvent?: Record<string, any>;
  fullAnalysis?: any;
  analysis?: any[];
  processing?: Record<string, any>;
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
  severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  source: string;
  signature: string | null;
  eventType: string | null;
  host: string | null;
  status: 'not_analyzed' | 'analyzing' | 'analyzed' | 'failed';
}

export interface TableColumn {
  title: string;
  dataIndex: string;
  key: string;
  render?: (value: any, record: any) => React.ReactNode;
  sorter?: boolean | ((a: any, b: any) => number);
  filters?: { text: string; value: any }[];
}

export type ThemeMode = 'light' | 'dark';
