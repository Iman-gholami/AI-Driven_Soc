import type {
  HistoricalReport,
  ReportCopilotResult,
  ReportFilterParams,
  ReportStats,
} from '../../types/reports';

// Constants, types and pure helpers shared by the Reports page and its widgets.
export const JALALI_MONTHS = ['فروردین', 'اردیبهشت', 'خرداد', 'تیر', 'مرداد', 'شهریور', 'مهر', 'آبان', 'آذر', 'دی', 'بهمن', 'اسفند'];
export const TARGET_LABEL: Record<string, string> = { single: 'تک‌هدف', multi_target: 'چندهدف', scope: 'حوزه‌ای', unknown: 'نامشخص' };
export const TARGET_COLOR: Record<string, string> = { single: 'blue', multi_target: 'orange', scope: 'purple', unknown: 'default' };
export const REPORT_TYPE_LABEL: Record<string, string> = { misconfiguration: 'Misconfiguration', vulnerability: 'Vulnerability', incident: 'Incident', malware: 'Malware', unknown: 'Unknown' };
export const SEVERITY_COLOR: Record<string, string> = { critical: 'red', high: 'volcano', medium: 'gold', low: 'blue', info: 'cyan', unknown: 'default', none: 'default' };
export const FILTER_LABELS: Record<string, string> = {
  month: 'ماه', day: 'روز', reportType: 'نوع گزارش', targetMode: 'نوع هدف', scopeName: 'حوزه', severity: 'شدت', urgency: 'فوریت', finding: 'Finding', organization: 'سازمان', ip: 'IP', port: 'Port', service: 'Service', domain: 'Domain', cve: 'CVE', provider: 'Provider', search: 'جستجو',
};
export const SAVED_VIEW_KEY = 'report-intelligence-saved-views-v2';

export type ReportYear = number | 'all';
export type ReportFilterState = Omit<ReportFilterParams, 'year'>;
export type EntitySelection = { type: 'organization' | 'scope' | 'ip' | 'finding'; value: string };
export type SavedView = { id: string; name: string; year: ReportYear; filters: ReportFilterState };
export type Density = 'compact' | 'comfortable';
export type ChatMessage = { role: 'user' | 'assistant'; content: string; result?: ReportCopilotResult };
export type ChangeItem = { label: string; value: string; direction: 'up' | 'down' | 'flat'; detail: string };

export const URL_FILTER_KEYS: Array<keyof ReportFilterState> = [
  'month',
  'day',
  'reportType',
  'targetMode',
  'scopeType',
  'scopeName',
  'severity',
  'urgency',
  'finding',
  'organization',
  'ip',
  'port',
  'service',
  'domain',
  'cve',
  'provider',
  'search',
];

export function readReportUrlState(): { year: ReportYear; filters: ReportFilterState } {
  if (typeof window === 'undefined') return { year: 1404, filters: {} };

  const search = new URLSearchParams(window.location.search);
  const rawYear = search.get('year');
  const parsedYear = Number(rawYear);
  const year: ReportYear =
    rawYear === 'all'
      ? 'all'
      : Number.isInteger(parsedYear) && parsedYear > 0
        ? parsedYear
        : 1404;

  const filters: ReportFilterState = {};

  for (const key of URL_FILTER_KEYS) {
    const raw = search.get(key);
    if (raw === null || raw === '') continue;

    if (key === 'month' || key === 'day' || key === 'port') {
      const numeric = Number(raw);
      if (Number.isFinite(numeric)) {
        (filters as Record<string, unknown>)[key] = numeric;
      }
      continue;
    }

    (filters as Record<string, unknown>)[key] = raw;
  }

  return { year, filters };
}

export function buildReportUrl(year: ReportYear, filters: ReportFilterState) {
  const url = new URL(window.location.href);
  const next = new URLSearchParams();

  next.set('year', String(year));

  for (const key of URL_FILTER_KEYS) {
    const value = filters[key];
    if (value === undefined || value === null || value === '') continue;
    next.set(key, String(value));
  }

  url.search = next.toString();
  return url.toString();
}

export function syncReportUrl(year: ReportYear, filters: ReportFilterState) {
  if (typeof window === 'undefined') return;

  const next = buildReportUrl(year, filters);
  if (next !== window.location.href) {
    window.history.replaceState(null, '', next);
  }
}

export function previousPeriodParams(params: ReportFilterParams): ReportFilterParams {
  const currentYear = Number(params.year || 1404);
  const next: ReportFilterParams = { ...params, year: currentYear, day: undefined };
  if (params.month) {
    if (params.month > 1) next.month = params.month - 1;
    else { next.year = currentYear - 1; next.month = 12; }
  } else {
    next.year = currentYear - 1;
  }
  return next;
}

export function buildComparison(current?: ReportStats, previous?: ReportStats, params?: ReportFilterParams, previousParams?: ReportFilterParams) {
  if (!previousParams) {
    return { label: 'نمای مجموع همه سال‌ها', items: [] as ChangeItem[] };
  }
  const label = params?.month ? `مقایسه با ${JALALI_MONTHS[Number(previousParams?.month || 1) - 1]} ${previousParams?.year}` : `مقایسه با سال ${previousParams?.year}`;
  if (!current || !previous) return { label, items: [] as ChangeItem[] };
  const metrics: Array<[string, number, number]> = [
    ['Reports', current.summary.total, previous.summary.total],
    ['Organizations', current.summary.uniqueOrganizations, previous.summary.uniqueOrganizations],
    ['High / Critical', current.summary.highCritical, previous.summary.highCritical],
    ['Scope-wide', current.byTargetMode.find((item) => item.mode === 'scope')?.count || 0, previous.byTargetMode.find((item) => item.mode === 'scope')?.count || 0],
  ];
  const items: ChangeItem[] = metrics.map(([name, now, before]) => {
    const delta = now - before;
    const pct = before ? Math.round((delta / before) * 100) : (now ? 100 : 0);
    return { label: name, value: `${delta > 0 ? '+' : ''}${delta}`, direction: delta > 0 ? 'up' : delta < 0 ? 'down' : 'flat', detail: `${pct > 0 ? '+' : ''}${pct}%` };
  });
  const currentTop = current.byFinding[0];
  const previousTop = previous.byFinding[0];
  if (currentTop) items.push({ label: 'Top finding', value: currentTop.name || currentTop.key, direction: currentTop.key === previousTop?.key ? 'flat' : 'up', detail: currentTop.key === previousTop?.key ? 'unchanged' : 'changed' });
  return { label, items };
}

export function targetModeDescription(mode: string) {
  if (mode === 'scope') return 'حوزه/گروه هدف';
  if (mode === 'multi_target') return 'چند سازمان یا دارایی';
  if (mode === 'single') return 'یک هدف مشخص';
  return 'نیازمند بررسی';
}

export function formatScopeLabel(year: ReportYear, filters: ReportFilterState) {
  if (year === 'all') return 'همه سال‌ها';
  if (filters.month && filters.day) return `${filters.day} ${JALALI_MONTHS[filters.month - 1]} ${year}`;
  if (filters.month) return `${JALALI_MONTHS[filters.month - 1]} ${year}`;
  return `سال ${year}`;
}

export function csvValues(value: string) { return value.split(',').map((item) => item.trim()).filter(Boolean); }
export function normalizeFa(value: string) { return String(value || '').replace(/ي/g, 'ی').replace(/ك/g, 'ک').replace(/\u200c/g, ' ').replace(/\s+/g, ' ').trim().toLocaleLowerCase('fa'); }
export function entityTitle(type: EntitySelection['type']) { return type === 'organization' ? 'Organization' : type === 'scope' ? 'Scope' : type === 'ip' ? 'IP' : 'Finding'; }
export function humanFilterValue(key: string, value: unknown) { if (key === 'month') return JALALI_MONTHS[Number(value) - 1] || String(value); if (key === 'targetMode') return csvValues(String(value)).map((item) => TARGET_LABEL[item] || item).join('، '); if (key === 'reportType') return csvValues(String(value)).map((item) => REPORT_TYPE_LABEL[item] || item).join('، '); return String(value); }
export function loadSavedViews(): SavedView[] { try { const raw = localStorage.getItem(SAVED_VIEW_KEY); const parsed = raw ? JSON.parse(raw) : []; return Array.isArray(parsed) ? parsed : []; } catch { return []; } }

export function toCsv(reports: HistoricalReport[]) {
  const headers = ['date', 'reportNumber', 'reportType', 'targetMode', 'scope', 'organization', 'ip', 'assets', 'finding', 'severity', 'score', 'urgency', 'quality'];
  const lines = reports.map((report) => [report.reportDateRaw, report.reportNumber, report.reportType, report.target?.mode, report.target?.scopeName, report.target?.organization, report.target?.ip, report.affectedSystems?.length || 0, report.finding?.name || report.finding?.type, report.severity?.level, report.severity?.score, report.urgency?.normalized, report.extraction?.warnings?.length ? 'review' : 'clean'].map(csvEscape).join(','));
  return [headers.join(','), ...lines].join('\n');
}
export function csvEscape(value: unknown) { const text = String(value ?? ''); return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text; }
