const { CopilotService } = require("./copilotService");
const { ReportCopilotService } = require("./reportCopilotService");
const { HistoricalReportContextService } = require("./historicalReportContextService");
const { normalizeConversationState } = require("../copilot/conversationState");

// Routes each question to the right backend: focused historical exposure lookups and
// historical-report analytics are answered deterministically; everything else goes to
// the LLM-planned SOC Copilot. Composition keeps each backend independently testable.
class UnifiedCopilotService {
  constructor({
    socCopilot,
    reportCopilot = new ReportCopilotService(),
    historicalReportContext = new HistoricalReportContextService(),
    ...socCopilotOptions
  } = {}) {
    this.socCopilot = socCopilot || new CopilotService(socCopilotOptions);
    this.reportCopilot = reportCopilot;
    this.historicalReportContext = historicalReportContext;
  }

  get timezone() {
    return this.socCopilot.timezone;
  }

  listTools() {
    return this.socCopilot.listTools();
  }

  describeSchema(dataset) {
    return this.socCopilot.describeSchema(dataset);
  }

  async query(question, options = {}) {
    const message = String(question || "").trim();
    const state = normalizeConversationState(options.state || {});

    if (looksLikeFocusedHistoricalExposureQuestion(message)) {
      const hints = resolveHistoricalFocus(message, state);
      if (hints && this.historicalReportContext?.getContext) {
        const context = await this.historicalReportContext.getContext(hints);
        return {
          supported: true,
          answer: formatHistoricalExposureAnswer(message, context),
          tool: "historical_report_context",
          queryPlan: {
            operation: "historical_exposure",
            organizations: hints.organizations || [],
            ips: hints.ips || [],
          },
          result: context,
          metadata: {
            readOnly: true,
            deterministic: true,
            historicalReports: true,
            focusedEntityShortcut: true,
            mcp: false,
            timezone: this.timezone,
          },
          state,
        };
      }
    }

    if (looksLikeHistoricalReportQuestion(message)) {
      const result = await this.reportCopilot.query(message);
      return {
        supported: result.supported,
        answer: result.answer,
        tool: "query_historical_reports",
        queryPlan: result.plan,
        result: result.data,
        metadata: {
          readOnly: true,
          deterministic: true,
          historicalReports: true,
          mcp: false,
          timezone: this.timezone,
        },
        state,
      };
    }

    return this.socCopilot.query(question, options);
  }
}

function looksLikeFocusedHistoricalExposureQuestion(value) {
  const text = normalizeText(value);
  return /(?:سابقه|قبلا|قبلاً|قبلی|پیشتر|تا\s*حالا|گزارش\s*های?\s*قبل|آسیب\s*پذیری\s*های?\s*قبل|رخداد\s*های?\s*قبل|history|historical|prior|previous|past\s+(?:report|vulnerabil|incident))/.test(text);
}

function resolveHistoricalFocus(message, state) {
  const text = normalizeText(message);
  const related = state?.relatedEntities || {};
  const organizations = [];
  const ips = [];

  if (state?.focus?.entityType === "organization" && state.focus.id) organizations.push(state.focus.id);
  if (state?.focus?.entityType === "ip" && state.focus.id) ips.push(state.focus.id);

  if (related.organization) organizations.push(related.organization);

  if (/(?:مقصد|destination|dst)/.test(text) && related.destinationIp) {
    ips.push(related.destinationIp);
  } else if (/(?:مبدا|مبدأ|source|src)/.test(text) && related.sourceIp) {
    ips.push(related.sourceIp);
  } else {
    if (related.sourceIp) ips.push(related.sourceIp);
    if (related.destinationIp) ips.push(related.destinationIp);
  }

  const cleanOrganizations = uniqueStrings(organizations);
  const cleanIps = uniqueStrings(ips);
  if (!cleanOrganizations.length && !cleanIps.length) return null;
  return { organizations: cleanOrganizations, ips: cleanIps };
}

function formatHistoricalExposureAnswer(question, context = {}) {
  const persian = /[\u0600-\u06FF]/.test(String(question || ""));
  if (context.status === "unavailable") {
    return persian
      ? "سابقه گزارش‌های تاریخی در حال حاضر قابل دسترسی نیست؛ تحلیل Alert همچنان می‌تواند با شواهد فعلی ادامه پیدا کند."
      : "Historical report context is currently unavailable; the alert can still be assessed from current evidence.";
  }

  if (context.status !== "matched" || !context.totalReports) {
    return persian
      ? "برای سازمان یا IP متمرکز فعلی، گزارش تاریخی منطبق پیدا نشد. این به معنی نبود ریسک نیست؛ فقط سابقه‌ای در دیتاست گزارش‌های import‌شده پیدا نشده است."
      : "No matching historical report was found for the focused organization or IP. This does not imply absence of risk; it only means the imported report dataset has no matching history.";
  }

  const organization = context.matchedOrganizations?.[0]
    || context.query?.organizations?.[0]
    || null;
  const findings = (context.findingCounts || [])
    .slice(0, 4)
    .map((item) => `${item.name || item.type} (${item.count})`)
    .join(persian ? "، " : ", ");
  const latest = context.latestReport;

  if (persian) {
    return [
      organization ? `برای «${organization}» ${context.totalReports} گزارش امنیتی تاریخی منطبق پیدا شد.` : `${context.totalReports} گزارش امنیتی تاریخی منطبق پیدا شد.`,
      `از این تعداد ${context.vulnerabilityReports || 0} گزارش آسیب‌پذیری، ${context.misconfigurationReports || 0} پیکربندی نامناسب و ${context.incidentReports || 0} گزارش حادثه/رخداد بوده است.`,
      `${context.highCriticalCount || 0} مورد High/Critical و ${context.immediateCount || 0} مورد نیازمند اقدام فوری بوده‌اند${context.sameIpReportCount ? `؛ ${context.sameIpReportCount} گزارش هم با IP فعلی match شده است` : ""}.`,
      findings ? `یافته‌های پرتکرار قبلی: ${findings}.` : null,
      latest?.reportDateRaw ? `آخرین گزارش منطبق مربوط به ${latest.reportDateRaw}${latest.title ? ` با عنوان «${latest.title}»` : ""} است.` : null,
      "این سابقه برای اولویت‌بندی و بررسی وضعیت remediation مهم است، اما به‌تنهایی اثبات نمی‌کند Alert فعلی ناشی از همان ضعف یا نشانه compromise باشد.",
    ].filter(Boolean).join("\n");
  }

  return [
    organization ? `${organization} has ${context.totalReports} matching historical security reports.` : `${context.totalReports} matching historical security reports were found.`,
    `${context.vulnerabilityReports || 0} vulnerability, ${context.misconfigurationReports || 0} misconfiguration, and ${context.incidentReports || 0} incident reports.`,
    `${context.highCriticalCount || 0} were high/critical and ${context.immediateCount || 0} required immediate action${context.sameIpReportCount ? `; ${context.sameIpReportCount} also matched the current IP context` : ""}.`,
    findings ? `Top prior findings: ${findings}.` : null,
    "Use this as prioritization and remediation context only; it does not prove causation or current compromise.",
  ].filter(Boolean).join("\n");
}

function looksLikeHistoricalReportQuestion(value) {
  const text = normalizeText(value);

  if (!/(گزارش|report)/.test(text)) return false;
  return /(?:13\d{2}|14\d{2}|15\d{2}|چند|تعداد|بیشترین|رایج|روند|ماهانه|درصد|finding|یافته|نوع گزارش|حادثه|رخداد|آسیب\s*پذیری|پیکربندی|xss|sql|rce|dependency|udp amplification|syn flood|tcp flood|ترافیک.*ناهنجار|routeros|mikrotik|cve-\d{4}-\d+|پورت\s*\d+|شدت|فوریت|جهت اطلاع|اقدام فوری|سازمان|(?:\d{1,3}\.){3}\d{1,3})/.test(text);
}

function normalizeText(value) {
  return String(value || "")
    .replace(/[۰-۹]/g, (char) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(char)))
    .replace(/[٠-٩]/g, (char) => String("٠١٢٣٤٥٦٧٨٩".indexOf(char)))
    .replace(/ي/g, "ی")
    .replace(/ك/g, "ک")
    .replace(/[‌\u200c]/g, " ")
    .replace(/آسیب[\s-]*پذیری/g, "آسیب پذیری")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function uniqueStrings(values) {
  return [...new Set((values || [])
    .filter((value) => value !== undefined && value !== null)
    .map((value) => String(value).trim())
    .filter(Boolean))];
}

module.exports = {
  UnifiedCopilotService,
  looksLikeHistoricalReportQuestion,
  looksLikeFocusedHistoricalExposureQuestion,
  resolveHistoricalFocus,
  formatHistoricalExposureAnswer,
};