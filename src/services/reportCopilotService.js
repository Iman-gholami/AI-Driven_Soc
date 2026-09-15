const HistoricalReport = require("../models/HistoricalReport");
const { ReportAnalyticsService, buildReportFilter } = require("./reportAnalyticsService");
const { toAsciiDigits } = require("./reportDocxParser");

class ReportCopilotService {
  constructor({ model = HistoricalReport, analytics = new ReportAnalyticsService({ model }) } = {}) {
    this.model = model;
    this.analytics = analytics;
  }

  async query(question) {
    const message = String(question || "").trim();
    if (!message) throw new ReportCopilotInputError("message is required");
    if (message.length > 2000) throw new ReportCopilotInputError("message is too long");

    const plan = planReportQuestion(message);
    const year = plan.year || await this.getLatestYear();
    if (!year) {
      return {
        supported: true,
        answer: "هنوز هیچ گزارش تاریخی import نشده است.",
        plan: { ...plan, year: null },
        data: null,
      };
    }

    const resolvedPlan = { ...plan, year };
    const data = await this.execute(resolvedPlan);
    return {
      supported: plan.operation !== "unsupported",
      answer: formatReportAnswer(message, resolvedPlan, data),
      plan: resolvedPlan,
      data,
      metadata: { deterministic: true, readOnly: true },
    };
  }

  async getLatestYear() {
    const years = await this.analytics.getYears();
    return years[0]?.year || null;
  }

  async execute(plan) {
    if (plan.operation === "count") {
      const filter = buildReportFilter({
        year: plan.year,
        severity: plan.severity,
        urgency: plan.urgency,
        vulnerability: plan.vulnerability,
        ip: plan.ip,
      });
      const count = await this.model.countDocuments(filter).exec();
      return { count };
    }

    if (plan.operation === "immediate_percentage") {
      const stats = await this.analytics.getStats(plan.year);
      return {
        total: stats.summary.total,
        immediate: stats.summary.immediate,
        percentage: stats.summary.immediatePercent,
      };
    }

    if (plan.operation === "top_vulnerabilities") {
      const stats = await this.analytics.getStats(plan.year);
      return { rows: stats.byVulnerability.slice(0, plan.limit || 10) };
    }

    if (plan.operation === "top_organizations") {
      const match = { year: plan.year };
      if (plan.severity) match["severity.level"] = plan.severity;
      const rows = await this.model.aggregate([
        { $match: match },
        { $match: { "target.organization": { $nin: [null, ""] } } },
        { $group: { _id: "$target.organization", count: { $sum: 1 } } },
        { $sort: { count: -1, _id: 1 } },
        { $limit: plan.limit || 10 },
        { $project: { _id: 0, organization: "$_id", count: 1 } },
      ]).exec();
      return { rows };
    }

    if (plan.operation === "monthly_trend") {
      const stats = await this.analytics.getStats(plan.year);
      return { rows: stats.byMonth };
    }

    if (plan.operation === "severity_breakdown") {
      const stats = await this.analytics.getStats(plan.year);
      return { rows: stats.bySeverity };
    }

    if (plan.operation === "urgency_breakdown") {
      const stats = await this.analytics.getStats(plan.year);
      return { rows: stats.byUrgency };
    }

    if (plan.operation === "ip_reports") {
      return this.analytics.list({ year: plan.year, ip: plan.ip, page: 1, limit: plan.limit || 20 });
    }

    return {
      examples: [
        "در سال ۱۴۰۴ چند گزارش داشتیم؟",
        "بیشترین آسیب‌پذیری سال ۱۴۰۴ چه بوده؟",
        "کدام سازمان بیشترین گزارش High داشته؟",
        "چند درصد گزارش‌های ۱۴۰۴ نیازمند اقدام فوری بوده‌اند؟",
        "روند ماهانه گزارش‌های ۱۴۰۴ را نشان بده",
        "برای IP 62.60.167.73 چه گزارش‌هایی داریم؟",
      ],
    };
  }
}

function planReportQuestion(question) {
  const normalized = normalizeQuestion(question);
  const yearMatch = normalized.match(/\b(13\d{2}|14\d{2}|15\d{2})\b/);
  const year = yearMatch ? Number(yearMatch[1]) : null;
  const ip = (normalized.match(/(?:\d{1,3}\.){3}\d{1,3}/) || [])[0] || null;
  const severity = detectSeverity(normalized);
  const vulnerability = detectVulnerability(normalized);
  const limit = detectLimit(normalized);

  if (ip) return { operation: "ip_reports", year, ip, limit };
  if (/درصد/.test(normalized) && /(فوری|اقدام فوری)/.test(normalized)) {
    return { operation: "immediate_percentage", year };
  }
  if (/(روند|ماهانه|به تفکیک ماه|ماه به ماه)/.test(normalized)) {
    return { operation: "monthly_trend", year };
  }
  if (/(بیشترین|رایج ترین|رایج‌ترین|top).*(آسیب پذیری|vulnerability)|آسیب پذیری.*(بیشترین|رایج)/.test(normalized)) {
    return { operation: "top_vulnerabilities", year, limit };
  }
  if (/(کدام|بیشترین|top).*(سازمان)|سازمان.*(بیشترین|top)/.test(normalized)) {
    return { operation: "top_organizations", year, severity, limit };
  }
  if (/(تفکیک|توزیع|آمار).*(شدت)|شدت.*(تفکیک|توزیع)/.test(normalized)) {
    return { operation: "severity_breakdown", year };
  }
  if (/(تفکیک|توزیع|آمار).*(فوریت)|فوریت.*(تفکیک|توزیع)/.test(normalized)) {
    return { operation: "urgency_breakdown", year };
  }
  if (/(چند|تعداد|count)/.test(normalized) && /(گزارش|report)/.test(normalized)) {
    return {
      operation: "count",
      year,
      severity,
      vulnerability,
      urgency: /(فوری|اقدام فوری)/.test(normalized) ? "immediate" : null,
    };
  }

  return { operation: "unsupported", year };
}

function detectSeverity(text) {
  if (/critical|بحرانی|خیلی شدید/.test(text)) return "critical";
  if (/\bhigh\b|شدت بالا|پرخطر/.test(text)) return "high";
  if (/\bmedium\b|متوسط/.test(text)) return "medium";
  if (/\blow\b|شدت کم/.test(text)) return "low";
  return null;
}

function detectVulnerability(text) {
  if (/cross[-\s]?site scripting|\bxss\b/.test(text)) return "xss";
  if (/sql injection|\bsqli\b|تزریق sql/.test(text)) return "sql_injection";
  if (/remote code execution|\brce\b/.test(text)) return "rce";
  if (/ssrf|server[-\s]?side request forgery/.test(text)) return "ssrf";
  if (/csrf|cross[-\s]?site request forgery/.test(text)) return "csrf";
  if (/directory traversal|path traversal/.test(text)) return "path_traversal";
  if (/xxe|xml external entity/.test(text)) return "xxe";
  if (/weak tls|tls ضعیف|ssl ضعیف/.test(text)) return "weak_tls";
  return null;
}

function detectLimit(text) {
  const match = text.match(/(?:top|اول|برتر)\s*(\d{1,2})/);
  if (!match) return 10;
  return Math.max(1, Math.min(20, Number(match[1])));
}

function normalizeQuestion(value) {
  return toAsciiDigits(String(value || ""))
    .replace(/ي/g, "ی")
    .replace(/ك/g, "ک")
    .replace(/[‌\u200c]/g, " ")
    .replace(/آسیب[‌\s-]*پذیری/g, "آسیب پذیری")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function formatReportAnswer(question, plan, data) {
  const year = plan.year;
  if (plan.operation === "count") {
    const qualifiers = [
      plan.severity ? `با شدت ${plan.severity}` : null,
      plan.vulnerability ? `از نوع ${plan.vulnerability}` : null,
      plan.urgency === "immediate" ? "نیازمند اقدام فوری" : null,
    ].filter(Boolean).join(" و ");
    return `در سال ${year}، ${Number(data.count || 0)} گزارش${qualifiers ? ` ${qualifiers}` : ""} ثبت شده است.`;
  }
  if (plan.operation === "immediate_percentage") {
    return `در سال ${year}، ${Number(data.immediate || 0)} گزارش از ${Number(data.total || 0)} گزارش نیازمند اقدام فوری بوده‌اند؛ یعنی ${Number(data.percentage || 0)}٪.`;
  }
  if (plan.operation === "top_vulnerabilities") {
    if (!data.rows?.length) return `برای سال ${year} داده‌ای برای آسیب‌پذیری‌ها وجود ندارد.`;
    return [`آسیب‌پذیری‌های پرتکرار سال ${year}:`, ...data.rows.map((row, index) => `${index + 1}. ${row.name || row.key}: ${row.count}`)].join("\n");
  }
  if (plan.operation === "top_organizations") {
    if (!data.rows?.length) return `برای سال ${year} داده سازمانی وجود ندارد.`;
    const qualifier = plan.severity ? ` با شدت ${plan.severity}` : "";
    return [`سازمان‌های دارای بیشترین گزارش${qualifier} در سال ${year}:`, ...data.rows.map((row, index) => `${index + 1}. ${row.organization}: ${row.count}`)].join("\n");
  }
  if (plan.operation === "monthly_trend") {
    return [`روند ماهانه گزارش‌های سال ${year}:`, ...(data.rows || []).map((row) => `ماه ${row.month ?? "نامشخص"}: ${row.count}`)].join("\n");
  }
  if (plan.operation === "severity_breakdown") {
    return [`توزیع شدت گزارش‌های سال ${year}:`, ...(data.rows || []).map((row) => `${row.severity}: ${row.count}`)].join("\n");
  }
  if (plan.operation === "urgency_breakdown") {
    return [`توزیع فوریت گزارش‌های سال ${year}:`, ...(data.rows || []).map((row) => `${row.urgency}: ${row.count}`)].join("\n");
  }
  if (plan.operation === "ip_reports") {
    const reports = data.reports || [];
    if (!reports.length) return `برای IP ${plan.ip} در سال ${year} گزارشی پیدا نشد.`;
    return [`برای IP ${plan.ip} در سال ${year}، ${data.pagination?.total || reports.length} گزارش پیدا شد:`, ...reports.slice(0, 10).map((report) => `- ${report.reportNumber || report.documentKey}: ${report.title}`)].join("\n");
  }
  return "این سؤال هنوز در Report Copilot پشتیبانی نمی‌شود. می‌توانی درباره تعداد گزارش‌ها، آسیب‌پذیری‌های پرتکرار، سازمان‌ها، شدت، فوریت، روند ماهانه یا یک IP سؤال کنی.";
}

class ReportCopilotInputError extends Error {
  constructor(message) {
    super(message);
    this.name = "ReportCopilotInputError";
  }
}

module.exports = {
  ReportCopilotService,
  ReportCopilotInputError,
  planReportQuestion,
  normalizeQuestion,
  detectSeverity,
  detectVulnerability,
  formatReportAnswer,
};
