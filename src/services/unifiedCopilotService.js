const { CopilotService } = require("./copilotService");
const { ReportCopilotService } = require("./reportCopilotService");
const { normalizeConversationState } = require("../copilot/conversationState");

class UnifiedCopilotService extends CopilotService {
  constructor({ reportCopilot = new ReportCopilotService(), ...options } = {}) {
    super(options);
    this.reportCopilot = reportCopilot;
  }

  async query(question, options = {}) {
    const message = String(question || "").trim();
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
        state: normalizeConversationState(options.state || {}),
      };
    }

    return super.query(question, options);
  }
}

function looksLikeHistoricalReportQuestion(value) {
  const text = String(value || "")
    .replace(/[۰-۹]/g, (char) => String("۰۱۲۳۴۵۶۷۸۹".indexOf(char)))
    .replace(/[٠-٩]/g, (char) => String("٠١٢٣٤٥٦٧٨٩".indexOf(char)))
    .replace(/ي/g, "ی")
    .replace(/ك/g, "ک")
    .replace(/[‌\u200c]/g, " ")
    .toLowerCase();

  if (!/(گزارش|report)/.test(text)) return false;
  return /(?:13\d{2}|14\d{2}|15\d{2}|چند|تعداد|بیشترین|رایج|روند|ماهانه|درصد|آسیب\s*پذیری|xss|sql|rce|شدت|فوریت|اقدام فوری|سازمان|(?:\d{1,3}\.){3}\d{1,3})/.test(text);
}

module.exports = {
  UnifiedCopilotService,
  looksLikeHistoricalReportQuestion,
};
