const { z } = require("zod");
const { settings } = require("../core/config");
const { LLMService } = require("./llmService");
const { SocMcpServer } = require("../mcp/socMcpServer");
const { InProcessMcpClient } = require("../mcp/inProcessClient");
const { copilotPlanSchema } = require("../copilot/querySchema");
const {
  normalizeConversationState,
  deriveConversationState,
} = require("../copilot/conversationState");
const {
  PLANNER_SYSTEM_PROMPT,
  ANSWER_SYSTEM_PROMPT,
  buildPlannerUserPrompt,
  buildAnswerUserPrompt,
} = require("../copilot/prompts");

const answerSchema = z.object({ answer: z.string().min(1).max(8000) }).strict();

class CopilotService {
  constructor({
    llm = new LLMService(),
    mcpClient = new InProcessMcpClient({ server: new SocMcpServer() }),
    timezone = settings.socTimezone || "Asia/Tehran",
    now = () => new Date(),
  } = {}) {
    this.llm = llm;
    this.mcpClient = mcpClient;
    this.timezone = timezone;
    this.now = now;
  }

  async listTools() {
    return this.mcpClient.listTools();
  }

  async describeSchema(dataset) {
    return this.mcpClient.callTool("describe_soc_schema", dataset ? { dataset } : {});
  }

  async query(question, { history = [], state = {} } = {}) {
    const message = String(question || "").trim();
    if (!message) throw new CopilotInputError("message is required");
    if (message.length > 4000) throw new CopilotInputError("message is too long");
    const safeHistory = normalizeHistory(history);
    const safeState = normalizeConversationState(state);

    const tools = await this.mcpClient.listTools();
    const schema = await this.mcpClient.callTool("describe_soc_schema", {});
    const currentTime = this.now();

    let plan;
    try {
      const plannerOutput = await this.llm.completeJson({
        systemPrompt: PLANNER_SYSTEM_PROMPT,
        userPrompt: buildPlannerUserPrompt({
          question: message,
          history: safeHistory,
          state: safeState,
          schema,
          tools,
          timezone: this.timezone,
          now: currentTime.toISOString(),
        }),
        temperature: 0,
      });
      plan = copilotPlanSchema.parse(plannerOutput);
    } catch (error) {
      throw new CopilotPlannerError("Unable to produce a valid read-only query plan", { cause: error });
    }
    if (plan.tool === "unsupported") {
      return {
        supported: false,
        answer: buildUnsupportedAnswer(message),
        tool: null,
        queryPlan: null,
        result: null,
        metadata: {
          ...this.buildMetadata(),
          unsupportedReason: plan.reason,
        },
        state: safeState,
      };
    }

    let queryResult;
    try {
      queryResult = await this.mcpClient.callTool(plan.tool, plan.arguments);
    } catch (error) {
      throw new CopilotQueryError("The planned SOC query was rejected or could not be executed", { cause: error });
    }
    let answer;

    try {
      const formatted = await this.llm.completeJson({
        systemPrompt: ANSWER_SYSTEM_PROMPT,
        userPrompt: buildAnswerUserPrompt({ question: message, queryResult }),
        temperature: 0,
      });
      answer = answerSchema.parse(formatted).answer;
    } catch (_) {
      answer = fallbackAnswer(queryResult);
    }

    const resolvedPlan = queryResult.queryPlan || plan.arguments;
    const nextState = deriveConversationState({
      previousState: safeState,
      tool: plan.tool,
      result: queryResult,
      queryPlan: resolvedPlan,
    });

    return {
      supported: true,
      answer,
      tool: plan.tool,
      queryPlan: resolvedPlan,
      result: queryResult,
      metadata: this.buildMetadata(),
      state: nextState,
    };
  }

  buildMetadata() {
    const provider = typeof this.llm.getMetadata === "function"
      ? this.llm.getMetadata()
      : { provider: "unknown", model: "unknown" };
    return {
      ...provider,
      readOnly: true,
      mcp: true,
      timezone: this.timezone,
    };
  }
}

class CopilotPlannerError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = "CopilotPlannerError";
  }
}

class CopilotQueryError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = "CopilotQueryError";
  }
}

class CopilotInputError extends Error {
  constructor(message) {
    super(message);
    this.name = "CopilotInputError";
  }
}

function normalizeHistory(history) {
  if (!Array.isArray(history)) return [];

  return history
    .slice(-8)
    .map((item) => ({
      role: item?.role === "assistant" ? "assistant" : "user",
      content: String(item?.content || "").trim().slice(0, 1200),
    }))
    .filter((item) => item.content);
}

function isPersianText(value) {
  return /[\u0600-\u06FF]/.test(String(value || ""));
}

function buildUnsupportedAnswer(question) {
  if (isPersianText(question)) {
    return "این سؤال با داده‌های فعلی SOC قابل پاسخ نیست. درباره Alertها، Ruleها، IPها، Threat Intelligence، Assetها یا MITRE سؤال بپرس.";
  }

  return "This question cannot be answered from the current SOC data. Ask about alerts, rules, IPs, threat intelligence, assets, or MITRE.";
}

function fallbackAnswer(queryResult) {
  if (Array.isArray(queryResult?.results)) {
    return JSON.stringify(queryResult.results.map((item) => ({
      dataset: item.dataset,
      operation: item.operation,
      data: item.data,
      timeRange: item.timeRange,
    })));
  }

  const count = queryResult?.data?.count;
  const rows = queryResult?.data?.rows;
  if (Array.isArray(rows) && rows.length) return JSON.stringify(rows);
  if (Number.isFinite(Number(count))) return String(Number(count));
  return "Query completed, but no displayable result was returned.";
}

module.exports = {
  CopilotService,
  CopilotInputError,
  CopilotPlannerError,
  CopilotQueryError,
  normalizeHistory,
  isPersianText,
  buildUnsupportedAnswer,
  fallbackAnswer,
};
