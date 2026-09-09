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
  buildPlannerRepairPrompt,
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

    const focusedPlan = buildFocusedEntityPlan(message, safeState);
    if (focusedPlan) {
      let focusedResult;
      try {
        focusedResult = await this.mcpClient.callTool(focusedPlan.tool, focusedPlan.arguments);
      } catch (error) {
        throw new CopilotQueryError("The focused SOC entity context could not be loaded", { cause: error });
      }

      let focusedAnswer;
      try {
        const formatted = await this.llm.completeJson({
          systemPrompt: ANSWER_SYSTEM_PROMPT,
          userPrompt: buildAnswerUserPrompt({ question: message, queryResult: focusedResult }),
          temperature: 0,
        });
        focusedAnswer = answerSchema.parse(formatted).answer;
      } catch (_) {
        focusedAnswer = fallbackAnswer(focusedResult, message);
      }

      const nextState = deriveConversationState({
        previousState: safeState,
        tool: focusedPlan.tool,
        result: focusedResult,
        queryPlan: focusedPlan.arguments,
      });

      return {
        supported: true,
        answer: focusedAnswer,
        tool: focusedPlan.tool,
        queryPlan: focusedPlan.arguments,
        result: focusedResult,
        metadata: {
          ...this.buildMetadata(),
          focusedEntityShortcut: true,
        },
        state: nextState,
      };
    }

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
    let plannerRepair = null;

    try {
      queryResult = await this.mcpClient.callTool(plan.tool, plan.arguments);
    } catch (error) {
      if (!isRepairableTool(plan.tool)) {
        throw new CopilotQueryError("The planned SOC query was rejected or could not be executed", { cause: error });
      }

      const rejectedPlan = plan;
      try {
        const repairedOutput = await this.llm.completeJson({
          systemPrompt: PLANNER_SYSTEM_PROMPT,
          userPrompt: buildPlannerRepairPrompt({
            question: message,
            history: safeHistory,
            state: safeState,
            schema,
            tools,
            timezone: this.timezone,
            now: currentTime.toISOString(),
            rejectedPlan,
            validationError: error?.message || error,
          }),
          temperature: 0,
        });

        const repairedPlan = copilotPlanSchema.parse(repairedOutput);
        if (repairedPlan.tool === "unsupported") {
          return {
            supported: false,
            answer: buildUnsupportedAnswer(message),
            tool: null,
            queryPlan: null,
            result: null,
            metadata: {
              ...this.buildMetadata(),
              unsupportedReason: repairedPlan.reason,
              plannerRepair: {
                attempted: true,
                succeeded: false,
              },
            },
            state: safeState,
          };
        }

        queryResult = await this.mcpClient.callTool(repairedPlan.tool, repairedPlan.arguments);
        plannerRepair = {
          attempted: true,
          succeeded: true,
          initialTool: rejectedPlan.tool,
        };
        plan = repairedPlan;
      } catch (repairError) {
        throw new CopilotQueryError("The planned SOC query was rejected and automatic repair failed", {
          cause: repairError,
        });
      }
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
      answer = fallbackAnswer(queryResult, message);
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
      metadata: {
        ...this.buildMetadata(),
        ...(plannerRepair ? { plannerRepair } : {}),
      },
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

function isRepairableTool(tool) {
  return [
    "query_soc_data",
    "query_soc_data_batch",
    "analyze_soc_metric",
    "correlate_soc_entities",
  ].includes(String(tool || ""));
}

function buildFocusedEntityPlan(question, state) {
  const normalizedState = normalizeConversationState(state);
  if (!normalizedState.focus?.entityType || !normalizedState.focus?.id) return null;

  const text = String(question || "").trim();
  if (!text) return null;

  if (looksQuantitativeOrCrossEntity(text)) return null;
  if (!looksLikeFocusedInvestigation(text)) return null;

  const entity = resolveExplicitFocusedReference(text, normalizedState) || normalizedState.focus;
  if (!entity?.entityType || !entity?.id) return null;

  return {
    tool: "get_soc_entity_context",
    arguments: {
      entityType: entity.entityType,
      id: entity.id,
    },
  };
}

function looksLikeFocusedInvestigation(value) {
  const text = String(value || "");
  return /(?:خلاصه|تحلیل|بررسی|چرا|دلیل|علت|اقدام|چه\s*کار|چیکار|پیشنهاد|توصیه|جزئیات|اطلاعات|مبدا|مبدأ|مقصد|سازمان|تهدید|ریسک|میترا|MITRE|IP|ip|آی[‌\s-]?پی|کجاست|مال\s+کدوم|verdict|summary|summarize|analysis|analyze|explain|why|recommend|action|investigat|detail|source|destination|organization|threat|risk)/i.test(text);
}

function looksQuantitativeOrCrossEntity(value) {
  const text = String(value || "");
  return /(?:چند|چندتا|تعداد|بیشترین|کمترین|پرتکرار|روند|مقایسه|درصد|لیست|همه\s+(?:alert|الر|هشدار)|count|how\s+many|top|most|least|trend|compare|percentage|list|show\s+all)/i.test(text);
}

function resolveExplicitFocusedReference(question, state) {
  const text = String(question || "");
  const related = state?.relatedEntities || {};

  if (/(?:این|همین)\s*(?:سازمان|organization)/i.test(text) && related.organization) {
    return { entityType: "organization", id: related.organization };
  }

  if (/(?:این|همین)\s*(?:rule|رول|قانون)/i.test(text) && related.ruleId) {
    return { entityType: "rule", id: related.ruleId };
  }

  if (/(?:این|همین)\s*(?:IP|ip|آی[‌\s-]?پی)/i.test(text)) {
    if (/(?:مقصد|destination|dst)/i.test(text) && related.destinationIp) {
      return { entityType: "ip", id: related.destinationIp };
    }
    if (/(?:مبدا|مبدأ|source|src)/i.test(text) && related.sourceIp) {
      return { entityType: "ip", id: related.sourceIp };
    }
    if (related.sourceIp) return { entityType: "ip", id: related.sourceIp };
    if (related.destinationIp) return { entityType: "ip", id: related.destinationIp };
  }

  const techniques = Array.isArray(related.mitreTechniques) ? related.mitreTechniques : [];
  if (/(?:این|همین)\s*(?:MITRE|میترا|تکنیک)/i.test(text) && techniques.length === 1) {
    return { entityType: "mitre_technique", id: techniques[0] };
  }

  return null;
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

function fallbackAnswer(queryResult, question = "") {
  const persian = isPersianText(question);

  if (queryResult?.entity?.type === "alert") {
    const sourceIp = queryResult.traffic?.sourceIp || queryResult.relatedEntities?.sourceIp || null;
    const destinationIp = queryResult.traffic?.destinationIp || queryResult.relatedEntities?.destinationIp || null;
    const organization = queryResult.relatedEntities?.organization || queryResult.destination?.asset?.organization || null;
    const verdict = queryResult.analysis?.verdict || null;
    const summary = queryResult.analysis?.oneLineSummary
      || queryResult.analysis?.incidentSummary?.what_happened
      || queryResult.analysis?.finalSocNote
      || null;
    const actions = Array.isArray(queryResult.recommendedActions)
      ? queryResult.recommendedActions.slice(0, 4)
      : [];

    if (persian) {
      return [
        `Alert ${queryResult.entity.id}`,
        summary ? `خلاصه: ${summary}` : null,
        sourceIp || destinationIp
          ? `ارتباط: ${sourceIp || "نامشخص"} → ${destinationIp || "نامشخص"}`
          : null,
        organization ? `سازمان: ${organization}` : null,
        verdict ? `Verdict: ${verdict}` : null,
        actions.length ? `اقدامات پیشنهادی: ${actions.join(" | ")}` : null,
      ].filter(Boolean).join("\n");
    }

    return [
      `Alert ${queryResult.entity.id}`,
      summary ? `Summary: ${summary}` : null,
      sourceIp || destinationIp
        ? `Traffic: ${sourceIp || "unknown"} -> ${destinationIp || "unknown"}`
        : null,
      organization ? `Organization: ${organization}` : null,
      verdict ? `Verdict: ${verdict}` : null,
      actions.length ? `Recommended actions: ${actions.join(" | ")}` : null,
    ].filter(Boolean).join("\n");
  }

  if (queryResult?.operation === "compare") {
    const left = Number(queryResult.left?.count || 0);
    const right = Number(queryResult.right?.count || 0);
    if (persian) {
      return `${queryResult.left?.label || "بازه اول"}: ${left}، ${queryResult.right?.label || "بازه دوم"}: ${right}، اختلاف: ${Number(queryResult.difference || 0)}${queryResult.changePercent === null ? "" : `، تغییر: ${queryResult.changePercent}%`}`;
    }
    return `${queryResult.left?.label || "left"}: ${left}, ${queryResult.right?.label || "right"}: ${right}, difference: ${Number(queryResult.difference || 0)}${queryResult.changePercent === null ? "" : `, change: ${queryResult.changePercent}%`}`;
  }

  if (queryResult?.operation === "percentage") {
    const value = queryResult.percentage;
    return value === null || value === undefined
      ? (persian ? "درصد قابل محاسبه نیست چون مخرج صفر است." : "Percentage is undefined because the denominator is zero.")
      : `${value}%`;
  }

  if (queryResult?.operation === "correlate" && Array.isArray(queryResult.rows)) {
    return JSON.stringify(queryResult.rows.slice(0, 10));
  }

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
  return persian
    ? "Query اجرا شد، اما نتیجه قابل نمایشی برنگشت."
    : "Query completed, but no displayable result was returned.";
}

module.exports = {
  CopilotService,
  CopilotInputError,
  CopilotPlannerError,
  CopilotQueryError,
  isRepairableTool,
  buildFocusedEntityPlan,
  looksLikeFocusedInvestigation,
  looksQuantitativeOrCrossEntity,
  resolveExplicitFocusedReference,
  normalizeHistory,
  isPersianText,
  buildUnsupportedAnswer,
  fallbackAnswer,
};
