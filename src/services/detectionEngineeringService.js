const { LLMService } = require("./llmService");
const { SocMcpServer } = require("../mcp/socMcpServer");
const { InProcessMcpClient } = require("../mcp/inProcessClient");
const { socQueryPlanSchema } = require("../copilot/querySchema");
const { detectionProposalSchema } = require("../hunting/schemas");
const {
  DETECTION_ENGINEER_SYSTEM_PROMPT,
  buildDetectionEngineerPrompt,
} = require("../hunting/prompts");

class DetectionEngineeringService {
  constructor({
    llm = new LLMService(),
    mcpClient = new InProcessMcpClient({ server: new SocMcpServer() }),
  } = {}) {
    this.llm = llm;
    this.mcpClient = mcpClient;
  }

  async generateAndBacktest({ goal, report, days = 30 } = {}) {
    const safeGoal = String(goal || "").trim();
    if (!safeGoal) throw new DetectionEngineeringInputError("hunt goal is required");
    if (!report || typeof report !== "object") throw new DetectionEngineeringInputError("hunt report is required");
    const backtestDays = Math.min(Math.max(Number(days) || 30, 1), 365);
    const alertsSchema = await this.mcpClient.callTool("describe_soc_schema", { dataset: "alerts" });

    let proposal = await this.generateProposal({
      goal: safeGoal,
      report,
      alertsSchema,
      backtestDays,
    });

    try {
      return await this.backtest({ proposal, backtestDays });
    } catch (error) {
      proposal = await this.generateProposal({
        goal: safeGoal,
        report,
        alertsSchema,
        backtestDays,
        validationError: error?.message || error,
      });
      return this.backtest({ proposal, backtestDays });
    }
  }

  async generateProposal({ goal, report, alertsSchema, backtestDays, validationError }) {
    const output = await this.llm.completeJson({
      systemPrompt: DETECTION_ENGINEER_SYSTEM_PROMPT,
      userPrompt: buildDetectionEngineerPrompt({
        goal,
        report,
        alertsSchema,
        backtestDays,
        validationError,
      }),
      temperature: 0,
    });
    return detectionProposalSchema.parse(output);
  }

  async backtest({ proposal, backtestDays }) {
    const timeRange = { type: "last_n_days", value: backtestDays };
    const baseFilters = proposal.filters;

    const totalQuery = socQueryPlanSchema.parse({
      dataset: "alerts",
      operation: "count",
      timeRange,
      filters: baseFilters,
      groupBy: [],
      metrics: [],
      select: [],
      sort: [],
      limit: 20,
    });

    const highRiskQuery = socQueryPlanSchema.parse({
      dataset: "alerts",
      operation: "count",
      timeRange,
      filters: [
        ...baseFilters,
        { field: "severity", operator: "in", value: ["critical", "high"] },
      ],
      groupBy: [],
      metrics: [],
      select: [],
      sort: [],
      limit: 20,
    });

    const sampleQuery = socQueryPlanSchema.parse({
      dataset: "alerts",
      operation: "list",
      timeRange,
      filters: baseFilters,
      groupBy: [],
      metrics: [],
      select: [
        "alertId",
        "signature",
        "host",
        "severity",
        "eventTime",
        "ruleMatch.ruleId",
        "aiStatus",
      ],
      sort: [{ field: "eventTime", direction: "desc" }],
      limit: 20,
    });

    const result = await this.mcpClient.callTool("query_soc_data_batch", {
      queries: [totalQuery, highRiskQuery, sampleQuery],
    });
    const results = Array.isArray(result?.results) ? result.results : [];
    const matchedCount = Number(results[0]?.data?.count || 0);
    const highRiskCount = Number(results[1]?.data?.count || 0);
    const samples = Array.isArray(results[2]?.data?.rows) ? results[2].data.rows : [];

    return {
      proposal: {
        ...proposal,
        deploymentStatus: "draft_only",
        autoDeploy: false,
      },
      backtest: {
        windowDays: backtestDays,
        matchedCount,
        highRiskCount,
        highRiskPercent: matchedCount ? Math.round((highRiskCount / matchedCount) * 1000) / 10 : 0,
        sampleCount: samples.length,
        samples,
        queryPlan: sampleQuery,
      },
      metadata: {
        readOnly: true,
        mcp: true,
        deterministicBacktest: true,
      },
    };
  }
}

class DetectionEngineeringInputError extends Error {
  constructor(message) {
    super(message);
    this.name = "DetectionEngineeringInputError";
  }
}

module.exports = {
  DetectionEngineeringService,
  DetectionEngineeringInputError,
};
