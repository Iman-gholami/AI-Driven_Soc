const crypto = require("node:crypto");
const { settings } = require("../core/config");
const { LLMService } = require("./llmService");
const { SocMcpServer } = require("../mcp/socMcpServer");
const { InProcessMcpClient } = require("../mcp/inProcessClient");
const {
  parseHuntDecision,
  huntReportSchema,
} = require("../hunting/schemas");
const {
  HUNT_PLANNER_SYSTEM_PROMPT,
  HUNT_FINALIZER_SYSTEM_PROMPT,
  buildHuntPlannerPrompt,
  buildHuntFinalizerPrompt,
} = require("../hunting/prompts");

class ThreatHuntingService {
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

  async run({ goal, maxSteps = 6, onEvent = async () => {}, shouldStop = () => false } = {}) {
    const safeGoal = normalizeGoal(goal);
    const safeMaxSteps = normalizeMaxSteps(maxSteps);
    const huntId = crypto.randomUUID();
    const startedAt = this.now();
    const metadata = this.buildMetadata();

    await emit(onEvent, {
      type: "hunt_started",
      huntId,
      goal: safeGoal,
      maxSteps: safeMaxSteps,
      startedAt: startedAt.toISOString(),
      metadata,
    });

    const [allTools, schema] = await Promise.all([
      this.mcpClient.listTools(),
      this.mcpClient.callTool("describe_soc_schema", {}),
    ]);
    const tools = allTools.filter((tool) => tool?.name !== "describe_soc_schema");
    const observations = [];
    const seenPlans = new Set();
    let forcedFinalizationReason = null;

    for (let step = 1; step <= safeMaxSteps; step += 1) {
      if (shouldStop()) throw new HuntCancelledError("Threat hunt cancelled by client");

      await emit(onEvent, {
        type: "planning",
        huntId,
        step,
        maxSteps: safeMaxSteps,
      });

      let decision;
      try {
        const plannerOutput = await this.llm.completeJson({
          systemPrompt: HUNT_PLANNER_SYSTEM_PROMPT,
          userPrompt: buildHuntPlannerPrompt({
            goal: safeGoal,
            tools,
            schema,
            observations: observations.map(observationForPrompt),
            timezone: this.timezone,
            now: this.now().toISOString(),
            step,
            maxSteps: safeMaxSteps,
          }),
          temperature: 0,
        });
        decision = parseHuntDecision(plannerOutput);
      } catch (error) {
        forcedFinalizationReason = `Planner could not produce a valid next step: ${String(error?.message || error)}`;
        await emit(onEvent, {
          type: "planning_failed",
          huntId,
          step,
          error: forcedFinalizationReason,
        });
        break;
      }

      if (decision.decision === "finish") {
        const report = sanitizeReportEvidence(decision.report, observations);
        const result = buildResult({
          huntId,
          goal: safeGoal,
          startedAt,
          completedAt: this.now(),
          report,
          observations,
          metadata,
          terminationReason: "planner_finished",
        });
        await emit(onEvent, { type: "hunt_completed", ...result });
        return result;
      }

      const planKey = stablePlanKey(decision.tool, decision.arguments);
      if (seenPlans.has(planKey)) {
        forcedFinalizationReason = "Planner attempted to repeat an identical tool call.";
        await emit(onEvent, {
          type: "step_rejected",
          huntId,
          step,
          rationale: decision.rationale,
          reason: forcedFinalizationReason,
        });
        break;
      }
      seenPlans.add(planKey);

      await emit(onEvent, {
        type: "step_planned",
        huntId,
        step,
        rationale: decision.rationale,
        tool: decision.tool,
        arguments: compactValue(decision.arguments),
      });

      const observationId = `obs-${observations.length + 1}`;
      const toolStartedAt = this.now();
      await emit(onEvent, {
        type: "tool_started",
        huntId,
        step,
        observationId,
        tool: decision.tool,
      });

      try {
        const result = await this.mcpClient.callTool(decision.tool, decision.arguments);
        const toolCompletedAt = this.now();
        const observation = {
          id: observationId,
          step,
          status: "success",
          rationale: decision.rationale,
          tool: decision.tool,
          arguments: compactValue(decision.arguments),
          result: compactValue(result),
          summary: summarizeToolResult(result),
          durationMs: Math.max(0, toolCompletedAt.getTime() - toolStartedAt.getTime()),
        };
        observations.push(observation);

        await emit(onEvent, {
          type: "tool_completed",
          huntId,
          step,
          observation: observationForClient(observation),
        });
      } catch (error) {
        const observation = {
          id: observationId,
          step,
          status: "error",
          rationale: decision.rationale,
          tool: decision.tool,
          arguments: compactValue(decision.arguments),
          error: String(error?.message || error || "MCP tool failed").slice(0, 1800),
          summary: "Tool call failed and produced no evidence.",
          durationMs: Math.max(0, this.now().getTime() - toolStartedAt.getTime()),
        };
        observations.push(observation);

        await emit(onEvent, {
          type: "tool_failed",
          huntId,
          step,
          observation: observationForClient(observation),
        });
      }
    }

    if (shouldStop()) throw new HuntCancelledError("Threat hunt cancelled by client");

    const report = await this.finalize({
      goal: safeGoal,
      observations,
      forcedFinalizationReason,
    });
    const result = buildResult({
      huntId,
      goal: safeGoal,
      startedAt,
      completedAt: this.now(),
      report,
      observations,
      metadata,
      terminationReason: forcedFinalizationReason ? "forced_finalization" : "max_steps_reached",
    });
    await emit(onEvent, { type: "hunt_completed", ...result });
    return result;
  }

  async finalize({ goal, observations, forcedFinalizationReason }) {
    if (!observations.some((item) => item.status === "success")) {
      return huntReportSchema.parse({
        verdict: "inconclusive",
        confidence: 0,
        summary: "The hunt did not obtain successful SOC evidence and cannot support a security conclusion.",
        findings: [],
        recommendedNextSteps: ["Retry the hunt after validating SOC data and MCP availability."],
        limitations: [forcedFinalizationReason || "No successful evidence-producing tool call completed."],
      });
    }

    try {
      const finalOutput = await this.llm.completeJson({
        systemPrompt: HUNT_FINALIZER_SYSTEM_PROMPT,
        userPrompt: buildHuntFinalizerPrompt({
          goal,
          observations: observations.map(observationForPrompt),
        }),
        temperature: 0,
      });
      const parsed = huntReportSchema.parse(finalOutput);
      const grounded = sanitizeReportEvidence(parsed, observations);
      if (forcedFinalizationReason) {
        grounded.limitations = [...new Set([
          ...grounded.limitations,
          forcedFinalizationReason.slice(0, 600),
        ])].slice(0, 10);
      }
      return huntReportSchema.parse(grounded);
    } catch (error) {
      return huntReportSchema.parse({
        verdict: "inconclusive",
        confidence: 20,
        summary: "SOC evidence was collected, but the model could not produce a valid evidence-grounded final report.",
        findings: [],
        recommendedNextSteps: ["Review the collected tool observations manually."],
        limitations: [
          String(forcedFinalizationReason || error?.message || error || "Final report generation failed").slice(0, 600),
        ],
      });
    }
  }

  buildMetadata() {
    const provider = typeof this.llm.getMetadata === "function"
      ? this.llm.getMetadata()
      : { provider: "unknown", model: "unknown" };
    return {
      ...provider,
      mcp: true,
      readOnly: true,
      agentic: true,
      timezone: this.timezone,
    };
  }
}

class HuntCancelledError extends Error {
  constructor(message) {
    super(message);
    this.name = "HuntCancelledError";
  }
}

function normalizeGoal(goal) {
  const value = String(goal || "").trim();
  if (!value) throw new TypeError("hunt goal is required");
  if (value.length > 3000) throw new TypeError("hunt goal is too long");
  return value;
}

function normalizeMaxSteps(maxSteps) {
  const value = Number(maxSteps);
  if (!Number.isFinite(value)) return 6;
  return Math.min(Math.max(Math.trunc(value), 2), 8);
}

function stablePlanKey(tool, args) {
  return `${String(tool)}:${stableStringify(args)}`;
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function compactValue(value, depth = 0) {
  if (depth > 6) return "[depth-limited]";
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return value.length > 1600 ? `${value.slice(0, 1600)}…` : value;
  if (typeof value !== "object") return value;
  if (Array.isArray(value)) return value.slice(0, 25).map((item) => compactValue(item, depth + 1));

  const output = {};
  for (const key of Object.keys(value).slice(0, 40)) {
    output[key] = compactValue(value[key], depth + 1);
  }
  return output;
}

function summarizeToolResult(result) {
  if (!result || typeof result !== "object") return "Tool completed.";
  if (result.entity?.type && result.entity?.id) return `Loaded ${result.entity.type} context for ${result.entity.id}.`;
  if (result.operation === "correlate") return `Correlation returned ${Number(result.count || result.rows?.length || 0)} row(s).`;
  if (["compare", "percentage", "trend"].includes(result.operation)) return `Deterministic metric ${result.operation} completed.`;
  if (Array.isArray(result.results)) return `Batch completed ${result.results.length} validated SOC queries.`;
  if (Number.isFinite(Number(result.data?.count))) return `Query returned count ${Number(result.data.count)}.`;
  if (Array.isArray(result.data?.rows)) return `Query returned ${result.data.rows.length} row(s).`;
  return "Tool completed with structured SOC evidence.";
}

function observationForPrompt(observation) {
  return {
    id: observation.id,
    status: observation.status,
    tool: observation.tool,
    rationale: observation.rationale,
    arguments: observation.arguments,
    summary: observation.summary,
    ...(observation.status === "success" ? { result: observation.result } : { error: observation.error }),
  };
}

function observationForClient(observation) {
  return {
    id: observation.id,
    step: observation.step,
    status: observation.status,
    tool: observation.tool,
    rationale: observation.rationale,
    arguments: observation.arguments,
    summary: observation.summary,
    durationMs: observation.durationMs,
    ...(observation.status === "success" ? { result: observation.result } : { error: observation.error }),
  };
}

function sanitizeReportEvidence(report, observations) {
  const validEvidence = new Set(
    observations.filter((item) => item.status === "success").map((item) => item.id),
  );

  const findings = (report.findings || [])
    .map((finding) => ({
      ...finding,
      evidenceRefs: (finding.evidenceRefs || []).filter((ref) => validEvidence.has(ref)),
    }))
    .filter((finding) => finding.evidenceRefs.length > 0);

  let verdict = report.verdict;
  let confidence = report.confidence;
  const limitations = [...(report.limitations || [])];
  if ((report.findings || []).length > 0 && findings.length === 0) {
    verdict = "inconclusive";
    confidence = Math.min(Number(confidence || 0), 35);
    limitations.push("Model-proposed findings were removed because they did not cite successful SOC observations.");
  }

  return huntReportSchema.parse({
    ...report,
    verdict,
    confidence,
    findings,
    limitations: [...new Set(limitations)].slice(0, 10),
  });
}

function buildResult({ huntId, goal, startedAt, completedAt, report, observations, metadata, terminationReason }) {
  return {
    huntId,
    goal,
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    durationMs: Math.max(0, completedAt.getTime() - startedAt.getTime()),
    terminationReason,
    report,
    observations: observations.map(observationForClient),
    metadata,
  };
}

async function emit(handler, event) {
  try {
    await handler(event);
  } catch (_) {
    // Streaming/telemetry must not corrupt the investigation itself.
  }
}

module.exports = {
  ThreatHuntingService,
  HuntCancelledError,
  normalizeGoal,
  normalizeMaxSteps,
  stablePlanKey,
  compactValue,
  summarizeToolResult,
  sanitizeReportEvidence,
};
