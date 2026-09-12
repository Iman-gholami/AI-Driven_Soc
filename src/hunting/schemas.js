const { z } = require("zod");
const {
  copilotPlanSchema,
  filterSchema,
} = require("../copilot/querySchema");

const evidenceRefSchema = z.string().regex(/^obs-\d+$/);

const huntFindingSchema = z.object({
  title: z.string().min(1).max(300),
  severity: z.enum(["info", "low", "medium", "high", "critical"]),
  summary: z.string().min(1).max(2400),
  evidenceRefs: z.array(evidenceRefSchema).min(1).max(8),
  entities: z.array(z.string().min(1).max(220)).max(12).default([]),
}).strict();

const huntReportSchema = z.object({
  verdict: z.enum([
    "no_significant_finding",
    "suspicious",
    "likely_malicious",
    "inconclusive",
  ]),
  confidence: z.number().int().min(0).max(100),
  summary: z.string().min(1).max(4000),
  findings: z.array(huntFindingSchema).max(12).default([]),
  recommendedNextSteps: z.array(z.string().min(1).max(600)).max(12).default([]),
  limitations: z.array(z.string().min(1).max(600)).max(10).default([]),
}).strict();

const rawToolDecisionSchema = z.object({
  decision: z.literal("tool"),
  rationale: z.string().min(1).max(1200),
  tool: z.string().min(1).max(120),
  arguments: z.unknown(),
}).strict();

const finishDecisionSchema = z.object({
  decision: z.literal("finish"),
  report: huntReportSchema,
}).strict();

const huntDecisionSchema = z.union([rawToolDecisionSchema, finishDecisionSchema]);

function parseHuntDecision(value) {
  const decision = huntDecisionSchema.parse(value);
  if (decision.decision === "finish") return decision;

  const plan = copilotPlanSchema.parse({
    tool: decision.tool,
    arguments: decision.arguments,
  });
  if (plan.tool === "unsupported") {
    throw new Error("Threat hunting planner selected an unsupported operation");
  }

  return {
    ...decision,
    tool: plan.tool,
    arguments: plan.arguments,
  };
}

const detectionProposalSchema = z.object({
  title: z.string().min(1).max(300),
  description: z.string().min(1).max(2000),
  severity: z.enum(["info", "low", "medium", "high", "critical"]),
  confidence: z.number().int().min(0).max(100),
  filters: z.array(filterSchema).min(1).max(12),
  rationale: z.string().min(1).max(3000),
  mitreTechniqueIds: z.array(z.string().min(1).max(40)).max(12).default([]),
  suricataDraft: z.string().max(8000).nullable().default(null),
  limitations: z.array(z.string().min(1).max(600)).max(10).default([]),
}).strict();

module.exports = {
  evidenceRefSchema,
  huntFindingSchema,
  huntReportSchema,
  huntDecisionSchema,
  detectionProposalSchema,
  parseHuntDecision,
};
