const { z } = require("zod");

const severitySchema = z.enum(["critical", "high", "medium", "low", "info", "unknown"]);

const analysisResponseSchema = z.object({
  incident_summary: z.record(z.any()),
  why_alert_triggered: z.record(z.any()).optional(),
  observed_evidence: z.array(z.any()).optional(),
  detection_analysis: z.record(z.any()),
  behavior_analysis: z.record(z.any()),
  attack_mapping: z.record(z.any()),
  risk_assessment: z.object({
    severity: severitySchema.or(z.string()),
    confidence: z.number().min(0).max(100).optional(),
    reasoning: z.string().optional(),
  }).passthrough(),
  false_positive_analysis: z.record(z.any()),
  recommended_investigation_steps: z.array(z.string()),
  analyst_note: z.string().optional(),
  final_soc_note: z.string(),
});

module.exports = { analysisResponseSchema };
