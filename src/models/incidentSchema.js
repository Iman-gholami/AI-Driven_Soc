const { z } = require("zod");

const analysisResponseSchema = z.object({
  incident_summary: z.record(z.any()),
  detection_analysis: z.record(z.any()),
  behavior_analysis: z.record(z.any()),
  attack_mapping: z.record(z.any()),
  risk_assessment: z.record(z.any()),
  false_positive_analysis: z.record(z.any()),
  recommended_investigation_steps: z.array(z.string()),
  final_soc_note: z.string(),
});

module.exports = { analysisResponseSchema };
