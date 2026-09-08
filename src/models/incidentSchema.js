const { z } = require("zod");

const severitySchema = z.enum(["critical", "high", "medium", "low", "info", "unknown"]);
const verdictSchema = z.enum(["BENIGN", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"]);
const analystActionSchema = z.enum(["INVESTIGATE", "ESCALATE", "MONITOR", "CLOSE", "UNKNOWN"]);
const relationshipAssessmentSchema = z.enum(["BENIGN", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"]);

const relationshipEndpointSchema = z.object({
  ip: z.string(),
  organization: z.string(),
  context: z.string(),
});

const analysisResponseSchema = z.object({
  verdict: verdictSchema,
  one_line_summary: z.string(),
  attack_story: z.array(z.string()),
  why_alert_triggered: z.object({
    rule: z.string(),
    evidence: z.array(z.string()),
  }),
  observed_evidence: z.array(z.string()),
  network_relationship_analysis: z.object({
    assessment: relationshipAssessmentSchema,
    summary: z.string(),
    source: relationshipEndpointSchema,
    destination: relationshipEndpointSchema,
    why_suspicious: z.array(z.string()),
    current_alert_domains: z.array(z.string()),
    current_alert_packet_evidence: z.array(z.string()),
    threat_feed_context: z.array(z.string()),
    limitations: z.string(),
  }),
  detection_analysis: z.object({
    rule_logic: z.string(),
    limitations: z.string(),
  }),
  behavior_analysis: z.string(),
  attack_mapping: z.array(z.object({
    technique: z.string(),
    name: z.string(),
  })),
  risk_assessment: z.object({
    severity: severitySchema,
    confidence: z.number().min(0).max(100),
    reasoning: z.string(),
  }),
  analyst_decision: z.object({
    action: analystActionSchema,
    reason: z.string(),
  }),
  false_positive_analysis: z.array(z.string()),
  recommended_investigation_steps: z.array(z.string()),
  final_soc_note: z.string(),
});

function normalizeAnalysisPayload(input = {}) {
  const payload = input && typeof input === "object" ? input : {};
  const incidentSummary = payload.incident_summary;
  const risk = payload.risk_assessment && typeof payload.risk_assessment === "object"
    ? payload.risk_assessment
    : {};

  const severity = normalizeSeverity(risk.severity);
  const confidence = normalizeConfidence(risk.confidence);
  const oneLineSummary = firstString(
    payload.one_line_summary,
    incidentSummary?.what_happened,
    incidentSummary?.summary,
    incidentSummary?.description,
    typeof incidentSummary === "string" ? incidentSummary : undefined,
    payload.final_soc_note,
  );

  const why = payload.why_alert_triggered && typeof payload.why_alert_triggered === "object"
    ? payload.why_alert_triggered
    : {};
  const detection = payload.detection_analysis;
  const relationship = payload.network_relationship_analysis && typeof payload.network_relationship_analysis === "object"
    ? payload.network_relationship_analysis
    : {};
  const relationshipSource = relationship.source && typeof relationship.source === "object"
    ? relationship.source
    : {};
  const relationshipDestination = relationship.destination && typeof relationship.destination === "object"
    ? relationship.destination
    : {};
  const decision = payload.analyst_decision && typeof payload.analyst_decision === "object"
    ? payload.analyst_decision
    : {};

  return {
    verdict: normalizeVerdict(payload.verdict),
    one_line_summary: oneLineSummary,
    attack_story: toStringArray(payload.attack_story),
    why_alert_triggered: {
      rule: firstString(why.rule, why.name, why.trigger_reason),
      evidence: toStringArray(why.evidence || why.matched_conditions),
    },
    observed_evidence: toStringArray(payload.observed_evidence),
    network_relationship_analysis: {
      assessment: normalizeRelationshipAssessment(relationship.assessment),
      summary: firstString(relationship.summary),
      source: {
        ip: firstString(relationshipSource.ip),
        organization: firstString(relationshipSource.organization),
        context: firstString(relationshipSource.context),
      },
      destination: {
        ip: firstString(relationshipDestination.ip),
        organization: firstString(relationshipDestination.organization),
        context: firstString(relationshipDestination.context),
      },
      why_suspicious: toStringArray(relationship.why_suspicious || relationship.reasons),
      current_alert_domains: toStringArray(relationship.current_alert_domains),
      current_alert_packet_evidence: toStringArray(relationship.current_alert_packet_evidence),
      threat_feed_context: toStringArray(relationship.threat_feed_context),
      limitations: firstString(relationship.limitations),
    },
    detection_analysis: {
      rule_logic: normalizeTextObject(
        detection,
        ["rule_logic", "trigger_reason", "description", "summary"],
      ),
      limitations: normalizeTextObject(detection, ["limitations", "limitation"]),
    },
    behavior_analysis: normalizeTextObject(
      payload.behavior_analysis,
      ["description", "summary", "analysis"],
    ),
    attack_mapping: normalizeAttackMapping(payload.attack_mapping),
    risk_assessment: {
      severity,
      confidence,
      reasoning: firstString(risk.reasoning, risk.reason),
    },
    analyst_decision: {
      action: normalizeAnalystAction(decision.action),
      reason: firstString(decision.reason, payload.analyst_note),
    },
    false_positive_analysis: toStringArray(payload.false_positive_analysis),
    recommended_investigation_steps: toStringArray(payload.recommended_investigation_steps),
    final_soc_note: firstString(payload.final_soc_note, oneLineSummary),
  };
}

function normalizeSeverity(value) {
  const normalized = String(value || "unknown").toLowerCase();
  return severitySchema.safeParse(normalized).success ? normalized : "unknown";
}

function normalizeVerdict(value) {
  const normalized = String(value || "UNKNOWN").toUpperCase();
  return verdictSchema.safeParse(normalized).success ? normalized : "UNKNOWN";
}

function normalizeRelationshipAssessment(value) {
  const normalized = String(value || "UNKNOWN").toUpperCase();
  return relationshipAssessmentSchema.safeParse(normalized).success ? normalized : "UNKNOWN";
}

function normalizeAnalystAction(value) {
  const normalized = String(value || "UNKNOWN").toUpperCase();
  return analystActionSchema.safeParse(normalized).success ? normalized : "UNKNOWN";
}

function normalizeConfidence(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  return Math.min(100, Math.max(0, numeric));
}

function firstString(...values) {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
}

function toStringArray(value) {
  const items = Array.isArray(value)
    ? value
    : typeof value === "string"
      ? [value]
      : value && typeof value === "object"
        ? Object.values(value).flatMap((item) => Array.isArray(item) ? item : [item])
        : [];

  return items
    .map((item) => {
      if (typeof item === "string") return item.trim();
      if (item === null || item === undefined) return "";
      try {
        return JSON.stringify(item);
      } catch (_) {
        return String(item);
      }
    })
    .filter(Boolean);
}

function normalizeTextObject(value, preferredKeys = []) {
  if (typeof value === "string") return value.trim();
  if (!value || typeof value !== "object") return "";

  for (const key of preferredKeys) {
    if (typeof value[key] === "string" && value[key].trim()) return value[key].trim();
  }

  if (Object.keys(value).length === 0) return "";
  try {
    return JSON.stringify(value);
  } catch (_) {
    return String(value);
  }
}

function normalizeAttackMapping(value) {
  const items = Array.isArray(value)
    ? value
    : Array.isArray(value?.mitre_techniques)
      ? value.mitre_techniques
      : [];

  return items
    .map((item) => {
      if (typeof item === "string") {
        return { technique: item.trim(), name: "" };
      }
      if (!item || typeof item !== "object") return null;
      return {
        technique: firstString(item.technique, item.id, item.technique_id),
        name: firstString(item.name, item.technique_name),
      };
    })
    .filter((item) => item && item.technique);
}

module.exports = {
  analysisResponseSchema,
  normalizeAnalysisPayload,
  severitySchema,
};
