const { settings } = require("../core/config");
const { sanitizeText } = require("../core/logging");

const INCIDENT_FIELDS = [
  "signature", "Signature", "rule_name", "event_id", "event_hash", "eventtype",
  "severity", "category", "count", "host", "source", "sourcetype", "index",
  "src_ip", "source_ip", "src_port", "dst_ip", "dest_ip", "dst_port", "dest_port",
  "protocol", "proto", "user", "process_name", "command_line", "parent_process",
  "timestamp", "_time", "raw_log", "_raw", "raw", "mitre",
];

const MAX_ADDITIONAL_FIELDS = 40;
const MAX_FIELD_CHARS = 2000;
const MAX_RULE_RAW_CHARS = 12000;

function toSafeValue(value, { maxChars = MAX_FIELD_CHARS } = {}) {
  if (value === null || value === undefined) return null;
  if (value instanceof Date) return value.toISOString();

  if (typeof value === "string") {
    return sanitizeText(value).slice(0, maxChars);
  }

  if (["number", "boolean"].includes(typeof value)) return value;

  try {
    return sanitizeText(JSON.stringify(value)).slice(0, maxChars);
  } catch (_) {
    return String(value).slice(0, maxChars);
  }
}

function buildIncidentEvidence(rawIncident = {}) {
  const incident = {};
  const selected = new Set(INCIDENT_FIELDS);

  for (const field of INCIDENT_FIELDS) {
    if (rawIncident[field] === undefined) continue;
    const maxChars = ["raw_log", "_raw", "raw"].includes(field)
      ? settings.maxRawLogChars
      : MAX_FIELD_CHARS;
    incident[field] = toSafeValue(rawIncident[field], { maxChars });
  }

  const additionalFields = {};
  for (const [key, value] of Object.entries(rawIncident)) {
    if (selected.has(key) || Object.keys(additionalFields).length >= MAX_ADDITIONAL_FIELDS) continue;
    if (value === undefined || typeof value === "function") continue;
    additionalFields[key] = toSafeValue(value, { maxChars: 1000 });
  }

  if (Object.keys(additionalFields).length > 0) incident.additional_fields = additionalFields;
  return incident;
}

function buildDetectionRuleContext(ruleResolution) {
  if (!ruleResolution) {
    return { status: "unavailable", reason: "rule_resolution_not_run" };
  }

  if (ruleResolution.status !== "matched" || !ruleResolution.rule) {
    return {
      status: ruleResolution.status,
      match_type: ruleResolution.matchType || null,
      signature: ruleResolution.signature || null,
      candidate_count: ruleResolution.candidateCount || 0,
      reason: ruleResolution.reason || null,
      candidates: ruleResolution.candidates || undefined,
      resolution_evidence: ruleResolution.resolutionEvidence || [],
    };
  }

  const rule = ruleResolution.rule;
  return {
    status: "matched",
    match_type: ruleResolution.matchType,
    candidate_count: ruleResolution.candidateCount,
    resolution_evidence: ruleResolution.resolutionEvidence || [],
    rule: {
      rule_id: rule.ruleId,
      action: rule.action || "alert",
      revision: rule.revision,
      title: rule.title,
      classtype: rule.classtype,
      protocol: rule.protocol,
      header: {
        src: rule.src,
        src_port: rule.srcPort,
        direction: rule.direction,
        dst: rule.dst,
        dst_port: rule.dstPort,
      },
      flow: rule.parsedRule?.flow || [],
      contents: rule.parsedRule?.contents || [],
      pcre: rule.parsedRule?.pcre || [],
      references: rule.parsedRule?.references || [],
      metadata: rule.parsedRule?.metadata,
      source_file: rule.sourceFile,
      raw_rule: String(rule.rawRule || "").slice(0, MAX_RULE_RAW_CHARS),
    },
  };
}

function buildContext(rawIncident, ruleResolution) {
  return {
    incident: buildIncidentEvidence(rawIncident || {}),
    detection_rule: buildDetectionRuleContext(ruleResolution),
  };
}

module.exports = { buildContext, buildIncidentEvidence, buildDetectionRuleContext };
