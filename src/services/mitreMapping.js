const TECHNIQUE_RE = /\bT\d{4}(?:\.\d{3})?\b/gi;
const TACTIC_RE = /\bTA\d{4}\b/gi;

function normalizeTechniqueId(value) {
  const match = String(value || "").toUpperCase().match(/^T\d{4}(?:\.\d{3})?$/);
  return match ? match[0] : null;
}

function normalizeTacticId(value) {
  const match = String(value || "").toUpperCase().match(/^TA\d{4}$/);
  return match ? match[0] : null;
}

function extractIds(value, regex) {
  const text = Array.isArray(value) ? value.join(" ") : String(value || "");
  return [...new Set((text.match(regex) || []).map((item) => item.toUpperCase()))];
}

function extractMitreMapping(source = {}, parsedRule = {}) {
  const explicitValues = [
    source.mitre,
    source.mitre_technique,
    source.mitre_techniques,
    source.mitre_technique_id,
    source.mitre_technique_ids,
    source.attack_technique,
    source.attack_techniques,
    source.attack_technique_id,
    source.attack_technique_ids,
    source.mitre_tactic,
    source.mitre_tactics,
    source.mitre_tactic_id,
    source.mitre_tactic_ids,
  ].filter((value) => value !== undefined && value !== null);

  const referenceValues = [
    parsedRule.metadata,
    ...(Array.isArray(parsedRule.references) ? parsedRule.references : []),
  ].filter(Boolean);

  const explicitText = explicitValues.map(toText).join(" ");
  const referenceText = referenceValues.map(toText).join(" ");

  const explicitTechniqueIds = extractIds(explicitText, TECHNIQUE_RE);
  const referenceTechniqueIds = extractIds(referenceText, TECHNIQUE_RE);
  const techniqueIds = [...new Set([...explicitTechniqueIds, ...referenceTechniqueIds])];

  const tacticIds = [...new Set([
    ...extractIds(explicitText, TACTIC_RE),
    ...extractIds(referenceText, TACTIC_RE),
  ])];

  const mappings = techniqueIds.map((techniqueId) => ({
    techniqueId,
    source: explicitTechniqueIds.includes(techniqueId) ? "explicit" : "reference",
    confidence: 1,
    reviewed: true,
  }));

  return {
    techniqueIds,
    tacticIds,
    mappings,
    mapped: techniqueIds.length > 0,
    enrichmentVersion: 1,
    lastEnrichedAt: new Date(),
  };
}

function inferRuleTier(source = {}) {
  const requested = String(source.tier || source.rule_tier || source.ruleTier || "").toLowerCase();
  if (["native", "imported", "community"].includes(requested)) return requested;
  if (source.community === true || String(source.source || "").toLowerCase() === "community") return "community";
  if (source.native === true || String(source.source || "").toLowerCase() === "native") return "native";
  return "imported";
}

function toText(value) {
  if (typeof value === "string") return value;
  try { return JSON.stringify(value); } catch (_) { return String(value); }
}

module.exports = {
  normalizeTechniqueId,
  normalizeTacticId,
  extractMitreMapping,
  inferRuleTier,
};
