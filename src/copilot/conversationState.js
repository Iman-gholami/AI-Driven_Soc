const { z } = require("zod");

const entityTypeSchema = z.enum(["alert", "ip", "organization", "rule", "mitre_technique"]);

const entityFocusSchema = z.object({
  entityType: entityTypeSchema,
  id: z.string().min(1).max(500),
}).strict();

const relatedEntitiesSchema = z.object({
  sourceIp: z.string().max(128).optional(),
  destinationIp: z.string().max(128).optional(),
  organization: z.string().max(500).optional(),
  ruleId: z.string().max(256).optional(),
  mitreTechniques: z.array(z.string().max(64)).max(20).optional(),
}).strict();

const conversationStateSchema = z.object({
  focus: entityFocusSchema.nullable().optional(),
  relatedEntities: relatedEntitiesSchema.default({}),
  lastTool: z.string().max(128).nullable().optional(),
  lastQueryPlan: z.any().nullable().optional(),
}).strict();

function normalizeConversationState(value) {
  const parsed = conversationStateSchema.safeParse(value || {});
  if (!parsed.success) {
    return {
      focus: null,
      relatedEntities: {},
      lastTool: null,
      lastQueryPlan: null,
    };
  }

  return {
    focus: parsed.data.focus || null,
    relatedEntities: parsed.data.relatedEntities || {},
    lastTool: parsed.data.lastTool || null,
    lastQueryPlan: parsed.data.lastQueryPlan || null,
  };
}

function deriveConversationState({
  previousState,
  tool,
  result,
  queryPlan,
} = {}) {
  const previous = normalizeConversationState(previousState);
  const next = {
    ...previous,
    relatedEntities: { ...(previous.relatedEntities || {}) },
    lastTool: tool || previous.lastTool || null,
    lastQueryPlan: queryPlan || previous.lastQueryPlan || null,
  };

  if (result?.entity?.type && result?.entity?.id) {
    next.focus = {
      entityType: normalizeEntityType(result.entity.type),
      id: String(result.entity.id),
    };
    Object.assign(next.relatedEntities, sanitizeRelatedEntities(result.relatedEntities));
    return normalizeConversationState(next);
  }

  if (Array.isArray(result?.results)) {
    return normalizeConversationState(next);
  }

  if (result?.operation === "correlate" && Array.isArray(result?.rows) && result.rows.length === 1) {
    const row = result.rows[0];
    const ip = firstString(row.ip);
    const ruleId = firstString(row.ruleId);
    const techniqueId = firstString(row.techniqueId);
    const organization = firstString(row.organization);

    if (ip) next.focus = { entityType: "ip", id: ip };
    else if (ruleId) next.focus = { entityType: "rule", id: ruleId };
    else if (techniqueId) next.focus = { entityType: "mitre_technique", id: techniqueId };
    else if (organization) next.focus = { entityType: "organization", id: organization };

    Object.assign(next.relatedEntities, sanitizeRelatedEntities({
      sourceIp: ip,
      organization,
      ruleId,
      mitreTechniques: techniqueId ? [techniqueId] : [],
    }));

    return normalizeConversationState(next);
  }

  const rows = Array.isArray(result?.data?.rows) ? result.data.rows : [];
  if (rows.length === 1) {
    const derived = deriveEntityFromRow(result.dataset, rows[0]);
    if (derived.focus) next.focus = derived.focus;
    Object.assign(next.relatedEntities, derived.relatedEntities);
  }

  return normalizeConversationState(next);
}

function deriveEntityFromRow(dataset, row = {}) {
  const relatedEntities = {
    sourceIp: firstString(
      getPath(row, "rawEvent.src_ip"),
      getPath(row, "rawEvent.source_ip"),
      row.src_ip,
      row.source_ip,
    ),
    destinationIp: firstString(
      getPath(row, "rawEvent.dst_ip"),
      getPath(row, "rawEvent.dest_ip"),
      row.dst_ip,
      row.dest_ip,
    ),
    organization: firstString(
      getPath(row, "soc.networkIntelligence.ips.asset.organization"),
      row.organization,
      row.bunit,
    ),
    ruleId: firstString(
      getPath(row, "ruleMatch.ruleId"),
      row.ruleId,
    ),
    mitreTechniques: uniqueStrings([
      ...arrayify(getPath(row, "soc.mitreAttack")).flatMap(extractMitreTechniqueIds),
      ...arrayify(getPath(row, "mitre.techniqueIds")),
      row.techniqueId,
    ]),
  };

  let focus = null;
  if (dataset === "alerts" && row.alertId) {
    focus = { entityType: "alert", id: String(row.alertId) };
  } else if (dataset === "detection_rules" && row.ruleId) {
    focus = { entityType: "rule", id: String(row.ruleId) };
  } else if (dataset === "ip_assets" && row.ip) {
    focus = { entityType: "ip", id: String(row.ip) };
  } else if (dataset === "mitre_techniques" && row.techniqueId) {
    focus = { entityType: "mitre_technique", id: String(row.techniqueId) };
  } else if (dataset === "threat_intelligence") {
    const ip = firstString(getPath(row, "source.ip"), getPath(row, "destination.ip"));
    if (ip) focus = { entityType: "ip", id: ip };
  }

  return {
    focus,
    relatedEntities: sanitizeRelatedEntities(relatedEntities),
  };
}

function normalizeEntityType(value) {
  const normalized = String(value || "").trim();
  return entityTypeSchema.safeParse(normalized).success ? normalized : "alert";
}

function sanitizeRelatedEntities(value = {}) {
  const candidate = {
    sourceIp: firstString(value.sourceIp),
    destinationIp: firstString(value.destinationIp),
    organization: firstString(value.organization),
    ruleId: firstString(value.ruleId),
    mitreTechniques: uniqueStrings(arrayify(value.mitreTechniques)).slice(0, 20),
  };

  return Object.fromEntries(
    Object.entries(candidate).filter(([, item]) => {
      if (Array.isArray(item)) return item.length > 0;
      return item !== undefined && item !== null && item !== "";
    }),
  );
}

function extractMitreTechniqueIds(item) {
  if (!item) return [];
  if (typeof item === "string") return /^T\d{4}(?:\.\d{3})?$/i.test(item.trim()) ? [item.trim()] : [];
  if (Array.isArray(item)) return item.flatMap(extractMitreTechniqueIds);
  if (typeof item === "object") {
    return [
      item.technique,
      item.techniqueId,
      item.id,
      item.technique_id,
    ].filter((value) => typeof value === "string" && /^T\d{4}(?:\.\d{3})?$/i.test(value.trim()));
  }
  return [];
}

function getPath(object, path) {
  if (!object || typeof object !== "object") return undefined;
  if (Object.prototype.hasOwnProperty.call(object, path)) return object[path];

  let current = object;
  for (const segment of String(path).split(".")) {
    if (!current || typeof current !== "object") return undefined;
    current = current[segment];
  }
  return current;
}

function firstString(...values) {
  for (const value of values) {
    if (value === undefined || value === null) continue;
    const text = String(value).trim();
    if (text) return text;
  }
  return undefined;
}

function arrayify(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function uniqueStrings(values) {
  return [...new Set(
    values
      .flat(Infinity)
      .filter((value) => value !== undefined && value !== null)
      .map((value) => String(value).trim())
      .filter(Boolean),
  )];
}

module.exports = {
  entityTypeSchema,
  conversationStateSchema,
  normalizeConversationState,
  deriveConversationState,
  deriveEntityFromRow,
  sanitizeRelatedEntities,
};
