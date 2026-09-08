const SOC_SCHEMA_VERSION = 1;

const COMMON_STRING_OPERATORS = ["eq", "neq", "contains", "in", "exists"];
const COMMON_NUMBER_OPERATORS = ["eq", "neq", "gt", "gte", "lt", "lte", "in", "exists"];
const COMMON_BOOLEAN_OPERATORS = ["eq", "neq", "exists"];
const COMMON_DATE_OPERATORS = ["eq", "neq", "gt", "gte", "lt", "lte", "exists"];

function field(path, type, description, options = {}) {
  const defaultOperators =
    type === "number" ? COMMON_NUMBER_OPERATORS :
    type === "boolean" ? COMMON_BOOLEAN_OPERATORS :
    type === "date" ? COMMON_DATE_OPERATORS :
    COMMON_STRING_OPERATORS;

  return {
    path,
    type,
    description,
    aliases: options.aliases || [],
    operators: options.operators || defaultOperators,
    filterable: options.filterable !== false,
    groupable: options.groupable !== false,
    selectable: options.selectable !== false,
    sortable: options.sortable !== false,
    unwind: options.unwind || null,
  };
}

const SOC_SCHEMA_CATALOG = {
  alerts: {
    name: "alerts",
    description: "Security alerts ingested into the SOC, including rule resolution, AI triage and network intelligence.",
    aliases: ["alert", "alerts", "الر‌ت", "الر‌تها", "هشدار", "هشدارها"],
    defaultTimeField: "createdAt",
    fields: {
      alertId: field("alertId", "string", "Unique alert identifier", { groupable: false }),
      signature: field("signature", "string", "Detection signature/title that fired", {
        aliases: ["signature", "sig", "سیگنیچر", "امضا"],
      }),
      severity: field("severity", "string", "Alert severity"),
      source: field("source", "string", "Alert source/integration"),
      host: field("host", "string", "Observed host"),
      eventType: field("eventType", "string", "Event type"),
      status: field("status", "string", "Alert processing status"),
      aiStatus: field("aiStatus", "string", "AI analysis status"),
      createdAt: field("createdAt", "date", "Alert ingestion timestamp"),
      updatedAt: field("updatedAt", "date", "Last alert update timestamp"),
      "ruleMatch.status": field("ruleMatch.status", "string", "Detection-rule resolution status", {
        aliases: ["rule match", "rule status"],
      }),
      "ruleMatch.ruleId": field("ruleMatch.ruleId", "string", "Matched rule identifier"),
      "fullAnalysis.verdict": field("fullAnalysis.verdict", "string", "AI verdict"),
      "fullAnalysis.risk_assessment.severity": field(
        "fullAnalysis.risk_assessment.severity",
        "string",
        "AI risk severity",
      ),
      "fullAnalysis.risk_assessment.confidence": field(
        "fullAnalysis.risk_assessment.confidence",
        "number",
        "AI confidence percentage",
      ),
      "fullAnalysis.analyst_decision.action": field(
        "fullAnalysis.analyst_decision.action",
        "string",
        "Recommended analyst action",
      ),
      "soc.mitreAttack.technique": field(
        "soc.mitreAttack.technique",
        "string",
        "MITRE ATT&CK technique ID attached to an analyzed alert",
        { aliases: ["mitre", "technique", "تکنیک"], unwind: "soc.mitreAttack" },
      ),
      "soc.iocs.value": field(
        "soc.iocs.value",
        "string",
        "IOC value stored on the alert",
        { aliases: ["ioc", "indicator"], unwind: "soc.iocs" },
      ),
      "soc.networkIntelligence.ips.ip": field(
        "soc.networkIntelligence.ips.ip",
        "string",
        "IPv4 indicator enriched for the alert",
        { aliases: ["ip", "آی‌پی"], unwind: "soc.networkIntelligence.ips" },
      ),
      "soc.networkIntelligence.ips.networkZone": field(
        "soc.networkIntelligence.ips.networkZone",
        "string",
        "Deployment-specific network zone",
        { unwind: "soc.networkIntelligence.ips" },
      ),
      "soc.networkIntelligence.ips.asset.organization": field(
        "soc.networkIntelligence.ips.asset.organization",
        "string",
        "Organizational owner of an alert IP when known",
        {
          aliases: ["organization", "org", "سازمان", "اداره"],
          unwind: "soc.networkIntelligence.ips",
        },
      ),
      "soc.networkIntelligence.ips.asset.category": field(
        "soc.networkIntelligence.ips.asset.category",
        "string",
        "Organizational asset category",
        { unwind: "soc.networkIntelligence.ips" },
      ),
      "soc.networkIntelligence.ips.asset.province": field(
        "soc.networkIntelligence.ips.asset.province",
        "string",
        "Organizational asset province",
        { unwind: "soc.networkIntelligence.ips" },
      ),
      "soc.networkIntelligence.ips.threat.directMatch": field(
        "soc.networkIntelligence.ips.threat.directMatch",
        "boolean",
        "Whether an alert IP has direct threat-feed evidence",
        {
          aliases: ["direct threat", "direct match", "آی‌پی مخرب"],
          unwind: "soc.networkIntelligence.ips",
        },
      ),
      "soc.networkIntelligence.ips.threat.relationshipMatch": field(
        "soc.networkIntelligence.ips.threat.relationshipMatch",
        "boolean",
        "Whether an alert IP has relationship-only threat-feed evidence",
        { unwind: "soc.networkIntelligence.ips" },
      ),
    },
  },

  detection_rules: {
    name: "detection_rules",
    description: "Detection-rule repository with rule metadata and deterministic MITRE mappings.",
    aliases: ["rule", "rules", "قانون", "رول"],
    defaultTimeField: "updatedAt",
    fields: {
      ruleId: field("ruleId", "string", "Detection rule identifier"),
      revision: field("revision", "number", "Rule revision"),
      title: field("title", "string", "Rule title/signature"),
      classtype: field("classtype", "string", "Rule classification type"),
      protocol: field("protocol", "string", "Rule protocol"),
      sourceFile: field("sourceFile", "string", "Source rule file"),
      tier: field("tier", "string", "Rule tier"),
      quarantined: field("quarantined", "boolean", "Whether the rule is quarantined"),
      isCurrent: field("isCurrent", "boolean", "Whether this is the current rule revision"),
      "mitre.mapped": field("mitre.mapped", "boolean", "Whether the rule has MITRE mapping"),
      "mitre.techniqueIds": field(
        "mitre.techniqueIds",
        "string",
        "MITRE ATT&CK technique IDs mapped to the rule",
        { aliases: ["mitre", "technique", "تکنیک"], unwind: "mitre.techniqueIds" },
      ),
      "mitre.tacticIds": field(
        "mitre.tacticIds",
        "string",
        "MITRE ATT&CK tactic IDs mapped to the rule",
        { aliases: ["tactic", "تاکتیک"], unwind: "mitre.tacticIds" },
      ),
      createdAt: field("createdAt", "date", "Rule creation timestamp"),
      updatedAt: field("updatedAt", "date", "Rule update timestamp"),
    },
  },

  ip_assets: {
    name: "ip_assets",
    description: "Current organizational IPv4 asset registry snapshot.",
    aliases: ["asset", "assets", "دارایی", "آی‌پی سازمانی"],
    defaultTimeField: "updatedAt",
    snapshotDataset: "asset_registry",
    fields: {
      ip: field("ip", "string", "Owned IPv4 address", { aliases: ["ip", "آی‌پی"] }),
      bunit: field("bunit", "string", "Owning organization/business unit", {
        aliases: ["organization", "org", "سازمان", "اداره"],
      }),
      category: field("category", "string", "Organization/asset category"),
      province: field("province", "string", "Province"),
      createdAt: field("createdAt", "date", "Asset record creation timestamp"),
      updatedAt: field("updatedAt", "date", "Asset record update timestamp"),
    },
  },

  threat_intelligence: {
    name: "threat_intelligence",
    description: "Current offline threat-intelligence observation snapshot.",
    aliases: ["threat intel", "threat intelligence", "ti", "تهدید", "اطلاعات تهدید"],
    defaultTimeField: "sourceTime",
    snapshotDataset: "threat_intel",
    fields: {
      provider: field("provider", "string", "Threat-feed provider"),
      feedName: field("feedName", "string", "Threat feed name"),
      "classification.identifier": field(
        "classification.identifier",
        "string",
        "Threat classification identifier",
        { aliases: ["classification", "کلاس تهدید"] },
      ),
      "classification.taxonomy": field("classification.taxonomy", "string", "Threat taxonomy"),
      "classification.type": field("classification.type", "string", "Threat classification type"),
      malwareName: field("malwareName", "string", "Malware family/name", {
        aliases: ["malware", "بدافزار", "میرای", "mirai"],
      }),
      protocol: field("protocol", "string", "Observed transport protocol"),
      "source.ip": field("source.ip", "string", "Threat observation source IPv4", {
        aliases: ["source ip", "src ip", "آی‌پی مبدا"],
      }),
      "source.port": field("source.port", "number", "Threat observation source port"),
      "source.asn": field("source.asn", "number", "Threat observation source ASN"),
      "source.asName": field("source.asName", "string", "Threat observation source AS name"),
      "destination.ip": field("destination.ip", "string", "Threat observation destination IPv4", {
        aliases: ["destination ip", "dst ip", "آی‌پی مقصد"],
      }),
      "destination.port": field("destination.port", "number", "Threat observation destination port"),
      "destination.fqdn": field("destination.fqdn", "string", "Threat observation destination FQDN", {
        aliases: ["domain", "fqdn", "دامنه"],
      }),
      sourceTime: field("sourceTime", "date", "Threat source timestamp"),
      observationTime: field("observationTime", "date", "Threat observation timestamp"),
      createdAt: field("createdAt", "date", "Database ingestion timestamp"),
    },
  },

  mitre_techniques: {
    name: "mitre_techniques",
    description: "Local MITRE ATT&CK technique catalog.",
    aliases: ["mitre", "attack", "technique", "تکنیک", "میترا"],
    defaultTimeField: "updatedAt",
    fields: {
      techniqueId: field("techniqueId", "string", "MITRE ATT&CK technique ID"),
      name: field("name", "string", "Technique name"),
      "tactics.shortName": field(
        "tactics.shortName",
        "string",
        "MITRE tactic short name",
        { aliases: ["tactic", "تاکتیک"], unwind: "tactics" },
      ),
      platforms: field("platforms", "string", "Supported platforms", { unwind: "platforms" }),
      isSubTechnique: field("isSubTechnique", "boolean", "Whether this is a sub-technique"),
      parentTechniqueId: field("parentTechniqueId", "string", "Parent technique ID"),
      revoked: field("revoked", "boolean", "Revoked flag"),
      deprecated: field("deprecated", "boolean", "Deprecated flag"),
      attackVersion: field("attackVersion", "string", "ATT&CK dataset version"),
      modified: field("modified", "date", "MITRE object modified timestamp"),
      updatedAt: field("updatedAt", "date", "Database update timestamp"),
    },
  },
};

function getDatasetSchema(dataset) {
  return SOC_SCHEMA_CATALOG[String(dataset || "").trim()] || null;
}

function getFieldSchema(dataset, fieldName) {
  const datasetSchema = getDatasetSchema(dataset);
  return datasetSchema?.fields?.[String(fieldName || "").trim()] || null;
}

function describeSocSchema(dataset) {
  if (dataset) {
    const schema = getDatasetSchema(dataset);
    if (!schema) return null;
    return describeDataset(schema);
  }

  return {
    version: SOC_SCHEMA_VERSION,
    datasets: Object.values(SOC_SCHEMA_CATALOG).map(describeDataset),
  };
}

function describeDataset(schema) {
  return {
    name: schema.name,
    description: schema.description,
    aliases: schema.aliases || [],
    defaultTimeField: schema.defaultTimeField || null,
    snapshotDataset: schema.snapshotDataset || null,
    fields: Object.entries(schema.fields).map(([name, metadata]) => ({
      name,
      type: metadata.type,
      description: metadata.description,
      aliases: metadata.aliases,
      operators: metadata.operators,
      filterable: metadata.filterable,
      groupable: metadata.groupable,
      selectable: metadata.selectable,
      sortable: metadata.sortable,
    })),
  };
}

module.exports = {
  SOC_SCHEMA_VERSION,
  SOC_SCHEMA_CATALOG,
  getDatasetSchema,
  getFieldSchema,
  describeSocSchema,
};
