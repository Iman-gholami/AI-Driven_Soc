const SOC_RELATIONSHIPS = {
  alert_source_ip_to_threat_source: {
    name: "alert_source_ip_to_threat_source",
    description: "Correlates an alert source IPv4 with direct threat-intelligence source observations.",
    from: { dataset: "alerts", fields: ["rawEvent.src_ip", "rawEvent.source_ip"] },
    to: { dataset: "threat_intelligence", field: "source.ip" },
    semantics: "Direct threat evidence for an observed alert source IP.",
  },
  alert_destination_ip_to_asset: {
    name: "alert_destination_ip_to_asset",
    description: "Maps an alert destination IPv4 to the current organizational asset registry.",
    from: { dataset: "alerts", fields: ["rawEvent.dst_ip", "rawEvent.dest_ip"] },
    to: { dataset: "ip_assets", field: "ip" },
    semantics: "Organizational ownership and province/category for an alert destination IP.",
  },
  alert_rule_to_detection_rule: {
    name: "alert_rule_to_detection_rule",
    description: "Maps an alert's resolved rule identifier to the detection-rule repository.",
    from: { dataset: "alerts", field: "ruleMatch.ruleId" },
    to: { dataset: "detection_rules", field: "ruleId" },
    semantics: "Resolved detection rule metadata for an alert.",
  },
  detection_rule_to_mitre_technique: {
    name: "detection_rule_to_mitre_technique",
    description: "Maps deterministic rule MITRE technique IDs to the local ATT&CK technique catalog.",
    from: { dataset: "detection_rules", field: "mitre.techniqueIds" },
    to: { dataset: "mitre_techniques", field: "techniqueId" },
    semantics: "Rule-level deterministic MITRE ATT&CK relationship.",
  },
  alert_ip_to_organization: {
    name: "alert_ip_to_organization",
    description: "Uses persisted network intelligence to associate an alert IP with its organizational owner.",
    from: { dataset: "alerts", field: "soc.networkIntelligence.ips.ip" },
    to: { dataset: "alerts", field: "soc.networkIntelligence.ips.asset.organization" },
    semantics: "Persisted enrichment relationship inside the analyzed alert.",
  },
};

function getRelationship(name) {
  return SOC_RELATIONSHIPS[String(name || "").trim()] || null;
}

function describeSocRelationships() {
  return Object.values(SOC_RELATIONSHIPS);
}

module.exports = {
  SOC_RELATIONSHIPS,
  getRelationship,
  describeSocRelationships,
};
