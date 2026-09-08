const SOC_SEMANTIC_CONCEPTS = {
  alert: {
    name: "alert",
    aliases: ["alert", "alerts", "هشدار", "الر‌ت", "آلارم"],
    preferredDataset: "alerts",
    description: "A persisted SOC security alert.",
  },
  signature: {
    name: "signature",
    aliases: ["signature", "sig", "سیگنیچر", "امضا", "rule title"],
    fields: ["alerts.signature", "detection_rules.title"],
    description: "The detection signature or rule title that fired.",
  },
  source_ip: {
    name: "source_ip",
    aliases: ["source ip", "src ip", "آی‌پی مبدا", "مبدا"],
    fields: ["alerts.rawEvent.src_ip", "alerts.rawEvent.source_ip", "threat_intelligence.source.ip"],
    description: "IPv4 observed as the source side of traffic.",
  },
  destination_ip: {
    name: "destination_ip",
    aliases: ["destination ip", "dst ip", "آی‌پی مقصد", "مقصد"],
    fields: ["alerts.rawEvent.dst_ip", "alerts.rawEvent.dest_ip", "threat_intelligence.destination.ip"],
    description: "IPv4 observed as the destination side of traffic.",
  },
  organization: {
    name: "organization",
    aliases: ["organization", "org", "سازمان", "اداره", "واحد سازمانی"],
    fields: [
      "alerts.soc.networkIntelligence.ips.asset.organization",
      "ip_assets.bunit",
      "threat_intelligence.source.orgFaName",
      "threat_intelligence.destination.orgFaName",
    ],
    description: "Organizational ownership or organization identity.",
  },
  malware: {
    name: "malware",
    aliases: ["malware", "بدافزار", "میرای", "mirai"],
    fields: ["threat_intelligence.malwareName"],
    description: "Threat-feed malware family or name.",
  },
  malicious_ip: {
    name: "malicious_ip",
    aliases: ["malicious ip", "threat ip", "آی‌پی مخرب", "آی‌پی آلوده"],
    fields: [
      "alerts.soc.networkIntelligence.ips.threat.directMatch",
      "threat_intelligence.source.ip",
    ],
    description: "An IP with direct threat-feed evidence; do not equate relationship-only evidence with direct malicious classification.",
  },
  direct_threat_match: {
    name: "direct_threat_match",
    aliases: ["direct threat match", "direct match", "تطبیق مستقیم تهدید"],
    fields: ["alerts.soc.networkIntelligence.ips.threat.directMatch"],
    description: "Persisted direct threat-feed evidence for an alert IP.",
  },
  mitre_technique: {
    name: "mitre_technique",
    aliases: ["MITRE", "ATT&CK", "technique", "تکنیک", "میترا"],
    fields: [
      "alerts.soc.mitreAttack.technique",
      "detection_rules.mitre.techniqueIds",
      "mitre_techniques.techniqueId",
    ],
    description: "MITRE ATT&CK technique identifier.",
  },
  verdict: {
    name: "verdict",
    aliases: ["verdict", "AI verdict", "نتیجه تحلیل", "حکم تحلیل"],
    fields: ["alerts.fullAnalysis.verdict"],
    description: "Persisted AI analysis verdict.",
  },
  event_time: {
    name: "event_time",
    aliases: ["event time", "زمان رخداد", "زمان رویداد", "زمان وقوع"],
    fields: ["alerts.eventTime"],
    description: "Canonical source-event time; legacy alerts fall back to ingestion time.",
  },
};

function describeSocConcepts() {
  return Object.values(SOC_SEMANTIC_CONCEPTS);
}

module.exports = {
  SOC_SEMANTIC_CONCEPTS,
  describeSocConcepts,
};
