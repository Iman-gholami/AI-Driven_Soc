const CURATION_VERSION = 1;

function deriveCuratedMitreMappings(rule = {}) {
  const sourceFile = lower(rule.sourceFile);
  const classtype = lower(rule.classtype);
  const protocol = lower(rule.protocol);
  const title = String(rule.title || "");
  const titleLower = title.toLowerCase();
  const metadata = String(rule.parsedRule?.metadata || "");
  const references = Array.isArray(rule.parsedRule?.references)
    ? rule.parsedRule.references.map(String)
    : [];

  const mappings = [];
  const add = (techniqueId, mappingRuleId, confidence, evidence) => {
    if (mappings.some((item) => item.techniqueId === techniqueId)) return;
    mappings.push({
      techniqueId,
      source: "curated",
      mappingRuleId,
      confidence,
      reviewed: false,
      evidence,
    });
  };

  // File provenance + classification describes phishing, but not a specific
  // delivery sub-technique. Keep this at the parent technique to avoid false precision.
  if (sourceFile === "phishing.rules" && classtype === "social-engineering") {
    add("T1566", "phishing-family-v1", 0.97, [
      "sourceFile=phishing.rules",
      "classtype=social-engineering",
    ]);
  }

  // C2 traffic over an identified application-layer protocol.
  if (["command-and-control", "domain-c2"].includes(classtype) && protocol === "dns") {
    add("T1071.004", "c2-dns-v1", 0.99, [
      `classtype=${classtype}`,
      "protocol=dns",
    ]);
  }

  if (classtype === "command-and-control" && protocol === "http") {
    add("T1071.001", "c2-http-v1", 0.99, [
      "classtype=command-and-control",
      "protocol=http",
    ]);
  }

  // Explicit process-hollowing semantics in a detection title.
  if (/\bprocess[ -]?hollow(?:ing|ed)?\b/i.test(title)
      || /\bzwunmapviewofsection\b/i.test(title)) {
    add("T1055.012", "process-hollowing-title-v1", 0.99, [
      "title=process-hollowing-indicator",
    ]);
  }

  // Strong obfuscation semantics only. Do not treat arbitrary encoding as ATT&CK.
  if (/\bobfuscat(?:e|ed|ion|ing)?\b/i.test(title)
      || (sourceFile === "hunting.rules" && /\bbase64\b/i.test(title))
      || (sourceFile === "web_client.rules" && /\bstring\.fromcharcode\b/i.test(titleLower))) {
    add("T1027", "obfuscation-title-v1", 0.93, [
      `sourceFile=${sourceFile || "unknown"}`,
      "title=obfuscation-indicator",
    ]);
  }

  // Client endpoint vulnerability exploitation. Requiring both target context and
  // exploit evidence prevents generic web-client detections from being over-mapped.
  const clientTarget = /\battack_target\s+Client_Endpoint\b/i.test(metadata);
  const clientRuleFamily = ["web_client.rules", "activex.rules"].includes(sourceFile);
  const exploitEvidence = hasCveReference(references, metadata)
    || /\b(?:buffer|integer|stack|heap) overflow\b/i.test(title)
    || /\buse[- ]after[- ]free\b/i.test(title)
    || /\bmemory corruption\b/i.test(title)
    || /\bremote code execution\b/i.test(title)
    || /\bcode execution\b/i.test(title)
    || /\bmalformed\b/i.test(title);

  if (clientRuleFamily && clientTarget && exploitEvidence) {
    add("T1203", "client-exploit-v1", 0.97, [
      `sourceFile=${sourceFile}`,
      "metadata.attack_target=Client_Endpoint",
      "evidence=client-vulnerability-exploit",
    ]);
  }

  // Exploit-kit rules are heterogeneous. Only map entries whose titles carry
  // concrete vulnerability/exploitation semantics.
  const exploitKitEvidence =
    /\b(?:buffer|integer|stack|heap) overflow\b/i.test(title)
    || /\buse[- ]after[- ]free\b/i.test(title)
    || /\bmemory corruption\b/i.test(title)
    || /\bcve[-_ ]?\d{4}[-_]\d+\b/i.test(title)
    || /\bvulnerabilit(?:y|ies)\b/i.test(title);

  if (sourceFile === "exploit_kit.rules" && exploitKitEvidence) {
    add("T1203", "exploit-kit-client-exploit-v1", 0.90, [
      "sourceFile=exploit_kit.rules",
      "title=concrete-exploit-indicator",
    ]);
  }

  if (sourceFile === "scan.rules" && classtype === "attempted-recon") {
    add("T1046", "network-scan-v1", 0.96, [
      "sourceFile=scan.rules",
      "classtype=attempted-recon",
    ]);
  }

  return {
    mapped: mappings.length > 0,
    techniqueIds: mappings.map((item) => item.techniqueId),
    mappings,
    curationVersion: CURATION_VERSION,
  };
}

function hasCveReference(references, metadata) {
  if (references.some((value) => /(?:^|,)cve[, _-]*(?:CVE[-_])?\d{4}[-_]\d+/i.test(value))) return true;
  return /\bcve\s+CVE[_-]\d{4}[_-]\d+\b/i.test(String(metadata || ""));
}

function lower(value) {
  return String(value || "").trim().toLowerCase();
}

module.exports = {
  CURATION_VERSION,
  deriveCuratedMitreMappings,
};
