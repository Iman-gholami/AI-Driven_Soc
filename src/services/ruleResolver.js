const { normalizeTitle, extractSearchableContent } = require("./ruleParser");

class RuleResolver {
  constructor({ detectionRuleRepository } = {}) {
    if (detectionRuleRepository) {
      this.detectionRuleRepository = detectionRuleRepository;
      return;
    }

    const { DetectionRuleRepository } = require("../repositories/DetectionRuleRepository");
    this.detectionRuleRepository = new DetectionRuleRepository();
  }

  async resolve(incident = {}) {
    const signature = getIncidentSignature(incident);
    if (!signature) {
      return unresolved("missing_signature");
    }

    let candidates = await this.detectionRuleRepository.findByExactTitle(signature);
    let matchType = "exact_signature";

    if (candidates.length === 0) {
      candidates = await this.detectionRuleRepository.findByNormalizedTitle(signature);
      matchType = "normalized_signature";
    }

    if (candidates.length === 0) {
      return unresolved("rule_not_found", signature);
    }

    if (candidates.length === 1) {
      return matched(candidates[0], matchType, 1);
    }

    const sameRuleId = candidates.every((rule) => String(rule.ruleId) === String(candidates[0].ruleId));
    if (sameRuleId) {
      const latest = [...candidates].sort((a, b) => Number(b.revision || 0) - Number(a.revision || 0))[0];
      return matched(latest, `${matchType}_latest_revision`, candidates.length, [`rule_id:${latest.ruleId}`]);
    }

    const resolution = disambiguateCandidates(candidates, incident);
    if (resolution.rule) {
      return matched(resolution.rule, `${matchType}_${resolution.reason}`, candidates.length, resolution.evidence);
    }

    return {
      status: "ambiguous",
      matchType,
      signature,
      candidateCount: candidates.length,
      candidates: candidates.slice(0, 20).map(toCandidateSummary),
      resolutionEvidence: resolution.evidence,
    };
  }
}

function getIncidentSignature(incident) {
  const value = incident.signature
    || incident.Signature
    || incident.msg
    || incident.rule_name
    || incident.ruleName
    || incident.alert?.signature
    || incident.alert?.signature_name;

  return value ? String(value).trim() : "";
}

function getIncidentProtocol(incident) {
  const value = incident.protocol
    || incident.proto
    || incident.transport
    || incident.network_transport
    || incident.Network_Transport;
  return value ? String(value).trim().toLowerCase() : "";
}

function incidentEvidenceText(incident) {
  try {
    return JSON.stringify(incident).toLowerCase();
  } catch (_) {
    return "";
  }
}

function disambiguateCandidates(candidates, incident) {
  const protocol = getIncidentProtocol(incident);
  const evidenceText = incidentEvidenceText(incident);
  let pool = candidates;
  const evidence = [];

  if (protocol) {
    const protocolMatches = candidates.filter((rule) => String(rule.protocol || "").toLowerCase() === protocol);
    if (protocolMatches.length === 1) {
      return { rule: protocolMatches[0], reason: "protocol", evidence: [`protocol:${protocol}`] };
    }
    if (protocolMatches.length > 1) {
      pool = protocolMatches;
      evidence.push(`protocol:${protocol}`);
    }
  }

  const scored = pool.map((rule) => {
    let score = 0;
    const matches = [];
    const parsedContents = rule.parsedRule?.contents || [];

    for (const content of parsedContents) {
      if (content?.negative) continue;
      const needle = extractSearchableContent(content?.value);
      if (needle && evidenceText.includes(needle)) {
        score += 3;
        matches.push(needle);
      }
    }

    return { rule, score, matches };
  }).sort((a, b) => b.score - a.score);

  const top = scored[0];
  const second = scored[1];
  if (top && top.score >= 3 && (!second || top.score >= second.score + 2)) {
    return {
      rule: top.rule,
      reason: "evidence",
      evidence: [...evidence, ...top.matches.map((item) => `content:${item}`)],
    };
  }

  return { rule: null, reason: null, evidence };
}

function matched(rule, matchType, candidateCount, evidence = []) {
  return {
    status: "matched",
    matchType,
    signature: rule.title,
    candidateCount,
    rule,
    resolutionEvidence: evidence,
  };
}

function unresolved(reason, signature = "") {
  return {
    status: "unresolved",
    matchType: null,
    signature,
    candidateCount: 0,
    reason,
  };
}

function toCandidateSummary(rule) {
  return {
    ruleId: rule.ruleId,
    revision: rule.revision,
    title: rule.title,
    protocol: rule.protocol,
    sourceFile: rule.sourceFile,
  };
}

module.exports = {
  RuleResolver,
  getIncidentSignature,
  disambiguateCandidates,
};
