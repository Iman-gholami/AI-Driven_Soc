const Alert = require("../models/Alert");
const DetectionRule = require("../models/DetectionRule");
const IpAsset = require("../models/IpAsset");
const ThreatIntelObservation = require("../models/ThreatIntelObservation");
const MitreTechnique = require("../models/MitreTechnique");
const IntelDatasetState = require("../models/IntelDatasetState");

class SocEntityContextService {
  constructor({
    alertModel = Alert,
    detectionRuleModel = DetectionRule,
    ipAssetModel = IpAsset,
    threatIntelModel = ThreatIntelObservation,
    mitreTechniqueModel = MitreTechnique,
    stateModel = IntelDatasetState,
  } = {}) {
    this.alertModel = alertModel;
    this.detectionRuleModel = detectionRuleModel;
    this.ipAssetModel = ipAssetModel;
    this.threatIntelModel = threatIntelModel;
    this.mitreTechniqueModel = mitreTechniqueModel;
    this.stateModel = stateModel;
  }

  async getContext({ entityType, id }) {
    const type = String(entityType || "").trim();
    const value = String(id || "").trim();
    if (!value) throw new Error("Entity id is required");

    if (type === "alert") return this.getAlertContext(value);
    if (type === "ip") return this.getIpContext(value);
    if (type === "organization") return this.getOrganizationContext(value);
    if (type === "rule") return this.getRuleContext(value);
    if (type === "mitre_technique") return this.getMitreTechniqueContext(value);

    throw new Error("Unsupported SOC entity type: " + type);
  }

  async getAlertContext(alertId) {
    const alert = await this.alertModel.findOne({ alertId }).lean().exec();
    if (!alert) throw new Error("Alert not found: " + alertId);

    const raw = alert.rawEvent || {};
    const network = alert.soc?.networkIntelligence || {};
    const tuple = network.tuple || {};
    const endpoints = Array.isArray(network.ips) ? network.ips : [];

    const sourceIp = firstString(
      tuple.sourceIp,
      raw.src_ip,
      raw.source_ip,
      raw.srcIp,
      raw.sourceIp,
    );
    const destinationIp = firstString(
      tuple.destinationIp,
      raw.dst_ip,
      raw.dest_ip,
      raw.destination_ip,
      raw.dstIp,
      raw.destinationIp,
    );

    const sourceEndpoint = findEndpoint(endpoints, sourceIp, "source");
    const destinationEndpoint = findEndpoint(endpoints, destinationIp, "destination");
    const organization = firstString(
      destinationEndpoint?.asset?.organization,
      sourceEndpoint?.asset?.organization,
    );

    const analysis = buildPersistedAlertAnalysis(alert.fullAnalysis);
    const relationship = alert.fullAnalysis?.network_relationship_analysis || null;
    const recommendedActions = uniqueStrings([
      ...arrayify(alert.fullAnalysis?.recommended_investigation_steps),
      ...arrayify(alert.fullAnalysis?.analyst_decision?.recommended_actions),
      ...arrayify(alert.fullAnalysis?.analyst_decision?.actions),
      ...arrayify(alert.fullAnalysis?.analyst_decision?.next_steps),
      ...arrayify(alert.fullAnalysis?.analyst_decision?.action),
      ...arrayify(alert.analysis?.at?.(-1)?.recommendations),
    ]).slice(0, 20);

    const relatedEntities = {
      sourceIp,
      destinationIp,
      organization,
      ruleId: firstString(alert.ruleMatch?.ruleId),
      mitreTechniques: extractMitreTechniqueIds([
        alert.soc?.mitreAttack,
        alert.fullAnalysis?.attack_mapping,
      ]),
    };

    return {
      entity: { type: "alert", id: alert.alertId },
      contextType: "investigation",
      alert: {
        alertId: alert.alertId,
        signature: alert.signature || getRawSignature(raw) || null,
        severity: alert.severity || null,
        status: alert.status || null,
        aiStatus: alert.aiStatus || null,
        source: alert.source || null,
        host: alert.host || null,
        eventTime: alert.eventTime || null,
        createdAt: alert.createdAt || null,
        updatedAt: alert.updatedAt || null,
        ruleMatch: summarizeRuleMatch(alert.ruleMatch),
      },
      traffic: {
        sourceIp: sourceIp || null,
        sourcePort: firstNumber(tuple.sourcePort, raw.src_port, raw.source_port),
        destinationIp: destinationIp || null,
        destinationPort: firstNumber(tuple.destinationPort, raw.dst_port, raw.dest_port, raw.destination_port),
        protocol: firstString(tuple.protocol, raw.protocol, raw.proto) || null,
        domains: collectStrings(raw, [
          "http_host", "domain", "fqdn", "destination_fqdn", "dst_fqdn", "dns_query",
        ], 8),
        urls: collectStrings(raw, ["request_url", "url", "uri", "request_uri"], 8),
      },
      source: summarizeEndpoint(sourceEndpoint),
      destination: summarizeEndpoint(destinationEndpoint),
      analysis,
      analysisAvailable: Boolean(alert.fullAnalysis && typeof alert.fullAnalysis === "object"),
      relationshipAnalysis: relationship,
      mitre: alert.soc?.mitreAttack || alert.fullAnalysis?.attack_mapping || [],
      iocs: Array.isArray(alert.soc?.iocs) ? alert.soc.iocs.slice(0, 30) : [],
      correlations: Array.isArray(alert.soc?.correlation) ? alert.soc.correlation.slice(0, 30) : [],
      recommendedActions,
      relatedEntities: sanitizeRelatedEntities(relatedEntities),
      evidencePolicy: {
        persistedAnalysis: Boolean(alert.fullAnalysis && typeof alert.fullAnalysis === "object"),
        deterministicNetworkIntelligence: Boolean(alert.soc?.networkIntelligence),
        rawPayloadIncluded: false,
      },
    };
  }

  async getIpContext(ip) {
    const [assetState, threatState] = await Promise.all([
      this.getDatasetState("asset_registry"),
      this.getDatasetState("threat_intel"),
    ]);

    const assetFilter = {
      ip,
      ...(assetState?.activeImportId ? { importId: assetState.activeImportId } : {}),
    };
    const threatBase = threatState?.activeImportId ? { importId: threatState.activeImportId } : {};

    const alertMatch = {
      $or: [
        { "rawEvent.src_ip": ip },
        { "rawEvent.source_ip": ip },
        { "rawEvent.dst_ip": ip },
        { "rawEvent.dest_ip": ip },
        { "rawEvent.destination_ip": ip },
        { "soc.networkIntelligence.ips.ip": ip },
      ],
    };

    const [
      asset,
      directCount,
      relationshipCount,
      latestDirect,
      latestRelationship,
      alertCount,
      recentAlerts,
    ] = await Promise.all([
      this.ipAssetModel.findOne(assetFilter).lean().exec(),
      this.threatIntelModel.countDocuments({ ...threatBase, "source.ip": ip }).exec(),
      this.threatIntelModel.countDocuments({ ...threatBase, "destination.ip": ip }).exec(),
      this.threatIntelModel.findOne({ ...threatBase, "source.ip": ip }).sort({ sourceTime: -1 }).lean().exec(),
      this.threatIntelModel.findOne({ ...threatBase, "destination.ip": ip }).sort({ sourceTime: -1 }).lean().exec(),
      this.alertModel.countDocuments(alertMatch).exec(),
      this.alertModel
        .find(alertMatch)
        .sort({ eventTime: -1, createdAt: -1 })
        .limit(10)
        .select("alertId signature severity eventTime createdAt ruleMatch soc.networkIntelligence.ips")
        .lean()
        .exec(),
    ]);

    const organizations = uniqueStrings([
      asset?.bunit,
      ...recentAlerts.flatMap((alert) =>
        (Array.isArray(alert.soc?.networkIntelligence?.ips) ? alert.soc.networkIntelligence.ips : [])
          .filter((item) => item.ip === ip)
          .map((item) => item.asset?.organization),
      ),
    ]);

    return {
      entity: { type: "ip", id: ip },
      contextType: "investigation",
      ip,
      asset: asset
        ? {
            owned: true,
            organization: asset.bunit || null,
            category: asset.category || null,
            province: asset.province || null,
          }
        : { owned: false },
      threatIntelligence: {
        directObservationCount: Number(directCount || 0),
        relationshipObservationCount: Number(relationshipCount || 0),
        latestDirect: summarizeThreatObservation(latestDirect),
        latestRelationship: summarizeThreatObservation(latestRelationship),
      },
      alerts: {
        count: Number(alertCount || 0),
        recent: recentAlerts.map(summarizeAlertReference),
      },
      relatedEntities: sanitizeRelatedEntities({
        sourceIp: ip,
        organization: organizations[0],
      }),
      organizations,
    };
  }

  async getOrganizationContext(organization) {
    const assetState = await this.getDatasetState("asset_registry");
    const assetFilter = {
      bunit: organization,
      ...(assetState?.activeImportId ? { importId: assetState.activeImportId } : {}),
    };
    const alertMatch = {
      "soc.networkIntelligence.ips": {
        $elemMatch: { "asset.organization": organization },
      },
    };

    const [assetCount, provinces, alertCount, recentAlerts] = await Promise.all([
      this.ipAssetModel.countDocuments(assetFilter).exec(),
      this.ipAssetModel.distinct("province", assetFilter).exec(),
      this.alertModel.countDocuments(alertMatch).exec(),
      this.alertModel
        .find(alertMatch)
        .sort({ eventTime: -1, createdAt: -1 })
        .limit(10)
        .select("alertId signature severity eventTime createdAt ruleMatch soc.networkIntelligence.ips")
        .lean()
        .exec(),
    ]);

    return {
      entity: { type: "organization", id: organization },
      contextType: "investigation",
      organization,
      assets: {
        count: Number(assetCount || 0),
        provinces: uniqueStrings(provinces).slice(0, 20),
      },
      alerts: {
        count: Number(alertCount || 0),
        recent: recentAlerts.map(summarizeAlertReference),
      },
      relatedEntities: { organization },
    };
  }

  async getRuleContext(ruleId) {
    let rule = await this.detectionRuleModel.findOne({ ruleId, isCurrent: true }).lean().exec();
    if (!rule) {
      rule = await this.detectionRuleModel.findOne({ ruleId }).sort({ revision: -1 }).lean().exec();
    }

    const [alertCount, recentAlerts] = await Promise.all([
      this.alertModel.countDocuments({ "ruleMatch.ruleId": ruleId }).exec(),
      this.alertModel
        .find({ "ruleMatch.ruleId": ruleId })
        .sort({ eventTime: -1, createdAt: -1 })
        .limit(10)
        .select("alertId signature severity eventTime createdAt ruleMatch")
        .lean()
        .exec(),
    ]);

    return {
      entity: { type: "rule", id: ruleId },
      contextType: "investigation",
      rule: rule
        ? {
            ruleId: rule.ruleId,
            revision: rule.revision,
            title: rule.title,
            classtype: rule.classtype,
            protocol: rule.protocol,
            sourceFile: rule.sourceFile,
            mitre: rule.mitre || null,
          }
        : null,
      alerts: {
        count: Number(alertCount || 0),
        recent: recentAlerts.map(summarizeAlertReference),
      },
      relatedEntities: sanitizeRelatedEntities({
        ruleId,
        mitreTechniques: rule?.mitre?.techniqueIds || [],
      }),
    };
  }

  async getMitreTechniqueContext(techniqueId) {
    const technique = await this.mitreTechniqueModel.findOne({ techniqueId }).lean().exec();
    const [ruleCount, alertCount, recentAlerts] = await Promise.all([
      this.detectionRuleModel.countDocuments({ "mitre.techniqueIds": techniqueId, isCurrent: true }).exec(),
      this.alertModel.countDocuments({
        $or: [
          { "fullAnalysis.attack_mapping.technique": techniqueId },
          { "fullAnalysis.attack_mapping.techniqueId": techniqueId },
          { "soc.mitreAttack.technique": techniqueId },
          { "soc.mitreAttack.techniqueId": techniqueId },
        ],
      }).exec(),
      this.alertModel
        .find({
          $or: [
            { "fullAnalysis.attack_mapping.technique": techniqueId },
            { "fullAnalysis.attack_mapping.techniqueId": techniqueId },
            { "soc.mitreAttack.technique": techniqueId },
            { "soc.mitreAttack.techniqueId": techniqueId },
          ],
        })
        .sort({ eventTime: -1, createdAt: -1 })
        .limit(10)
        .select("alertId signature severity eventTime createdAt ruleMatch")
        .lean()
        .exec(),
    ]);

    return {
      entity: { type: "mitre_technique", id: techniqueId },
      contextType: "investigation",
      technique: technique
        ? {
            techniqueId: technique.techniqueId,
            name: technique.name,
            tactics: technique.tactics || [],
            platforms: technique.platforms || [],
            isSubTechnique: Boolean(technique.isSubTechnique),
            parentTechniqueId: technique.parentTechniqueId || null,
            revoked: Boolean(technique.revoked),
            deprecated: Boolean(technique.deprecated),
          }
        : null,
      coverage: {
        currentRuleCount: Number(ruleCount || 0),
        alertCount: Number(alertCount || 0),
      },
      alerts: {
        recent: recentAlerts.map(summarizeAlertReference),
      },
      relatedEntities: {
        mitreTechniques: [techniqueId],
      },
    };
  }

  async getDatasetState(dataset) {
    return this.stateModel.findOne({ dataset }).lean().exec();
  }
}

function buildPersistedAlertAnalysis(fullAnalysis = {}) {
  if (!fullAnalysis || typeof fullAnalysis !== "object") return null;

  return {
    verdict: fullAnalysis.verdict || null,
    oneLineSummary: fullAnalysis.one_line_summary || null,
    incidentSummary: fullAnalysis.incident_summary || null,
    riskAssessment: fullAnalysis.risk_assessment || null,
    detectionAnalysis: fullAnalysis.detection_analysis || null,
    behaviorAnalysis: fullAnalysis.behavior_analysis || null,
    falsePositiveAnalysis: fullAnalysis.false_positive_analysis || null,
    analystDecision: fullAnalysis.analyst_decision || null,
    finalSocNote: fullAnalysis.final_soc_note || null,
  };
}

function summarizeEndpoint(endpoint) {
  if (!endpoint) return null;
  return {
    ip: endpoint.ip || null,
    roles: endpoint.roles || [],
    scope: endpoint.scope || null,
    networkZone: endpoint.networkZone || null,
    nationalNetwork: Boolean(endpoint.nationalNetwork),
    asset: endpoint.asset
      ? {
          owned: Boolean(endpoint.asset.owned),
          organization: endpoint.asset.organization || null,
          category: endpoint.asset.category || null,
          province: endpoint.asset.province || null,
        }
      : null,
    geo: endpoint.geo || null,
    asn: endpoint.asn || null,
    threat: endpoint.threat
      ? {
          directMatch: Boolean(endpoint.threat.directMatch),
          relationshipMatch: Boolean(endpoint.threat.relationshipMatch),
          directObservationCount: Number(endpoint.threat.directObservationCount || 0),
          relationshipObservationCount: Number(endpoint.threat.relationshipObservationCount || 0),
          direct: summarizeThreatEvidenceContainer(endpoint.threat.direct),
          relationship: summarizeThreatEvidenceContainer(endpoint.threat.relationship),
        }
      : null,
  };
}

function summarizeThreatEvidenceContainer(container) {
  if (!container || typeof container !== "object") return null;
  return {
    latest: container.latest || null,
    evidence: Array.isArray(container.evidence) ? container.evidence.slice(0, 8) : [],
  };
}

function summarizeThreatObservation(observation) {
  if (!observation) return null;
  return {
    provider: observation.provider || null,
    feedName: observation.feedName || null,
    malwareName: observation.malwareName || null,
    classification: observation.classification || null,
    protocol: observation.protocol || null,
    source: observation.source || null,
    destination: observation.destination || null,
    sourceTime: observation.sourceTime || null,
    observationTime: observation.observationTime || null,
  };
}

function summarizeRuleMatch(ruleMatch) {
  if (!ruleMatch || typeof ruleMatch !== "object") return null;
  return {
    status: ruleMatch.status || null,
    matchType: ruleMatch.matchType || null,
    ruleId: ruleMatch.ruleId || null,
    revision: ruleMatch.revision ?? null,
    title: ruleMatch.title || null,
    protocol: ruleMatch.protocol || null,
    classtype: ruleMatch.classtype || null,
    sourceFile: ruleMatch.sourceFile || null,
  };
}

function summarizeAlertReference(alert) {
  return {
    alertId: alert.alertId,
    signature: alert.signature || null,
    severity: alert.severity || null,
    eventTime: alert.eventTime || alert.createdAt || null,
    ruleId: alert.ruleMatch?.ruleId || null,
  };
}

function getRawSignature(rawEvent = {}) {
  return firstString(rawEvent.signature, rawEvent.Signature, rawEvent.rule_name, rawEvent.ruleName);
}

function findEndpoint(endpoints, ip, role) {
  return endpoints.find((item) => item?.ip === ip)
    || endpoints.find((item) => Array.isArray(item?.roles) && item.roles.includes(role))
    || null;
}

function collectStrings(object, keys, limit) {
  return uniqueStrings(keys.flatMap((key) => arrayify(object?.[key]))).slice(0, limit);
}

function extractMitreTechniqueIds(values) {
  const output = [];

  function visit(value) {
    if (!value) return;
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (typeof value === "string") {
      const text = value.trim();
      if (/^T\d{4}(?:\.\d{3})?$/i.test(text)) output.push(text);
      return;
    }
    if (typeof value === "object") {
      [value.technique, value.techniqueId, value.id, value.technique_id].forEach(visit);
    }
  }

  visit(values);
  return uniqueStrings(output);
}

function sanitizeRelatedEntities(value = {}) {
  return Object.fromEntries(
    Object.entries({
      sourceIp: firstString(value.sourceIp),
      destinationIp: firstString(value.destinationIp),
      organization: firstString(value.organization),
      ruleId: firstString(value.ruleId),
      mitreTechniques: uniqueStrings(arrayify(value.mitreTechniques)).slice(0, 20),
    }).filter(([, item]) => Array.isArray(item) ? item.length > 0 : Boolean(item)),
  );
}

function firstString(...values) {
  for (const value of values) {
    if (value === undefined || value === null) continue;
    const text = String(value).trim();
    if (text) return text;
  }
  return undefined;
}

function firstNumber(...values) {
  for (const value of values) {
    if (value === undefined || value === null || value === "") continue;
    const number = Number(value);
    if (Number.isFinite(number)) return number;
  }
  return null;
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
  SocEntityContextService,
  buildPersistedAlertAnalysis,
  summarizeEndpoint,
  extractMitreTechniqueIds,
};
