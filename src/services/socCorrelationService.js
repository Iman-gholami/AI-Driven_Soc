const Alert = require("../models/Alert");
const DetectionRule = require("../models/DetectionRule");
const IpAsset = require("../models/IpAsset");
const ThreatIntelObservation = require("../models/ThreatIntelObservation");
const MitreTechnique = require("../models/MitreTechnique");
const IntelDatasetState = require("../models/IntelDatasetState");
const { settings } = require("../core/config");
const { getRelationship } = require("../copilot/relationshipCatalog");
const { resolveTimeRange } = require("../copilot/timeRange");

class SocCorrelationService {
  constructor({
    alertModel = Alert,
    detectionRuleModel = DetectionRule,
    ipAssetModel = IpAsset,
    threatIntelModel = ThreatIntelObservation,
    mitreTechniqueModel = MitreTechnique,
    stateModel = IntelDatasetState,
    timezone = settings.socTimezone || "Asia/Tehran",
    weekStart = settings.socWeekStart || "saturday",
    now = () => new Date(),
  } = {}) {
    this.alertModel = alertModel;
    this.detectionRuleModel = detectionRuleModel;
    this.ipAssetModel = ipAssetModel;
    this.threatIntelModel = threatIntelModel;
    this.mitreTechniqueModel = mitreTechniqueModel;
    this.stateModel = stateModel;
    this.timezone = timezone;
    this.weekStart = weekStart;
    this.now = now;
  }

  async correlate(input = {}) {
    const relationshipName = String(input.relationship || "").trim();
    const relationship = getRelationship(relationshipName);
    if (!relationship) throw new Error("Unknown SOC relationship: " + relationshipName);

    const limit = Math.min(Math.max(Number(input.limit) || 20, 1), 100);
    const range = input.timeRange
      ? resolveTimeRange(input.timeRange, {
          now: this.now(),
          timezone: this.timezone,
          weekStart: this.weekStart,
        })
      : { from: null, to: null, timezone: this.timezone, label: "all time" };

    let rows;
    if (relationshipName === "alert_source_ip_to_threat_source") {
      rows = await this.alertSourceIpToThreatSource(range, limit);
    } else if (relationshipName === "alert_destination_ip_to_asset") {
      rows = await this.alertDestinationIpToAsset(range, limit);
    } else if (relationshipName === "alert_rule_to_detection_rule") {
      rows = await this.alertRuleToDetectionRule(range, limit);
    } else if (relationshipName === "detection_rule_to_mitre_technique") {
      rows = await this.detectionRuleToMitreTechnique(limit);
    } else if (relationshipName === "alert_ip_to_organization") {
      rows = await this.alertIpToOrganization(range, limit);
    } else {
      throw new Error("Relationship is described but not executable: " + relationshipName);
    }

    return {
      operation: "correlate",
      relationship: relationshipName,
      relationshipDescription: relationship.description,
      timeRange: {
        from: range.from ? range.from.toISOString() : null,
        to: range.to ? range.to.toISOString() : null,
        timezone: range.timezone,
        label: range.label,
      },
      rows,
      count: rows.length,
      metadata: {
        readOnly: true,
        deterministicJoin: true,
      },
    };
  }

  async alertSourceIpToThreatSource(range, limit) {
    const alertRows = await this.aggregateAlertKey({
      expression: {
        $ifNull: [
          "$rawEvent.src_ip",
          { $ifNull: ["$rawEvent.source_ip", "$rawEvent.srcIp"] },
        ],
      },
      range,
      candidateLimit: Math.min(Math.max(limit * 20, 200), 2000),
    });

    const ips = alertRows.map((item) => item.key).filter(Boolean);
    if (!ips.length) return [];

    const state = await this.getDatasetState("threat_intel");
    const match = {
      "source.ip": { $in: ips },
      ...(state?.activeImportId ? { importId: state.activeImportId } : {}),
    };

    const observations = await this.threatIntelModel.aggregate([
      { $match: match },
      {
        $group: {
          _id: "$source.ip",
          threatObservationCount: { $sum: 1 },
          providers: { $addToSet: "$provider" },
          malware: { $addToSet: "$malwareName" },
          classifications: { $addToSet: "$classification.identifier" },
          latestSourceTime: { $max: "$sourceTime" },
        },
      },
    ]).exec();

    const threatByIp = new Map(observations.map((item) => [item._id, item]));
    return alertRows
      .filter((item) => threatByIp.has(item.key))
      .map((item) => {
        const threat = threatByIp.get(item.key);
        return {
          ip: item.key,
          alertCount: item.count,
          threatObservationCount: Number(threat.threatObservationCount || 0),
          providers: cleanStrings(threat.providers),
          malware: cleanStrings(threat.malware),
          classifications: cleanStrings(threat.classifications),
          latestThreatObservation: threat.latestSourceTime || null,
        };
      })
      .sort((a, b) => b.alertCount - a.alertCount || b.threatObservationCount - a.threatObservationCount)
      .slice(0, limit);
  }

  async alertDestinationIpToAsset(range, limit) {
    const alertRows = await this.aggregateAlertKey({
      expression: {
        $ifNull: [
          "$rawEvent.dst_ip",
          {
            $ifNull: [
              "$rawEvent.dest_ip",
              { $ifNull: ["$rawEvent.destination_ip", "$rawEvent.dstIp"] },
            ],
          },
        ],
      },
      range,
      candidateLimit: Math.min(Math.max(limit * 20, 200), 2000),
    });

    const ips = alertRows.map((item) => item.key).filter(Boolean);
    if (!ips.length) return [];

    const state = await this.getDatasetState("asset_registry");
    const assets = await this.ipAssetModel.find({
      ip: { $in: ips },
      ...(state?.activeImportId ? { importId: state.activeImportId } : {}),
    })
      .select("ip bunit category province")
      .lean()
      .exec();

    const assetByIp = new Map(assets.map((item) => [item.ip, item]));
    return alertRows
      .filter((item) => assetByIp.has(item.key))
      .map((item) => {
        const asset = assetByIp.get(item.key);
        return {
          ip: item.key,
          alertCount: item.count,
          organization: asset.bunit || null,
          category: asset.category || null,
          province: asset.province || null,
        };
      })
      .sort((a, b) => b.alertCount - a.alertCount)
      .slice(0, limit);
  }

  async alertRuleToDetectionRule(range, limit) {
    const alertRows = await this.aggregateAlertKey({
      expression: "$ruleMatch.ruleId",
      range,
      candidateLimit: Math.min(Math.max(limit * 10, 100), 1000),
    });

    const ruleIds = alertRows.map((item) => item.key).filter(Boolean);
    if (!ruleIds.length) return [];

    const rules = await this.detectionRuleModel.find({
      ruleId: { $in: ruleIds },
      isCurrent: true,
    })
      .select("ruleId revision title protocol classtype mitre")
      .lean()
      .exec();

    const ruleById = new Map(rules.map((item) => [String(item.ruleId), item]));
    return alertRows
      .filter((item) => ruleById.has(String(item.key)))
      .map((item) => {
        const rule = ruleById.get(String(item.key));
        return {
          ruleId: String(item.key),
          alertCount: item.count,
          revision: rule.revision ?? null,
          title: rule.title || null,
          protocol: rule.protocol || null,
          classtype: rule.classtype || null,
          mitreTechniqueIds: Array.isArray(rule.mitre?.techniqueIds) ? rule.mitre.techniqueIds : [],
        };
      })
      .sort((a, b) => b.alertCount - a.alertCount)
      .slice(0, limit);
  }

  async detectionRuleToMitreTechnique(limit) {
    const rows = await this.detectionRuleModel.aggregate([
      {
        $match: {
          isCurrent: true,
          "mitre.techniqueIds.0": { $exists: true },
        },
      },
      { $unwind: "$mitre.techniqueIds" },
      {
        $group: {
          _id: "$mitre.techniqueIds",
          ruleCount: { $sum: 1 },
        },
      },
      { $sort: { ruleCount: -1, _id: 1 } },
      { $limit: limit },
    ]).exec();

    const techniqueIds = rows.map((item) => item._id).filter(Boolean);
    const techniques = await this.mitreTechniqueModel.find({
      techniqueId: { $in: techniqueIds },
    })
      .select("techniqueId name tactics")
      .lean()
      .exec();

    const techniqueById = new Map(techniques.map((item) => [item.techniqueId, item]));
    return rows.map((item) => {
      const technique = techniqueById.get(item._id);
      return {
        techniqueId: item._id,
        techniqueName: technique?.name || null,
        ruleCount: Number(item.ruleCount || 0),
        tactics: technique?.tactics || [],
      };
    });
  }

  async alertIpToOrganization(range, limit) {
    const pipeline = [];
    const timeMatch = buildAlertTimeMatch(range);
    if (timeMatch) pipeline.push({ $match: timeMatch });

    pipeline.push(
      { $unwind: "$soc.networkIntelligence.ips" },
      {
        $match: {
          "soc.networkIntelligence.ips.asset.owned": true,
          "soc.networkIntelligence.ips.asset.organization": { $nin: [null, ""] },
          "soc.networkIntelligence.ips.ip": { $nin: [null, ""] },
        },
      },
      {
        $group: {
          _id: {
            document: "$_id",
            ip: "$soc.networkIntelligence.ips.ip",
            organization: "$soc.networkIntelligence.ips.asset.organization",
          },
        },
      },
      {
        $group: {
          _id: {
            ip: "$_id.ip",
            organization: "$_id.organization",
          },
          alertCount: { $sum: 1 },
        },
      },
      { $sort: { alertCount: -1 } },
      { $limit: limit },
      {
        $project: {
          _id: 0,
          ip: "$_id.ip",
          organization: "$_id.organization",
          alertCount: 1,
        },
      },
    );

    return this.alertModel.aggregate(pipeline).allowDiskUse(true).exec();
  }

  async aggregateAlertKey({ expression, range, candidateLimit }) {
    const pipeline = [];
    const timeMatch = buildAlertTimeMatch(range);
    if (timeMatch) pipeline.push({ $match: timeMatch });

    pipeline.push(
      { $project: { key: expression } },
      { $match: { key: { $nin: [null, ""] } } },
      { $group: { _id: "$key", count: { $sum: 1 } } },
      { $sort: { count: -1, _id: 1 } },
      { $limit: candidateLimit },
      { $project: { _id: 0, key: "$_id", count: 1 } },
    );

    return this.alertModel.aggregate(pipeline).allowDiskUse(true).exec();
  }

  async getDatasetState(dataset) {
    return this.stateModel.findOne({ dataset }).lean().exec();
  }
}

function buildAlertTimeMatch(range) {
  if (!range?.from && !range?.to) return null;

  const effectiveTime = { $ifNull: ["$eventTime", "$createdAt"] };
  const clauses = [];
  if (range.from) clauses.push({ $gte: [effectiveTime, range.from] });
  if (range.to) clauses.push({ $lt: [effectiveTime, range.to] });

  if (clauses.length === 1) return { $expr: clauses[0] };
  return { $expr: { $and: clauses } };
}

function cleanStrings(values) {
  return [...new Set(
    (Array.isArray(values) ? values : [])
      .filter((value) => value !== undefined && value !== null)
      .map((value) => String(value).trim())
      .filter(Boolean),
  )];
}

module.exports = {
  SocCorrelationService,
  buildAlertTimeMatch,
};
