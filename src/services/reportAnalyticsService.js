const HistoricalReport = require("../models/HistoricalReport");
const { normalizeYear } = require("./reportImportService");

class ReportAnalyticsService {
  constructor({ model = HistoricalReport } = {}) {
    this.model = model;
  }

  async getYears() {
    return this.model.aggregate([
      { $group: { _id: "$year", count: { $sum: 1 } } },
      { $sort: { _id: -1 } },
      { $project: { _id: 0, year: "$_id", count: 1 } },
    ]).exec();
  }

  async getStats(yearInput) {
    const year = normalizeYear(yearInput);
    const [result = {}] = await this.model.aggregate([
      { $match: { year } },
      {
        $facet: {
          summary: [
            {
              $group: {
                _id: null,
                total: { $sum: 1 },
                organizations: { $addToSet: "$target.organization" },
                targetIps: { $addToSet: "$target.ip" },
                highCritical: {
                  $sum: { $cond: [{ $in: ["$severity.level", ["high", "critical"]] }, 1, 0] },
                },
                immediate: {
                  $sum: { $cond: [{ $eq: ["$urgency.normalized", "immediate"] }, 1, 0] },
                },
                actionRequired: {
                  $sum: { $cond: [{ $eq: ["$urgency.normalized", "action_required"] }, 1, 0] },
                },
                informational: {
                  $sum: { $cond: [{ $eq: ["$urgency.normalized", "informational"] }, 1, 0] },
                },
                qualityWarnings: {
                  $sum: {
                    $cond: [
                      {
                        $or: [
                          "$extraction.organizationMismatch",
                          "$extraction.ipMismatch",
                          { $gt: [{ $size: { $ifNull: ["$extraction.warnings", []] } }, 0] },
                        ],
                      },
                      1,
                      0,
                    ],
                  },
                },
              },
            },
            {
              $project: {
                _id: 0,
                total: 1,
                uniqueOrganizations: {
                  $size: {
                    $filter: {
                      input: "$organizations",
                      as: "item",
                      cond: { $and: [{ $ne: ["$$item", null] }, { $ne: ["$$item", ""] }] },
                    },
                  },
                },
                uniqueIps: {
                  $size: {
                    $filter: {
                      input: "$targetIps",
                      as: "item",
                      cond: { $and: [{ $ne: ["$$item", null] }, { $ne: ["$$item", ""] }] },
                    },
                  },
                },
                highCritical: 1,
                immediate: 1,
                actionRequired: 1,
                informational: 1,
                qualityWarnings: 1,
              },
            },
          ],
          byMonth: [
            { $group: { _id: "$month", count: { $sum: 1 } } },
            { $sort: { _id: 1 } },
            { $project: { _id: 0, month: "$_id", count: 1 } },
          ],
          byFinding: [
            { $group: { _id: "$finding.type", count: { $sum: 1 }, name: { $first: "$finding.name" }, category: { $first: "$finding.category" } } },
            { $sort: { count: -1, _id: 1 } },
            { $limit: 15 },
            { $project: { _id: 0, key: "$_id", name: { $ifNull: ["$name", "$_id"] }, category: 1, count: 1 } },
          ],
          byVulnerability: [
            { $match: { "vulnerability.normalizedName": { $nin: [null, "", "unknown"] } } },
            { $group: { _id: "$vulnerability.normalizedName", count: { $sum: 1 }, name: { $first: "$vulnerability.name" } } },
            { $sort: { count: -1, _id: 1 } },
            { $limit: 12 },
            { $project: { _id: 0, key: "$_id", name: { $ifNull: ["$name", "$_id"] }, count: 1 } },
          ],
          byReportType: [
            { $group: { _id: "$reportType", count: { $sum: 1 } } },
            { $sort: { count: -1, _id: 1 } },
            { $project: { _id: 0, reportType: "$_id", count: 1 } },
          ],
          bySeverity: [
            { $group: { _id: "$severity.level", count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $project: { _id: 0, severity: "$_id", count: 1 } },
          ],
          byUrgency: [
            { $group: { _id: "$urgency.normalized", count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $project: { _id: 0, urgency: "$_id", count: 1 } },
          ],
          topOrganizations: [
            { $match: { "target.organization": { $nin: [null, ""] } } },
            { $group: { _id: "$target.organization", count: { $sum: 1 } } },
            { $sort: { count: -1, _id: 1 } },
            { $limit: 10 },
            { $project: { _id: 0, organization: "$_id", count: 1 } },
          ],
          topIps: [
            { $match: { "target.ip": { $nin: [null, ""] } } },
            { $group: { _id: "$target.ip", count: { $sum: 1 } } },
            { $sort: { count: -1, _id: 1 } },
            { $limit: 10 },
            { $project: { _id: 0, ip: "$_id", count: 1 } },
          ],
          topPorts: [
            { $unwind: "$affectedSystems" },
            { $match: { "affectedSystems.port": { $ne: null } } },
            { $group: { _id: "$affectedSystems.port", count: { $sum: 1 } } },
            { $sort: { count: -1, _id: 1 } },
            { $limit: 10 },
            { $project: { _id: 0, port: "$_id", count: 1 } },
          ],
          repeated: [
            {
              $match: {
                "target.organization": { $nin: [null, ""] },
                "finding.type": { $nin: [null, "", "unknown"] },
              },
            },
            {
              $group: {
                _id: {
                  organization: "$target.organization",
                  finding: "$finding.type",
                },
                count: { $sum: 1 },
              },
            },
            { $match: { count: { $gt: 1 } } },
            { $group: { _id: null, repeatedGroups: { $sum: 1 }, reportsInRepeatedGroups: { $sum: "$count" } } },
            { $project: { _id: 0, repeatedGroups: 1, reportsInRepeatedGroups: 1 } },
          ],
        },
      },
    ]).exec();

    const summary = result.summary?.[0] || {
      total: 0,
      uniqueOrganizations: 0,
      uniqueIps: 0,
      highCritical: 0,
      immediate: 0,
      actionRequired: 0,
      informational: 0,
      qualityWarnings: 0,
    };

    return {
      year,
      summary: {
        ...summary,
        immediatePercent: percent(summary.immediate, summary.total),
        highCriticalPercent: percent(summary.highCritical, summary.total),
      },
      byMonth: result.byMonth || [],
      byFinding: result.byFinding || [],
      byVulnerability: result.byVulnerability || [],
      byReportType: result.byReportType || [],
      bySeverity: result.bySeverity || [],
      byUrgency: result.byUrgency || [],
      topOrganizations: result.topOrganizations || [],
      topIps: result.topIps || [],
      topPorts: result.topPorts || [],
      repeated: result.repeated?.[0] || { repeatedGroups: 0, reportsInRepeatedGroups: 0 },
    };
  }

  async list(input = {}) {
    const page = clampInt(input.page, 1, 100000, 1);
    const limit = clampInt(input.limit, 1, 100, 25);
    const filter = buildReportFilter(input);
    const sort = input.sort === "oldest" ? { year: 1, month: 1, day: 1, _id: 1 } : { year: -1, month: -1, day: -1, _id: -1 };

    const [reports, total] = await Promise.all([
      this.model.find(filter)
        .sort(sort)
        .skip((page - 1) * limit)
        .limit(limit)
        .lean()
        .exec(),
      this.model.countDocuments(filter).exec(),
    ]);

    return {
      reports,
      pagination: {
        page,
        limit,
        total,
        pages: total ? Math.ceil(total / limit) : 0,
      },
    };
  }

  async getById(id) {
    if (!id) return null;
    const query = /^[a-f\d]{24}$/i.test(String(id))
      ? { _id: id }
      : { documentKey: String(id) };
    return this.model.findOne(query).lean().exec();
  }
}

function buildReportFilter(input = {}) {
  const filter = {};
  if (input.year !== undefined && input.year !== null && input.year !== "") filter.year = normalizeYear(input.year);
  if (input.month) filter.month = clampInt(input.month, 1, 12, 1);
  if (input.severity) filter["severity.level"] = String(input.severity).toLowerCase();
  if (input.urgency) filter["urgency.normalized"] = String(input.urgency).toLowerCase();
  if (input.reportType) filter.reportType = String(input.reportType).toLowerCase();
  if (input.finding) filter["finding.type"] = String(input.finding).toLowerCase();
  if (input.vulnerability) filter["vulnerability.normalizedName"] = String(input.vulnerability).toLowerCase();
  if (input.organization) filter["target.organization"] = { $regex: escapeRegex(input.organization), $options: "i" };
  if (input.cve) filter.cves = String(input.cve).toUpperCase();
  if (input.port) filter["affectedSystems.port"] = clampInt(input.port, 0, 65535, 0);
  if (input.ip) {
    const ip = String(input.ip).trim();
    filter.$or = [{ "target.ip": ip }, { "affectedSystems.ip": ip }];
  }
  if (input.search) {
    const regex = { $regex: escapeRegex(String(input.search).trim()), $options: "i" };
    const searchOr = [
      { title: regex },
      { reportNumber: regex },
      { "target.organization": regex },
      { "target.ip": regex },
      { "finding.name": regex },
      { "vulnerability.name": regex },
      { description: regex },
      { conclusion: regex },
      { cves: regex },
      { "affectedSystems.domain": regex },
      { "affectedSystems.service": regex },
    ];
    if (filter.$or) filter.$and = [{ $or: filter.$or }, { $or: searchOr }], delete filter.$or;
    else filter.$or = searchOr;
  }
  return filter;
}

function percent(numerator, denominator) {
  const top = Number(numerator || 0);
  const bottom = Number(denominator || 0);
  if (!bottom) return 0;
  return Math.round((top / bottom) * 1000) / 10;
}

function clampInt(value, min, max, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function escapeRegex(value) {
  return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

module.exports = {
  ReportAnalyticsService,
  buildReportFilter,
  percent,
  clampInt,
};
