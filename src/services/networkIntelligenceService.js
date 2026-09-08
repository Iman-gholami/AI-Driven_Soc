const { settings } = require("../core/config");
const { IpAssetRepository } = require("../repositories/IpAssetRepository");
const { ThreatIntelRepository } = require("../repositories/ThreatIntelRepository");
const { IpMetadataService } = require("./ipMetadataService");
const {
  extractIpIndicators,
  extractNetworkTuple,
} = require("./ipExtractor");

class NetworkIntelligenceService {
  constructor({
    assetRepository = new IpAssetRepository(),
    threatRepository = new ThreatIntelRepository(),
    ipMetadataService = new IpMetadataService(),
    evidenceLimit = settings.threatIntelEvidenceLimit,
    logger = null,
  } = {}) {
    this.assetRepository = assetRepository;
    this.threatRepository = threatRepository;
    this.ipMetadataService = ipMetadataService;
    this.evidenceLimit = Math.min(Math.max(Number(evidenceLimit) || 12, 1), 50);
    this.logger = logger;
  }

  async enrich(event = {}) {
    const indicators = extractIpIndicators(event);
    const tuple = extractNetworkTuple(event);
    const generatedAt = new Date().toISOString();

    if (indicators.length === 0) {
      return {
        status: "not_applicable",
        reason: "no_ipv4_indicators",
        generatedAt,
        tuple,
        ips: [],
        correlations: [],
      };
    }

    const [assetStateResult, threatStateResult] = await Promise.allSettled([
      this.assetRepository.getActiveState(),
      this.threatRepository.getActiveState(),
    ]);

    const assetState = assetStateResult.status === "fulfilled" ? assetStateResult.value : null;
    const threatState = threatStateResult.status === "fulfilled" ? threatStateResult.value : null;

    if (assetStateResult.status === "rejected") {
      this.logger?.warn?.({ err: assetStateResult.reason }, "Asset registry state lookup failed");
    }
    if (threatStateResult.status === "rejected") {
      this.logger?.warn?.({ err: threatStateResult.reason }, "Threat-intel state lookup failed");
    }

    const ips = await Promise.all(
      indicators.map((indicator) => this.enrichIndicator(indicator, { assetState, threatState })),
    );

    let flowMatches = [];
    if (threatState?.activeImportId && tuple.sourceIp && tuple.destinationIp) {
      try {
        flowMatches = await this.threatRepository.findFlowMatches({
          sourceIp: tuple.sourceIp,
          destinationIp: tuple.destinationIp,
          destinationPort: tuple.destinationPort,
          protocol: tuple.protocol,
          limit: 8,
        });
      } catch (error) {
        this.logger?.warn?.({ err: error }, "Threat-intel flow correlation failed");
      }
    }

    const correlations = buildCorrelations({ tuple, ips, flowMatches });
    const sourceStatuses = {
      assetRegistry: assetStateResult.status === "rejected"
        ? "unavailable"
        : assetState?.activeImportId
          ? "available"
          : "not_configured",
      threatIntel: threatStateResult.status === "rejected"
        ? "unavailable"
        : threatState?.activeImportId
          ? "available"
          : "not_configured",
      ipMetadata: summarizeMetadataSourceStatus(ips),
    };

    const unavailable = Object.values(sourceStatuses).filter((value) => value === "unavailable").length;
    const status = unavailable > 0 ? "partial" : "complete";

    return {
      status,
      generatedAt,
      tuple,
      sources: {
        ...sourceStatuses,
        assetDataset: assetState
          ? {
              sourceFile: assetState.sourceFile || null,
              recordCount: Number(assetState.recordCount || 0),
              importedAt: dateIso(assetState.importedAt),
            }
          : null,
        threatDataset: threatState
          ? {
              sourceFile: threatState.sourceFile || null,
              checksumSha256: threatState.checksumSha256 || null,
              recordCount: Number(threatState.recordCount || 0),
              importedAt: dateIso(threatState.importedAt),
            }
          : null,
      },
      ips,
      correlations,
    };
  }

  async enrichIndicator(indicator, { assetState, threatState }) {
    const assetPromise = assetState?.activeImportId
      ? this.assetRepository.findByIp(indicator.ip)
      : Promise.resolve(null);

    const threatPromise = threatState?.activeImportId
      ? this.threatRepository.lookupIp(indicator.ip, { limit: this.evidenceLimit })
      : Promise.resolve({
          status: "not_configured",
          direct: { count: 0, evidence: [] },
          relationship: { count: 0, evidence: [] },
        });

    const metadataPromise = indicator.scope === "public"
      ? this.ipMetadataService.lookup(indicator.ip)
      : Promise.resolve({ status: "not_applicable", provider: "ipinfo-mmdb" });

    const [assetResult, threatResult, metadataResult] = await Promise.allSettled([
      assetPromise,
      threatPromise,
      metadataPromise,
    ]);

    if (assetResult.status === "rejected") {
      this.logger?.warn?.({ err: assetResult.reason, ip: indicator.ip }, "Asset IP lookup failed");
    }
    if (threatResult.status === "rejected") {
      this.logger?.warn?.({ err: threatResult.reason, ip: indicator.ip }, "Threat IP lookup failed");
    }
    if (metadataResult.status === "rejected") {
      this.logger?.warn?.({ err: metadataResult.reason, ip: indicator.ip }, "IP metadata lookup failed");
    }

    const asset = assetResult.status === "fulfilled" ? assetResult.value : null;
    const threat = threatResult.status === "fulfilled"
      ? summarizeThreatLookup(threatResult.value)
      : {
          status: "unavailable",
          directMatch: false,
          relationshipMatch: false,
        };

    return {
      ip: indicator.ip,
      roles: indicator.roles,
      fields: indicator.fields,
      scope: indicator.scope,
      asset: {
        status: assetResult.status === "rejected"
          ? "unavailable"
          : assetState?.activeImportId
            ? "available"
            : "not_configured",
        owned: Boolean(asset),
        organization: asset?.bunit || null,
        category: asset?.category || null,
        province: asset?.province || null,
      },
      ipMetadata: metadataResult.status === "fulfilled"
        ? metadataResult.value
        : {
            status: "unavailable",
            provider: "ipinfo-mmdb",
            reason: "lookup_failed",
          },
      threat,
    };
  }
}

function summarizeThreatLookup(lookup = {}) {
  if (lookup.status !== "available") {
    return {
      status: lookup.status || "not_configured",
      directMatch: false,
      relationshipMatch: false,
      directObservationCount: 0,
      relationshipObservationCount: 0,
    };
  }

  const directEvidence = Array.isArray(lookup.direct?.evidence) ? lookup.direct.evidence : [];
  const relationshipEvidence = Array.isArray(lookup.relationship?.evidence)
    ? lookup.relationship.evidence
    : [];

  return {
    status: "available",
    dataset: lookup.dataset || null,
    directMatch: Number(lookup.direct?.count || 0) > 0,
    relationshipMatch: Number(lookup.relationship?.count || 0) > 0,
    directObservationCount: Number(lookup.direct?.count || 0),
    relationshipObservationCount: Number(lookup.relationship?.count || 0),
    direct: summarizeEvidence(directEvidence, "direct"),
    relationship: summarizeEvidence(relationshipEvidence, "relationship"),
  };
}

function summarizeEvidence(observations, mode) {
  if (!observations.length) return null;

  const providers = unique(observations.map((item) => item.provider));
  const malware = unique(observations.map((item) => item.malwareName));
  const classifications = uniqueObjects(
    observations.map((item) => compactObject({
      identifier: item.classification?.identifier,
      taxonomy: item.classification?.taxonomy,
      type: item.classification?.type,
    })),
  );

  const latestTimestamp = observations
    .map((item) => item.sourceTime || item.observationTime)
    .filter(Boolean)
    .map((value) => new Date(value))
    .filter((value) => !Number.isNaN(value.getTime()))
    .sort((a, b) => b.getTime() - a.getTime())[0];

  return {
    providers,
    malware,
    classifications,
    latestObservedAt: latestTimestamp ? latestTimestamp.toISOString() : null,
    evidence: observations.slice(0, 5).map((item) => mapEvidence(item, mode)),
  };
}

function mapEvidence(item, mode) {
  const base = {
    provider: item.provider || null,
    classification: compactObject({
      identifier: item.classification?.identifier,
      taxonomy: item.classification?.taxonomy,
      type: item.classification?.type,
    }),
    malware: item.malwareName || null,
    protocol: item.protocol || null,
    sourceTime: dateIso(item.sourceTime),
    observationTime: dateIso(item.observationTime),
  };

  if (mode === "direct") {
    return {
      ...base,
      observedRole: "source",
      destination: compactObject({
        ip: item.destination?.ip,
        port: item.destination?.port,
        fqdn: item.destination?.fqdn,
      }),
    };
  }

  return {
    ...base,
    observedRole: "destination",
    source: compactObject({
      ip: item.source?.ip,
      port: item.source?.port,
    }),
    destination: compactObject({
      port: item.destination?.port,
      fqdn: item.destination?.fqdn,
    }),
  };
}

function buildCorrelations({ tuple, ips, flowMatches }) {
  const correlations = [];

  if (Array.isArray(flowMatches) && flowMatches.length > 0) {
    const matchedFields = ["source.ip", "destination.ip"];
    if (tuple.destinationPort !== null) matchedFields.push("destination.port");
    if (tuple.protocol) matchedFields.push("protocol");

    correlations.push({
      type: "exact_feed_flow_match",
      strength: matchedFields.length >= 4 ? "very_high" : "high",
      matchedFields,
      observationCount: flowMatches.length,
      evidence: flowMatches.slice(0, 3).map((item) => mapEvidence(item, "direct")),
    });
  }

  for (const endpoint of ips) {
    if (endpoint.threat?.directMatch) {
      correlations.push({
        type: endpoint.asset?.owned
          ? "organizational_asset_with_direct_threat_evidence"
          : "direct_threat_ip_match",
        ip: endpoint.ip,
        roles: endpoint.roles,
        strength: "high",
        evidenceType: "feed_source_classification",
        classification: endpoint.threat.direct?.classifications || [],
        malware: endpoint.threat.direct?.malware || [],
        latestObservedAt: endpoint.threat.direct?.latestObservedAt || null,
      });
    }

    if (endpoint.threat?.relationshipMatch) {
      const matchedFields = ["ip"];
      const relationshipEvidence = endpoint.threat.relationship?.evidence || [];

      if (
        endpoint.roles.includes("destination") &&
        tuple.destinationPort !== null &&
        relationshipEvidence.some((item) => item.destination?.port === tuple.destinationPort)
      ) {
        matchedFields.push("destination.port");
      }

      if (
        tuple.protocol &&
        relationshipEvidence.some((item) => String(item.protocol || "").toLowerCase() === tuple.protocol)
      ) {
        matchedFields.push("protocol");
      }

      const isOwnedSourceToExternalThreatRelation =
        ips.some((candidate) => candidate.roles.includes("source") && candidate.asset?.owned) &&
        endpoint.roles.includes("destination") &&
        !endpoint.asset?.owned;

      correlations.push({
        type: isOwnedSourceToExternalThreatRelation
          ? "organizational_asset_to_threat_related_destination"
          : "threat_relationship_ip_match",
        ip: endpoint.ip,
        roles: endpoint.roles,
        strength: matchedFields.length >= 3 ? "high" : "moderate",
        evidenceType: "feed_destination_relationship",
        matchedFields,
        relatedMalware: endpoint.threat.relationship?.malware || [],
        latestObservedAt: endpoint.threat.relationship?.latestObservedAt || null,
      });
    }
  }

  return dedupeCorrelations(correlations);
}

function dedupeCorrelations(items) {
  const seen = new Set();
  return items.filter((item) => {
    const key = JSON.stringify([
      item.type,
      item.ip || null,
      item.strength,
      item.matchedFields || null,
    ]);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function summarizeMetadataSourceStatus(ips) {
  const statuses = ips.map((item) => item.ipMetadata?.status).filter(Boolean);
  if (statuses.includes("available")) return "available";
  if (statuses.includes("unavailable")) return "unavailable";
  if (statuses.includes("not_configured")) return "not_configured";
  return "not_applicable";
}

function compactObject(value) {
  return Object.fromEntries(
    Object.entries(value || {}).filter(([, item]) => item !== undefined && item !== null && item !== ""),
  );
}

function unique(values) {
  return [...new Set(values.filter((value) => value !== undefined && value !== null && value !== ""))];
}

function uniqueObjects(values) {
  const seen = new Set();
  return values.filter((value) => {
    if (!value || Object.keys(value).length === 0) return false;
    const key = JSON.stringify(value);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function dateIso(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

module.exports = {
  NetworkIntelligenceService,
  summarizeThreatLookup,
  buildCorrelations,
};
