const ThreatIntelObservation = require("../models/ThreatIntelObservation");
const IntelDatasetState = require("../models/IntelDatasetState");

class ThreatIntelRepository {
  constructor({
    observationModel = ThreatIntelObservation,
    stateModel = IntelDatasetState,
    stateTtlMs = 30000,
  } = {}) {
    this.observationModel = observationModel;
    this.stateModel = stateModel;
    this.stateTtlMs = stateTtlMs;
    this.stateCache = null;
  }

  async getActiveState() {
    const now = Date.now();
    if (this.stateCache && now - this.stateCache.loadedAt < this.stateTtlMs) {
      return this.stateCache.value;
    }

    const value = await this.stateModel
      .findOne({ dataset: "threat_intel" })
      .lean()
      .exec();

    this.stateCache = { value, loadedAt: now };
    return value;
  }

  invalidateStateCache() {
    this.stateCache = null;
  }

  async lookupIp(ip, { limit = 12 } = {}) {
    const state = await this.getActiveState();
    if (!state?.activeImportId) {
      return {
        status: "not_configured",
        dataset: null,
        direct: { count: 0, evidence: [] },
        relationship: { count: 0, evidence: [] },
      };
    }

    const filter = { importId: state.activeImportId };
    const safeLimit = Math.min(Math.max(Number(limit) || 12, 1), 50);

    const [directCount, relationshipCount, directEvidence, relationshipEvidence] = await Promise.all([
      this.observationModel.countDocuments({ ...filter, "source.ip": ip }),
      this.observationModel.countDocuments({ ...filter, "destination.ip": ip }),
      this.observationModel
        .find({ ...filter, "source.ip": ip })
        .sort({ sourceTime: -1, observationTime: -1 })
        .limit(safeLimit)
        .lean()
        .exec(),
      this.observationModel
        .find({ ...filter, "destination.ip": ip })
        .sort({ sourceTime: -1, observationTime: -1 })
        .limit(safeLimit)
        .lean()
        .exec(),
    ]);

    return {
      status: "available",
      dataset: {
        importId: state.activeImportId,
        sourceFile: state.sourceFile || null,
        checksumSha256: state.checksumSha256 || null,
        recordCount: Number(state.recordCount || 0),
        importedAt: state.importedAt || null,
      },
      direct: { count: Number(directCount || 0), evidence: directEvidence },
      relationship: { count: Number(relationshipCount || 0), evidence: relationshipEvidence },
    };
  }

  async findFlowMatches({
    sourceIp,
    destinationIp,
    destinationPort,
    protocol,
    limit = 8,
  } = {}) {
    if (!sourceIp || !destinationIp) return [];

    const state = await this.getActiveState();
    if (!state?.activeImportId) return [];

    const filter = {
      importId: state.activeImportId,
      "source.ip": sourceIp,
      "destination.ip": destinationIp,
    };

    if (Number.isInteger(destinationPort)) {
      filter["destination.port"] = destinationPort;
    }
    if (protocol) {
      filter.protocol = String(protocol).toLowerCase();
    }

    return this.observationModel
      .find(filter)
      .sort({ sourceTime: -1, observationTime: -1 })
      .limit(Math.min(Math.max(Number(limit) || 8, 1), 20))
      .lean()
      .exec();
  }
}

module.exports = { ThreatIntelRepository };
