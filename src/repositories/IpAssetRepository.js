const IpAsset = require("../models/IpAsset");
const IntelDatasetState = require("../models/IntelDatasetState");

class IpAssetRepository {
  constructor({
    assetModel = IpAsset,
    stateModel = IntelDatasetState,
    stateTtlMs = 0,
  } = {}) {
    this.assetModel = assetModel;
    this.stateModel = stateModel;
    this.stateTtlMs = stateTtlMs;
    this.stateCache = null;
  }

  async getActiveState() {
    const now = Date.now();
    if (
      this.stateTtlMs > 0 &&
      this.stateCache &&
      now - this.stateCache.loadedAt < this.stateTtlMs
    ) {
      return this.stateCache.value;
    }

    const value = await this.stateModel
      .findOne({ dataset: "asset_registry" })
      .lean()
      .exec();

    this.stateCache = { value, loadedAt: now };
    return value;
  }

  invalidateStateCache() {
    this.stateCache = null;
  }

  async findByIp(ip) {
    const state = await this.getActiveState();
    if (!state?.activeImportId) return null;

    return this.assetModel
      .findOne({ importId: state.activeImportId, ip })
      .lean()
      .exec();
  }
}

module.exports = { IpAssetRepository };
