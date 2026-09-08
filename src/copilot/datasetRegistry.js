const Alert = require("../models/Alert");
const DetectionRule = require("../models/DetectionRule");
const IpAsset = require("../models/IpAsset");
const ThreatIntelObservation = require("../models/ThreatIntelObservation");
const MitreTechnique = require("../models/MitreTechnique");
const IntelDatasetState = require("../models/IntelDatasetState");

function createDefaultDatasetRegistry({
  alertModel = Alert,
  detectionRuleModel = DetectionRule,
  ipAssetModel = IpAsset,
  threatIntelModel = ThreatIntelObservation,
  mitreTechniqueModel = MitreTechnique,
  stateModel = IntelDatasetState,
} = {}) {
  return {
    alerts: {
      model: alertModel,
      async getBaseContext() {
        return { match: {}, metadata: {} };
      },
    },
    detection_rules: {
      model: detectionRuleModel,
      async getBaseContext() {
        return { match: {}, metadata: {} };
      },
    },
    ip_assets: {
      model: ipAssetModel,
      async getBaseContext() {
        const state = await stateModel.findOne({ dataset: "asset_registry" }).lean().exec();
        if (!state?.activeImportId) {
          return {
            match: { _id: { $exists: false } },
            metadata: { snapshot: null, warning: "asset_registry_not_configured" },
          };
        }
        return {
          match: { importId: state.activeImportId },
          metadata: { snapshot: summarizeDatasetState(state) },
        };
      },
    },
    threat_intelligence: {
      model: threatIntelModel,
      async getBaseContext() {
        const state = await stateModel.findOne({ dataset: "threat_intel" }).lean().exec();
        if (!state?.activeImportId) {
          return {
            match: { _id: { $exists: false } },
            metadata: { snapshot: null, warning: "threat_intel_not_configured" },
          };
        }
        return {
          match: { importId: state.activeImportId },
          metadata: { snapshot: summarizeDatasetState(state) },
        };
      },
    },
    mitre_techniques: {
      model: mitreTechniqueModel,
      async getBaseContext() {
        return { match: {}, metadata: {} };
      },
    },
  };
}

function summarizeDatasetState(state) {
  return {
    dataset: state.dataset,
    activeImportId: state.activeImportId,
    sourceFile: state.sourceFile || null,
    recordCount: Number(state.recordCount || 0),
    importedAt: state.importedAt || null,
  };
}

module.exports = {
  createDefaultDatasetRegistry,
  summarizeDatasetState,
};
