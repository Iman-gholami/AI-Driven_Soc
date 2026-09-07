const mongoose = require("mongoose");

const { Schema } = mongoose;

const tacticSchema = new Schema(
  {
    id: { type: String, required: true, trim: true },
    name: { type: String, required: true, trim: true },
    shortName: { type: String, required: true, trim: true },
  },
  { _id: false },
);

const mitreTechniqueSchema = new Schema(
  {
    techniqueId: { type: String, required: true, unique: true, trim: true },
    stixId: { type: String, required: true, trim: true },
    name: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    tactics: { type: [tacticSchema], default: [] },
    platforms: { type: [String], default: [] },
    dataSources: { type: [String], default: [] },
    isSubTechnique: { type: Boolean, default: false },
    parentTechniqueId: { type: String, default: undefined, trim: true },
    replacementTechniqueId: { type: String, default: undefined, trim: true },
    revoked: { type: Boolean, default: false },
    deprecated: { type: Boolean, default: false },
    modified: { type: Date, default: undefined },
    attackVersion: { type: String, default: undefined, trim: true },
    sourceUrl: { type: String, default: undefined, trim: true },
  },
  {
    timestamps: true,
    minimize: false,
  },
);

mitreTechniqueSchema.index({ "tactics.id": 1 });
mitreTechniqueSchema.index({ isSubTechnique: 1 });
mitreTechniqueSchema.index({ revoked: 1, deprecated: 1 });
mitreTechniqueSchema.index({ replacementTechniqueId: 1 });

module.exports = mongoose.models.MitreTechnique || mongoose.model("MitreTechnique", mitreTechniqueSchema);
