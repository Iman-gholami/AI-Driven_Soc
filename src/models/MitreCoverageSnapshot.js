const mongoose = require("mongoose");

const { Schema } = mongoose;

const mitreCoverageSnapshotSchema = new Schema(
  {
    scopeTier: {
      type: String,
      required: true,
      enum: ["all", "native", "imported", "community"],
      default: "all",
    },
    generatedAt: { type: Date, required: true, default: Date.now },
    attackVersion: { type: String, default: undefined },
    summary: { type: Schema.Types.Mixed, required: true },
    tactics: { type: [Schema.Types.Mixed], default: [] },
    techniqueStats: { type: [Schema.Types.Mixed], default: [] },
  },
  {
    timestamps: true,
    minimize: false,
  },
);

mitreCoverageSnapshotSchema.index({ scopeTier: 1 }, { unique: true });

module.exports = mongoose.models.MitreCoverageSnapshot
  || mongoose.model("MitreCoverageSnapshot", mitreCoverageSnapshotSchema);
