const mongoose = require("mongoose");

const { Schema } = mongoose;

const intelDatasetStateSchema = new Schema(
  {
    dataset: {
      type: String,
      required: true,
      trim: true,
      enum: ["asset_registry", "threat_intel"],
      unique: true,
    },
    activeImportId: { type: String, required: true, trim: true },
    sourceFile: { type: String, trim: true },
    checksumSha256: { type: String, trim: true },
    recordCount: { type: Number, default: 0, min: 0 },
    invalidCount: { type: Number, default: 0, min: 0 },
    importedAt: { type: Date, default: Date.now },
  },
  { timestamps: true, minimize: false },
);

module.exports =
  mongoose.models.IntelDatasetState ||
  mongoose.model("IntelDatasetState", intelDatasetStateSchema);
