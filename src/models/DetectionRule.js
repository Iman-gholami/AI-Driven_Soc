const mongoose = require("mongoose");

const { Schema } = mongoose;

const detectionRuleSchema = new Schema(
  {
    ruleId: { type: String, required: true, trim: true },
    action: { type: String, default: "alert", trim: true, lowercase: true },
    revision: { type: Number, required: true, min: 0 },
    title: { type: String, required: true, trim: true },
    normalizedTitle: { type: String, required: true, trim: true },
    classtype: { type: String, trim: true },
    protocol: { type: String, trim: true, lowercase: true },
    src: { type: String, trim: true },
    srcPort: { type: String, trim: true },
    direction: { type: String, trim: true },
    dst: { type: String, trim: true },
    dstPort: { type: String, trim: true },
    sourceContents: { type: [String], default: [] },
    sourcePcre: { type: String, default: undefined },
    rawRule: { type: String, required: true },
    sourceFile: { type: String, trim: true },
    parsedRule: { type: Schema.Types.Mixed, default: () => ({}) },
  },
  {
    timestamps: true,
    minimize: false,
  },
);

detectionRuleSchema.index({ ruleId: 1, revision: 1 }, { unique: true });
detectionRuleSchema.index({ title: 1 });
detectionRuleSchema.index({ normalizedTitle: 1 });
detectionRuleSchema.index({ protocol: 1 });
detectionRuleSchema.index({ sourceFile: 1 });

module.exports = mongoose.models.DetectionRule || mongoose.model("DetectionRule", detectionRuleSchema);
