const mongoose = require('mongoose');

const ruleSchema = new mongoose.Schema(
  {
    ruleId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    action: {
      type: String,
      required: true,
      lowercase: true,
      enum: ['alert', 'drop', 'pass', 'reject', 'log'],
    },
    revision: {
      type: Number,
      default: 0,
    },
    title: {
      type: String,
      required: true,
      trim: true,
    },
    normalizedTitle: {
      type: String,
      required: true,
      index: true,
    },
    classtype: {
      type: String,
      trim: true,
    },
    protocol: {
      type: String,
      lowercase: true,
      trim: true,
    },
    src: {
      type: String,
      trim: true,
    },
    srcPort: {
      type: String,
      trim: true,
    },
    direction: {
      type: String,
      trim: true,
    },
    dst: {
      type: String,
      trim: true,
    },
    dstPort: {
      type: String,
      trim: true,
    },
    sourceContents: [
      {
        type: String,
      },
    ],
    sourcePcre: {
      type: String,
    },
    rawRule: {
      type: String,
      required: true,
    },
    sourceFile: {
      type: String,
      trim: true,
    },
    parsedRule: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
  },
);

// Compound index for faster lookups
ruleSchema.index({ ruleId: 1, revision: -1 });
ruleSchema.index({ normalizedTitle: 'text' });

module.exports = mongoose.model('Rule', ruleSchema);
