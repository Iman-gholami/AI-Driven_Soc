const mongoose = require('mongoose');

const { Schema } = mongoose;

const alertResolutionSchema = new Schema(
  {
    alertRef: {
      type: Schema.Types.ObjectId,
      ref: 'Alert',
      required: true,
      unique: true,
      index: true,
    },
    alertId: { type: String, required: true, trim: true, index: true },
    outcome: {
      type: String,
      required: true,
      enum: ['true_positive', 'benign_true_positive', 'false_positive', 'inconclusive'],
      trim: true,
    },
    note: { type: String, default: undefined, trim: true, maxlength: 2000 },
    ticketNumber: { type: String, default: undefined, trim: true, maxlength: 128 },
    resolvedAt: { type: Date, required: true, default: Date.now },
    resolvedBy: {
      id: { type: String, required: true, trim: true, maxlength: 200 },
      displayName: { type: String, required: true, trim: true, maxlength: 200 },
    },
  },
  {
    timestamps: true,
    minimize: false,
  },
);

alertResolutionSchema.index({ outcome: 1, resolvedAt: -1 });

module.exports =
  mongoose.models.AlertResolution || mongoose.model('AlertResolution', alertResolutionSchema);
