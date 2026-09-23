const mongoose = require('mongoose');
const { EVENT_TYPES, ACTOR_KINDS } = require('../investigation/eventSchemas');

const { Schema } = mongoose;

const actorSchema = new Schema(
  {
    kind: { type: String, enum: ACTOR_KINDS, required: true },
    id: { type: String, required: true },
    displayName: { type: String, required: true },
  },
  { _id: false },
);

const analysisRefSchema = new Schema(
  {
    analysisIndex: { type: Number, required: true, min: 0 },
    analyzedAt: { type: Date, required: true },
    fingerprint: { type: String, required: true },
  },
  { _id: false },
);

const contextSchema = new Schema(
  {
    // Exact analysis the event refers to, and the AI output captured from it at write time.
    analysisRef: { type: analysisRefSchema, default: null },
    analysisSnapshot: { type: Schema.Types.Mixed, default: null },
    // Detection rule on the alert when the event was written.
    rule: { type: Schema.Types.Mixed, default: null },
  },
  { _id: false, minimize: false },
);

// Append-only investigation history. Payloads are validated with Zod (src/investigation/eventSchemas.js)
// before insert; corrections are new events, never edits.
const investigationEventSchema = new Schema(
  {
    alertRef: { type: Schema.Types.ObjectId, ref: 'Alert', required: true },
    alertId: { type: String, required: true },
    schemaVersion: { type: Number, required: true },
    type: { type: String, enum: EVENT_TYPES, required: true },
    sequence: { type: Number, required: true, min: 1 },
    createdAt: { type: Date, required: true },
    actor: { type: actorSchema, required: true },
    payload: { type: Schema.Types.Mixed, required: true },
    context: { type: contextSchema, default: () => ({}) },
    idempotencyKey: { type: String, required: true },
    requestHash: { type: String, required: true },
  },
  {
    collection: 'investigation_events',
    timestamps: false,
    versionKey: false,
    minimize: false,
    strict: 'throw',
  },
);

// Total order per alert, one event per idempotency key per alert.
investigationEventSchema.index({ alertRef: 1, sequence: 1 }, { unique: true });
investigationEventSchema.index({ alertRef: 1, idempotencyKey: 1 }, { unique: true });
investigationEventSchema.index({ alertRef: 1, type: 1, sequence: -1 });
investigationEventSchema.index({ type: 1, 'actor.kind': 1, createdAt: 1 });

function rejectMutation() {
  throw new Error('Investigation events are append-only and cannot be updated or deleted');
}

investigationEventSchema.pre(
  [
    'updateOne',
    'updateMany',
    'findOneAndUpdate',
    'findOneAndReplace',
    'replaceOne',
    'findOneAndDelete',
    'deleteMany',
  ],
  rejectMutation,
);
investigationEventSchema.pre('deleteOne', { document: true, query: true }, rejectMutation);
investigationEventSchema.pre('save', function rejectResave() {
  if (!this.isNew) rejectMutation();
});

module.exports =
  mongoose.models.InvestigationEvent || mongoose.model('InvestigationEvent', investigationEventSchema);
