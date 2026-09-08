const mongoose = require("mongoose");

const { Schema } = mongoose;

const endpointSchema = new Schema(
  {
    ip: { type: String, trim: true },
    port: { type: Number, min: 0, max: 65535 },
    fqdn: { type: String, trim: true },
    asn: { type: Number, min: 0 },
    asName: { type: String, trim: true },
    orgEnName: { type: String, trim: true },
    orgFaName: { type: String, trim: true },
    orgFullName: { type: String, trim: true },
    orgType: { type: String, trim: true },
    geo: {
      country: { type: String, trim: true },
      city: { type: String, trim: true },
      latitude: Number,
      longitude: Number,
    },
  },
  { _id: false, minimize: false },
);

const threatIntelObservationSchema = new Schema(
  {
    importId: { type: String, required: true, trim: true },
    uniqueId: { type: String, required: true, trim: true },
    provider: { type: String, trim: true },
    feedName: { type: String, trim: true },
    classification: {
      identifier: { type: String, trim: true },
      taxonomy: { type: String, trim: true },
      type: { type: String, trim: true },
    },
    malwareName: { type: String, trim: true },
    protocol: { type: String, trim: true, lowercase: true },
    source: { type: endpointSchema, default: () => ({}) },
    destination: { type: endpointSchema, default: () => ({}) },
    sourceTime: Date,
    observationTime: Date,
  },
  { timestamps: true, minimize: false },
);

threatIntelObservationSchema.index({ importId: 1, uniqueId: 1 }, { unique: true });
threatIntelObservationSchema.index({ importId: 1, "source.ip": 1, sourceTime: -1 });
threatIntelObservationSchema.index({ importId: 1, "destination.ip": 1, sourceTime: -1 });
threatIntelObservationSchema.index({
  importId: 1,
  "destination.ip": 1,
  "destination.port": 1,
  protocol: 1,
  sourceTime: -1,
});
threatIntelObservationSchema.index({
  importId: 1,
  "source.ip": 1,
  "destination.ip": 1,
  "destination.port": 1,
  protocol: 1,
});

module.exports =
  mongoose.models.ThreatIntelObservation ||
  mongoose.model("ThreatIntelObservation", threatIntelObservationSchema);
