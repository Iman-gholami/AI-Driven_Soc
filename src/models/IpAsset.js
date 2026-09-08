const mongoose = require("mongoose");

const { Schema } = mongoose;

const ipAssetSchema = new Schema(
  {
    importId: { type: String, required: true, trim: true },
    ip: { type: String, required: true, trim: true },
    bunit: { type: String, required: true, trim: true },
    category: { type: String, trim: true },
    province: { type: String, trim: true },
  },
  { timestamps: true, minimize: false },
);

ipAssetSchema.index({ importId: 1, ip: 1 }, { unique: true });
ipAssetSchema.index({ importId: 1, bunit: 1 });

module.exports = mongoose.models.IpAsset || mongoose.model("IpAsset", ipAssetSchema);
