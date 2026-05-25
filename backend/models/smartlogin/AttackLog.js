const mongoose = require("mongoose");
const { slConnection } = require("../../config/db");

const attackLogSchema = new mongoose.Schema(
  {
    ownerId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    websiteId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    ip: {
      type: String,
      required: true,
    },
    location: {
      country: { type: String, default: "Unknown" },
      state: { type: String, default: "Unknown" },
      city: { type: String, default: "Unknown" },
      latitude: { type: Number, default: 0 },
      longitude: { type: Number, default: 0 },
      isp: { type: String, default: "Unknown" },
      timezone: { type: String, default: "Unknown" },
    },
    attackType: {
      type: String,
      required: true,
    },
    severity: {
      type: String,
      required: true,
      enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
      default: "LOW",
    },
    email: {
      type: String,
    },
    status: {
      type: String,
      enum: ["success", "failed", "blocked"],
    },
    reason: {
      type: String,
    },
    actionTaken: {
      type: String,
    },
    userAgent: {
      type: String,
    },
    payload: {
      type: mongoose.Schema.Types.Mixed,
      default: null,
    },
    timestamp: {
      type: Date,
      default: Date.now,
    }
  },
  { timestamps: true }
);

module.exports = slConnection.models.AttackLog || slConnection.model("AttackLog", attackLogSchema);
