const mongoose = require("mongoose");
const { slConnection } = require("../../config/db");

const WebsiteUserSchema = new mongoose.Schema(
  {
    websiteId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Website",
      required: true,
    },
    ownerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Owner",
      required: true,
    },
    email: {
      type: String,
      required: true,
    },
    name: {
      type: String,
      default: "Unknown",
    },
    totalLogins: {
      type: Number,
      default: 0,
    },
    successfulLogins: {
      type: Number,
      default: 0,
    },
    failedLogins: {
      type: Number,
      default: 0,
    },
    attackCount: {
      type: Number,
      default: 0,
    },
    attackTypes: [
      {
        type: String,
      },
    ],
    attackLocations: [
      {
        type: String,
      },
    ],
    lastLogin: {
      type: Date,
      default: Date.now,
    },
    lastAttackLocation: {
      type: String,
      default: "None",
    },
    lastIp: {
      type: String,
      default: null,
    },
    lastCountry: {
      type: String,
      default: null,
    },
    lastCity: {
      type: String,
      default: null,
    },
    lastDeviceFingerprint: {
      type: String,
      default: null,
    },
    lastLoginAt: {
      type: Date,
      default: null,
    }
  },
  { timestamps: true }
);

// Compound index for quick lookup and upserting per website
WebsiteUserSchema.index({ websiteId: 1, email: 1 }, { unique: true });

module.exports = slConnection.models.WebsiteUser || slConnection.model("WebsiteUser", WebsiteUserSchema);
