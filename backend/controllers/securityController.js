const EmailAction = require("../models/smartlogin/EmailAction");
const AttackLog = require("../models/smartlogin/AttackLog");
const BlockedIP = require("../models/smartlogin/BlockedIP");
const Website = require("../models/threatguard/Website");
const WebsiteUser = require("../models/smartlogin/WebsiteUser");
const TrustedDevice = require("../models/smartlogin/TrustedDevice");
const jwt = require("jsonwebtoken");

// ================= HELPER =================
const getUserWebsiteIds = async (userId) => {
  const websites = await Website.find({ ownerId: userId });
  return websites.map((w) => w._id);
};

// ================= IT WAS ME =================
exports.itWasMe = async (req, res) => {
  try {
    const { token } = req.query;

    const action = await EmailAction.findOne({ token });

    if (!action) {
      return res.send("❌ Invalid or expired link.");
    }

    await AttackLog.updateMany(
      {
        email: action.email,
        status: "failed"
      },
      {
        actionTaken: "user-confirmed"
      }
    );

    await EmailAction.deleteOne({ token });

    res.send("✅ Login confirmed.");

  } catch (err) {
    console.error(err);
    res.send("❌ Server error.");
  }
};

// ================= BLOCK IP =================
exports.blockIP = async (req, res) => {
  try {
    const { token } = req.query;
    const { ip: bodyIp, websiteId: bodyWebsiteId } = req.body;
    
    let targetIp, targetWebsiteId, ownerId;

    if (token) {
      const action = await EmailAction.findOne({ token });
      if (!action) return res.send("❌ Invalid or expired link.");
      targetIp = action.ip;
      targetWebsiteId = action.websiteId;
      ownerId = action.ownerId;
      await EmailAction.deleteOne({ token });
    } else {
      // Dashboard manual block
      targetIp = bodyIp || req.query.ip;
      targetWebsiteId = bodyWebsiteId || req.query.websiteId;
      
      if (!targetIp || !targetWebsiteId) {
        return res.status(400).json({ message: "IP and Website ID are required." });
      }

      const website = await Website.findById(targetWebsiteId);
      ownerId = website?.ownerId;
    }

    console.log("Blocking IP:", targetIp);

    const blockedUntil = new Date(
      Date.now() + 24 * 60 * 60 * 1000
    );

    await BlockedIP.create({
      ownerId,
      websiteId: targetWebsiteId,
      ip: targetIp,
      reason: "Manual block",
      blockedUntil
    });

    await AttackLog.updateMany(
      { ip: targetIp, websiteId: targetWebsiteId },
      { actionTaken: "ip-blocked" }
    );

    // Emit socket event for instant UI refresh
    const io = req.app.get("io");
    if (io && ownerId) {
      console.log("Emitting dashboard_refresh to owner:", ownerId);
      io.to(ownerId.toString()).emit("dashboard_refresh");
    }

    if (token) {
      res.send("🚫 IP blocked for 24 hours.");
    } else {
      res.json({ message: "IP blocked successfully" });
    }

  } catch (err) {
    console.error("Block IP error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= ATTACK MAP =================
exports.getAttackMap = async (req, res) => {
  try {
    const websiteIds = await getUserWebsiteIds(req.user.id);

    const attacks = await AttackLog.find({
      websiteId: { $in: websiteIds },
      "location.latitude": { $ne: 0 },
      "location.longitude": { $ne: 0 }
    })
      .sort({ createdAt: -1 })
      .limit(100);

    const mapData = attacks.map((attack) => ({
      _id: attack._id,
      ip: attack.ip,
      country: attack.location?.country || "Unknown",
      state: attack.location?.state || "Unknown",
      city: attack.location?.city || "Unknown",
      latitude: attack.location?.latitude || 0,
      longitude: attack.location?.longitude || 0,
      isp: attack.location?.isp || "Unknown",
      timezone: attack.location?.timezone || "Unknown",
      attackType: attack.attackType,
      severity: attack.severity,
      status: attack.status,
      createdAt: attack.createdAt
    }));

    res.json(mapData);

  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= ATTACK TIMELINE =================
exports.getAttackTimeline = async (req, res) => {
  try {
    const websiteIds = await getUserWebsiteIds(req.user.id);

    const timeline = await AttackLog.aggregate([
      {
        $match: {
          websiteId: { $in: websiteIds },
          status: "failed",
          attackType: {
            $in: ["Failed Login", "Brute Force Attack", "Credential Stuffing", "Password Spraying"]
          }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%H:%M", date: "$createdAt" }
          },
          count: { $sum: 1 }
        }
      },
      {
        $project: {
          _id: 0,
          time: "$_id",
          count: 1
        }
      },
      { $sort: { time: 1 } }
    ]);

    res.json(timeline);

  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= LOGIN HISTORY =================
exports.getLoginHistory = async (req, res) => {
  try {
    const websiteIds = await getUserWebsiteIds(req.user.id);

    const { type } = req.query;
    const query = { websiteId: { $in: websiteIds } };
    
    if (type === "attacks") {
      query.attackType = { $nin: ["none", "Failed Login"] };
      query.status = { $ne: "success" };
    }

    const history = await AttackLog.find(query)
      .sort({ createdAt: -1 })
      .limit(50);

    const data = history.map((log) => ({
      userId: log.userId,
      ip: log.ip,
      country: log.location?.country || "Unknown",
      state: log.location?.state || "Unknown",
      city: log.location?.city || "Unknown",
      latitude: log.location?.latitude || 0,
      longitude: log.location?.longitude || 0,
      attackType: log.attackType,
      severity: log.severity,
      status: log.status,
      createdAt: log.createdAt
    }));

    res.json(data);

  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= BLOCKED IPS =================
exports.getBlockedIPs = async (req, res) => {
  try {
    const websiteIds = await getUserWebsiteIds(req.user.id);

    const blocked = await BlockedIP.find({
      websiteId: { $in: websiteIds }
    }).sort({ createdAt: -1 });

    const data = blocked.map((b) => ({
      _id: b._id,
      ip: b.ip,
      reason: b.reason,
      blockedUntil: b.blockedUntil,
      createdAt: b.createdAt
    }));

    res.json(data);

  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= SECURITY STATS =================
exports.getSecurityStats = async (req, res) => {
  try {
    const websiteIds = await getUserWebsiteIds(req.user.id);

    // const totalAttacks =
    //   await AttackLog.countDocuments({
    //     websiteId: { $in: websiteIds },
    //     status: { $in: ["failed", "blocked"] }
    //   });
    const totalAttacks =
      await AttackLog.countDocuments({
        websiteId: { $in: websiteIds },
        attackType: {
          $ne: "none"
        },
        status: { $ne: "success" }
      });

    const threatCount =
      await AttackLog.countDocuments({
        websiteId: { $in: websiteIds },
        attackType: {
          $nin: ["none", "Failed Login"]
        },
        status: { $ne: "success" }
      });

    const successfulLogins =
      await AttackLog.countDocuments({
        websiteId: { $in: websiteIds },
        status: "success"
      });

    const blockedIPs =
      await BlockedIP.countDocuments({
        websiteId: { $in: websiteIds }
      });

    res.json({
      totalAttacks,
      threatCount,
      successfulLogins,
      blockedIPs
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= SECURITY SCORE =================
exports.getSecurityScore = async (req, res) => {
  try {
    const websiteIds = await getUserWebsiteIds(req.user.id);

    // const totalAttacks =
    //   await AttackLog.countDocuments({
    //     websiteId: { $in: websiteIds },
    //     status: "failed"
    //   });
    const totalAttacks =
      await AttackLog.countDocuments({
        websiteId: { $in: websiteIds },
        attackType: {
          $ne: "none"
        },
        status: { $ne: "success" }
      });

    const threatCount =
      await AttackLog.countDocuments({
        websiteId: { $in: websiteIds },
        attackType: {
          $nin: ["none", "Failed Login"]
        },
        status: { $ne: "success" }
      });

    const blockedIPs =
      await BlockedIP.countDocuments({
        websiteId: { $in: websiteIds }
      });

    const criticalAttacks =
      await AttackLog.countDocuments({
        websiteId: { $in: websiteIds },
        severity: "CRITICAL"
      });

    const successfulLogins =
      await AttackLog.countDocuments({
        websiteId: { $in: websiteIds },
        status: "success"
      });

    let score = 100;

    score -= totalAttacks * 1;
    score -= blockedIPs * 2;
    score -= criticalAttacks * 5;

    if (score < 0) score = 0;

    res.json({
      securityScore: score,
      totalAttacks,
      threatCount,
      blockedIPs,
      criticalAttacks,
      successfulLogins
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= UNBLOCK IP =================
exports.unblockIP = async (req, res) => {
  try {
    const { ip } = req.body;

    if (!ip) {
      return res.status(400).json({
        message: "IP required"
      });
    }

    await BlockedIP.deleteMany({ ip });

    res.json({
      message: `IP ${ip} unblocked successfully`
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= AI EXPLANATION =================
exports.getAIExplanation = async (req, res) => {
  try {
    const { logId } = req.params;

    const log = await AttackLog.findById(logId);

    if (!log) {
      return res.status(404).json({
        message: "Attack log not found"
      });
    }

    res.json({
      logId: log._id,
      attackType: log.attackType,
      severity: log.severity,
      explanation: `Threat detected from IP ${log.ip}`,
      mitigation: "Keep monitoring and maintain rate limiting.",
      generatedAt: new Date()
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= GLOBAL STATS =================
exports.getGlobalStats = async (req, res) => {
  try {
    const totalWebsites =
      await Website.countDocuments();

    const totalAttacks =
      await AttackLog.countDocuments();

    const totalBlockedIPs =
      await BlockedIP.countDocuments();

    res.json({
      totalWebsites,
      totalAttacks,
      totalBlockedIPs
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= WEBSITE USERS =================
exports.getWebsiteUsers = async (req, res) => {
  try {
    const { websiteId } = req.params;
    
    // Ensure the website belongs to the owner
    const websites = await getUserWebsiteIds(req.user.id);
    if (!websites.some(id => id.toString() === websiteId)) {
      return res.status(403).json({ message: "Access denied." });
    }

    const users = await WebsiteUser.find({ websiteId }).sort({ lastLogin: -1 });
    res.json(users);
  } catch (err) {
    console.error("Fetch website users failed:", err);
    res.status(500).json({ message: "Server error" });
  }
};

exports.getWebsiteUserByEmail = async (req, res) => {
  try {
    const { websiteId, email } = req.params;

    const websites = await getUserWebsiteIds(req.user.id);
    if (!websites.some(id => id.toString() === websiteId)) {
      return res.status(403).json({ message: "Access denied." });
    }

    const user = await WebsiteUser.findOne({ websiteId, email });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }
    
    res.json(user);
  } catch (err) {
    console.error("Fetch website user failed:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= CONFIRM SAFE (BEHAVIORAL) =================
exports.confirmSafe = async (req, res) => {
  try {
    const { token } = req.params;
    let decoded;
    
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(400).send(`
        <div style="text-align:center; padding: 50px; font-family: Arial;">
          <h2>❌ Link Expired or Invalid</h2>
          <p>This security link has expired or is no longer valid.</p>
        </div>
      `);
    }

    const { email, ip, websiteId, deviceFingerprint } = decoded;

    // 1. Delete all failed/suspicious AttackLogs for this user/IP
    await AttackLog.deleteMany({ email, ip, websiteId });

    // 2. Remove blocked IP records
    await BlockedIP.deleteMany({ ip, websiteId });

    // 3. Reset WebsiteUser counters and update trusted info
    await WebsiteUser.updateOne(
      { email, websiteId },
      { 
        $set: { 
          failedLogins: 0, 
          attackCount: 0,
          lastIp: ip,
          lastLoginAt: new Date()
        } 
      }
    );

    // 4. Save current device as trusted if fingerprint exists
    if (deviceFingerprint && deviceFingerprint !== "unknown") {
      const existingTrusted = await TrustedDevice.findOne({ websiteId, deviceFingerprint });
      if (!existingTrusted) {
        await TrustedDevice.create({
          websiteId,
          deviceFingerprint,
          ipAddress: ip,
          userAgent: "Verified via Email Alert",
          lastUsedAt: new Date()
        });
      }
    }

    // 5. Emit socket event for dashboard refresh
    const website = await Website.findById(websiteId);
    const io = req.app.get("io");
    if (io && website?.ownerId) {
      io.to(website.ownerId.toString()).emit("dashboard_refresh");
    }

    res.send(`
      <div style="text-align:center; padding: 50px; font-family: Arial;">
        <h2 style="color: #10b981;">✅ Security Alert Resolved</h2>
        <p>Thank you for confirming. We have marked this activity as safe.</p>
        <p>Your account is fully restored and you can now log in normally.</p>
      </div>
    `);

  } catch (err) {
    console.error("Confirm safe error:", err);
    res.status(500).send("❌ Server error.");
  }
};

// ================= REPORT THREAT (BEHAVIORAL) =================
exports.reportThreat = async (req, res) => {
  try {
    const { token } = req.params;
    let decoded;
    
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(400).send(`
        <div style="text-align:center; padding: 50px; font-family: Arial;">
          <h2>❌ Link Expired or Invalid</h2>
          <p>This security link has expired or is no longer valid.</p>
        </div>
      `);
    }

    const { attackLogId, email, ip, websiteId } = decoded;
    const blockedUntil = new Date(Date.now() + 24 * 60 * 60 * 1000);

    // 1. Create blocked IP entry (avoid duplicates)
    const website = await Website.findById(websiteId);
    const ownerId = website?.ownerId;

    await BlockedIP.findOneAndUpdate(
      { ip, websiteId },
      {
        ip,
        websiteId,
        ownerId,
        reason: "User confirmed malicious login",
        blockedUntil
      },
      { upsert: true, new: true }
    );

    console.log("Blocked malicious IP:", ip);
    console.log("Blocked until:", blockedUntil);

    // 2. Escalate AttackLog severity to CRITICAL
    if (attackLogId) {
      await AttackLog.updateOne(
        { _id: attackLogId },
        { severity: "CRITICAL", actionTaken: "user-reported-threat" }
      );
    }

    // 3. Emit socket refresh event after saving
    const io = req.app.get("io");
    if (io && ownerId) {
      io.to(ownerId.toString()).emit("dashboard_refresh");
    }

    res.send(`
      <div style="text-align:center; padding: 50px; font-family: Arial;">
        <h2 style="color: #dc2626;">🚨 Threat Reported</h2>
        <p>Thank you for reporting this. We have escalated the severity of this incident.</p>
        <p>The originating IP address will remain restricted.</p>
      </div>
    `);

  } catch (err) {
    console.error("Report threat error:", err);
    res.status(500).send("❌ Server error.");
  }
};