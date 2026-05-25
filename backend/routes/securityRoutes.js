const express = require("express");
const jwtAuth = require("../middleware/jwtAuth");

const {
  itWasMe,
  blockIP,
  getAttackMap,
  getAttackTimeline,
  getLoginHistory,
  getBlockedIPs,
  getSecurityStats,
  getSecurityScore,
  unblockIP,
  getAIExplanation,
  getGlobalStats,
  getWebsiteUsers,
  getWebsiteUserByEmail,
  confirmSafe,
  reportThreat
} = require("../controllers/securityController");

const router = express.Router();

// Email action links (no auth — from email links)
router.get("/it-was-me", itWasMe);
router.get("/block-ip", blockIP);
router.get("/confirm-safe/:token", confirmSafe);
router.get("/report-threat/:token", reportThreat);

// Dashboard APIs — JWT protected
router.get("/attack-map", jwtAuth, getAttackMap);
router.get("/attack-timeline", jwtAuth, getAttackTimeline);
router.get("/login-history", jwtAuth, getLoginHistory);
router.get("/blocked-ips", jwtAuth, getBlockedIPs);
router.get("/security-stats", jwtAuth, getSecurityStats);
router.get("/security-score", jwtAuth, getSecurityScore);
router.post("/unblock-ip", jwtAuth, unblockIP);

router.get("/explain-attack/:logId", jwtAuth, getAIExplanation);
router.get("/global-stats", jwtAuth, getGlobalStats);

// Website Users APIs
router.get("/website-users/:websiteId", jwtAuth, getWebsiteUsers);
router.get("/website-user/:websiteId/:email", jwtAuth, getWebsiteUserByEmail);

module.exports = router;