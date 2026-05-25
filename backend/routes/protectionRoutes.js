const express = require("express");
const router = express.Router();

const apiKeyAuth = require("../middleware/apiKeyAuth");
const behaviorScanner = require("../middleware/behaviorScanner"); // Behavioral scans
const securityScanner = require("../middleware/securityScanner"); // Security scans for SQLi/XSS
const { loginAttempt, otpRequest } = require("../controllers/protectionController");

// ================= PROTECTION API =================

// Standard Endpoint (called by existing clients)
router.post("/login-attempt", apiKeyAuth, behaviorScanner, securityScanner, loginAttempt);

// OTP tracking endpoint
router.post("/otp-request", apiKeyAuth, otpRequest);

module.exports = router;