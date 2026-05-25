const nodemailer = require("nodemailer");
const EmailAction = require("../models/smartlogin/EmailAction");
const jwt = require("jsonwebtoken");

// const BASE_URL = process.env.BASE_URL || "http://localhost:5000";
const BASE_URL = process.env.BASE_URL || "https://threadguard-backends-production.up.railway.app";

const sendSecurityAlert = async (
  userEmail,
  ip,
  location,
  attempts,
  ownerId,
  websiteId,
  device = "Unknown Device",
  isLocked = false,
  blockToken = "",
  resetToken = "",
  attackType = "Brute Force",
  attackLogId = null
) => {
  try {
    await EmailAction.create({
      email: userEmail,
      ownerId,
      websiteId,
      actionType: isLocked ? "block" : "warning",
      status: "sent",
      timestamp: new Date()
    });

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    // Generate JWT token before email render
    const tokenPayload = {
      attackLogId,
      email: userEmail,
      ip,
      websiteId,
      attackType,
      timestamp: new Date().getTime()
    };
    const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '15m' });
    console.log("Generated token:", token);

    const appBaseUrl = process.env.APP_BASE_URL || BASE_URL;
    const blockUrl = `${appBaseUrl}/api/security/report-threat/${token}`;
    const resetUrl = `${appBaseUrl}/api/security/confirm-safe/${token}`;

    const behavioralAttacks = [
      "Suspicious User-Agent",
      "New Device Login",
      "Location Change Detected",
      "Impossible Travel Detected",
      "OTP Abuse"
    ];
    const isBehavioral = behavioralAttacks.includes(attackType);

    let subject = isLocked
      ? `🚨 ThreatGuard: Account Locked (${attempts} Failed Attempts)`
      : `⚠️ ThreatGuard: Unrecognized Login Attempts`;

    let alertTitle = "ThreatGuard Security Alert";
    let alertMessage = "We've detected multiple failed login attempts on your account.";
    let attemptsLabel = "Attempts:";
    let attemptsValue = attempts;
    let severity = isLocked ? "HIGH" : "MEDIUM";

    if (isBehavioral) {
      subject = "Security Alert: Suspicious Activity Detected";
      alertTitle = "Suspicious Activity Detected";
      alertMessage = `We detected unusual activity (${attackType}) on your account.`;
      attemptsLabel = "Attack Type:";
      attemptsValue = attackType;
    } else if (attackType === "Password Spraying") {
      subject = "Password Spraying Attack Detected";
      alertTitle = "Password Spraying Detected";
      alertMessage = `A Password Spraying attack was detected from IP ${ip} targeting multiple accounts on your website.`;
      attemptsLabel = "Targeted Accounts:";
      severity = "HIGH";
    }

    const severityColor = severity === "CRITICAL" ? "#ff003c" : severity === "HIGH" ? "#ff8a00" : "#00f0ff";

    let htmlContent = `
      <div style="background-color: #0a0a0c; margin: 0; padding: 20px; font-family: 'Courier New', Courier, monospace; color: #e5e7eb; line-height: 1.5;">
        <div style="max-width: 600px; margin: 0 auto; border: 2px solid #00f0ff; border-radius: 4px; box-shadow: 0 0 15px rgba(0, 240, 255, 0.3); overflow: hidden; background-color: #111827;">
          
          <!-- Cyber Warning Header -->
          <div style="background-color: #ff003c; color: #fff; padding: 15px; text-align: center; font-weight: bold; letter-spacing: 2px; text-transform: uppercase; border-bottom: 2px solid #ff003c;">
            <span style="font-size: 18px;">⚠️ SECURITY BREACH DETECTED</span>
          </div>

          <div style="padding: 30px;">
            <div style="display: inline-block; padding: 4px 12px; border-radius: 2px; background-color: ${severityColor}; color: #000; font-weight: bold; font-size: 11px; margin-bottom: 20px; text-transform: uppercase;">
              THREAT_LEVEL: ${severity}
            </div>

            <h2 style="color: #00f0ff; margin-top: 0; font-size: 22px; border-bottom: 1px solid #1f2937; padding-bottom: 10px; text-transform: uppercase; letter-spacing: 1px;">
              ${alertTitle}
            </h2>
            
            <p style="color: #9ca3af; font-size: 14px; background: #0f172a; padding: 15px; border-left: 3px solid #00f0ff; margin: 20px 0;">
              ${alertMessage}
            </p>

            <!-- Attack Intelligence Card -->
            <div style="margin: 30px 0; background-color: #0a0a0c; border: 1px solid #1f2937; border-radius: 4px; padding: 20px; position: relative;">
              <div style="position: absolute; top: -10px; left: 10px; background: #111827; padding: 0 10px; color: #00f0ff; font-size: 10px; font-weight: bold;">
                [INTELLIGENCE_REPORT]
              </div>
              <table style="width: 100%; border-collapse: collapse; font-size: 13px; color: #d1d5db;">
                <tr>
                  <td style="padding: 10px; color: #6b7280; width: 40%;">💻 ${attemptsLabel}</td>
                  <td style="padding: 10px; color: #ff003c; font-weight: bold;">${attemptsValue}</td>
                </tr>
                <tr>
                  <td style="padding: 10px; color: #6b7280;">📍 ORIGIN_IP:</td>
                  <td style="padding: 10px; color: #00f0ff; font-weight: bold;"><code>${ip}</code></td>
                </tr>
                <tr>
                  <td style="padding: 10px; color: #6b7280;">🌍 LOCATION:</td>
                  <td style="padding: 10px;">${location.city || "Unknown"}, ${location.country || "Unknown"}</td>
                </tr>
                ${attackType === "Password Spraying"
        ? `<tr><td style="padding: 10px; color: #6b7280;">🔥 SEVERITY:</td><td style="padding: 10px; color: #ff003c; font-weight: bold;">${severity}</td></tr>`
        : !isLocked ? `<tr><td style="padding: 10px; color: #6b7280;">🛡 DEVICE_ID:</td><td style="padding: 10px;">${device}</td></tr>` : ""
      }
                <tr>
                  <td style="padding: 10px; color: #6b7280;">⏳ TIMESTAMP:</td>
                  <td style="padding: 10px;">${new Date().toLocaleString()}</td>
                </tr>
              </table>
            </div>
    `;

    if (isBehavioral) {
      htmlContent += `
          <div style="margin-top: 30px; text-align: center;">
            <a href="${resetUrl}" style="display: inline-block; background-color: #00ff66; color: #000; padding: 12px 24px; text-decoration: none; border-radius: 2px; font-weight: bold; margin: 10px; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; box-shadow: 0 0 10px rgba(0, 255, 102, 0.3);">
              ✅ YES, IT’S ME
            </a>
            <a href="${blockUrl}" style="display: inline-block; background-color: #ff003c; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 2px; font-weight: bold; margin: 10px; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; box-shadow: 0 0 10px rgba(255, 0, 60, 0.3);">
              🔥 NO, IT’S NOT ME
            </a>
          </div>
      `;
    } else if (attackType === "Password Spraying") {
      htmlContent += `
          <div style="background: #1e1b1b; border: 1px solid #ff003c; border-left: 4px solid #ff003c; padding: 15px; margin-bottom: 20px;">
            <h4 style="margin: 0 0 5px 0; color: #ff003c; font-size: 14px;">[ADMIN_ACTION_REQUIRED]</h4>
            <p style="margin: 0; font-size: 12px; color: #d1d5db;">IP is systematically probing authentication barriers. Immediate manual isolation recommended via Command Center.</p>
          </div>
      `;
    } else if (isLocked) {
      htmlContent += `
          <div style="background: #1e1b1b; border: 1px solid #ff003c; border-left: 4px solid #ff003c; padding: 15px; margin-bottom: 20px;">
            <h4 style="margin: 0 0 5px 0; color: #ff003c; font-size: 14px;">[ACCOUNT_LOCKED]</h4>
            <p style="margin: 0; font-size: 12px; color: #d1d5db;">Exceeded failure threshold (${attempts}). Security protocols engaged. Origin IP has been quarantined.</p>
          </div>
      `;
    } else {
      htmlContent += `
          <div style="margin-top: 30px;">
            <a href="${blockUrl}" style="display: inline-block; background-color: #ff003c; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 2px; font-weight: bold; margin-right: 10px; font-size: 12px; text-transform: uppercase;">
              🚨 BLOCK THIS IP
            </a>
            <a href="${resetUrl}" style="display: inline-block; background-color: #00f0ff; color: #000; padding: 12px 24px; text-decoration: none; border-radius: 2px; font-weight: bold; font-size: 12px; text-transform: uppercase;">
              🛡 IT'S ME
            </a>
          </div>
      `;
    }

    htmlContent += `
        </div>
        <!-- Cyber Terminal Footer -->
        <div style="background-color: #0f172a; border-top: 1px solid #1f2937; padding: 25px; text-align: center; font-size: 10px; color: #4b5563;">
          <p style="margin: 0; color: #00f0ff; font-weight: bold; letter-spacing: 1px;">[THREATGUARD SECURITY ENGINE ACTIVE]</p>
          <p style="margin: 5px 0;">Monitoring malicious activity... <span style="color: #ff003c;">●</span> LIVE_FEED_SECURE</p>
          <p style="margin-top: 10px; font-size: 9px; opacity: 0.5;">This is an automated encrypted alert generated by ThreatGuard AI Defense System. System Ref: TG-SCAN-${Math.floor(Math.random()*90000) + 10000}</p>
        </div>
      </div>
    </div>
    `;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: userEmail,
      subject: subject,
      html: htmlContent
    };

    console.log("Before sendMail");
    await transporter.sendMail(mailOptions);
    console.log("After sendMail");
    console.log(`✅ Security alert email sent to ${userEmail} (Type: ${attackType}, Locked: ${isLocked})`);

  } catch (error) {
    console.log("Catch sendMail error");
    console.error("❌ Email alert error:", error.message);
  }
};

module.exports = sendSecurityAlert;