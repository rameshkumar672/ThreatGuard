const crypto = require("crypto");
const AttackLog = require("../models/smartlogin/AttackLog");
const WebsiteUser = require("../models/smartlogin/WebsiteUser");
const TrustedDevice = require("../models/smartlogin/TrustedDevice");
const sendSecurityAlert = require("../utils/sendSecurityEmail");
const Owner = require("../models/threatguard/Owner");

const jwt = require("jsonwebtoken");

// --- Helper: Haversine distance in km ---
const getDistanceInKm = (lat1, lon1, lat2, lon2) => {
    if (!lat1 || !lon1 || !lat2 || !lon2) return 0;
    const R = 6371; // Earth's radius in km
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
              Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
};

const behaviorScanner = async (req, res, next) => {
    try {
        if (!req.website) return next();

        const { email, status } = req.body;
        // We only process behavior on successful or failed logins that actually have an email
        if (!email) return next();

        const normalizedEmail = email.trim().toLowerCase();
        const ip = req.headers["x-forwarded-for"]?.split(',')[0] || req.socket.remoteAddress || "Unknown";
        const userAgent = req.headers["user-agent"] || "";
        const providedFingerprint = req.headers["x-device-fingerprint"] || req.body.deviceFingerprint;
        
        // Generate fallback fingerprint if none provided
        const deviceFingerprint = providedFingerprint || crypto.createHash("sha256").update(`${userAgent}|${ip}`).digest("hex");
        
        const io = req.app.get("io");
        const emitAlert = (attackType, severity, fields) => {
            if (io && req.website.ownerId) {
                io.to(req.website.ownerId.toString()).emit("new_attack", {
                    ip,
                    attackType,
                    severity,
                    location: req.location || { country: "Unknown", state: "Unknown", city: "Unknown", latitude: 0, longitude: 0, isp: "Unknown", timezone: "Unknown" },
                    website: req.website.websiteUrl,
                    email: normalizedEmail,
                    time: new Date(),
                    ...fields
                });
            }
        };

        const saveLog = async (attackType, severity, payload) => {
            const log = await AttackLog.create({
                ip,
                attackType,
                severity,
                ownerId: req.website.ownerId,
                websiteId: req.website._id,
                location: req.location || { country: "Unknown", state: "Unknown", city: "Unknown", latitude: 0, longitude: 0, isp: "Unknown", timezone: "Unknown" },
                email: normalizedEmail,
                status: "failed", // It's an attack detection
                reason: `Behavioral Alert: ${attackType}`,
                actionTaken: "alert-triggered",
                userAgent,
                payload,
                timestamp: new Date()
            });
            emitAlert(attackType, severity, { payload });

            try {
                await sendSecurityAlert(
                    normalizedEmail, // Send to affected user email
                    ip,
                    req.location || { country: "Unknown", city: "Unknown" },
                    1,
                    req.website.ownerId,
                    req.website._id,
                    userAgent || "Unknown Device",
                    false,
                    "", // blockToken (generated inside)
                    "", // resetToken (generated inside)
                    attackType,
                    log._id // Pass attackLogId
                );
            } catch (err) {
                console.error("Failed to send behavioral alert email:", err);
            }
        };

        // --- 1. Suspicious User-Agent Detection ---
        let uaSeverity = null;
        let uaConfidence = 0;
        const uaLower = userAgent.toLowerCase();

        if (!userAgent || userAgent.trim() === "") {
            uaSeverity = "MEDIUM";
            uaConfidence = 60;
        } else if (/(headlesschrome|puppeteer|playwright|selenium)/.test(uaLower)) {
            uaSeverity = "CRITICAL";
            uaConfidence = 100;
        } else if (/(curl|python-requests|wget|postmanruntime|sqlmap|nikto|bot)/.test(uaLower)) {
            uaSeverity = "HIGH";
            uaConfidence = 90;
        }

        if (uaSeverity) {
            await saveLog("Suspicious User-Agent", uaSeverity, {
                userAgent,
                confidenceScore: uaConfidence,
                severity: uaSeverity
            });
        }

        // Fetch User state before it gets updated by protectionController
        const user = await WebsiteUser.findOne({ websiteId: req.website._id, email: normalizedEmail });

        if (user) {
            // --- 3. Location Change Detection & 4. Impossible Travel Detection ---
            if (user.lastIp && user.lastIp !== ip && req.location) {
                const prevCountry = user.lastCountry || "Unknown";
                const prevCity = user.lastCity || "Unknown";
                const currCountry = req.location.country;
                const currCity = req.location.city;

                // Impossible Travel Check
                if (user.lastLoginAt && req.location.ll) {
                    // Note: We need the previous lat/lon. Since we didn't store it, we estimate or skip distance if we don't have it.
                    // To do it properly, we should store `lastLocationLl` in WebsiteUser.
                    // For now, if we have country/city changes, we can flag it. 
                    // Let's rely on time difference if country changed.
                    const hoursDiff = (Date.now() - new Date(user.lastLoginAt).getTime()) / (1000 * 60 * 60);
                    
                    if (prevCountry !== "Unknown" && currCountry !== "Unknown" && prevCountry !== currCountry) {
                        // Rough impossible travel: different country in under 2 hours
                        if (hoursDiff < 2) {
                            await saveLog("Impossible Travel Detected", "CRITICAL", {
                                previousLocation: `${prevCity}, ${prevCountry}`,
                                currentLocation: `${currCity}, ${currCountry}`,
                                timeDifference: `${Math.round(hoursDiff * 60)} minutes`,
                                estimatedTravelSpeed: "Impossible"
                            });
                        } else {
                            // Just a location change
                            await saveLog("Location Change Detected", "HIGH", {
                                previousLocation: `${prevCity}, ${prevCountry}`,
                                currentLocation: `${currCity}, ${currCountry}`,
                                ip
                            });
                        }
                    } else if (prevCity !== "Unknown" && currCity !== "Unknown" && prevCity !== currCity) {
                        // Same country, different city
                        await saveLog("Location Change Detected", "MEDIUM", {
                            previousLocation: `${prevCity}, ${prevCountry}`,
                            currentLocation: `${currCity}, ${currCountry}`,
                            ip
                        });
                    }
                }
            }

            // --- 2. New Device Detection ---
            // If the user's last fingerprint is different OR it doesn't exist in TrustedDevice
            if (user.lastDeviceFingerprint && user.lastDeviceFingerprint !== deviceFingerprint) {
                // Check if it's explicitly trusted
                const trusted = await TrustedDevice.findOne({ 
                    websiteId: req.website._id, 
                    deviceFingerprint 
                });

                if (trusted) {
                    await saveLog("New Device Login", "LOW", {
                        deviceFingerprint,
                        userId: user._id, // actually WebsiteUser _id
                        ip
                    });
                } else {
                    await saveLog("New Device Login", "MEDIUM", {
                        deviceFingerprint,
                        userId: user._id,
                        ip
                    });
                }
            }
        }

        // Pass fingerprint to req so protectionController can save it
        req.behaviorUpdates = {
            lastIp: ip,
            lastCountry: req.location?.country || "Unknown",
            lastCity: req.location?.city || "Unknown",
            lastDeviceFingerprint: deviceFingerprint,
            lastLoginAt: new Date()
        };

        next();

    } catch (err) {
        console.error("Behavior Scanner Error:", err);
        next();
    }
};

module.exports = behaviorScanner;
