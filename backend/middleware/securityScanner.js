const AttackLog = require("../models/smartlogin/AttackLog");
const BlockedIP = require("../models/smartlogin/BlockedIP");

// --- Advanced SQLi Patterns ---
const SQLI_PATTERNS = [
  { type: "Authentication Bypass", regex: /('|").*\s*(OR|AND)\s+.*?=.*?/i, score: 90 },
  { type: "UNION-based", regex: /\bUNION\s+(?:ALL\s+)?SELECT\b/i, score: 100 },
  { type: "Stacked Queries", regex: /;\s*(?:DROP|INSERT|UPDATE|DELETE|ALTER|CREATE|EXEC)\b/i, score: 100 },
  { type: "Time-based", regex: /\b(?:SLEEP\s*\(|WAITFOR\s+DELAY|pg_sleep\s*\()/i, score: 100 },
  { type: "Boolean-based", regex: /\b(?:AND|OR)\s+(?:\d+=\d+|'[^']+'='[^']+'|"[^"]+"="[^"]+")/i, score: 70 },
  { type: "Database Fingerprinting", regex: /\b(?:information_schema|@@version|database\(\)|user\(\)|version\(\))/i, score: 80 },
  { type: "Error-based", regex: /\b(?:extractvalue|updatexml|convert|cast)\s*\(/i, score: 90 },
  { type: "Comments & Hex", regex: /(?:--\s*$|--\s+.*|\/\*.*?\*\/|0x[0-9a-fA-F]+)/i, score: 60 }
];

// --- Advanced XSS Patterns ---
const XSS_PATTERNS = [
  { type: "Script Injection", regex: /<\s*script\b[^>]*>[\s\S]*?(<\s*\/script\b[^>]*>)?/i, score: 100, severity: "CRITICAL" },
  { type: "JavaScript URI", regex: /href\s*=\s*(?:'|")?\s*javascript:/i, score: 100, severity: "CRITICAL" },
  { type: "JavaScript URI (Iframe/Src)", regex: /src\s*=\s*(?:'|")?\s*javascript:/i, score: 100, severity: "CRITICAL" },
  { type: "Cookie Theft", regex: /\bdocument\.cookie\b/i, score: 90, severity: "HIGH" },
  { type: "Redirect Hijack", regex: /\b(?:window|document)\.location\b/i, score: 90, severity: "HIGH" },
  { type: "Event Handler Injection", regex: /\b(?:on(?:load|error|mouseover|click|focus|blur|keydown|keyup|submit|change))\s*=/i, score: 80, severity: "HIGH" },
  { type: "Code Execution Engine", regex: /\b(?:eval|setTimeout|setInterval)\s*\(/i, score: 70, severity: "MEDIUM" }
];

// --- NoSQLi Patterns ---
const NOSQL_OPERATORS = ['$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin', '$or', '$and', '$not', '$regex', '$where'];

// --- Advanced Command Injection Patterns ---
const CMD_INJECTION_PATTERNS = [
  // Reverse Shells & Bind Shells
  { type: "Reverse Shell", regex: /\b(?:nc|ncat|netcat)\s+-[e|c]\s+(?:bash|sh|cmd)|\bbash\s+-i\b|\bsh\s+-i\b|\bpython\s+-c\s+['"]import\s+pty/i, score: 100, severity: "CRITICAL" },
  // File access
  { type: "Sensitive File Access", regex: /\/etc\/(?:passwd|shadow|group|hosts)|\bC:\\Windows\\System32\\(?:config|drivers\\etc\\hosts)\b/i, score: 100, severity: "CRITICAL" },
  // Separator + Command (Linux & Windows)
  { type: "Separator + Command", regex: /(?:;|&&|\|\||\||&|`|\$\()\s*(?:ls|cat|whoami|pwd|wget|curl|rm|chmod|bash|sh|nc|dir|ipconfig|tasklist|del|powershell|net\s+user)\b/i, score: 90, severity: "HIGH" },
  // Standalone dangerous
  { type: "Dangerous Shell Command", regex: /\b(?:wget|curl|powershell\.exe|Invoke-WebRequest)\b\s+http/i, score: 80, severity: "HIGH" },
];


// --- Other Strict Patterns ---
const BAD_EXTENSIONS = ['.php', '.exe', '.sh'];

// Helper to check if string contains ANY of the substrings (case insensitive)
const containsAny = (str, arr) => arr.some(pattern => str.toUpperCase().includes(pattern.toUpperCase()));

// --- Payload Normalization ---
const normalizeInput = (str) => {
  if (typeof str !== 'string') return '';
  try {
    str = decodeURIComponent(str);
  } catch (e) {
    // Keep raw string if URI decoding fails
  }
  return str.toLowerCase().trim().replace(/\s+/g, ' ');
};

// --- Deep Payload Extraction (Values Only for SQLi & XSS) ---
const extractValues = (obj) => {
  let values = [];
  if (typeof obj === 'string') {
    values.push(obj);
  } else if (Array.isArray(obj)) {
    obj.forEach(item => values.push(...extractValues(item)));
  } else if (obj !== null && typeof obj === 'object') {
    Object.values(obj).forEach(val => values.push(...extractValues(val)));
  }
  return values;
};

// --- Deep Key/Value Extraction (For NoSQLi) ---
// Scans for NoSQL operator keys in nested JSON
const checkNoSQLInjection = (obj) => {
  if (typeof obj === 'string') {
     // Sometimes attackers stringify the injection payload: {"username": "{\"$ne\": null}"}
     if (obj.includes('$ne') || obj.includes('$where') || obj.includes('$regex')) {
        return { detected: true, payload: obj };
     }
  } else if (Array.isArray(obj)) {
    for (let item of obj) {
      const result = checkNoSQLInjection(item);
      if (result.detected) return result;
    }
  } else if (obj !== null && typeof obj === 'object') {
    for (const [key, value] of Object.entries(obj)) {
      // Check if the key itself is an operator
      if (NOSQL_OPERATORS.includes(key)) {
        return { detected: true, payload: `Key operator: ${key}` };
      }
      
      // Explicit check for $where passing javascript
      if (key === '$where' || (typeof value === 'string' && value.includes('this.'))) {
         return { detected: true, payload: `JavaScript execution in NoSQL` };
      }

      // Check values recursively
      const result = checkNoSQLInjection(value);
      if (result.detected) return result;
    }
  }
  return { detected: false };
};
// --- DDoS / Request Flood Tracker ---
const ddosTracker = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of ddosTracker.entries()) {
    if (now - data.firstRequestAt > 10000) {
      ddosTracker.delete(ip);
    }
  }
}, 60000); // Cleanup every minute

const securityScanner = async (req, res, next) => {
  try {
    const ip = req.headers["x-forwarded-for"]?.split(',')[0] || req.socket.remoteAddress || "Unknown";
    
    // Check if IP is blocked
    const blocked = await BlockedIP.findOne({ ip });
    if (blocked && (!blocked.blockedUntil || blocked.blockedUntil > new Date())) {
      return res.status(403).json({ message: "Access denied. Your IP is quarantined." });
    }

    const path = req.path;
    const isLoginRequest = path.includes("/login");
    const isQueryInput = Object.keys(req.query).length > 0;
    
    // Combine basic inspection string for generic checks
    const bodyStr = JSON.stringify(req.body || {});
    const queryStr = JSON.stringify(req.query || {});
    const inspectStr = bodyStr + queryStr;

    let attackType = null;
    let severity = "LOW";
    let payloadStr = "";
    let reason = "";
    let actionTaken = "blocked";
    let confidenceScore = 0;
    let matchedPatterns = [];
    let suspiciousOrigin = undefined;
    let suspiciousReferer = undefined;
    let actionRoute = undefined;
    let requestFrequency = undefined;
    let route = undefined;

    // --- 0. DDoS / Request Flood Detection ---
    const now = Date.now();
    if (!ddosTracker.has(ip)) {
      ddosTracker.set(ip, { count: 1, firstRequestAt: now, endpoints: new Set([path]) });
    } else {
      const data = ddosTracker.get(ip);
      if (now - data.firstRequestAt > 10000) {
        data.count = 1;
        data.firstRequestAt = now;
        data.endpoints = new Set([path]);
      } else {
        data.count++;
        data.endpoints.add(path);
      }
    }

    const currentFreq = ddosTracker.get(ip).count;
    if (currentFreq >= 10) {
      attackType = "DDoS / Request Flood Attack";
      reason = "High-frequency request flood detected";
      confidenceScore = 100;
      requestFrequency = currentFreq;
      route = path;
      
      if (currentFreq >= 50) {
        severity = "CRITICAL";
      } else if (currentFreq >= 20) {
        severity = "HIGH";
      } else {
        severity = "MEDIUM";
      }
      
      payloadStr = `Detected ${currentFreq} requests within 10 seconds. Targeted endpoints: ${Array.from(ddosTracker.get(ip).endpoints).join(', ')}`;
      matchedPatterns.push("High-Frequency Flood");
    }

    // --- 1. Advanced SQL Injection & XSS Detection ---
    if (!attackType) {
       // Extract all dynamic values from body, query, and specific headers
       const scanTargets = [
         ...extractValues(req.body || {}),
         ...extractValues(req.query || {}),
         req.headers['user-agent'] || '',
         req.headers['referer'] || '',
         req.headers['x-forwarded-for'] || ''
       ];

       let isSqli = false;
       let isXss = false;
       let maxSeverity = "LOW";

       for (let target of scanTargets) {
          const normalizedTarget = normalizeInput(target);
          if (!normalizedTarget) continue;

          // SQLi Scanner
          for (const pattern of SQLI_PATTERNS) {
             if (pattern.regex.test(normalizedTarget)) {
                // Avoid simple false positives like "1=1" alone, unless it's a specific pattern
                if (pattern.type === "Boolean-based" && !normalizedTarget.match(/\b(?:AND|OR|UNION|SELECT)\b/i)) {
                   continue; // Skip if no SQL keyword accompanies the boolean check
                }

                isSqli = true;
                matchedPatterns.push(pattern.type);
                if (pattern.score > confidenceScore) {
                   confidenceScore = pattern.score;
                   payloadStr = target; // Capture the actual exact suspicious payload
                }
             }
          }

          // XSS Scanner
          for (const pattern of XSS_PATTERNS) {
             if (pattern.regex.test(normalizedTarget)) {
                isXss = true;
                matchedPatterns.push(pattern.type);
                
                // Track max severity required by XSS
                if (
                   pattern.severity === "CRITICAL" || 
                   (pattern.severity === "HIGH" && maxSeverity !== "CRITICAL") || 
                   (pattern.severity === "MEDIUM" && maxSeverity === "LOW")
                ) {
                   maxSeverity = pattern.severity;
                }

                if (pattern.score > confidenceScore) {
                   confidenceScore = pattern.score;
                   payloadStr = target; // Capture exact payload
                }
             }
          }
       }

       if (isXss) { // Prioritize XSS if both trigger to keep logs distinct, or just rely on highest score. XSS chosen here as explicit requested feature.
          attackType = "Cross-Site Scripting (XSS)";
          severity = maxSeverity;
          reason = `Malicious script payload detected`;
          actionTaken = "alert-triggered";
       } else if (isSqli) {
          attackType = "SQL Injection (SQLi)";
          if (confidenceScore >= 100) severity = "CRITICAL";
          else if (confidenceScore >= 80) severity = "HIGH";
          else if (confidenceScore >= 60) severity = "MEDIUM";
          else severity = "LOW";
          
          reason = `Advanced SQLi detected (${matchedPatterns.join(', ')})`;
          actionTaken = "alert-triggered";
       }
    }

    // --- 2. NoSQL Injection Detection ---
    if (!attackType && (isLoginRequest || isQueryInput)) {
       const nosqlBodyCheck = checkNoSQLInjection(req.body);
       const nosqlQueryCheck = checkNoSQLInjection(req.query);

       if (nosqlBodyCheck.detected || nosqlQueryCheck.detected) {
          attackType = "NoSQL Injection";
          severity = "HIGH"; // Can be mapped to CRITICAL if specific dangerous operators like $where are used
          
          if (nosqlBodyCheck.payload?.includes('$where') || nosqlQueryCheck.payload?.includes('$where')) {
             severity = "CRITICAL";
          }

          payloadStr = nosqlBodyCheck.detected ? nosqlBodyCheck.payload : nosqlQueryCheck.payload;
          reason = "Malicious MongoDB operator detected";
          actionTaken = "alert-triggered";
          confidenceScore = 95; 
          matchedPatterns = ["Operator Injection"];
       }
    }

    // 3. Command Injection
    if (!attackType) {
       let isCmdi = false;
       let maxSeverity = "LOW";

       const scanTargets = [
         ...extractValues(req.body || {}),
         ...extractValues(req.query || {}),
         req.headers['user-agent'] || '',
         req.headers['referer'] || '',
         req.headers['x-forwarded-for'] || ''
       ];

       for (let target of scanTargets) {
          const normalizedTarget = normalizeInput(target);
          if (!normalizedTarget) continue;

          for (const pattern of CMD_INJECTION_PATTERNS) {
             if (pattern.regex.test(normalizedTarget)) {
                isCmdi = true;
                matchedPatterns.push(pattern.type);
                
                if (
                   pattern.severity === "CRITICAL" || 
                   (pattern.severity === "HIGH" && maxSeverity !== "CRITICAL") || 
                   (pattern.severity === "MEDIUM" && maxSeverity === "LOW")
                ) {
                   maxSeverity = pattern.severity;
                }

                if (pattern.score > confidenceScore) {
                   confidenceScore = pattern.score;
                   payloadStr = target; // Capture exact malicious payload
                }
             }
          }
       }

       if (isCmdi) {
          attackType = "Command Injection";
          severity = maxSeverity;
          reason = "Malicious shell command pattern detected";
          actionTaken = "alert-triggered";
       }
    }


    // 4. File Upload Attack
    if (!attackType && (req.files || req.file)) {
      const files = req.files ? (Array.isArray(req.files) ? req.files : Object.values(req.files).flat()) : [req.file];
      for (const file of files) {
        if (file && file.originalname) {
           const extMatch = BAD_EXTENSIONS.some(ext => file.originalname.toLowerCase().endsWith(ext));
           const mimeMismatch = file.mimetype === "application/x-msdownload" || file.mimetype.includes("php");
           if (extMatch || mimeMismatch) {
             attackType = "FILE_UPLOAD_ATTACK";
             severity = "CRITICAL";
             payloadStr = "Malicious file extension or MIME type detected";
             reason = "malicious file extension or MIME detected";
             break;
           }
        }
      }
    }

    // 5. CSRF Detection (Production-Grade)
    if (!attackType && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
      const originHeader = req.headers['origin'];
      const refererHeader = req.headers['referer'];
      
      const token = req.headers['x-csrf-token'] || (req.body && req.body.csrfToken) || (req.query && req.query.csrfToken);
      const isMissingToken = !token || token.length < 10;
      
      let originMismatch = false;
      let refererMismatch = false;
      
      actionRoute = req.path;
      suspiciousOrigin = originHeader || "none";
      suspiciousReferer = refererHeader || "none";

      let registeredDomain = "none";

      if (req.website && req.website.websiteUrl) {
        try {
          const registeredUrl = new URL(req.website.websiteUrl);
          registeredDomain = registeredUrl.hostname;

          if (originHeader) {
            const originUrl = new URL(originHeader);
            if (originUrl.hostname !== registeredDomain) {
              originMismatch = true;
            }
          }

          if (refererHeader) {
            const refererUrl = new URL(refererHeader);
            if (refererUrl.hostname !== registeredDomain) {
              refererMismatch = true;
            }
          }
        } catch (e) {
          // URL parsing failed, might be malformed headers
        }
      }

      // 1. Add debug logs inside CSRF block
      console.log("\n--- CSRF DEBUG ---");
      console.log("req.method:", req.method);
      console.log("origin:", suspiciousOrigin);
      console.log("referer:", suspiciousReferer);
      console.log("csrfToken:", token ? "Present" : "Missing");
      console.log("website domain:", registeredDomain);
      console.log("originMismatch:", originMismatch);
      console.log("------------------\n");

      // Required rule: method is POST/PUT/PATCH/DELETE AND no csrfToken AND origin domain != website domain
      if (isMissingToken && originMismatch) {
        attackType = "CSRF Attack";
        severity = "CRITICAL";
        confidenceScore = 100;
        reason = "Missing CSRF token and Origin mismatch detected";
        
        payloadStr = `Method: ${req.method}, Route: ${actionRoute}, Origin: ${suspiciousOrigin}, Referer: ${suspiciousReferer}`;
        
        matchedPatterns.push("Cross-Site Request Forgery", "Origin Mismatch", "Missing CSRF Token");
        
        const sensitiveActions = ['password', 'email', 'delete', 'transfer', 'admin', 'login'];
        if (sensitiveActions.some(action => actionRoute.toLowerCase().includes(action))) {
           matchedPatterns.push("Sensitive Action Target");
        }
      } else {
        // Reset captured fields if it wasn't an attack
        actionRoute = undefined;
        suspiciousOrigin = undefined;
        suspiciousReferer = undefined;
      }
    }

    // 6. IDOR
    if (!attackType && req.user && req.user.id) {
      const targetUserId = req.params.userId || req.body.userId;
      if (targetUserId && String(targetUserId) !== String(req.user.id)) {
        attackType = "IDOR";
        severity = "HIGH";
        payloadStr = `Attempt to access resource for user ${targetUserId} by ${req.user.id}`;
        reason = "attempted IDOR access";
      }
    }

    // Attack Detection Response Logic
    if (attackType) {
      const location = req.location || { 
         country: "Unknown", 
         state: "Unknown", 
         city: "Unknown", 
         latitude: 0, 
         longitude: 0,
         isp: "Unknown",
         timezone: "Unknown"
      };

      const userId = (req.user && req.user.id) ? req.user.id : null;
      const email = req.body?.email ? req.body.email.trim().toLowerCase() : "unknown";

      // Distinct matchedPatterns to avoid duplicates if same attack type repeats in same payload
      const uniqueMatchedPatterns = [...new Set(matchedPatterns)];

      const logData = {
        userId,
        ip,
        location,
        attackType,
        severity,
        payload: { 
           raw: payloadStr,
           matchedPatterns: uniqueMatchedPatterns.length > 0 ? uniqueMatchedPatterns : undefined,
           confidenceScore: confidenceScore > 0 ? confidenceScore : undefined,
           suspiciousOrigin: suspiciousOrigin !== undefined ? suspiciousOrigin : undefined,
           suspiciousReferer: suspiciousReferer !== undefined ? suspiciousReferer : undefined,
           actionRoute: actionRoute !== undefined ? actionRoute : undefined,
           requestFrequency: requestFrequency !== undefined ? requestFrequency : undefined,
           route: route !== undefined ? route : undefined,
           suspiciousPayload: payloadStr ? payloadStr : undefined
        },
        timestamp: new Date(),
        reason: reason || payloadStr,
        actionTaken: actionTaken || "blocked",
        userAgent: req.headers["user-agent"] || "unknown",
        email,
        status: "failed" // Mark as failed security scan
      };
      
      // Ensure ownerId and websiteId are populated if this is a protected route
      if (req.website) {
         logData.websiteId = req.website._id;
         logData.ownerId = req.website.ownerId;
      } else {
         logData.websiteId = null;
         logData.ownerId = null;
      }

      if (logData.websiteId && logData.ownerId) {
        await AttackLog.create(logData);
      }

      // BLOCK IP for Command Injection or Critical SQLi/XSS
      if (attackType === "Command Injection" || attackType === "COMMAND_INJECTION" || severity === "CRITICAL") {
        if (req.website) {
           await BlockedIP.create({
             ip,
             ipAddress: ip,
             reason: `Critical security violation: ${attackType}`,
             ownerId: req.website.ownerId,
             websiteId: req.website._id,
             blockedUntil: new Date(Date.now() + 24 * 60 * 60 * 1000)
           });
        } else {
           await BlockedIP.create({
             ip,
             reason: `Critical security violation: ${attackType}`,
             blockedAt: new Date()
           });
        }
      }

      // Emit Socket Event to Owner Dashboard
      if (req.website) {
         const io = req.app.get("io");
         if (io) {
            io.to(req.website.ownerId.toString()).emit("new_attack", {
              ip,
              attackType,
              severity,
              location,
              website: req.website.websiteUrl,
              email,
              time: new Date(),
              confidenceScore,
              matchedPatterns: uniqueMatchedPatterns,
              suspiciousOrigin: suspiciousOrigin !== undefined ? suspiciousOrigin : undefined,
              suspiciousReferer: suspiciousReferer !== undefined ? suspiciousReferer : undefined,
              actionRoute: actionRoute !== undefined ? actionRoute : undefined,
              requestFrequency: requestFrequency !== undefined ? requestFrequency : undefined,
              route: route !== undefined ? route : undefined,
              suspiciousPayload: payloadStr ? payloadStr : undefined
            });
         }
      }

      return res.status(403).json({
        message: `Security Lockdown: Malicious request blocked [${attackType}]`
      });
    }

    next();

  } catch (err) {
    console.error("Security Scanner Error:", err);
    next();
  }
};

module.exports = securityScanner;

