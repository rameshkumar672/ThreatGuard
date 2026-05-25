const PDFDocument = require("pdfkit");
const { Parser } = require("json2csv");
const AttackLog = require("../models/smartlogin/AttackLog");
const Website = require("../models/threatguard/Website");

const getUserWebsiteIds = async (userId) => {
  const websites = await Website.find({ ownerId: userId });
  return websites.map((w) => w._id);
};

// ================= EXPORT PDF REPORT =================
exports.exportPDFReport = async (req, res) => {
  try {
    const websiteIds = await getUserWebsiteIds(req.user.id);
    const logs = await AttackLog.find({ 
      websiteId: { $in: websiteIds },
      attackType: { $nin: ["none", "Failed Login"] },
      status: { $ne: "success" }
    })
      .limit(100)
      .sort({ createdAt: -1 });

    const doc = new PDFDocument();

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", "attachment; filename=attack_report.pdf");

    doc.pipe(res);

    doc.fontSize(20).text("ThreatGuard Security Report", { align: "center" });
    doc.moveDown();

    logs.forEach((log, index) => {
      doc.fontSize(12).text(
        `${index + 1}. IP: ${log.ip} | Type: ${log.attackType} | Severity: ${log.severity} | Time: ${log.createdAt}`
      );
      doc.moveDown();
    });

    doc.end();

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};


// ================= EXPORT CSV REPORT =================
exports.exportCSVReport = async (req, res) => {
  try {
    const websiteIds = await getUserWebsiteIds(req.user.id);
    const logs = await AttackLog.find({ 
      websiteId: { $in: websiteIds },
      attackType: { $nin: ["none", "Failed Login"] },
      status: { $ne: "success" }
    })
      .limit(100)
      .sort({ createdAt: -1 });

    const fields = ["ip", "location.country", "location.state", "location.city", "location.isp", "location.timezone", "attackType", "severity", "status", "createdAt"];

    const parser = new Parser({ fields });

    const csv = parser.parse(logs);

    res.header("Content-Type", "text/csv");
    res.attachment("attack_report.csv");

    res.send(csv);

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= ATTACK SUMMARY =================
exports.getAttackSummary = async (req, res) => {
  try {
    const websiteIds = await getUserWebsiteIds(req.user.id);

    const attackTypes = await AttackLog.aggregate([
      { $match: { websiteId: { $in: websiteIds }, attackType: { $nin: ["Failed Login", "none"] }, status: { $ne: "success" } } },
      { $group: { _id: "$attackType", count: { $sum: 1 } } },
      { $project: { type: "$_id", count: 1, _id: 0 } }
    ]);

    const locations = await AttackLog.aggregate([
      { $match: { websiteId: { $in: websiteIds }, attackType: { $nin: ["Failed Login", "none"] }, status: { $ne: "success" } } },
      { $group: { _id: "$location.country", count: { $sum: 1 } } },
      { $project: { country: "$_id", count: 1, _id: 0 } }
    ]);

    res.json({
      attackTypes,
      locations
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};