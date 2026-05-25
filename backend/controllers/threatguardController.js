const Owner = require("../models/threatguard/Owner");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// ================= REGISTER OWNER (ThreatGuard Platform) =================
exports.registerOwner = async (req, res) => {
  try {
    const { name, email, password, websiteName } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        message: "Name, email and password are required."
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    let owner = await Owner.findOne({ email: normalizedEmail });
    console.log("EMAIL RECEIVED:", normalizedEmail);
    console.log("OWNER FOUND:", owner ? "YES" : "NO");
    if (owner) {
      return res.status(400).json({
        message: "Account already exists with this email."
      });
    }

    const hash = await bcrypt.hash(password, 10);

    owner = await Owner.create({
      name,
      email: normalizedEmail,
      password: hash,
      websiteName: websiteName || ""
    });

    res.status(201).json({
      message: "Account created successfully.",
      userId: owner._id
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= LOGIN OWNER (ThreatGuard Platform) =================
exports.loginOwner = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required." });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const owner = await Owner.findOne({ email: normalizedEmail });

    if (!owner) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, owner.password);
    console.log("PASSWORD MATCH:", isMatch);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: owner._id, email: owner.email },
      process.env.JWT_SECRET || "threatguard_secret_key",
      { expiresIn: "10h" }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: owner._id,
        name: owner.name,
        email: owner.email,
        websiteName: owner.websiteName
      }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};
