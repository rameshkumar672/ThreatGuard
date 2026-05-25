const axios = require("axios");

module.exports = async (req, res, next) => {
    let ip = req.headers["x-forwarded-for"]?.split(',')[0] || req.socket.remoteAddress || "Unknown";

    // Handle local/private IPs
    if (ip === "::1" || ip === "127.0.0.1" || ip.startsWith("192.168.") || ip.startsWith("10.")) {
        req.location = {
            country: "Localhost",
            state: "Internal",
            city: "Internal Network",
            latitude: 0,
            longitude: 0,
            isp: "Internal",
            timezone: "UTC"
        };
        return next();
    }

    try {
        const response = await axios.get(`http://ip-api.com/json/${ip}`);
        const data = response.data;

        if (data && data.status === "success") {
            req.location = {
                country: data.country || "Unknown",
                state: data.regionName || "Unknown",
                city: data.city || "Unknown",
                latitude: data.lat || 0,
                longitude: data.lon || 0,
                isp: data.isp || "Unknown",
                timezone: data.timezone || "Unknown"
            };
        } else {
            throw new Error("IP Geolocation Failed");
        }
    } catch (err) {
        req.location = {
            country: "Unknown",
            state: "Unknown",
            city: "Unknown",
            latitude: 0,
            longitude: 0,
            isp: "Unknown",
            timezone: "Unknown"
        };
    }

    next();
};
