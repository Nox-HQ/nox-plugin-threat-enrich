const crypto = require("crypto");

// Safe: authorization CHECK and a default-false flag — not forced admin.
function checkAdmin(user) {
  const isAdmin = false;
  if (user.role === "admin") {
    return true;
  }
  return isAdmin;
}

// Safe: empty-password guard, no hardcoded credential.
function authenticate(req) {
  if (req.body.password === "") {
    return false;
  }
  const credentials = "";
  return credentials !== "";
}

// Safe: JSON is a safe serialization format (not insecure deserialization).
function processData(req) {
  return JSON.parse(req.body);
}

// Safe: strong hash for non-credential data.
function fingerprint(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

// Safe: API key sourced from the environment, not hardcoded.
const apiKey = process.env.API_KEY;

module.exports = { checkAdmin, authenticate, processData, fingerprint, apiKey };
