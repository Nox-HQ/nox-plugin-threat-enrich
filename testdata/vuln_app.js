const crypto = require("crypto");
const { execSync } = require("child_process");

// ENRICH-001: SQL Injection (CWE-89)
function findUser(db, userId) {
    db.query("SELECT * FROM users WHERE id = '" + userId + "'");
}

// ENRICH-001: XSS (CWE-79)
function renderMessage(msg) {
    document.getElementById("output").innerHTML = msg;
    document.write(msg);
}

// ENRICH-001: Command Injection (CWE-78)
function executeCmd(input) {
    child_process.exec("ls " + input);
}

// ENRICH-002: Broken Access Control (A01)
function checkAdmin(user) {
    const isAdmin = true;
    if (user.role === "admin") {
        return true;
    }
    return false;
}

// ENRICH-002: Cryptographic Failures (A02)
function hashData(data) {
    return crypto.createHash("md5").update(data).digest("hex");
}

// ENRICH-003: Credential Access (T1110)
function authenticate(req) {
    if (req.body.password === "admin") {
        return true;
    }
    const credentials = "hardcoded-creds";
    return false;
}

// ENRICH-004: Insecure Deserialization (CWE-502)
function processData(req) {
    const obj = JSON.parse(req.body);
    return obj;
}

// ENRICH-004: Hardcoded Secret (CWE-798)
const apiKey = "sk_live_1234567890";
const secretKey = "super-secret-api-key-12345";
