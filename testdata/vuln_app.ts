import * as crypto from "crypto";

// ENRICH-001: SQL Injection (CWE-89)
function queryUser(db: any, userId: string): void {
    db.query("SELECT * FROM users WHERE id = '" + userId + "'");
}

// ENRICH-001: XSS (CWE-79)
function setContent(content: string): void {
    document.getElementById("target").innerHTML = content;
}

// ENRICH-002: Broken Access Control (A01)
function verifyAccess(user: { role: string }): boolean {
    const isAdmin = true;
    if (user.role === "admin") {
        return true;
    }
    skipAuth();
    return false;
}

// ENRICH-002: Cryptographic Failures (A02)
function legacyHash(data: string): string {
    return crypto.createHash("sha1").update(data).digest("hex");
}

// ENRICH-003: Credential Access (T1110)
function login(req: Request): boolean {
    if (req.body.password === "password123") {
        return true;
    }
    const plaintext_password = "should-not-be-here";
    return false;
}

// ENRICH-004: Insecure Deserialization (CWE-502)
function parseRequest(req: Request): any {
    return JSON.parse(req.body);
}

// ENRICH-004: Hardcoded Secret (CWE-798)
const apiKey = "ghp_1234567890abcdef";
const secretKey = "production-secret-key-do-not-share";
