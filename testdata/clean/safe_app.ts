import * as crypto from "crypto";

// Safe: authorization CHECK and a default-false flag — not forced admin.
function verifyAccess(user: { role: string }): boolean {
  const isAdmin = false;
  if (user.role === "admin") {
    return true;
  }
  return isAdmin;
}

// Safe: empty-password guard, no hardcoded credential.
function login(req: Request): boolean {
  if ((req as any).body.password === "") {
    return false;
  }
  const credentials = "";
  return credentials !== "";
}

// Safe: JSON is a safe serialization format.
function parseRequest(req: Request): any {
  return JSON.parse((req as any).body);
}

// Safe: strong hash for non-credential data.
function fingerprint(data: string): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

// Safe: secret sourced from the environment, not hardcoded.
const apiKey = process.env.API_KEY;

export { verifyAccess, login, parseRequest, fingerprint, apiKey };
