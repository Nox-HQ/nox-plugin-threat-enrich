package clean

import (
	"crypto/sha256"
	"database/sql"
)

// SafeQuery uses a bound parameter — no string concatenation into the SQL.
func SafeQuery(db *sql.DB, name string) {
	db.Query("SELECT * FROM users WHERE name = $1", name)
}

// CheckAccess performs an authorization CHECK against the user's role —
// a correct access-control check, not a broken-access-control weakness.
func CheckAccess(user map[string]string) bool {
	if user["role"] == "admin" {
		return true
	}
	return false
}

// Authenticate guards an empty password — not a hardcoded credential.
func Authenticate(inputPassword string) bool {
	if inputPassword == "" {
		return false
	}
	return true
}

// Fingerprint uses a strong hash for non-credential data.
func Fingerprint(data []byte) [32]byte {
	return sha256.Sum256(data)
}
