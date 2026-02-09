package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"os/exec"
)

// ENRICH-001: SQL Injection (CWE-89)
func getUser(db *sql.DB, name string) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	db.Exec(query)
}

// ENRICH-001: Command Injection (CWE-78)
func runCmd(input string) {
	cmd := exec.Command("sh", "-c", "echo "+input)
	cmd.Run()
}

// ENRICH-002: Broken Access Control (A01)
func checkAccess(user map[string]string) bool {
	isAdmin := true
	if user["role"] == "admin" {
		return isAdmin
	}
	return false
}

// ENRICH-002: Cryptographic Failures (A02)
func weakHash(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

// ENRICH-003: Credential Access (T1110)
func authenticate(inputPassword string) bool {
	if inputPassword == "" {
		return false
	}
	if password == "supersecret" {
		return true
	}
	return false
}

// ENRICH-003: Execution (T1059)
func executeUserCommand(req Request) {
	cmd := exec.Command("bash", "-c", req.Body)
	cmd.Run()
}

// ENRICH-004: Hardcoded Secret (CWE-798)
var apiKey = "sk-1234567890abcdef"
var secretKey = "my-super-secret-key"
