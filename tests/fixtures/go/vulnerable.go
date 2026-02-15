package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
)

// SQL Injection - string concatenation
func getUser(db *sql.DB, id string) {
	query := "SELECT * FROM users WHERE id=" + id
	db.Query(query)
}

// SQL Injection - fmt.Sprintf
func getUserByName(db *sql.DB, name string) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name='%s'", name)
	db.Query(query)
}

// Command Injection
func runCommand(input string) {
	exec.Command("sh", "-c", input)
}

// Hardcoded secret
var apiKey = "sk-1234567890abcdef1234567890abcdef"

// Insecure random
func generateToken() int {
	return rand.Intn(999999)
}

// Path traversal
func readFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	data, _ := os.ReadFile("/uploads/" + filename)
	w.Write(data)
}

// Weak hash MD5
func hashData(data []byte) []byte {
	h := md5.Sum(data)
	return h[:]
}

// TLS skip verify
func insecureClient() {
	// InsecureSkipVerify: true
}

// Error info leak
func handleError(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), 500)
}
