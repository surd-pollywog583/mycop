package main

import "C"

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"database/sql"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"time"
	"unsafe"

	"archive/zip"
	"gopkg.in/yaml.v3"
)

// GO-SEC-001: SQL injection via fmt.Sprintf
func sqlInjectionSprintf(db *sql.DB, id string) {
	query := fmt.Sprintf("SELECT * FROM users WHERE id='%s'", id)
	db.Query(query)
}

// GO-SEC-002: Command injection
func commandInjection(input string) {
	exec.Command("sh", "-c", input)
}

// GO-SEC-003: Hardcoded secret
var apiKey = "sk-1234567890abcdef1234567890abcdef"

// GO-SEC-004: Insecure random
func insecureRandom() int {
	return rand.Intn(999999)
}

// GO-SEC-005: Path traversal
func pathTraversal(filename string) {
	os.ReadFile("/uploads/" + filename)
}

// GO-SEC-006: SSRF
func ssrf(url string) {
	http.Get("http://example.com/" + url)
}

// GO-SEC-007: XSS template bypass
func xssTemplate(userInput string) template.HTML {
	return template.HTML(userInput)
}

// GO-SEC-008: Unsafe reflect
func unsafeReflect(x interface{}) {
	reflect.ValueOf(x).Elem().Set(reflect.ValueOf("hacked"))
}

// GO-SEC-009: Hardcoded credentials
var password = "admin123pass"

// GO-SEC-010: TLS insecure skip verify
func tlsSkipVerify() {
	config := struct{ InsecureSkipVerify bool }{InsecureSkipVerify: true}
	_ = config
}

// GO-SEC-011: Weak hash MD5
func weakMd5(data []byte) {
	md5.Sum(data)
}

// GO-SEC-012: Weak hash SHA1
func weakSha1(data []byte) {
	sha1.Sum(data)
}

// GO-SEC-013: Weak cipher DES
func weakCipher(key []byte) {
	des.NewCipher(key)
}

// GO-SEC-014: ECB/CBC mode
func cbcMode(block cipher.Block, ivBytes []byte) {
	cipher.NewCBCEncrypter(block, ivBytes)
}

// GO-SEC-015: Hardcoded IV
var iv = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}

// GO-SEC-016: Unhandled error
func unhandledError(path string) {
	result, _ := os.Open(path)
	_ = result
}

// GO-SEC-017: Defer in loop
func deferInLoop(files []string) {
	for _, f := range files {
		file, _ := os.Open(f)
		defer file.Close()
	}
}

// GO-SEC-018: Unsafe pointer
func unsafePointerUse(ptr *int) {
	p := unsafe.Pointer(ptr)
	_ = p
}

// GO-SEC-019: CGo injection
func cgoInjection(input string) {
	C.CString(input)
}

// GO-SEC-020: Open redirect
func openRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("next"), 302)
}

// GO-SEC-021: CORS wildcard
func corsWildcard() {
	config := struct{ AllowAllOrigins bool }{AllowAllOrigins: true}
	_ = config
}

// GO-SEC-022: JWT none algorithm
func jwtNone() {
	_ = jwt.UnsafeAllowNoneSignatureType
}

// GO-SEC-023: Missing CSRF
func setupRoutes() {
	router.POST("/submit", handleSubmit)
}

// GO-SEC-024: Debug mode
func debugMode() {
	gin.SetMode(gin.DebugMode)
}

// GO-SEC-025: Error info leak
func errorInfoLeak(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), 500)
}

// GO-SEC-026: Sensitive logging
func sensitiveLog(password string) {
	log.Println("password:", password)
}

// GO-SEC-027: File permissions
func insecureFilePerms(data []byte) {
	os.WriteFile("data.txt", data, 0777)
}

// GO-SEC-028: Race condition (goroutine)
func raceCondition() {
	go func() {
		sharedVar := 1
		_ = sharedVar
	}()
}

// GO-SEC-029: Goroutine leak
func goroutineLeak(n int64) {
	go func() {
		time.Sleep(time.Duration(n))
	}()
}

// GO-SEC-030: Template injection
func templateInjection(userInput string) {
	template.New("t").Parse(userInput + " extra")
}

// GO-SEC-031: XXE parsing
func xxeParsing(reader interface{}) {
	xml.NewDecoder(nil)
}

// GO-SEC-032: Insecure deserialization (gob)
func insecureDeserialization(conn interface{}) {
	gob.NewDecoder(nil)
}

// GO-SEC-033: Unsafe YAML unmarshal
func unsafeYaml(data []byte) {
	var cfg interface{}
	yaml.Unmarshal(data, &cfg)
}

// GO-SEC-034: Hardcoded connection string
func hardcodedConnStr() {
	sql.Open("postgres", "postgres://user:pass@host/db")
}

// GO-SEC-035: Unvalidated redirect
func unvalidatedRedirect(w http.ResponseWriter, r *http.Request, target string) {
	http.Redirect(w, r, target, 302)
}

// GO-SEC-036: Zip slip
func zipSlip(path string, dest string) {
	reader, _ := zip.OpenReader(path)
	for _, f := range reader.File {
		outPath := filepath.Join(dest, f.Name)
		_ = outPath
	}
}

// GO-SEC-037: Missing TLS
func missingTLS() {
	addr := "http://localhost:8080"
	_ = addr
	http.ListenAndServe(":8080", nil)
}

// GO-SEC-038: HTTP serve no timeout
func httpNoTimeout() {
	http.ListenAndServe(":9090", nil)
}

// GO-SEC-039: SQL string concat
func sqlStringConcat(id string) {
	query := "SELECT * FROM users WHERE id=" + id
	_ = query
}

// GO-SEC-040: NoSQL injection
func nosqlInjection(name string, input string) {
	filter := bson.M{"name": name + input}
	_ = filter
}

// GO-SEC-041: LDAP injection
func ldapInjection(username string) {
	fmt.Sprintf("(cn=%s)", username)
}

// GO-SEC-042: Regex DoS
func regexDos() {
	regexp.MustCompile("(a+)*b")
}

// GO-SEC-043: Mass assignment
func massAssignment(r *http.Request) {
	var user struct{ Name string }
	json.NewDecoder(r.Body).Decode(&user)
}

// GO-SEC-044: Timing attack
func timingAttack(token string, secret string) {
	if token == secret {
		return
	}
}

// GO-SEC-045: Gin no trusted proxies
func ginNoTrustedProxies() {
	r := gin.Default()
	_ = r
}

// GO-SEC-046: gRPC no TLS
func grpcNoTLS(addr string) {
	conn, _ := grpc.Dial(addr, grpc.WithInsecure())
	_ = conn
}

// GO-SEC-047: Filepath clean
func filepathClean(r *http.Request) {
	file, _ := os.Open(r.URL.Query().Get("path"))
	_ = file
}

// GO-SEC-048: Integer overflow
func integerOverflow(bigNum int64) {
	small := int32(bigNum)
	_ = small
}

// GO-SEC-049: DNS rebinding
func dnsRebinding(hostname string) {
	addrs, _ := net.LookupHost(hostname)
	_ = addrs
}

// GO-SEC-050: Unescaped HTML
func unescapedHTML(w http.ResponseWriter) {
	fmt.Fprintf(w, "<h1>Hello</h1>")
}
