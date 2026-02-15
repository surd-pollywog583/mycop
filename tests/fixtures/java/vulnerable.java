import java.sql.*;
import java.util.Random;
import java.io.*;
import java.security.MessageDigest;
import java.util.regex.Pattern;
import java.net.Socket;
import java.net.URL;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.crypto.spec.IvParameterSpec;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

@SuppressWarnings("all")
class vulnerable {

    private static final Logger logger = Logger.getLogger(vulnerable.class.getName());

    // JAVA-SEC-001: SQL injection
    public void sqlInjection(Connection conn, String id) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id=" + id);
    }

    // JAVA-SEC-002: Command injection
    public void commandInjection(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }

    // JAVA-SEC-003: Hardcoded secret
    public static final String API_KEY = "sk-1234567890abcdef1234567890abcdef";

    // JAVA-SEC-004: Insecure random
    public int insecureRandom() {
        Random random = new Random();
        return random.nextInt(999999);
    }

    // JAVA-SEC-005: Path traversal
    public void pathTraversal(String filename) throws Exception {
        File file = new File("/uploads/" + filename);
        FileInputStream fis = new FileInputStream(file);
        fis.read();
        fis.close();
    }

    // JAVA-SEC-006: XXE parsing
    public void xxeParsing(InputStream is) throws Exception {
        javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder().parse(is);
    }

    // JAVA-SEC-007: XSS servlet
    public void xssServlet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.getWriter().println(request.getParameter("name"));
    }

    // JAVA-SEC-008: Insecure deserialization
    public Object insecureDeserialization(InputStream is) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(is);
        return ois.readObject();
    }

    // JAVA-SEC-009: SSRF
    public void ssrf(String url) throws Exception {
        new URL("http://api.example.com/" + url);
    }

    // JAVA-SEC-010: LDAP injection
    public void ldapInjection(DirContext ctx, String searchBase, String username) throws Exception {
        ctx.search(searchBase, "(cn=" + username);
    }

    // JAVA-SEC-011: Weak hash MD5
    public byte[] weakMd5(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data.getBytes());
    }

    // JAVA-SEC-012: Weak hash SHA1
    public byte[] weakSha1(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(data.getBytes());
    }

    // JAVA-SEC-013: Weak cipher DES
    public void weakCipherDes() throws Exception {
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding");
    }

    // JAVA-SEC-014: ECB mode
    public void ecbMode() throws Exception {
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    // JAVA-SEC-015: Hardcoded IV
    public void hardcodedIV() throws Exception {
        new IvParameterSpec(new byte[]{0x00, 0x01, 0x02, 0x03});
    }

    // JAVA-SEC-016: Insecure TLS
    public void insecureTLS() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1");
    }

    // JAVA-SEC-017: JWT none algorithm
    public void jwtNone() {
        Object alg = SignatureAlgorithm.NONE;
    }

    // JAVA-SEC-018: Open redirect
    public void openRedirect(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.sendRedirect(request.getParameter("url"));
    }

    // JAVA-SEC-019: CORS wildcard
    public void corsWildcard(CorsRegistry registry) {
        registry.allowedOrigins("*");
    }

    // JAVA-SEC-020: CSRF disabled
    public void csrfDisabled(HttpSecurity http) throws Exception {
        http.csrf().disable();
    }

    // JAVA-SEC-021: Debug mode
    public void debugEnabled() {
        boolean debug = true;
    }

    // JAVA-SEC-022: Error info leak
    public void errorInfoLeak(Exception e) {
        e.printStackTrace();
    }

    // JAVA-SEC-023: Sensitive logging
    public void sensitiveLogging(String password) {
        logger.info("password: " + password);
    }

    // JAVA-SEC-024: Hardcoded credentials
    String password = "admin123secret";

    // JAVA-SEC-025: Hardcoded connection string
    public void hardcodedConnectionString() throws Exception {
        DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb");
    }

    // JAVA-SEC-026: Eval expression
    public void evalExpression(String input) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        engine.eval(input + " code");
    }

    // JAVA-SEC-027: Template injection
    public void templateInjection(String userInput) throws Exception {
        String template = "Hello";
        String result = Velocity.evaluate(template + userInput);
    }

    // JAVA-SEC-028: XPath injection
    public void xpathInjection(XPathEvaluator xpath, String id) throws Exception {
        xpath.evaluate("//user[@id='" + id + "']");
    }

    // JAVA-SEC-029: Header injection
    public void headerInjection(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.setHeader("X-Custom", request.getParameter("value"));
    }

    // JAVA-SEC-030: Mass assignment
    @ModelAttribute
    public void massAssignment() {
    }

    // JAVA-SEC-031: File upload unrestricted
    public void fileUpload(MultipartFile file) throws Exception {
        String name = file.getOriginalFilename();
    }

    // JAVA-SEC-032: Zip slip
    public void zipSlip(InputStream input) throws Exception {
        java.util.zip.ZipInputStream zis = new java.util.zip.ZipInputStream(input);
        java.util.zip.ZipEntry entry = zis.getNextEntry();
        String name = entry.getName();
    }

    // JAVA-SEC-033: Insecure temp file
    public void insecureTempFile() throws Exception {
        File.createTempFile("data", ".tmp");
    }

    // JAVA-SEC-034: Regex DoS
    public void regexDos() {
        Pattern.compile("(a+)*b");
    }

    // JAVA-SEC-035: Timing attack
    public boolean timingAttack(String input, String password) {
        return password.equals(input);
    }

    // JAVA-SEC-036: Empty catch
    public void emptyCatch() {
        try { riskyMethod(); } catch (Exception e) { }
    }

    // JAVA-SEC-037: NoSQL injection
    public void nosqlInjection(String name, String input) {
        BasicDBObject filter = new BasicDBObject("name", name + input);
    }

    // JAVA-SEC-038: Spring actuator exposed
    public void springActuator() {
        String config = "management.endpoints.web.exposure.include=*";
    }

    // JAVA-SEC-039: Spring SQL injection
    public void springSqlInjection(String param) throws Exception {
        NamedParameterJdbcTemplate namedParameterJdbcTemplate = new NamedParameterJdbcTemplate();
        namedParameterJdbcTemplate.queryForObject("SELECT " + param, String.class);
    }

    // JAVA-SEC-040: Spring XSS
    public void springXss(Model model, HttpServletRequest request) {
        model.addAttribute("data", request.getParameter("input"));
    }

    // JAVA-SEC-041: Hibernate injection
    public void hibernateInjection(HibernateSession session, int minAge) {
        session.createQuery("SELECT u FROM User u WHERE u.age+1 > " + minAge);
    }

    // JAVA-SEC-042: Unsafe reflection
    public void unsafeReflection(String className) throws Exception {
        Class.forName(className + ".Impl");
    }

    // JAVA-SEC-043: Runtime exec with concat
    public void runtimeExecConcat(String cmd, String args) throws Exception {
        Runtime.getRuntime().exec(cmd + args);
    }

    // JAVA-SEC-044: Trust all certificates
    public void trustAllCerts() {
        TrustManager[] managers = new TrustManager[]{ new X509TrustManager() {
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            public X509Certificate[] getAcceptedIssuers() { return null; }
        }};
    }

    // JAVA-SEC-045: Weak password hash
    public byte[] weakPasswordHash(String password) throws Exception {
        return MessageDigest.getInstance("MD5").digest(password.getBytes());
    }

    // JAVA-SEC-046: Session fixation
    public void sessionFixation(HttpSession session, Object user) {
        session.setAttribute("login", user);
    }

    // JAVA-SEC-047: Unencrypted socket
    public void unencryptedSocket(String host, int port) throws Exception {
        Socket sock = new Socket(host, port);
        sock.close();
    }

    // JAVA-SEC-048: Log injection
    public void logInjection(HttpServletRequest request) {
        logger.info(request.getParameter("data"));
    }

    // JAVA-SEC-049: IDOR
    public void idor(HttpServletRequest request) {
        String id = request.getParameter("id");
    }

    // JAVA-SEC-050: Spring security disabled
    public void springSecurityDisabled(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().permitAll();
    }

    private void riskyMethod() throws Exception {
        throw new Exception("error");
    }
}

// === Stub types for third-party framework dependencies ===
// These allow the fixture to compile without adding framework JARs.

@interface ModelAttribute {}

class HttpServletRequest {
    String getParameter(String name) { return ""; }
}

class HttpServletResponse {
    PrintWriter getWriter() { return null; }
    void sendRedirect(String url) {}
    void setHeader(String name, String value) {}
}

class HttpSession {
    void setAttribute(String name, Object value) {}
}

class HttpSecurity {
    CsrfConfigurer csrf() { return new CsrfConfigurer(); }
    AuthConfigurer authorizeRequests() { return new AuthConfigurer(); }
}

class CsrfConfigurer {
    CsrfConfigurer disable() { return this; }
}

class AuthConfigurer {
    AuthConfigurer anyRequest() { return this; }
    AuthConfigurer permitAll() { return this; }
}

class Model {
    void addAttribute(String name, Object value) {}
}

class CorsRegistry {
    void allowedOrigins(String... origins) {}
}

class MultipartFile {
    String getOriginalFilename() { return ""; }
}

class NamedParameterJdbcTemplate {
    Object queryForObject(String sql, Class<?> type) { return null; }
}

class Velocity {
    static String evaluate(String template) { return ""; }
}

class SignatureAlgorithm {
    static final SignatureAlgorithm NONE = new SignatureAlgorithm();
}

class BasicDBObject {
    BasicDBObject(String key, Object value) {}
}

class DirContext {
    void search(String base, String filter) {}
}

class XPathEvaluator {
    void evaluate(String expr) {}
}

class HibernateSession {
    void createQuery(String hql) {}
}
