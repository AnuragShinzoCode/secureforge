package com.kiro.security.scanners;

import com.kiro.security.core.*;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Source Code Scanner — detects common vulnerabilities via pattern matching:
 * SQL injection, XSS, hardcoded secrets, insecure crypto, command injection,
 * path traversal, insecure deserialization, debug/logging leaks, etc.
 */
public class SourceCodeScanner implements BaseScanner {

    private static final Set<String> EXTENSIONS = Set.of(
            ".js", ".ts", ".jsx", ".tsx", ".py", ".java", ".rb",
            ".php", ".go", ".cs", ".swift"
    );

    private static final Set<String> IGNORE_DIRS = Set.of(
            "node_modules", "vendor", ".git", "dist", "build", "target", ".gradle"
    );

    private final List<ScanRule> rules = buildRules();

    @Override
    public String getName() { return "Source Code Scanner"; }

    @Override
    public String getCategory() { return "source-code"; }

    @Override
    public List<Finding> scan(Path targetDir) throws Exception {
        List<Finding> findings = new ArrayList<>();
        List<Path> files = collectFiles(targetDir);

        for (Path file : files) {
            String relativePath = targetDir.relativize(file).toString();
            try {
                List<String> lines = Files.readAllLines(file);
                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i);
                    for (ScanRule rule : rules) {
                        var matcher = rule.pattern().matcher(line);
                        if (matcher.find()) {
                            findings.add(Finding.builder()
                                    .id("SRC-%s-%s-%d".formatted(rule.id(), relativePath, i + 1))
                                    .title(rule.title())
                                    .description(rule.description())
                                    .severity(rule.severity())
                                    .category("source-code")
                                    .subcategory(rule.subcategory())
                                    .file(relativePath)
                                    .line(i + 1)
                                    .column(matcher.start() + 1)
                                    .snippet(line.trim())
                                    .remediation(rule.remediation())
                                    .references(rule.references())
                                    .cweId(rule.cweId())
                                    .businessImpact(rule.businessImpact())
                                    .confidence(rule.confidence())
                                    .build());
                        }
                    }
                }
            } catch (IOException e) {
                // skip unreadable files
            }
        }

        return findings;
    }

    private List<Path> collectFiles(Path targetDir) throws IOException {
        List<Path> files = new ArrayList<>();
        Files.walkFileTree(targetDir, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (IGNORE_DIRS.contains(dir.getFileName().toString())) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                String name = file.getFileName().toString();
                int dot = name.lastIndexOf('.');
                if (dot >= 0 && EXTENSIONS.contains(name.substring(dot))) {
                    files.add(file);
                }
                return FileVisitResult.CONTINUE;
            }
        });
        return files;
    }

    private static List<ScanRule> buildRules() {
        return List.of(
                // --- SQL Injection ---
                new ScanRule("SQLI-001", "Potential SQL Injection",
                        "String concatenation used in SQL query construction. User input may be directly interpolated into SQL statements.",
                        "sql-injection",
                        Pattern.compile("(?:query|execute|exec|raw)\\s*\\(\\s*[`\"'].*?\\$\\{|(?:query|execute|exec)\\s*\\(\\s*[\"'].*?\\+\\s*(?:req\\.|input|user|params|body)", Pattern.CASE_INSENSITIVE),
                        Severity.CRITICAL, BusinessImpact.CRITICAL, Confidence.HIGH,
                        "CWE-89",
                        "Use parameterized queries or prepared statements instead of string concatenation. For example, use db.query(\"SELECT * FROM users WHERE id = ?\", [userId]) instead of string interpolation.",
                        List.of("https://owasp.org/www-community/attacks/SQL_Injection")),

                new ScanRule("SQLI-002", "SQL Query Built with String Concatenation",
                        "SQL query is constructed using string concatenation, which may allow SQL injection.",
                        "sql-injection",
                        Pattern.compile("[\"'](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\\s+.*[\"']\\s*\\+", Pattern.CASE_INSENSITIVE),
                        Severity.CRITICAL, BusinessImpact.CRITICAL, Confidence.HIGH,
                        "CWE-89",
                        "Replace string concatenation with parameterized queries. Use your ORM or database driver's built-in parameter binding.",
                        List.of("https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html")),

                // --- XSS ---
                new ScanRule("XSS-001", "Potential Cross-Site Scripting (XSS)",
                        "Direct use of innerHTML or dangerouslySetInnerHTML with potentially unsanitized input.",
                        "xss",
                        Pattern.compile("(?:innerHTML|outerHTML)\\s*=|dangerouslySetInnerHTML|document\\.write\\s*\\(", Pattern.CASE_INSENSITIVE),
                        Severity.HIGH, BusinessImpact.HIGH, Confidence.MEDIUM,
                        "CWE-79",
                        "Use textContent instead of innerHTML, or sanitize HTML using a library like DOMPurify before injection. In React, avoid dangerouslySetInnerHTML unless the content is trusted and sanitized.",
                        List.of("https://owasp.org/www-community/attacks/xss/")),

                new ScanRule("XSS-002", "Unescaped Output in Template",
                        "Using unescaped template syntax that could lead to XSS.",
                        "xss",
                        Pattern.compile("\\{\\{\\{.*\\}\\}\\}|<%[-=].*%>|v-html\\s*=", Pattern.CASE_INSENSITIVE),
                        Severity.HIGH, BusinessImpact.HIGH, Confidence.MEDIUM,
                        "CWE-79",
                        "Use escaped template output (e.g., {{}} instead of {{{}}} in Handlebars). Always sanitize user-generated content before rendering.",
                        List.of("https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html")),

                // --- Hardcoded Secrets ---
                new ScanRule("SEC-001", "Hardcoded API Key or Secret",
                        "A potential API key, secret, or token is hardcoded in source code.",
                        "hardcoded-secret",
                        Pattern.compile("(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|password|passwd|credentials)\\s*[:=]\\s*[\"'][A-Za-z0-9+/=_\\-]{8,}", Pattern.CASE_INSENSITIVE),
                        Severity.CRITICAL, BusinessImpact.CRITICAL, Confidence.HIGH,
                        "CWE-798",
                        "Move secrets to environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.). Use .env files for local development and never commit them to version control.",
                        List.of("https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password")),

                new ScanRule("SEC-002", "Potential AWS Access Key",
                        "A string matching AWS access key format was found in source code.",
                        "hardcoded-secret",
                        Pattern.compile("(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"),
                        Severity.CRITICAL, BusinessImpact.CRITICAL, Confidence.HIGH,
                        "CWE-798",
                        "Immediately rotate the exposed AWS key. Use IAM roles, instance profiles, or AWS Secrets Manager instead of hardcoded credentials.",
                        List.of("https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html")),

                new ScanRule("SEC-003", "Private Key Embedded in Code",
                        "A private key header was found embedded in source code.",
                        "hardcoded-secret",
                        Pattern.compile("-----BEGIN\\s+(?:RSA\\s+)?PRIVATE\\s+KEY-----"),
                        Severity.CRITICAL, BusinessImpact.CRITICAL, Confidence.HIGH,
                        "CWE-321",
                        "Never embed private keys in source code. Store them in a secure key management system and reference them via environment variables or config files excluded from version control.",
                        List.of("https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html")),

                // --- Insecure Cryptography ---
                new ScanRule("CRYPTO-001", "Use of Weak Hashing Algorithm (MD5/SHA1)",
                        "MD5 or SHA1 are cryptographically broken and should not be used for security purposes.",
                        "insecure-crypto",
                        Pattern.compile("(?:createHash|hashlib\\.)\\s*\\(\\s*[\"'](?:md5|sha1)[\"']\\)|MD5\\s*\\(|SHA1\\s*\\(", Pattern.CASE_INSENSITIVE),
                        Severity.HIGH, BusinessImpact.HIGH, Confidence.HIGH,
                        "CWE-328",
                        "Use SHA-256 or SHA-3 for hashing. For password hashing, use bcrypt, scrypt, or Argon2. MD5 and SHA1 are vulnerable to collision attacks.",
                        List.of("https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html")),

                new ScanRule("CRYPTO-002", "Use of Insecure Random Number Generator",
                        "Math.random() is not cryptographically secure and should not be used for security-sensitive operations.",
                        "insecure-crypto",
                        Pattern.compile("Math\\.random\\s*\\(\\s*\\)"),
                        Severity.MEDIUM, BusinessImpact.MEDIUM, Confidence.MEDIUM,
                        "CWE-338",
                        "Use crypto.randomBytes() or crypto.randomUUID() in Node.js, or java.security.SecureRandom in Java for security-sensitive random generation.",
                        List.of("https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html")),

                // --- Command Injection ---
                new ScanRule("CMDI-001", "Potential Command Injection",
                        "User input may be passed directly to shell execution functions.",
                        "command-injection",
                        Pattern.compile("(?:exec|execSync|spawn|spawnSync|system|popen|subprocess\\.call)\\s*\\(\\s*(?:[`\"'].*?\\$\\{|.*?\\+\\s*(?:req\\.|input|user|params))", Pattern.CASE_INSENSITIVE),
                        Severity.CRITICAL, BusinessImpact.CRITICAL, Confidence.MEDIUM,
                        "CWE-78",
                        "Avoid passing user input to shell commands. If necessary, use parameterized APIs (e.g., spawn with argument arrays instead of exec with string interpolation), and validate/sanitize all inputs.",
                        List.of("https://owasp.org/www-community/attacks/Command_Injection")),

                new ScanRule("CMDI-002", "Use of eval() or Function Constructor",
                        "eval() and new Function() can execute arbitrary code and are a common injection vector.",
                        "code-injection",
                        Pattern.compile("\\beval\\s*\\(|new\\s+Function\\s*\\("),
                        Severity.HIGH, BusinessImpact.HIGH, Confidence.MEDIUM,
                        "CWE-95",
                        "Avoid eval() and new Function(). Use JSON.parse() for JSON data, or safer alternatives like vm2 sandboxing if dynamic code execution is truly required.",
                        List.of("https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!")),

                // --- Path Traversal ---
                new ScanRule("PATH-001", "Potential Path Traversal",
                        "File path constructed from user input without validation could allow directory traversal.",
                        "path-traversal",
                        Pattern.compile("(?:readFile|readFileSync|createReadStream|writeFile|open)\\s*\\(\\s*(?:.*?req\\.|.*?params\\.|.*?query\\.|.*?body\\.)", Pattern.CASE_INSENSITIVE),
                        Severity.HIGH, BusinessImpact.HIGH, Confidence.MEDIUM,
                        "CWE-22",
                        "Validate and sanitize file paths. Use path.resolve() and verify the resolved path starts with the intended base directory. Never pass raw user input to file system operations.",
                        List.of("https://owasp.org/www-community/attacks/Path_Traversal")),

                // --- Insecure Configuration ---
                new ScanRule("CFG-001", "CORS Wildcard Origin",
                        "CORS is configured to allow all origins, which could expose the API to cross-origin attacks.",
                        "insecure-config",
                        Pattern.compile("(?:Access-Control-Allow-Origin|cors)\\s*[:(]\\s*[\"']\\*[\"']", Pattern.CASE_INSENSITIVE),
                        Severity.MEDIUM, BusinessImpact.MEDIUM, Confidence.HIGH,
                        "CWE-942",
                        "Restrict CORS to specific trusted origins instead of using wildcard (*). Configure allowed origins explicitly in your CORS middleware.",
                        List.of("https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS")),

                new ScanRule("CFG-002", "TLS/SSL Verification Disabled",
                        "SSL certificate verification is disabled, making the application vulnerable to man-in-the-middle attacks.",
                        "insecure-config",
                        Pattern.compile("rejectUnauthorized\\s*:\\s*false|VERIFY_NONE|verify\\s*=\\s*False|InsecureSkipVerify\\s*:\\s*true", Pattern.CASE_INSENSITIVE),
                        Severity.HIGH, BusinessImpact.HIGH, Confidence.HIGH,
                        "CWE-295",
                        "Always enable SSL/TLS certificate verification in production. If self-signed certificates are needed for development, use a local CA instead of disabling verification.",
                        List.of("https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html")),

                // --- Debug / Logging ---
                new ScanRule("LOG-001", "Sensitive Data in Logs",
                        "Logging statements appear to interpolate sensitive data such as passwords, tokens, or personal information into output.",
                        "info-leak",
                        Pattern.compile("(?:console\\.log|log\\.(?:info|debug|warn|error|trace)|System\\.out\\.print|logger\\.(?:info|debug|warn|error))\\s*\\(.*(?:\\+\\s*(?:password|token|secret|apiKey|credential)|\\{\\}.*(?:password|token|secret|apiKey|credential)|,\\s*(?:password|token|secret|apiKey|credential)\\b)", Pattern.CASE_INSENSITIVE),
                        Severity.MEDIUM, BusinessImpact.MEDIUM, Confidence.MEDIUM,
                        "CWE-532",
                        "Sanitize log output to remove sensitive data. Use structured logging libraries that support field redaction. Never log passwords, tokens, or PII.",
                        List.of("https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html")),

                // --- Java-Specific ---
                new ScanRule("JAVA-SQLI-001", "Java SQL Injection via String Concatenation",
                        "SQL query built with string concatenation in Java. Use PreparedStatement with parameterized queries instead.",
                        "sql-injection",
                        Pattern.compile("(?:createStatement|executeQuery|executeUpdate|execute)\\s*\\(\\s*[\"'].*\\+|Statement\\s+.*=.*createStatement", Pattern.CASE_INSENSITIVE),
                        Severity.CRITICAL, BusinessImpact.CRITICAL, Confidence.HIGH,
                        "CWE-89",
                        "Use PreparedStatement with parameter binding instead of string concatenation: conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\").",
                        List.of("https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html")),

                new ScanRule("JAVA-CRYPTO-001", "Java Weak Hashing (MD5/SHA1)",
                        "MessageDigest.getInstance with MD5 or SHA-1 is cryptographically weak.",
                        "insecure-crypto",
                        Pattern.compile("MessageDigest\\.getInstance\\s*\\(\\s*[\"'](?:MD5|SHA-?1)[\"']", Pattern.CASE_INSENSITIVE),
                        Severity.HIGH, BusinessImpact.HIGH, Confidence.HIGH,
                        "CWE-328",
                        "Use MessageDigest.getInstance(\"SHA-256\") or stronger. For passwords, use BCrypt, SCrypt, or Argon2.",
                        List.of("https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html")),

                new ScanRule("JAVA-CRYPTO-002", "Java Insecure Random (java.util.Random)",
                        "java.util.Random is not cryptographically secure. Use java.security.SecureRandom for security-sensitive operations.",
                        "insecure-crypto",
                        Pattern.compile("new\\s+Random\\s*\\(|java\\.util\\.Random"),
                        Severity.MEDIUM, BusinessImpact.MEDIUM, Confidence.MEDIUM,
                        "CWE-338",
                        "Use java.security.SecureRandom instead of java.util.Random for generating tokens, keys, or other security-sensitive values.",
                        List.of("https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html")),

                new ScanRule("JAVA-DESER-001", "Java Unsafe Deserialization",
                        "ObjectInputStream.readObject() without input validation can lead to remote code execution.",
                        "insecure-deserialization",
                        Pattern.compile("ObjectInputStream|readObject\\s*\\(|readUnshared\\s*\\(|\\.fromXML\\s*\\(", Pattern.CASE_INSENSITIVE),
                        Severity.CRITICAL, BusinessImpact.CRITICAL, Confidence.MEDIUM,
                        "CWE-502",
                        "Avoid Java native deserialization with untrusted input. Use safe alternatives like JSON (Jackson/Gson). If unavoidable, use ValidatingObjectInputStream with allowlists.",
                        List.of("https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html")),

                new ScanRule("JAVA-JNDI-001", "Potential JNDI Injection",
                        "JNDI lookups with user-controlled input can lead to remote code execution (Log4Shell-style attacks).",
                        "code-injection",
                        Pattern.compile("(?:InitialContext|Context)\\.lookup\\s*\\(|JndiLookup|jndi:", Pattern.CASE_INSENSITIVE),
                        Severity.CRITICAL, BusinessImpact.CRITICAL, Confidence.MEDIUM,
                        "CWE-917",
                        "Never pass user-controlled input to JNDI lookups. Disable JNDI lookup in logging frameworks. Use allowlists for JNDI names.",
                        List.of("https://cheatsheetseries.owasp.org/cheatsheets/JNDI_Injection_Prevention_Cheat_Sheet.html")),

                new ScanRule("JAVA-XXEI-001", "XML External Entity (XXE) Risk",
                        "XML parsing without disabling external entities can lead to XXE attacks causing data exfiltration or SSRF.",
                        "xxe",
                        Pattern.compile("DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory", Pattern.CASE_INSENSITIVE),
                        Severity.MEDIUM, BusinessImpact.HIGH, Confidence.LOW,
                        "CWE-611",
                        "Disable external entities and DTDs in XML parsers. Set features: FEATURE_SECURE_PROCESSING, disallow-doctype-decl, external-general-entities=false.",
                        List.of("https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html")),

                new ScanRule("JAVA-CMD-001", "Java Runtime Command Execution",
                        "Runtime.exec() or ProcessBuilder with dynamic input may allow command injection.",
                        "command-injection",
                        Pattern.compile("Runtime\\.getRuntime\\s*\\(\\s*\\)\\.exec|new\\s+ProcessBuilder\\s*\\(", Pattern.CASE_INSENSITIVE),
                        Severity.HIGH, BusinessImpact.HIGH, Confidence.MEDIUM,
                        "CWE-78",
                        "Avoid Runtime.exec(). If shell commands are necessary, use ProcessBuilder with explicit argument lists (not a single string) and validate all inputs.",
                        List.of("https://owasp.org/www-community/attacks/Command_Injection")),

                new ScanRule("JAVA-SSL-001", "Java TLS Verification Disabled",
                        "TrustAllCerts or disabled hostname verification makes the app vulnerable to MITM attacks.",
                        "insecure-config",
                        Pattern.compile("TrustAll|ALLOW_ALL_HOSTNAME|setHostnameVerifier|TrustSelfSignedStrategy|X509TrustManager\\s*\\(\\s*\\)|trustAllCerts", Pattern.CASE_INSENSITIVE),
                        Severity.HIGH, BusinessImpact.HIGH, Confidence.HIGH,
                        "CWE-295",
                        "Never disable TLS certificate or hostname verification in production. Use proper certificate management and trusted CAs.",
                        List.of("https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html")),

                new ScanRule("JAVA-SPRING-001", "Spring CSRF Protection Disabled",
                        "Disabling CSRF protection in Spring Security removes protection against cross-site request forgery attacks.",
                        "insecure-config",
                        Pattern.compile("csrf\\s*\\(\\s*\\)\\s*\\.\\s*disable|csrf\\.disable", Pattern.CASE_INSENSITIVE),
                        Severity.MEDIUM, BusinessImpact.MEDIUM, Confidence.HIGH,
                        "CWE-352",
                        "Keep CSRF protection enabled for web applications that use session cookies. Only disable for purely stateless APIs using token-based auth.",
                        List.of("https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html"))
        );
    }
}
