package com.kiro.security.scanners;

import com.kiro.security.core.*;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.regex.*;

/**
 * Dependency Scanner — parses package.json and requirements.txt to check
 * for packages with known CVEs using an embedded vulnerability database.
 */
public class DependencyScanner implements BaseScanner {

    @Override
    public String getName() { return "Dependency Scanner"; }

    @Override
    public String getCategory() { return "dependency"; }

    @Override
    public List<Finding> scan(Path targetDir) throws Exception {
        List<Finding> findings = new ArrayList<>();

        // Scan npm package.json files
        for (Path pj : findFiles(targetDir, "package.json")) {
            String relativePath = targetDir.relativize(pj).toString();
            try {
                String content = Files.readString(pj);
                Map<String, String> deps = parsePackageJson(content);
                findings.addAll(checkDeps(deps, "npm", relativePath));
            } catch (IOException e) { /* skip */ }
        }

        // Scan Python requirements.txt files
        for (Path req : findFiles(targetDir, "requirements*.txt")) {
            String relativePath = targetDir.relativize(req).toString();
            try {
                String content = Files.readString(req);
                Map<String, String> deps = parseRequirementsTxt(content);
                findings.addAll(checkDeps(deps, "pip", relativePath));
            } catch (IOException e) { /* skip */ }
        }

        // Scan Maven pom.xml files
        for (Path pom : findFiles(targetDir, "pom.xml")) {
            String relativePath = targetDir.relativize(pom).toString();
            try {
                String content = Files.readString(pom);
                Map<String, String> deps = parsePomXml(content);
                findings.addAll(checkDeps(deps, "maven", relativePath));
            } catch (IOException e) { /* skip */ }
        }

        return findings;
    }

    private List<Path> findFiles(Path targetDir, String globPattern) throws IOException {
        List<Path> matches = new ArrayList<>();
        String glob = "glob:**/" + globPattern;
        PathMatcher matcher = FileSystems.getDefault().getPathMatcher(glob);

        Files.walkFileTree(targetDir, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                String name = dir.getFileName().toString();
                if (Set.of("node_modules", ".git", ".venv", "venv", "target").contains(name)) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (matcher.matches(file)) {
                    matches.add(file);
                }
                return FileVisitResult.CONTINUE;
            }
        });
        return matches;
    }

    /**
     * Parse Maven pom.xml — extracts groupId:artifactId and version from dependency blocks.
     */
    private Map<String, String> parsePomXml(String content) {
        Map<String, String> deps = new HashMap<>();
        // Match <dependency> blocks
        Pattern depBlock = Pattern.compile("<dependency>\\s*(.*?)\\s*</dependency>", Pattern.DOTALL);
        Pattern groupId = Pattern.compile("<groupId>([^<]+)</groupId>");
        Pattern artifactId = Pattern.compile("<artifactId>([^<]+)</artifactId>");
        Pattern version = Pattern.compile("<version>([^<$]+)</version>");

        var blockMatcher = depBlock.matcher(content);
        while (blockMatcher.find()) {
            String block = blockMatcher.group(1);
            var gm = groupId.matcher(block);
            var am = artifactId.matcher(block);
            var vm = version.matcher(block);
            if (gm.find() && am.find()) {
                String key = am.group(1).toLowerCase();
                String ver = vm.find() ? vm.group(1) : "0.0.0";
                deps.put(key, ver);
            }
        }
        return deps;
    }

    /**
     * Simple package.json parser — extracts dependency name:version from
     * "dependencies" and "devDependencies" sections.
     */
    private Map<String, String> parsePackageJson(String content) {
        Map<String, String> deps = new HashMap<>();
        Pattern depBlock = Pattern.compile("\"(?:dependencies|devDependencies)\"\\s*:\\s*\\{([^}]*)\\}", Pattern.DOTALL);
        Pattern entry = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"([^\"]+)\"");

        var blockMatcher = depBlock.matcher(content);
        while (blockMatcher.find()) {
            var entryMatcher = entry.matcher(blockMatcher.group(1));
            while (entryMatcher.find()) {
                deps.put(entryMatcher.group(1).toLowerCase(), entryMatcher.group(2));
            }
        }
        return deps;
    }

    /**
     * Parse requirements.txt — extracts package==version or package>=version.
     */
    private Map<String, String> parseRequirementsTxt(String content) {
        Map<String, String> deps = new HashMap<>();
        Pattern pattern = Pattern.compile("^([a-zA-Z0-9_.-]+)\\s*[=><~!]+\\s*([0-9.]+)", Pattern.MULTILINE);
        var matcher = pattern.matcher(content);
        while (matcher.find()) {
            deps.put(matcher.group(1).toLowerCase(), matcher.group(2));
        }
        return deps;
    }

    private List<Finding> checkDeps(Map<String, String> deps, String ecosystem, String file) {
        List<Finding> findings = new ArrayList<>();
        Map<String, List<VulnEntry>> db = switch (ecosystem) {
            case "npm" -> NPM_VULNS;
            case "pip" -> PIP_VULNS;
            case "maven" -> MAVEN_VULNS;
            default -> Map.of();
        };

        for (var entry : deps.entrySet()) {
            String name = entry.getKey();
            String versionRaw = entry.getValue();
            String version = versionRaw.replaceAll("^[\\^~>=<]+", "");

            List<VulnEntry> vulns = db.get(name);
            if (vulns == null) continue;

            for (VulnEntry vuln : vulns) {
                if (isBelow(version, vuln.below)) {
                    findings.add(Finding.builder()
                            .id("DEP-%s-%s".formatted(vuln.cve, name))
                            .title(vuln.title)
                            .description("%s\n\nInstalled: %s@%s (vulnerable below %s)".formatted(
                                    vuln.description, name, version, vuln.below))
                            .severity(vuln.severity)
                            .category("dependency")
                            .subcategory("known-cve")
                            .file(file)
                            .snippet("%s: %s".formatted(name, versionRaw))
                            .remediation(vuln.remediation)
                            .references(List.of("https://nvd.nist.gov/vuln/detail/" + vuln.cve))
                            .cweId(vuln.cweId)
                            .cveId(vuln.cve)
                            .businessImpact(vuln.severity == Severity.CRITICAL ? BusinessImpact.CRITICAL :
                                    vuln.severity == Severity.HIGH ? BusinessImpact.HIGH : BusinessImpact.MEDIUM)
                            .confidence(Confidence.HIGH)
                            .build());
                }
            }
        }
        return findings;
    }

    /**
     * Simple semver "below" comparison (major.minor.patch).
     */
    private boolean isBelow(String current, String threshold) {
        int[] c = parseSemver(current);
        int[] t = parseSemver(threshold);
        for (int i = 0; i < 3; i++) {
            if (c[i] != t[i]) return c[i] < t[i];
        }
        return false;
    }

    private int[] parseSemver(String version) {
        String[] parts = (version == null ? "0.0.0" : version).split("\\.");
        int[] result = new int[3];
        for (int i = 0; i < Math.min(parts.length, 3); i++) {
            try { result[i] = Integer.parseInt(parts[i]); } catch (NumberFormatException e) { result[i] = 0; }
        }
        return result;
    }

    // --- Embedded Vulnerability Database ---

    private record VulnEntry(String below, String cve, Severity severity, String title,
                             String description, String remediation, String cweId) {}

    private static final Map<String, List<VulnEntry>> NPM_VULNS = Map.ofEntries(
            Map.entry("lodash", List.of(
                    new VulnEntry("4.17.21", "CVE-2021-23337", Severity.HIGH, "Lodash Command Injection",
                            "Lodash versions before 4.17.21 are vulnerable to Command Injection via the template function.",
                            "Upgrade lodash to >= 4.17.21", "CWE-77"),
                    new VulnEntry("4.17.20", "CVE-2020-28500", Severity.MEDIUM, "Lodash ReDoS",
                            "Lodash versions before 4.17.20 are vulnerable to Regular Expression Denial of Service (ReDoS).",
                            "Upgrade lodash to >= 4.17.21", "CWE-1333"))),
            Map.entry("express", List.of(
                    new VulnEntry("4.19.2", "CVE-2024-29041", Severity.MEDIUM, "Express Open Redirect",
                            "Express before 4.19.2 allows open redirect via malicious URL in res.redirect().",
                            "Upgrade express to >= 4.19.2", "CWE-601"))),
            Map.entry("axios", List.of(
                    new VulnEntry("1.6.0", "CVE-2023-45857", Severity.HIGH, "Axios CSRF Token Exposure",
                            "Axios before 1.6.0 inadvertently leaks the XSRF-TOKEN cookie to third-party hosts.",
                            "Upgrade axios to >= 1.6.0", "CWE-352"))),
            Map.entry("jsonwebtoken", List.of(
                    new VulnEntry("9.0.0", "CVE-2022-23529", Severity.CRITICAL, "JWT Secret Poisoning",
                            "jsonwebtoken before 9.0.0 allows attackers to forge tokens by exploiting insecure key handling.",
                            "Upgrade jsonwebtoken to >= 9.0.0", "CWE-20"))),
            Map.entry("minimist", List.of(
                    new VulnEntry("1.2.6", "CVE-2021-44906", Severity.CRITICAL, "Minimist Prototype Pollution",
                            "Minimist before 1.2.6 is vulnerable to prototype pollution.",
                            "Upgrade minimist to >= 1.2.6", "CWE-1321"))),
            Map.entry("tar", List.of(
                    new VulnEntry("6.1.9", "CVE-2021-37701", Severity.HIGH, "Tar Arbitrary File Creation",
                            "The tar package before 6.1.9 allows arbitrary file creation/overwrite via symlink.",
                            "Upgrade tar to >= 6.1.9", "CWE-22"))),
            Map.entry("node-fetch", List.of(
                    new VulnEntry("2.6.7", "CVE-2022-0235", Severity.HIGH, "Node-fetch Credential Exposure",
                            "node-fetch before 2.6.7 forwards authorization headers to third-party domains on redirect.",
                            "Upgrade node-fetch to >= 2.6.7 or 3.1.1+", "CWE-601"))),
            Map.entry("ejs", List.of(
                    new VulnEntry("3.1.7", "CVE-2022-29078", Severity.CRITICAL, "EJS Server-Side Template Injection",
                            "EJS before 3.1.7 allows server-side template injection via settings[view options][outputFunctionName].",
                            "Upgrade ejs to >= 3.1.7", "CWE-94"))),
            Map.entry("moment", List.of(
                    new VulnEntry("999.0.0", "CVE-2022-31129", Severity.HIGH, "Moment.js ReDoS",
                            "Moment.js is vulnerable to ReDoS when parsing user-supplied dates. The library is now deprecated.",
                            "Migrate to date-fns, dayjs, or Luxon.", "CWE-1333")))
    );

    private static final Map<String, List<VulnEntry>> PIP_VULNS = Map.ofEntries(
            Map.entry("django", List.of(
                    new VulnEntry("4.2.11", "CVE-2024-27351", Severity.HIGH, "Django ReDoS in Truncator",
                            "Django before 4.2.11 is vulnerable to ReDoS via django.utils.text.Truncator.",
                            "Upgrade Django to >= 4.2.11", "CWE-1333"))),
            Map.entry("flask", List.of(
                    new VulnEntry("2.3.2", "CVE-2023-30861", Severity.HIGH, "Flask Session Cookie Exposure",
                            "Flask before 2.3.2 may expose session cookies to unauthorized parties.",
                            "Upgrade Flask to >= 2.3.2", "CWE-539"))),
            Map.entry("requests", List.of(
                    new VulnEntry("2.31.0", "CVE-2023-32681", Severity.MEDIUM, "Requests Auth Header Leak",
                            "Python requests before 2.31.0 leaks Proxy-Authorization headers to destination servers.",
                            "Upgrade requests to >= 2.31.0", "CWE-200"))),
            Map.entry("pyyaml", List.of(
                    new VulnEntry("6.0.1", "CVE-2020-14343", Severity.CRITICAL, "PyYAML Arbitrary Code Execution",
                            "PyYAML before 6.0.1 allows arbitrary code execution via yaml.load() with unsafe Loader.",
                            "Upgrade PyYAML and always use yaml.safe_load()", "CWE-502"))),
            Map.entry("pillow", List.of(
                    new VulnEntry("10.2.0", "CVE-2023-50447", Severity.CRITICAL, "Pillow Arbitrary Code Execution",
                            "Pillow before 10.2.0 allows arbitrary code execution if ImageMath.eval is used with user input.",
                            "Upgrade Pillow to >= 10.2.0", "CWE-94")))
    );

    private static final Map<String, List<VulnEntry>> MAVEN_VULNS = Map.ofEntries(
            Map.entry("spring-boot-starter", List.of(
                    new VulnEntry("3.2.4", "CVE-2024-22243", Severity.HIGH, "Spring Framework URL Parsing Vulnerability",
                            "Spring Boot before 3.2.4 includes Spring Framework vulnerable to URL parsing issues that can lead to open redirect or SSRF.",
                            "Upgrade Spring Boot to >= 3.2.4", "CWE-601"))),
            Map.entry("spring-boot-starter-web", List.of(
                    new VulnEntry("3.2.4", "CVE-2024-22259", Severity.HIGH, "Spring MVC URL Parsing Vulnerability",
                            "Spring Boot Starter Web before 3.2.4 is vulnerable to URL parsing attacks in Spring MVC.",
                            "Upgrade Spring Boot to >= 3.2.4", "CWE-601"))),
            Map.entry("spring-boot-starter-security", List.of(
                    new VulnEntry("3.2.3", "CVE-2024-22234", Severity.HIGH, "Spring Security Authorization Bypass",
                            "Spring Security before 6.2.2 (Boot 3.2.3) may allow authorization bypass under certain configurations.",
                            "Upgrade Spring Boot to >= 3.2.3", "CWE-863"))),
            Map.entry("log4j-core", List.of(
                    new VulnEntry("2.17.1", "CVE-2021-44228", Severity.CRITICAL, "Log4Shell Remote Code Execution",
                            "Apache Log4j2 before 2.17.1 allows remote code execution via JNDI lookup in log messages. This is the Log4Shell vulnerability.",
                            "Upgrade log4j-core to >= 2.17.1", "CWE-502"))),
            Map.entry("log4j-api", List.of(
                    new VulnEntry("2.17.1", "CVE-2021-44228", Severity.CRITICAL, "Log4Shell (API)",
                            "Log4j API should be updated alongside log4j-core to >= 2.17.1.",
                            "Upgrade log4j-api to >= 2.17.1", "CWE-502"))),
            Map.entry("jackson-databind", List.of(
                    new VulnEntry("2.15.0", "CVE-2022-42003", Severity.HIGH, "Jackson Deserialization Vulnerability",
                            "Jackson-databind before 2.15.0 is vulnerable to unsafe deserialization when UNWRAP_SINGLE_VALUE_ARRAYS is enabled.",
                            "Upgrade jackson-databind to >= 2.15.0", "CWE-502"))),
            Map.entry("commons-text", List.of(
                    new VulnEntry("1.10.0", "CVE-2022-42889", Severity.CRITICAL, "Apache Commons Text RCE (Text4Shell)",
                            "Apache Commons Text before 1.10.0 allows remote code execution via StringSubstitutor interpolation.",
                            "Upgrade commons-text to >= 1.10.0", "CWE-94"))),
            Map.entry("snakeyaml", List.of(
                    new VulnEntry("2.0", "CVE-2022-1471", Severity.CRITICAL, "SnakeYAML RCE via Constructor",
                            "SnakeYAML before 2.0 allows remote code execution when using the Constructor class with untrusted input.",
                            "Upgrade SnakeYAML to >= 2.0 or use SafeConstructor", "CWE-502"))),
            Map.entry("h2", List.of(
                    new VulnEntry("2.1.210", "CVE-2021-42392", Severity.CRITICAL, "H2 Database RCE",
                            "H2 Database before 2.1.210 allows remote code execution via JNDI injection in the H2 Console.",
                            "Upgrade H2 to >= 2.1.210 and disable H2 Console in production", "CWE-502"))),
            Map.entry("tomcat-embed-core", List.of(
                    new VulnEntry("10.1.19", "CVE-2024-23672", Severity.HIGH, "Tomcat WebSocket DoS",
                            "Apache Tomcat before 10.1.19 is vulnerable to denial of service via WebSocket connections.",
                            "Upgrade Tomcat to >= 10.1.19", "CWE-400"))),
            Map.entry("spring-web", List.of(
                    new VulnEntry("6.1.5", "CVE-2024-22243", Severity.HIGH, "Spring Web URL Parsing Issue",
                            "Spring Web before 6.1.5 has URL parsing vulnerabilities that could allow open redirect attacks.",
                            "Upgrade spring-web to >= 6.1.5", "CWE-601"))),
            Map.entry("camel-spring-boot-starter", List.of(
                    new VulnEntry("4.4.0", "CVE-2024-22369", Severity.HIGH, "Apache Camel XML Injection",
                            "Apache Camel before 4.4.0 is vulnerable to XML injection attacks in certain components.",
                            "Upgrade Camel to >= 4.4.0", "CWE-91"))),
            Map.entry("guava", List.of(
                    new VulnEntry("32.0.0", "CVE-2023-2976", Severity.MEDIUM, "Guava Temp Directory Vulnerability",
                            "Google Guava before 32.0.0 creates temp directories with overly permissive access, allowing local information disclosure.",
                            "Upgrade Guava to >= 32.0.0", "CWE-732"))),
            Map.entry("commons-io", List.of(
                    new VulnEntry("2.14.0", "CVE-2024-47554", Severity.MEDIUM, "Commons IO Path Traversal",
                            "Apache Commons IO before 2.14.0 may be vulnerable to path traversal in certain file operations.",
                            "Upgrade commons-io to >= 2.14.0", "CWE-22"))),
            Map.entry("junit", List.of(
                    new VulnEntry("4.13.1", "CVE-2020-15250", Severity.MEDIUM, "JUnit4 Temp Folder Vulnerability",
                            "JUnit4 before 4.13.1 creates temp files with insecure permissions in TemporaryFolder rule.",
                            "Upgrade JUnit to >= 4.13.1 or migrate to JUnit 5", "CWE-732")))
    );
}
