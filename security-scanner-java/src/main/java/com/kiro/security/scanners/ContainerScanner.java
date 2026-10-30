package com.kiro.security.scanners;

import com.kiro.security.core.*;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.regex.*;

/**
 * Container Scanner — analyzes Dockerfiles and docker-compose files for
 * security best practices: running as root, insecure base images,
 * exposed sensitive ports, missing health checks, etc.
 */
public class ContainerScanner implements BaseScanner {

    private final List<ScanRule> dockerRules = buildDockerfileRules();
    private final List<ScanRule> composeRules = buildComposeRules();

    @Override
    public String getName() { return "Container Scanner"; }

    @Override
    public String getCategory() { return "container"; }

    @Override
    public List<Finding> scan(Path targetDir) throws Exception {
        List<Finding> findings = new ArrayList<>();

        // Scan Dockerfiles
        for (Path df : findByGlob(targetDir, "glob:**/Dockerfile*")) {
            String rel = targetDir.relativize(df).toString();
            try {
                String content = Files.readString(df);
                findings.addAll(analyzeDockerfile(content, rel));
            } catch (IOException e) { /* skip */ }
        }

        // Scan docker-compose files
        for (Path cf : findByGlob(targetDir, "glob:**/docker-compose*.{yml,yaml}")) {
            String rel = targetDir.relativize(cf).toString();
            try {
                String content = Files.readString(cf);
                findings.addAll(analyzeCompose(content, rel));
            } catch (IOException e) { /* skip */ }
        }

        return findings;
    }

    private List<Finding> analyzeDockerfile(String content, String file) {
        List<Finding> findings = new ArrayList<>();
        String[] lines = content.split("\n");

        boolean hasUser = false;
        boolean hasHealthcheck = false;
        String fromImage = null;
        int fromLine = -1;
        String fromText = null;

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();

            if (line.matches("(?i)^USER\\s+(?!root).*")) hasUser = true;
            if (line.matches("(?i)^HEALTHCHECK\\s+.*")) hasHealthcheck = true;

            // Track FROM
            Matcher fromMatch = Pattern.compile("(?i)^FROM\\s+(.+?)(?:\\s+AS\\s+|$)").matcher(line);
            if (fromMatch.find()) {
                fromImage = fromMatch.group(1).trim();
                fromLine = i + 1;
                fromText = line;
            }

            // Check rules
            for (ScanRule rule : dockerRules) {
                if (rule.pattern().matcher(line).find()) {
                    findings.add(createFinding("DOCKER", rule, file, i + 1, line));
                }
            }
        }

        // No USER instruction — runs as root
        if (!hasUser && lines.length > 2) {
            findings.add(Finding.builder()
                    .id("DOCKER-ROOT-%s".formatted(file))
                    .title("Container Runs as Root")
                    .description("No USER instruction found. The container will run as root by default, increasing the blast radius of any container escape.")
                    .severity(Severity.HIGH).category("container").subcategory("privilege-escalation")
                    .file(file).line(1).snippet(lines[0].trim())
                    .remediation("Add a USER instruction to run the container as a non-root user:\n  RUN addgroup -S appgroup && adduser -S appuser -G appgroup\n  USER appuser")
                    .references(List.of("https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user"))
                    .cweId("CWE-250").businessImpact(BusinessImpact.HIGH).confidence(Confidence.HIGH)
                    .build());
        }

        // No HEALTHCHECK
        if (!hasHealthcheck && lines.length > 2) {
            findings.add(Finding.builder()
                    .id("DOCKER-NOHEALTH-%s".formatted(file))
                    .title("Missing HEALTHCHECK Instruction")
                    .description("No HEALTHCHECK instruction found. Without a health check, Docker cannot determine if the application inside the container is healthy.")
                    .severity(Severity.LOW).category("container").subcategory("best-practice")
                    .file(file).line(1)
                    .remediation("Add a HEALTHCHECK instruction:\n  HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8080/health || exit 1")
                    .references(List.of("https://docs.docker.com/engine/reference/builder/#healthcheck"))
                    .businessImpact(BusinessImpact.LOW).confidence(Confidence.HIGH)
                    .build());
        }

        // Base image checks
        if (fromImage != null) {
            record ImageCheck(Pattern pattern, String msg) {}
            List<ImageCheck> checks = List.of(
                    new ImageCheck(Pattern.compile(":latest$", Pattern.CASE_INSENSITIVE), "Using :latest tag is unpredictable. Pin to a specific version."),
                    new ImageCheck(Pattern.compile("^node:\\d+(?!.*(?:alpine|slim|distroless))", Pattern.CASE_INSENSITIVE), "Using full Node.js image. Prefer alpine or slim variants to reduce attack surface."),
                    new ImageCheck(Pattern.compile("^python:\\d+(?!.*(?:alpine|slim))", Pattern.CASE_INSENSITIVE), "Using full Python image. Prefer alpine or slim variants.")
            );
            for (ImageCheck check : checks) {
                if (check.pattern.matcher(fromImage).find()) {
                    findings.add(Finding.builder()
                            .id("DOCKER-IMAGE-%s-%d".formatted(file, fromLine))
                            .title("Insecure or Oversized Base Image")
                            .description("Base image \"%s\": %s".formatted(fromImage, check.msg))
                            .severity(Severity.MEDIUM).category("container").subcategory("base-image")
                            .file(file).line(fromLine).snippet(fromText)
                            .remediation(check.msg + " Smaller images have fewer packages and a reduced attack surface.")
                            .references(List.of("https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#from"))
                            .businessImpact(BusinessImpact.MEDIUM).confidence(Confidence.HIGH)
                            .build());
                    break;
                }
            }
        }

        return findings;
    }

    private List<Finding> analyzeCompose(String content, String file) {
        List<Finding> findings = new ArrayList<>();
        String[] lines = content.split("\n");

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            for (ScanRule rule : composeRules) {
                if (rule.pattern().matcher(line).find()) {
                    findings.add(createFinding("COMPOSE", rule, file, i + 1, line.trim()));
                }
            }
        }
        return findings;
    }

    private Finding createFinding(String prefix, ScanRule rule, String file, int line, String snippet) {
        return Finding.builder()
                .id("%s-%s-%s-%d".formatted(prefix, rule.id(), file, line))
                .title(rule.title()).description(rule.description())
                .severity(rule.severity()).category("container").subcategory(rule.subcategory())
                .file(file).line(line).snippet(snippet)
                .remediation(rule.remediation()).references(rule.references())
                .cweId(rule.cweId()).businessImpact(rule.businessImpact()).confidence(rule.confidence())
                .build();
    }

    private List<Path> findByGlob(Path targetDir, String globStr) throws IOException {
        List<Path> matches = new ArrayList<>();
        PathMatcher matcher = FileSystems.getDefault().getPathMatcher(globStr);
        Files.walkFileTree(targetDir, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                String name = dir.getFileName().toString();
                if (Set.of("node_modules", ".git", "target").contains(name)) return FileVisitResult.SKIP_SUBTREE;
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (matcher.matches(file)) matches.add(file);
                return FileVisitResult.CONTINUE;
            }
        });
        return matches;
    }

    private static List<ScanRule> buildDockerfileRules() {
        return List.of(
                new ScanRule("ADD-001", "Use COPY Instead of ADD",
                        "ADD has extra features (URL fetch, tar extraction) that can be exploited. Use COPY for simple file copying.",
                        "best-practice", Pattern.compile("(?i)^ADD\\s+(?!https?:)"),
                        Severity.LOW, BusinessImpact.LOW, Confidence.HIGH, "CWE-829",
                        "Replace ADD with COPY unless you specifically need ADD's tar extraction or URL download capability.",
                        List.of("https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy")),

                new ScanRule("EXPOSE-001", "Sensitive Port Exposed",
                        "A potentially sensitive port (22/SSH, 3306/MySQL, 5432/PostgreSQL, 6379/Redis, 27017/MongoDB) is exposed.",
                        "network-exposure", Pattern.compile("(?i)^EXPOSE\\s+.*(22|3306|5432|6379|27017|2375)\\b"),
                        Severity.MEDIUM, BusinessImpact.HIGH, Confidence.MEDIUM, "CWE-200",
                        "Avoid exposing database and management ports directly. Use Docker networks for inter-service communication.",
                        List.of("https://docs.docker.com/engine/reference/builder/#expose")),

                new ScanRule("ENV-001", "Secret in ENV Instruction",
                        "Secrets should not be baked into image layers via ENV instructions.",
                        "hardcoded-secret", Pattern.compile("(?i)^ENV\\s+.*(?:PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\\s*="),
                        Severity.CRITICAL, BusinessImpact.CRITICAL, Confidence.HIGH, "CWE-798",
                        "Use Docker secrets, runtime environment variables, or a secrets manager. ENV values are visible in image history.",
                        List.of("https://docs.docker.com/engine/swarm/secrets/")),

                new ScanRule("APT-001", "Package Cache Not Cleaned",
                        "apt-get install without cleanup leaves package cache in the image layer.",
                        "best-practice", Pattern.compile("(?i)apt-get\\s+install(?!.*&&\\s*(?:apt-get\\s+clean|rm\\s+-rf))"),
                        Severity.LOW, BusinessImpact.LOW, Confidence.MEDIUM, "CWE-459",
                        "Chain apt-get install with cleanup:\n  RUN apt-get update && apt-get install -y pkg && rm -rf /var/lib/apt/lists/*",
                        List.of("https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run"))
        );
    }

    private static List<ScanRule> buildComposeRules() {
        return List.of(
                new ScanRule("PRIV-001", "Privileged Container",
                        "Container is running in privileged mode, which gives it full access to the host.",
                        "privilege-escalation", Pattern.compile("(?i)privileged\\s*:\\s*true"),
                        Severity.CRITICAL, BusinessImpact.CRITICAL, Confidence.HIGH, "CWE-250",
                        "Remove privileged: true. Use cap_add to grant only required Linux capabilities.",
                        List.of("https://docs.docker.com/compose/compose-file/compose-file-v3/#privileged")),

                new ScanRule("NET-001", "Host Network Mode",
                        "Container uses host network mode, sharing the host's network namespace.",
                        "network-exposure", Pattern.compile("(?i)network_mode\\s*:\\s*[\"']?host[\"']?"),
                        Severity.HIGH, BusinessImpact.HIGH, Confidence.HIGH, "CWE-668",
                        "Use bridge networking (default) or a custom Docker network.",
                        List.of("https://docs.docker.com/network/host/")),

                new ScanRule("VOL-001", "Sensitive Host Path Mounted",
                        "A sensitive host directory (/var/run/docker.sock, /etc) is mounted into the container.",
                        "privilege-escalation", Pattern.compile("/var/run/docker\\.sock|/etc[/\"']"),
                        Severity.CRITICAL, BusinessImpact.CRITICAL, Confidence.HIGH, "CWE-276",
                        "Avoid mounting the Docker socket or sensitive host directories. Use a Docker socket proxy with limited permissions.",
                        List.of("https://docs.docker.com/storage/volumes/"))
        );
    }
}
