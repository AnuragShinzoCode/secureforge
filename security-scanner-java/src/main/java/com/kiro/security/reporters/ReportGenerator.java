package com.kiro.security.reporters;

import com.google.gson.GsonBuilder;
import com.kiro.security.core.*;
import com.kiro.security.core.ScoringEngine.SummaryStats;

import java.io.IOException;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Generates comprehensive security scan reports in multiple formats:
 * - Markdown (human-readable, for dev & security teams)
 * - JSON (machine-readable, for CI/CD integration)
 * - Console summary (terminal output)
 */
public class ReportGenerator {

    /**
     * Generate all reports and write to outputDir.
     */
    public ReportPaths generate(ScannerResult scanResult, List<Finding> scoredFindings,
                                SummaryStats stats, Path outputDir) throws IOException {
        Files.createDirectories(outputDir);

        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH-mm-ss"));
        Path mdPath = outputDir.resolve("security-report-%s.md".formatted(timestamp));
        Path jsonPath = outputDir.resolve("security-report-%s.json".formatted(timestamp));

        String mdContent = generateMarkdown(scanResult, scoredFindings, stats);
        String jsonContent = generateJson(scanResult, scoredFindings, stats);

        // Generate HTML dashboard
        DashboardGenerator dashboardGen = new DashboardGenerator();
        String dashboardContent = dashboardGen.generate(scanResult, scoredFindings, stats);
        Path dashboardPath = outputDir.resolve("security-dashboard-%s.html".formatted(timestamp));

        Files.writeString(mdPath, mdContent);
        Files.writeString(jsonPath, jsonContent);
        Files.writeString(dashboardPath, dashboardContent);

        // Latest copies
        Files.writeString(outputDir.resolve("security-report-latest.md"), mdContent);
        Files.writeString(outputDir.resolve("security-report-latest.json"), jsonContent);
        Files.writeString(outputDir.resolve("security-dashboard-latest.html"), dashboardContent);

        return new ReportPaths(mdPath, jsonPath, dashboardPath);
    }

    /**
     * Print console summary.
     */
    public void printConsoleSummary(SummaryStats stats) {
        String bar = "═".repeat(60);
        System.out.println("\n" + bar);
        System.out.println("  🛡️  SECUREFORGE — SCAN REPORT");
        System.out.println(bar);

        System.out.println("\n  📊 SUMMARY");
        System.out.printf("  Total findings: %d%n", stats.total());
        System.out.printf("  Average risk score: %d/100%n%n", stats.averageRiskScore());

        System.out.println("  By Severity:");
        for (var entry : stats.bySeverity().entrySet()) {
            if (entry.getValue() > 0) {
                String icon = switch (entry.getKey()) {
                    case "critical" -> "🔴";
                    case "high" -> "🟠";
                    case "medium" -> "🟡";
                    case "low" -> "🔵";
                    default -> "⚪";
                };
                System.out.printf("    %s %s: %d%n", icon, entry.getKey().toUpperCase(), entry.getValue());
            }
        }

        System.out.println("\n  By Category:");
        for (var entry : stats.byCategory().entrySet()) {
            System.out.printf("    📁 %s: %d%n", entry.getKey(), entry.getValue());
        }

        System.out.println("\n  By Risk Tier (with SLAs):");
        Map<String, String> slas = Map.of(
                "CRITICAL", "24h", "HIGH", "1 week", "MEDIUM", "2 weeks", "LOW", "1 month", "INFO", "best effort");
        for (var entry : stats.byRiskTier().entrySet()) {
            if (entry.getValue() > 0) {
                System.out.printf("    ⏱️  %s: %d findings (SLA: %s)%n",
                        entry.getKey(), entry.getValue(), slas.getOrDefault(entry.getKey(), "N/A"));
            }
        }

        if (!stats.topRisks().isEmpty()) {
            System.out.println("\n  🔝 TOP RISKS:");
            stats.topRisks().stream().limit(5).forEach(risk ->
                    System.out.printf("    [%d] %s - %s%n         %s%n",
                            risk.riskScore(), risk.severity().toUpperCase(), risk.title(),
                            risk.file() != null ? risk.file() : "N/A"));
        }

        System.out.println("\n" + bar + "\n");
    }

    // ── Markdown ──────────────────────────────────────────

    private String generateMarkdown(ScannerResult scanResult, List<Finding> scoredFindings, SummaryStats stats) {
        var sb = new StringBuilder();
        var meta = scanResult.metadata();

        sb.append("# 🛡️ Kiro Security Scan Report\n\n");
        sb.append("**Scan Date:** %s\n".formatted(meta.scanDate()));
        sb.append("**Target:** `%s`\n".formatted(meta.targetDir()));
        sb.append("**Duration:** %dms\n".formatted(meta.duration()));
        sb.append("**Total Findings:** %d\n\n".formatted(meta.totalFindings()));

        // Executive Summary
        sb.append("## 📋 Executive Summary\n\n");
        sb.append("This automated security scan identified **%d findings** across the target project.\n\n".formatted(stats.total()));

        int critical = stats.bySeverity().getOrDefault("critical", 0);
        if (critical > 0) {
            sb.append("> ⚠️ **%d CRITICAL findings require immediate attention.**\n\n".formatted(critical));
        }

        sb.append("| Severity | Count |\n|----------|-------|\n");
        for (var entry : stats.bySeverity().entrySet()) {
            if (entry.getValue() > 0) {
                sb.append("| %s %s | %d |\n".formatted(sevIcon(entry.getKey()), entry.getKey().toUpperCase(), entry.getValue()));
            }
        }
        sb.append("\n");

        sb.append("| Category | Count |\n|----------|-------|\n");
        for (var entry : stats.byCategory().entrySet()) {
            sb.append("| %s | %d |\n".formatted(entry.getKey(), entry.getValue()));
        }
        sb.append("\n");

        sb.append("| Risk Tier | Count | SLA |\n|-----------|-------|-----|\n");
        Map<String, String> slas = Map.of(
                "CRITICAL", "24 hours", "HIGH", "1 week", "MEDIUM", "2 weeks", "LOW", "1 month", "INFO", "Best effort");
        for (var entry : stats.byRiskTier().entrySet()) {
            if (entry.getValue() > 0) {
                sb.append("| %s | %d | %s |\n".formatted(entry.getKey(), entry.getValue(),
                        slas.getOrDefault(entry.getKey(), "N/A")));
            }
        }
        sb.append("\n");

        // Scanner Results
        sb.append("## 🔍 Scanner Results\n\n");
        sb.append("| Scanner | Findings | Duration | Status |\n|---------|----------|----------|--------|\n");
        for (var entry : meta.scannerResults().entrySet()) {
            var r = entry.getValue();
            String status = "completed".equals(r.status()) ? "✅" : "❌";
            sb.append("| %s | %d | %dms | %s |\n".formatted(entry.getKey(), r.findingsCount(), r.duration(), status));
        }
        sb.append("\n");

        // Detailed Findings
        sb.append("## 🔎 Detailed Findings\n\n");
        Map<String, List<Finding>> bySeverity = scoredFindings.stream()
                .collect(Collectors.groupingBy(f -> f.getSeverity().name().toLowerCase(), LinkedHashMap::new, Collectors.toList()));

        for (String sev : List.of("critical", "high", "medium", "low", "info")) {
            List<Finding> group = bySeverity.get(sev);
            if (group == null || group.isEmpty()) continue;

            sb.append("### %s %s (%d)\n\n".formatted(sevIcon(sev), sev.toUpperCase(), group.size()));

            for (Finding f : group) {
                sb.append("#### %s\n\n".formatted(f.getTitle()));
                sb.append("- **ID:** `%s`\n".formatted(f.getId()));
                sb.append("- **Risk Score:** %d/100\n".formatted(f.getRiskScore()));
                sb.append("- **Category:** %s / %s\n".formatted(f.getCategory(), f.getSubcategory()));
                if (f.getFile() != null) {
                    sb.append("- **File:** `%s`%s\n".formatted(f.getFile(), f.getLine() != null ? ":" + f.getLine() : ""));
                }
                if (f.getCweId() != null) sb.append("- **CWE:** %s\n".formatted(f.getCweId()));
                if (f.getCveId() != null) sb.append("- **CVE:** %s\n".formatted(f.getCveId()));
                sb.append("- **Confidence:** %s\n".formatted(f.getConfidence().name().toLowerCase()));
                sb.append("- **SLA:** %s\n\n".formatted(f.getRiskTier().sla()));
                sb.append("**Description:** %s\n\n".formatted(f.getDescription()));

                if (f.getSnippet() != null && !f.getSnippet().isEmpty()) {
                    sb.append("**Code:**\n```\n%s\n```\n\n".formatted(f.getSnippet()));
                }
                sb.append("**Remediation:** %s\n\n".formatted(f.getRemediation()));

                if (!f.getReferences().isEmpty()) {
                    sb.append("**References:**\n");
                    for (String ref : f.getReferences()) {
                        sb.append("- %s\n".formatted(ref));
                    }
                    sb.append("\n");
                }
                sb.append("---\n\n");
            }
        }

        // Remediation Roadmap
        sb.append("## 🗺️ Remediation Roadmap\n\n");
        sb.append("| Priority | Action | Timeline |\n|----------|--------|----------|\n");
        sb.append("| 1 - Immediate | Fix %d CRITICAL findings | Within 24 hours |\n".formatted(stats.byRiskTier().getOrDefault("CRITICAL", 0)));
        sb.append("| 2 - Urgent | Fix %d HIGH findings | Within 1 week |\n".formatted(stats.byRiskTier().getOrDefault("HIGH", 0)));
        sb.append("| 3 - Planned | Fix %d MEDIUM findings | Within 2 weeks |\n".formatted(stats.byRiskTier().getOrDefault("MEDIUM", 0)));
        sb.append("| 4 - Backlog | Review %d LOW/INFO findings | Within 1 month |\n\n".formatted(
                stats.byRiskTier().getOrDefault("LOW", 0) + stats.byRiskTier().getOrDefault("INFO", 0)));

        sb.append("---\n\n*Generated by Kiro Security Agent (Java)*\n");
        sb.append("*Scan completed: %s*\n".formatted(meta.scanDate()));

        return sb.toString();
    }

    // ── JSON ──────────────────────────────────────────────

    private String generateJson(ScannerResult scanResult, List<Finding> scoredFindings, SummaryStats stats) {
        var report = new LinkedHashMap<String, Object>();
        report.put("reportVersion", "1.0.0");
        report.put("generator", "kiro-security-agent-java");
        report.put("scanMetadata", scanResult.metadata());
        report.put("summary", stats);

        List<Map<String, Object>> findingsList = new ArrayList<>();
        for (Finding f : scoredFindings) {
            var fm = new LinkedHashMap<String, Object>();
            fm.put("id", f.getId());
            fm.put("title", f.getTitle());
            fm.put("description", f.getDescription());
            fm.put("severity", f.getSeverity().name().toLowerCase());
            fm.put("riskScore", f.getRiskScore());
            fm.put("riskTier", Map.of("tier", f.getRiskTier().tier(), "action", f.getRiskTier().action(), "sla", f.getRiskTier().sla()));
            fm.put("category", f.getCategory());
            fm.put("subcategory", f.getSubcategory());
            fm.put("file", f.getFile());
            fm.put("line", f.getLine());
            fm.put("snippet", f.getSnippet());
            fm.put("remediation", f.getRemediation());
            fm.put("references", f.getReferences());
            fm.put("cweId", f.getCweId());
            fm.put("cveId", f.getCveId());
            fm.put("businessImpact", f.getBusinessImpact().name().toLowerCase());
            fm.put("confidence", f.getConfidence().name().toLowerCase());
            fm.put("timestamp", f.getTimestamp());
            findingsList.add(fm);
        }
        report.put("findings", findingsList);

        return new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(report);
    }

    // ── Helpers ───────────────────────────────────────────

    private String sevIcon(String severity) {
        return switch (severity) {
            case "critical" -> "🔴";
            case "high" -> "🟠";
            case "medium" -> "🟡";
            case "low" -> "🔵";
            default -> "⚪";
        };
    }

    public record ReportPaths(Path mdPath, Path jsonPath, Path dashboardPath) {}
}
