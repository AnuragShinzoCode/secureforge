package com.kiro.security.core;

import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/**
 * Core engine that orchestrates all registered scanner plugins,
 * collects findings, and produces structured results.
 */
public class ScannerEngine {

    private final List<BaseScanner> scanners = new ArrayList<>();
    private final List<Finding> findings = new ArrayList<>();

    public ScannerEngine register(BaseScanner scanner) {
        scanners.add(scanner);
        return this;
    }

    /**
     * Run all registered scanners against the target directory.
     */
    public ScannerResult run(Path targetDir) {
        long startTime = System.currentTimeMillis();
        findings.clear();

        Map<String, ScannerResult.ScannerStatus> scannerResults = new LinkedHashMap<>();

        System.out.println("\n\uD83D\uDD0D Starting security scan on: " + targetDir);
        System.out.println("   Registered scanners: " +
                scanners.stream().map(BaseScanner::getName).reduce((a, b) -> a + ", " + b).orElse("none"));
        System.out.println();

        for (BaseScanner scanner : scanners) {
            try {
                System.out.println("  ▶ Running " + scanner.getName() + "...");
                long scanStart = System.currentTimeMillis();
                List<Finding> result = scanner.scan(targetDir);
                long scanDuration = System.currentTimeMillis() - scanStart;

                findings.addAll(result);
                scannerResults.put(scanner.getName(), new ScannerResult.ScannerStatus(
                        result.size(), scanDuration, "completed", null));

                System.out.printf("    ✓ %s: %d findings (%dms)%n",
                        scanner.getName(), result.size(), scanDuration);
            } catch (Exception e) {
                scannerResults.put(scanner.getName(), new ScannerResult.ScannerStatus(
                        0, 0, "error", e.getMessage()));
                System.err.printf("    ✗ %s failed: %s%n", scanner.getName(), e.getMessage());
            }
        }

        long duration = System.currentTimeMillis() - startTime;
        System.out.printf("%n✅ Scan complete: %d total findings in %dms%n%n", findings.size(), duration);

        var metadata = new ScannerResult.ScanMetadata(
                targetDir.toString(),
                Instant.now().toString(),
                duration,
                findings.size(),
                scannerResults,
                buildSeveritySummary(),
                buildCategorySummary()
        );

        return new ScannerResult(List.copyOf(findings), metadata);
    }

    private Map<String, Integer> buildSeveritySummary() {
        Map<String, Integer> summary = new LinkedHashMap<>();
        for (Severity s : Severity.values()) {
            summary.put(s.name().toLowerCase(), 0);
        }
        for (Finding f : findings) {
            String key = f.getSeverity().name().toLowerCase();
            summary.merge(key, 1, Integer::sum);
        }
        return summary;
    }

    private Map<String, Integer> buildCategorySummary() {
        Map<String, Integer> summary = new LinkedHashMap<>();
        for (Finding f : findings) {
            summary.merge(f.getCategory(), 1, Integer::sum);
        }
        return summary;
    }
}
