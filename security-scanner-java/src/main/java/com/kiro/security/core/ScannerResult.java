package com.kiro.security.core;

import java.util.List;
import java.util.Map;

/**
 * Holds the complete result of a scanner run — findings plus metadata.
 */
public record ScannerResult(
    List<Finding> findings,
    ScanMetadata metadata
) {

    public record ScanMetadata(
        String targetDir,
        String scanDate,
        long duration,
        int totalFindings,
        Map<String, ScannerStatus> scannerResults,
        Map<String, Integer> severitySummary,
        Map<String, Integer> categorySummary
    ) {}

    public record ScannerStatus(
        int findingsCount,
        long duration,
        String status,
        String error
    ) {}
}
