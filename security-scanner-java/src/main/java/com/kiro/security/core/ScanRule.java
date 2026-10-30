package com.kiro.security.core;

import java.util.List;
import java.util.regex.Pattern;

/**
 * A single detection rule — pattern + metadata for creating findings.
 */
public record ScanRule(
    String id,
    String title,
    String description,
    String subcategory,
    Pattern pattern,
    Severity severity,
    BusinessImpact businessImpact,
    Confidence confidence,
    String cweId,
    String remediation,
    List<String> references
) {}
