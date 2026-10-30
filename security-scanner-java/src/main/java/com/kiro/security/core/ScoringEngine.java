package com.kiro.security.core;

import java.util.*;

/**
 * Severity scoring and business impact prioritisation engine.
 * Computes a composite risk score for each finding based on:
 *   - Technical severity
 *   - Business impact
 *   - Confidence level
 *   - Category weight
 */
public class ScoringEngine {

    private static final Map<String, Double> CATEGORY_WEIGHT = Map.of(
            "source-code", 1.0,
            "dependency", 0.95,
            "container", 0.85,
            "infrastructure", 1.0
    );

    /**
     * Calculate a composite risk score (0–100) for a finding.
     */
    public static int calculateRiskScore(Finding finding) {
        double sevWeight = finding.getSeverity().getLevel() / 5.0;
        double impactWeight = finding.getBusinessImpact().getLevel() / 4.0;
        double confWeight = finding.getConfidence().getWeight();
        double catWeight = CATEGORY_WEIGHT.getOrDefault(finding.getCategory(), 0.8);

        double raw = (sevWeight * 0.4) + (impactWeight * 0.3) + (confWeight * 0.15) + (catWeight * 0.15);
        return (int) Math.round(raw * 100);
    }

    /**
     * Score and sort all findings, enriching each with riskScore and riskTier.
     * Returns findings sorted by riskScore descending.
     */
    public static List<Finding> prioritise(List<Finding> findings) {
        for (Finding f : findings) {
            int score = calculateRiskScore(f);
            f.setRiskScore(score);
            f.setRiskTier(RiskTier.fromScore(score));
        }

        List<Finding> sorted = new ArrayList<>(findings);
        sorted.sort(Comparator.comparingInt(Finding::getRiskScore).reversed());
        return sorted;
    }

    /**
     * Generate summary statistics from scored findings.
     */
    public static SummaryStats generateSummaryStats(List<Finding> scoredFindings) {
        Map<String, Integer> bySeverity = new LinkedHashMap<>();
        for (Severity s : Severity.values()) bySeverity.put(s.name().toLowerCase(), 0);

        Map<String, Integer> byCategory = new LinkedHashMap<>();
        Map<String, Integer> byRiskTier = new LinkedHashMap<>();
        for (String tier : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")) {
            byRiskTier.put(tier, 0);
        }

        int totalScore = 0;

        for (Finding f : scoredFindings) {
            bySeverity.merge(f.getSeverity().name().toLowerCase(), 1, Integer::sum);
            byCategory.merge(f.getCategory(), 1, Integer::sum);
            byRiskTier.merge(f.getRiskTier().tier(), 1, Integer::sum);
            totalScore += f.getRiskScore();
        }

        int avgScore = scoredFindings.isEmpty() ? 0 : Math.round((float) totalScore / scoredFindings.size());

        List<TopRisk> topRisks = scoredFindings.stream()
                .limit(10)
                .map(f -> new TopRisk(f.getId(), f.getTitle(), f.getSeverity().name().toLowerCase(),
                        f.getRiskScore(), f.getFile()))
                .toList();

        return new SummaryStats(scoredFindings.size(), bySeverity, byCategory, byRiskTier, avgScore, topRisks);
    }

    // --- Summary Records ---

    public record SummaryStats(
            int total,
            Map<String, Integer> bySeverity,
            Map<String, Integer> byCategory,
            Map<String, Integer> byRiskTier,
            int averageRiskScore,
            List<TopRisk> topRisks
    ) {}

    public record TopRisk(String id, String title, String severity, int riskScore, String file) {}
}
