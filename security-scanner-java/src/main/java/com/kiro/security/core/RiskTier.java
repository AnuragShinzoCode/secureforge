package com.kiro.security.core;

public record RiskTier(String tier, String action, String sla) {

    public static RiskTier fromScore(int score) {
        if (score >= 80) return new RiskTier("CRITICAL", "Immediate remediation required", "24 hours");
        if (score >= 60) return new RiskTier("HIGH", "Remediation required before next release", "1 week");
        if (score >= 40) return new RiskTier("MEDIUM", "Schedule remediation in current sprint", "2 weeks");
        if (score >= 20) return new RiskTier("LOW", "Add to backlog", "1 month");
        return new RiskTier("INFO", "Review and assess", "Best effort");
    }
}
