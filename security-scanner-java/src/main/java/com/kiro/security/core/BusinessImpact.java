package com.kiro.security.core;

public enum BusinessImpact {
    CRITICAL(4, "Critical Business Impact", "Could cause data breach, system compromise, or regulatory violation"),
    HIGH(3, "High Business Impact", "Could lead to significant data exposure or service disruption"),
    MEDIUM(2, "Medium Business Impact", "Could cause limited data exposure or partial service impact"),
    LOW(1, "Low Business Impact", "Minimal direct business impact, but should be addressed");

    private final int level;
    private final String label;
    private final String description;

    BusinessImpact(int level, String label, String description) {
        this.level = level;
        this.label = label;
        this.description = description;
    }

    public int getLevel() { return level; }
    public String getLabel() { return label; }
    public String getDescription() { return description; }
}
