package com.kiro.security.core;

public enum Severity {
    CRITICAL(5, "CRITICAL", "🔴"),
    HIGH(4, "HIGH", "🟠"),
    MEDIUM(3, "MEDIUM", "🟡"),
    LOW(2, "LOW", "🔵"),
    INFO(1, "INFO", "⚪");

    private final int level;
    private final String label;
    private final String icon;

    Severity(int level, String label, String icon) {
        this.level = level;
        this.label = label;
        this.icon = icon;
    }

    public int getLevel() { return level; }
    public String getLabel() { return label; }
    public String getIcon() { return icon; }
}
