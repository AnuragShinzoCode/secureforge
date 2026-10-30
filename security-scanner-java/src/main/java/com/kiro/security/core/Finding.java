package com.kiro.security.core;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Represents a single security finding/vulnerability.
 */
public class Finding {

    private final String id;
    private final String title;
    private final String description;
    private final Severity severity;
    private final String category;       // source-code, dependency, container, infrastructure
    private final String subcategory;    // sql-injection, xss, hardcoded-secret, cve, etc.
    private final String file;
    private final Integer line;
    private final Integer column;
    private final String snippet;
    private final String remediation;
    private final List<String> references;
    private final String cweId;
    private final String cveId;
    private final BusinessImpact businessImpact;
    private final Confidence confidence;
    private final String timestamp;

    // Enriched by scoring engine
    private int riskScore;
    private RiskTier riskTier;

    private Finding(Builder b) {
        this.id = b.id;
        this.title = b.title;
        this.description = b.description;
        this.severity = b.severity;
        this.category = b.category;
        this.subcategory = b.subcategory;
        this.file = b.file;
        this.line = b.line;
        this.column = b.column;
        this.snippet = b.snippet;
        this.remediation = b.remediation;
        this.references = b.references == null ? List.of() : List.copyOf(b.references);
        this.cweId = b.cweId;
        this.cveId = b.cveId;
        this.businessImpact = b.businessImpact;
        this.confidence = b.confidence;
        this.timestamp = Instant.now().toString();
    }

    // --- Getters ---

    public String getId() { return id; }
    public String getTitle() { return title; }
    public String getDescription() { return description; }
    public Severity getSeverity() { return severity; }
    public String getCategory() { return category; }
    public String getSubcategory() { return subcategory; }
    public String getFile() { return file; }
    public Integer getLine() { return line; }
    public Integer getColumn() { return column; }
    public String getSnippet() { return snippet; }
    public String getRemediation() { return remediation; }
    public List<String> getReferences() { return references; }
    public String getCweId() { return cweId; }
    public String getCveId() { return cveId; }
    public BusinessImpact getBusinessImpact() { return businessImpact; }
    public Confidence getConfidence() { return confidence; }
    public String getTimestamp() { return timestamp; }

    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public RiskTier getRiskTier() { return riskTier; }
    public void setRiskTier(RiskTier riskTier) { this.riskTier = riskTier; }

    // --- Builder ---

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private String id;
        private String title;
        private String description;
        private Severity severity;
        private String category;
        private String subcategory;
        private String file;
        private Integer line;
        private Integer column;
        private String snippet;
        private String remediation;
        private List<String> references;
        private String cweId;
        private String cveId;
        private BusinessImpact businessImpact;
        private Confidence confidence;

        public Builder id(String id) { this.id = id; return this; }
        public Builder title(String title) { this.title = title; return this; }
        public Builder description(String description) { this.description = description; return this; }
        public Builder severity(Severity severity) { this.severity = severity; return this; }
        public Builder category(String category) { this.category = category; return this; }
        public Builder subcategory(String subcategory) { this.subcategory = subcategory; return this; }
        public Builder file(String file) { this.file = file; return this; }
        public Builder line(Integer line) { this.line = line; return this; }
        public Builder column(Integer column) { this.column = column; return this; }
        public Builder snippet(String snippet) { this.snippet = snippet; return this; }
        public Builder remediation(String remediation) { this.remediation = remediation; return this; }
        public Builder references(List<String> references) { this.references = references; return this; }
        public Builder cweId(String cweId) { this.cweId = cweId; return this; }
        public Builder cveId(String cveId) { this.cveId = cveId; return this; }
        public Builder businessImpact(BusinessImpact businessImpact) { this.businessImpact = businessImpact; return this; }
        public Builder confidence(Confidence confidence) { this.confidence = confidence; return this; }

        public Finding build() { return new Finding(this); }
    }
}
