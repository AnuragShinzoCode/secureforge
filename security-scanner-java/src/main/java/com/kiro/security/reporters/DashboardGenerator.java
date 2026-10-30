package com.kiro.security.reporters;

import com.kiro.security.core.*;
import com.kiro.security.core.ScoringEngine.SummaryStats;

import java.util.*;

/**
 * Generates a self-contained HTML dashboard with Chart.js visualizations.
 * Light theme with BT purple (#7B2FE0) accents.
 */
public class DashboardGenerator {

    public String generate(ScannerResult scanResult, List<Finding> scoredFindings, SummaryStats stats) {
        var meta = scanResult.metadata();
        String jsonData = buildInlineJson(stats, meta);

        var html = new StringBuilder();
        html.append("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SecureForge — Dashboard</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }

                body {
                    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
                    background: #F5F3FA;
                    color: #333;
                    min-height: 100vh;
                    padding: 24px;
                }

                /* Purple top banner */
                .top-banner {
                    background: #7B2FE0;
                    border-radius: 16px;
                    padding: 40px 48px;
                    color: #FFF;
                    max-width: 1200px;
                    margin: 0 auto 28px;
                    position: relative;
                    overflow: hidden;
                }

                .top-banner::before {
                    content: '';
                    position: absolute;
                    top: 0; left: 0; right: 0; bottom: 0;
                    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 600 200'%3E%3Cpath d='M-50,80 Q150,20 300,80 T650,80' fill='none' stroke='rgba(255,255,255,0.08)' stroke-width='80'/%3E%3Cpath d='M-50,140 Q200,80 400,140 T700,120' fill='none' stroke='rgba(255,255,255,0.05)' stroke-width='100'/%3E%3C/svg%3E");
                    background-size: cover;
                    pointer-events: none;
                }

                .top-banner h1 {
                    font-size: 1.8rem; font-weight: 700; margin-bottom: 6px;
                    position: relative; z-index: 1;
                }

                .top-banner .subtitle {
                    font-size: 0.9rem; color: rgba(255,255,255,0.8);
                    position: relative; z-index: 1;
                }

                .meta-bar {
                    display: flex; justify-content: center; gap: 32px; flex-wrap: wrap;
                    margin: 0 auto 28px; font-size: 0.82rem; color: #7B2FE0;
                    max-width: 1200px;
                }
                .meta-bar span { display: flex; align-items: center; gap: 6px; background: #FFF; padding: 8px 18px; border-radius: 10px; box-shadow: 0 1px 4px rgba(0,0,0,0.06); }

                /* KPI Cards */
                .kpi-row {
                    display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
                    gap: 16px; margin-bottom: 28px; max-width: 1200px; margin-left: auto; margin-right: auto;
                }

                .kpi-card {
                    background: #FFF; border-radius: 14px; padding: 22px; text-align: center;
                    box-shadow: 0 2px 8px rgba(123, 47, 224, 0.08);
                    border: 1px solid #EDE7F6;
                    transition: transform 0.2s, box-shadow 0.2s;
                }
                .kpi-card:hover { transform: translateY(-3px); box-shadow: 0 6px 20px rgba(123, 47, 224, 0.15); }
                .kpi-card .value { font-size: 2.4rem; font-weight: 800; line-height: 1.1; }
                .kpi-card .label { font-size: 0.72rem; color: #888; text-transform: uppercase; letter-spacing: 1px; margin-top: 6px; }
                .kpi-critical .value { color: #D32F2F; }
                .kpi-high .value { color: #E65100; }
                .kpi-medium .value { color: #F9A825; }
                .kpi-low .value { color: #1565C0; }
                .kpi-total .value { color: #7B2FE0; }
                .kpi-score .value { color: #4A148C; }

                /* Scanner chips */
                .scanner-chips {
                    display: flex; gap: 12px; flex-wrap: wrap; justify-content: center;
                    margin-bottom: 28px; max-width: 1200px; margin-left: auto; margin-right: auto;
                }
                .scanner-chip {
                    background: #FFF; border: 1px solid #EDE7F6;
                    border-radius: 10px; padding: 10px 18px; display: flex; align-items: center;
                    gap: 10px; font-size: 0.82rem; box-shadow: 0 1px 4px rgba(0,0,0,0.04); color: #555;
                }
                .scanner-chip .dot { width: 10px; height: 10px; border-radius: 50%; background: #4CAF50; }
                .scanner-chip .dot.error { background: #D32F2F; }
                .scanner-chip strong { color: #7B2FE0; }

                /* Charts */
                .charts-grid {
                    display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
                    gap: 20px; max-width: 1200px; margin: 0 auto 28px;
                }

                .chart-card {
                    background: #FFF; border: 1px solid #EDE7F6;
                    border-radius: 14px; padding: 24px;
                    box-shadow: 0 2px 8px rgba(123, 47, 224, 0.06);
                }
                .chart-card h3 {
                    font-size: 0.85rem; color: #7B2FE0; margin-bottom: 16px;
                    text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700;
                }
                .chart-container { position: relative; width: 100%; max-height: 320px; display: flex; justify-content: center; }
                .chart-container canvas { max-height: 300px; }

                /* Findings Table */
                .table-section { max-width: 1200px; margin: 0 auto 32px; }
                .table-section h2 { font-size: 1rem; color: #7B2FE0; margin-bottom: 14px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; }

                .table-wrapper {
                    background: #FFF; border: 1px solid #EDE7F6;
                    border-radius: 14px; overflow: hidden; box-shadow: 0 2px 8px rgba(123, 47, 224, 0.06);
                }

                table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
                th {
                    background: #7B2FE0; color: #FFF;
                    text-transform: uppercase; letter-spacing: 0.5px; font-size: 0.7rem;
                    font-weight: 600; padding: 13px 16px; text-align: left; position: sticky; top: 0;
                }
                td { padding: 11px 16px; border-bottom: 1px solid #F0ECF8; vertical-align: top; color: #444; }
                tr:hover td { background: #F8F5FF; }

                .sev-badge {
                    display: inline-block; padding: 3px 10px; border-radius: 20px;
                    font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
                }
                .sev-critical { background: #FFEBEE; color: #C62828; }
                .sev-high     { background: #FFF3E0; color: #E65100; }
                .sev-medium   { background: #FFFDE7; color: #F57F17; }
                .sev-low      { background: #E3F2FD; color: #1565C0; }
                .sev-info     { background: #ECEFF1; color: #546E7A; }

                .score-bar {
                    width: 60px; height: 8px; background: #EDE7F6;
                    border-radius: 4px; overflow: hidden; display: inline-block; vertical-align: middle; margin-right: 6px;
                }
                .score-fill { height: 100%; border-radius: 4px; background: linear-gradient(90deg, #7B2FE0, #D32F2F); }

                .file-path { color: #7B2FE0; font-family: 'SF Mono', 'Cascadia Code', monospace; font-size: 0.75rem; }

                .scrollable-table { max-height: 520px; overflow-y: auto; }
                .scrollable-table::-webkit-scrollbar { width: 6px; }
                .scrollable-table::-webkit-scrollbar-track { background: transparent; }
                .scrollable-table::-webkit-scrollbar-thumb { background: #D1C4E9; border-radius: 3px; }

                .back-btn {
                    display: inline-flex; align-items: center; gap: 8px;
                    background: #7B2FE0; color: #FFF;
                    padding: 10px 24px; border-radius: 10px;
                    font-size: 0.82rem; font-weight: 600; cursor: pointer; text-decoration: none; margin-bottom: 16px;
                    transition: background 0.2s;
                    border: none;
                }
                .back-btn:hover { background: #6B21D1; }

                .footer { text-align: center; padding: 24px; color: #999; font-size: 0.78rem; }

                /* File Tree */
                .tree-section { max-width: 1200px; margin: 0 auto 28px; }
                .tree-section h2 { font-size: 1rem; color: #7B2FE0; margin-bottom: 14px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; }
                .tree-wrapper {
                    background: #FFF; border: 1px solid #EDE7F6;
                    border-radius: 14px; padding: 20px; box-shadow: 0 2px 8px rgba(123, 47, 224, 0.06);
                    max-height: 600px; overflow-y: auto;
                }
                .tree-wrapper::-webkit-scrollbar { width: 6px; }
                .tree-wrapper::-webkit-scrollbar-thumb { background: #D1C4E9; border-radius: 3px; }

                .tree-node { margin-left: 0; }
                .tree-node .tree-node { margin-left: 22px; }

                .tree-folder, .tree-file {
                    display: flex; align-items: center; gap: 8px;
                    padding: 6px 10px; border-radius: 8px; cursor: pointer;
                    font-size: 0.82rem; transition: background 0.15s; user-select: none;
                }
                .tree-folder:hover, .tree-file:hover { background: #F8F5FF; }

                .tree-folder { font-weight: 600; color: #333; }
                .tree-file { color: #555; font-weight: 400; }

                .tree-icon { font-size: 1rem; flex-shrink: 0; }
                .tree-name { flex: 1; }

                .tree-badges { display: flex; gap: 4px; flex-shrink: 0; }
                .tree-badge {
                    font-size: 0.6rem; font-weight: 700; padding: 2px 7px; border-radius: 10px;
                    min-width: 18px; text-align: center;
                }
                .tree-badge-critical { background: #FFEBEE; color: #C62828; }
                .tree-badge-high { background: #FFF3E0; color: #E65100; }
                .tree-badge-medium { background: #FFFDE7; color: #F57F17; }
                .tree-badge-low { background: #E3F2FD; color: #1565C0; }

                .tree-children { display: none; }
                .tree-children.open { display: block; }

                .tree-arrow { font-size: 0.65rem; color: #999; transition: transform 0.2s; width: 12px; }
                .tree-arrow.open { transform: rotate(90deg); }

                .tree-finding {
                    display: flex; align-items: center; gap: 8px;
                    padding: 4px 10px 4px 28px; font-size: 0.75rem; color: #666;
                    border-left: 2px solid #EDE7F6; margin-left: 18px;
                }
                .tree-finding-title { flex: 1; }
                .tree-finding-line { color: #999; font-family: 'SF Mono', monospace; font-size: 0.7rem; }

                @media (max-width: 768px) {
                    .charts-grid { grid-template-columns: 1fr; }
                    .kpi-row { grid-template-columns: repeat(2, 1fr); }
                    body { padding: 12px; }
                    .top-banner { padding: 28px 24px; }
                }
            </style>
        </head>
        <body>
            <div style="max-width:1200px;margin:0 auto;">
                <a href="/" class="back-btn">← Back to Home</a>
            </div>

            <div class="top-banner">
                <h1>🛡️ SecureForge Dashboard</h1>
                <p class="subtitle">Automated Vulnerability Detection &amp; Prioritized Reporting</p>
            </div>
        """);

        // Meta bar
        html.append("<div class=\"meta-bar\">");
        html.append("<span>📅 <strong>").append(meta.scanDate()).append("</strong></span>");
        html.append("<span>📁 <strong>").append(escapeHtml(meta.targetDir())).append("</strong></span>");
        html.append("<span>⏱️ <strong>").append(meta.duration()).append("ms</strong></span>");
        html.append("</div>");

        // KPI Cards
        int critical = stats.bySeverity().getOrDefault("critical", 0);
        int high = stats.bySeverity().getOrDefault("high", 0);
        int medium = stats.bySeverity().getOrDefault("medium", 0);
        int low = stats.bySeverity().getOrDefault("low", 0);

        html.append("<div class=\"kpi-row\">");
        html.append(kpiCard("kpi-total", String.valueOf(stats.total()), "Total Findings"));
        html.append(kpiCard("kpi-critical", String.valueOf(critical), "Critical"));
        html.append(kpiCard("kpi-high", String.valueOf(high), "High"));
        html.append(kpiCard("kpi-medium", String.valueOf(medium), "Medium"));
        html.append(kpiCard("kpi-low", String.valueOf(low), "Low"));
        html.append(kpiCard("kpi-score", String.valueOf(stats.averageRiskScore()), "Avg Risk Score"));
        html.append("</div>");

        // Scanner chips
        html.append("<div class=\"scanner-chips\">");
        for (var entry : meta.scannerResults().entrySet()) {
            var r = entry.getValue();
            String dotClass = "completed".equals(r.status()) ? "dot" : "dot error";
            html.append("<div class=\"scanner-chip\">");
            html.append("<span class=\"").append(dotClass).append("\"></span>");
            html.append("<span>").append(entry.getKey()).append(" — <strong>").append(r.findingsCount())
                    .append("</strong> findings (").append(r.duration()).append("ms)</span>");
            html.append("</div>");
        }
        html.append("</div>");

        // Charts
        html.append("""
            <div class="charts-grid">
                <div class="chart-card">
                    <h3>📊 Findings by Severity</h3>
                    <div class="chart-container"><canvas id="severityPie"></canvas></div>
                </div>
                <div class="chart-card">
                    <h3>📂 Findings by Category</h3>
                    <div class="chart-container"><canvas id="categoryPie"></canvas></div>
                </div>
                <div class="chart-card">
                    <h3>⚡ Risk Tier Distribution</h3>
                    <div class="chart-container"><canvas id="riskTierBar"></canvas></div>
                </div>
                <div class="chart-card">
                    <h3>🔍 Scanner Findings Breakdown</h3>
                    <div class="chart-container"><canvas id="scannerBar"></canvas></div>
                </div>
            </div>
        """);

        // File tree section
        html.append("<div class=\"tree-section\">");
        html.append("<h2>📂 Findings by File Structure</h2>");
        html.append("<div class=\"tree-wrapper\">");
        html.append(buildFileTree(scoredFindings));
        html.append("</div></div>");

        // Findings table
        html.append("<div class=\"table-section\">");
        html.append("<h2>🔝 All Findings — Ranked by Risk Score</h2>");
        html.append("<div class=\"table-wrapper\"><div class=\"scrollable-table\">");
        html.append("<table><thead><tr><th>Score</th><th>Severity</th><th>Title</th><th>Category</th><th>File</th><th>CWE</th><th>SLA</th></tr></thead><tbody>");

        for (Finding f : scoredFindings) {
            String sevClass = "sev-" + f.getSeverity().name().toLowerCase();
            int score = f.getRiskScore();
            String file = f.getFile() != null ? f.getFile() + (f.getLine() != null ? ":" + f.getLine() : "") : "—";
            String cwe = f.getCweId() != null ? f.getCweId() : "—";
            String sla = f.getRiskTier() != null ? f.getRiskTier().sla() : "—";

            html.append("<tr><td><span class=\"score-bar\"><span class=\"score-fill\" style=\"width:")
                    .append(score).append("%\"></span></span> ").append(score).append("</td>");
            html.append("<td><span class=\"sev-badge ").append(sevClass).append("\">").append(f.getSeverity().name()).append("</span></td>");
            html.append("<td>").append(escapeHtml(f.getTitle())).append("</td>");
            html.append("<td>").append(f.getCategory()).append("</td>");
            html.append("<td class=\"file-path\">").append(escapeHtml(file)).append("</td>");
            html.append("<td>").append(cwe).append("</td>");
            html.append("<td>").append(sla).append("</td></tr>");
        }

        html.append("</tbody></table></div></div></div>");

        // Footer
        html.append("<div class=\"footer\">Generated by <strong>SecureForge</strong> &nbsp;|&nbsp; ")
                .append(meta.scanDate()).append("</div>");

        // Chart.js
        html.append("<script>\n");
        html.append("function toggleTree(id) { var el = document.getElementById(id); var arrow = document.getElementById('arrow-' + id); if (el.classList.contains('open')) { el.classList.remove('open'); arrow.classList.remove('open'); } else { el.classList.add('open'); arrow.classList.add('open'); } }\n");
        html.append("Chart.defaults.color = '#666';\n");
        html.append("Chart.defaults.font.family = \"'Segoe UI', system-ui, sans-serif\";\n");
        html.append("const data = ").append(jsonData).append(";\n");

        html.append("""
            new Chart(document.getElementById('severityPie'), {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    datasets: [{
                        data: [data.severity.critical, data.severity.high, data.severity.medium, data.severity.low, data.severity.info],
                        backgroundColor: ['#D32F2F', '#E65100', '#F9A825', '#1565C0', '#78909C'],
                        borderColor: '#FFF', borderWidth: 3, hoverOffset: 8
                    }]
                },
                options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { position: 'bottom', labels: { padding: 16, usePointStyle: true, pointStyle: 'circle' } } }, cutout: '55%' }
            });

            new Chart(document.getElementById('categoryPie'), {
                type: 'doughnut',
                data: {
                    labels: Object.keys(data.category),
                    datasets: [{
                        data: Object.values(data.category),
                        backgroundColor: ['#7B2FE0', '#9C4DFF', '#B388FF', '#D1C4E9'],
                        borderColor: '#FFF', borderWidth: 3, hoverOffset: 8
                    }]
                },
                options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { position: 'bottom', labels: { padding: 16, usePointStyle: true, pointStyle: 'circle' } } }, cutout: '55%' }
            });

            new Chart(document.getElementById('riskTierBar'), {
                type: 'bar',
                data: {
                    labels: Object.keys(data.riskTier),
                    datasets: [{
                        label: 'Findings',
                        data: Object.values(data.riskTier),
                        backgroundColor: ['#D32F2F', '#E65100', '#F9A825', '#1565C0', '#78909C'],
                        borderColor: ['#C62828', '#BF360C', '#F57F17', '#0D47A1', '#546E7A'],
                        borderWidth: 1, borderRadius: 8
                    }]
                },
                options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { display: false } },
                    scales: { y: { beginAtZero: true, grid: { color: '#F0ECF8' }, ticks: { stepSize: 5 } }, x: { grid: { display: false } } } }
            });

            new Chart(document.getElementById('scannerBar'), {
                type: 'bar',
                data: {
                    labels: Object.keys(data.scanners),
                    datasets: [{
                        label: 'Findings',
                        data: Object.values(data.scanners).map(s => s.count),
                        backgroundColor: '#7B2FE0', borderColor: '#6B21D1', borderWidth: 1, borderRadius: 8
                    }, {
                        label: 'Duration (ms)',
                        data: Object.values(data.scanners).map(s => s.duration),
                        backgroundColor: '#D1C4E9', borderColor: '#B39DDB', borderWidth: 1, borderRadius: 8
                    }]
                },
                options: { responsive: true, maintainAspectRatio: true,
                    plugins: { legend: { position: 'bottom', labels: { padding: 12, usePointStyle: true, pointStyle: 'circle' } } },
                    scales: { y: { beginAtZero: true, grid: { color: '#F0ECF8' } }, x: { grid: { display: false } } } }
            });
        """);

        html.append("</script></body></html>");
        return html.toString();
    }

    private String buildFileTree(List<Finding> findings) {
        // Build a tree structure: path -> list of findings
        var tree = new java.util.TreeMap<String, List<Finding>>();
        for (Finding f : findings) {
            String file = f.getFile() != null ? f.getFile() : "unknown";
            tree.computeIfAbsent(file, k -> new ArrayList<>()).add(f);
        }

        // Group by top-level folder
        var folderTree = new java.util.TreeMap<String, java.util.TreeMap<String, List<Finding>>>();
        for (var entry : tree.entrySet()) {
            String filePath = entry.getKey();
            String[] parts = filePath.split("/|\\\\");
            String topFolder = parts.length > 1 ? parts[0] : "(root)";
            String rest = parts.length > 1 ? filePath.substring(topFolder.length() + 1) : filePath;
            folderTree.computeIfAbsent(topFolder, k -> new java.util.TreeMap<>()).put(rest, entry.getValue());
        }

        var sb = new StringBuilder();
        int folderId = 0;

        for (var folderEntry : folderTree.entrySet()) {
            String folder = folderEntry.getKey();
            var files = folderEntry.getValue();
            int totalFindings = files.values().stream().mapToInt(List::size).sum();

            // Count severities for the folder
            int crit = 0, high = 0, med = 0, low = 0;
            for (var fl : files.values()) {
                for (Finding f : fl) {
                    switch (f.getSeverity()) {
                        case CRITICAL -> crit++;
                        case HIGH -> high++;
                        case MEDIUM -> med++;
                        case LOW -> low++;
                        default -> {}
                    }
                }
            }

            String fid = "folder-" + folderId++;
            sb.append("<div class=\"tree-node\">");
            sb.append("<div class=\"tree-folder\" onclick=\"toggleTree('").append(fid).append("')\">");
            sb.append("<span class=\"tree-arrow\" id=\"arrow-").append(fid).append("\">▶</span>");
            sb.append("<span class=\"tree-icon\">📁</span>");
            sb.append("<span class=\"tree-name\">").append(escapeHtml(folder)).append("</span>");
            sb.append("<span class=\"tree-badges\">");
            if (crit > 0) sb.append("<span class=\"tree-badge tree-badge-critical\">").append(crit).append("</span>");
            if (high > 0) sb.append("<span class=\"tree-badge tree-badge-high\">").append(high).append("</span>");
            if (med > 0) sb.append("<span class=\"tree-badge tree-badge-medium\">").append(med).append("</span>");
            if (low > 0) sb.append("<span class=\"tree-badge tree-badge-low\">").append(low).append("</span>");
            sb.append("</span></div>");

            sb.append("<div class=\"tree-children\" id=\"").append(fid).append("\">");

            for (var fileEntry : files.entrySet()) {
                String fileName = fileEntry.getKey();
                List<Finding> fileFindings = fileEntry.getValue();
                String ffid = fid + "-f" + fileName.hashCode();

                // File-level severity counts
                int fc = 0, fh = 0, fm = 0, fl2 = 0;
                for (Finding f : fileFindings) {
                    switch (f.getSeverity()) {
                        case CRITICAL -> fc++;
                        case HIGH -> fh++;
                        case MEDIUM -> fm++;
                        case LOW -> fl2++;
                        default -> {}
                    }
                }

                sb.append("<div class=\"tree-node\">");
                sb.append("<div class=\"tree-file\" onclick=\"toggleTree('").append(ffid).append("')\">");
                sb.append("<span class=\"tree-arrow\" id=\"arrow-").append(ffid).append("\">▶</span>");
                String fileIcon = fileName.endsWith(".java") ? "☕" : fileName.endsWith(".xml") ? "📄" : fileName.endsWith(".yml") || fileName.endsWith(".yaml") ? "⚙️" : "📄";
                sb.append("<span class=\"tree-icon\">").append(fileIcon).append("</span>");
                sb.append("<span class=\"tree-name\">").append(escapeHtml(fileName)).append("</span>");
                sb.append("<span class=\"tree-badges\">");
                if (fc > 0) sb.append("<span class=\"tree-badge tree-badge-critical\">").append(fc).append("</span>");
                if (fh > 0) sb.append("<span class=\"tree-badge tree-badge-high\">").append(fh).append("</span>");
                if (fm > 0) sb.append("<span class=\"tree-badge tree-badge-medium\">").append(fm).append("</span>");
                if (fl2 > 0) sb.append("<span class=\"tree-badge tree-badge-low\">").append(fl2).append("</span>");
                sb.append("</span></div>");

                sb.append("<div class=\"tree-children\" id=\"").append(ffid).append("\">");
                for (Finding f : fileFindings) {
                    String sevClass = "tree-badge-" + f.getSeverity().name().toLowerCase();
                    sb.append("<div class=\"tree-finding\">");
                    sb.append("<span class=\"tree-badge ").append(sevClass).append("\">").append(f.getSeverity().name().charAt(0)).append("</span>");
                    sb.append("<span class=\"tree-finding-title\">").append(escapeHtml(f.getTitle())).append("</span>");
                    if (f.getLine() != null) {
                        sb.append("<span class=\"tree-finding-line\">L").append(f.getLine()).append("</span>");
                    }
                    sb.append("</div>");
                }
                sb.append("</div></div>");
            }

            sb.append("</div></div>");
        }

        return sb.toString();
    }

    private String kpiCard(String cssClass, String value, String label) {
        return "<div class=\"kpi-card " + cssClass + "\"><div class=\"value\">" + value
                + "</div><div class=\"label\">" + label + "</div></div>";
    }

    private String buildInlineJson(SummaryStats stats, ScannerResult.ScanMetadata meta) {
        var sb = new StringBuilder();
        sb.append("{");
        sb.append("\"severity\":{");
        sb.append("\"critical\":").append(stats.bySeverity().getOrDefault("critical", 0)).append(",");
        sb.append("\"high\":").append(stats.bySeverity().getOrDefault("high", 0)).append(",");
        sb.append("\"medium\":").append(stats.bySeverity().getOrDefault("medium", 0)).append(",");
        sb.append("\"low\":").append(stats.bySeverity().getOrDefault("low", 0)).append(",");
        sb.append("\"info\":").append(stats.bySeverity().getOrDefault("info", 0));
        sb.append("},");
        sb.append("\"category\":{");
        var catEntries = new ArrayList<>(stats.byCategory().entrySet());
        for (int i = 0; i < catEntries.size(); i++) {
            var e = catEntries.get(i);
            sb.append("\"").append(e.getKey()).append("\":").append(e.getValue());
            if (i < catEntries.size() - 1) sb.append(",");
        }
        sb.append("},");
        sb.append("\"riskTier\":{");
        sb.append("\"CRITICAL\":").append(stats.byRiskTier().getOrDefault("CRITICAL", 0)).append(",");
        sb.append("\"HIGH\":").append(stats.byRiskTier().getOrDefault("HIGH", 0)).append(",");
        sb.append("\"MEDIUM\":").append(stats.byRiskTier().getOrDefault("MEDIUM", 0)).append(",");
        sb.append("\"LOW\":").append(stats.byRiskTier().getOrDefault("LOW", 0)).append(",");
        sb.append("\"INFO\":").append(stats.byRiskTier().getOrDefault("INFO", 0));
        sb.append("},");
        sb.append("\"scanners\":{");
        var scanEntries = new ArrayList<>(meta.scannerResults().entrySet());
        for (int i = 0; i < scanEntries.size(); i++) {
            var e = scanEntries.get(i);
            sb.append("\"").append(e.getKey()).append("\":{\"count\":").append(e.getValue().findingsCount())
                    .append(",\"duration\":").append(e.getValue().duration()).append("}");
            if (i < scanEntries.size() - 1) sb.append(",");
        }
        sb.append("}");
        sb.append("}");
        return sb.toString();
    }

    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                   .replace("\"", "&quot;").replace("'", "&#39;");
    }
}
