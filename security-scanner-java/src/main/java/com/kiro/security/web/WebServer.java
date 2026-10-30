package com.kiro.security.web;

import com.kiro.security.core.*;
import com.kiro.security.reporters.DashboardGenerator;
import com.kiro.security.scanners.*;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;

public class WebServer {

    private final int port;
    private final Path sampleProjectDir;

    public WebServer(int port, Path sampleProjectDir) {
        this.port = port;
        this.sampleProjectDir = sampleProjectDir.toAbsolutePath().normalize();
    }

    public void start() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", this::serveLandingPage);
        server.createContext("/api/scan", this::handleScan);
        server.setExecutor(null);
        server.start();

        System.out.println();
        System.out.println("🛡️  ╔═══════════════════════════════════════════════╗");
        System.out.println("   ║            SecureForge — WEB UI               ║");
        System.out.println("   ╚═══════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("   🌐 Dashboard running at: http://localhost:" + port);
        System.out.println();
    }

    private void serveLandingPage(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }
        String html = buildLandingPage();
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) { os.write(bytes); }
    }

    private void handleScan(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
        Path clonedRepo = null;
        try {
            // Read target from request body
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Path scanTarget = sampleProjectDir; // fallback
            String rawTarget = null;

            if (body != null && !body.isBlank()) {
                var targetMatch = java.util.regex.Pattern.compile("\"target\"\\s*:\\s*\"([^\"]+)\"").matcher(body);
                if (targetMatch.find()) {
                    rawTarget = targetMatch.group(1).trim();
                }
            }

            if (rawTarget != null && !rawTarget.isEmpty()) {
                if (GitCloner.isGitUrl(rawTarget)) {
                    // Clone the Git repo, then scan the clone
                    GitCloner.RepoTarget repo = GitCloner.parse(rawTarget);
                    clonedRepo = GitCloner.clone(repo);
                    scanTarget = clonedRepo;
                } else {
                    Path requested = Path.of(rawTarget).toAbsolutePath().normalize();
                    if (java.nio.file.Files.isDirectory(requested)) {
                        scanTarget = requested;
                    }
                }
            }

            ScannerEngine engine = new ScannerEngine();
            engine.register(new SourceCodeScanner())
                  .register(new DependencyScanner())
                  .register(new ContainerScanner())
                  .register(new InfraScanner());

            ScannerResult scanResult = engine.run(scanTarget);
            List<Finding> scoredFindings = ScoringEngine.prioritise(scanResult.findings());
            ScoringEngine.SummaryStats stats = ScoringEngine.generateSummaryStats(scoredFindings);

            DashboardGenerator dashGen = new DashboardGenerator();
            String dashboardHtml = dashGen.generate(scanResult, scoredFindings, stats);

            byte[] bytes = dashboardHtml.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(bytes); }
        } catch (Exception e) {
            String errorHtml = buildErrorPage(e.getMessage());
            byte[] bytes = errorHtml.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(500, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(bytes); }
        } finally {
            // Clean up any cloned repo to avoid filling the disk
            if (clonedRepo != null) {
                GitCloner.cleanup(clonedRepo);
            }
        }
    }

    private String buildErrorPage(String message) {
        return "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Scan Error</title>"
                + "<style>body{font-family:'Segoe UI',sans-serif;background:#F5F3FA;color:#333;"
                + "display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:40px;text-align:center;}"
                + "h1{color:#D32F2F;}a{display:inline-block;margin-top:24px;background:#7B2FE0;color:#FFF;"
                + "padding:12px 28px;border-radius:10px;text-decoration:none;font-weight:600;}"
                + "pre{background:#FFF;border:1px solid #EDE7F6;border-radius:10px;padding:16px;max-width:700px;"
                + "overflow:auto;text-align:left;color:#C62828;font-size:0.85rem;}</style></head><body>"
                + "<h1>⚠️ Scan Could Not Complete</h1>"
                + "<pre>" + (message == null ? "Unknown error" : message
                    .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")) + "</pre>"
                + "<a href='/'>← Back to Home</a></body></html>";
    }

    private String buildLandingPage() {
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SecureForge</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
                    min-height: 100vh;
                    display: flex;
                }

                /* Left purple panel — BT style */
                .left-panel {
                    width: 50%;
                    background: #7B2FE0;
                    position: relative;
                    display: flex;
                    flex-direction: column;
                    justify-content: center;
                    padding: 60px;
                    overflow: hidden;
                    color: #FFFFFF;
                }

                /* Subtle wave texture overlay */
                .left-panel::before {
                    content: '';
                    position: absolute;
                    top: 0; left: 0; right: 0; bottom: 0;
                    background:
                        radial-gradient(ellipse at 20% 50%, rgba(255,255,255,0.06) 0%, transparent 50%),
                        radial-gradient(ellipse at 80% 20%, rgba(255,255,255,0.04) 0%, transparent 40%),
                        radial-gradient(ellipse at 60% 80%, rgba(255,255,255,0.05) 0%, transparent 45%);
                    pointer-events: none;
                }

                /* Wavy SVG curves */
                .left-panel::after {
                    content: '';
                    position: absolute;
                    top: 0; left: 0; right: 0; bottom: 0;
                    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 500 1000'%3E%3Cpath d='M-50,200 Q150,150 100,400 T200,700 T50,1000' fill='none' stroke='rgba(255,255,255,0.07)' stroke-width='80'/%3E%3Cpath d='M400,0 Q300,200 350,400 T250,700 T400,1000' fill='none' stroke='rgba(255,255,255,0.05)' stroke-width='100'/%3E%3Cpath d='M150,-50 Q250,100 200,350 T300,600 T150,900' fill='none' stroke='rgba(255,255,255,0.04)' stroke-width='120'/%3E%3C/svg%3E");
                    background-size: cover;
                    pointer-events: none;
                }

                .left-content { position: relative; z-index: 1; }

                .shield-icon { font-size: 4rem; margin-bottom: 24px; }

                .left-panel h1 {
                    font-size: 2.6rem;
                    font-weight: 800;
                    line-height: 1.15;
                    margin-bottom: 16px;
                    color: #FFFFFF;
                }

                .left-panel .subtitle {
                    font-size: 1rem;
                    color: rgba(255,255,255,0.8);
                    line-height: 1.6;
                    max-width: 420px;
                }

                /* Right white panel */
                .right-panel {
                    width: 50%;
                    background: #FFFFFF;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    padding: 60px 40px;
                    color: #333333;
                }

                .features {
                    display: grid;
                    grid-template-columns: repeat(2, 1fr);
                    gap: 20px;
                    margin-bottom: 48px;
                    max-width: 480px;
                }

                .feature {
                    text-align: center;
                    padding: 24px 16px;
                }

                .feature .icon-circle {
                    width: 72px; height: 72px;
                    border-radius: 50%;
                    background: #F0EAFB;
                    display: flex; align-items: center; justify-content: center;
                    margin: 0 auto 12px;
                    font-size: 1.8rem;
                    transition: transform 0.2s, background 0.2s;
                }

                .feature:hover .icon-circle {
                    transform: scale(1.1);
                    background: #E0D4F5;
                }

                .feature .name {
                    font-weight: 700;
                    font-size: 0.8rem;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    color: #444;
                }

                .target-info {
                    background: #F8F5FF;
                    border: 1px solid #E8E0F5;
                    border-radius: 10px;
                    padding: 12px 24px;
                    margin-bottom: 28px;
                    display: inline-flex;
                    align-items: center;
                    gap: 10px;
                    font-size: 0.85rem;
                    color: #666;
                }

                .target-info code {
                    background: #7B2FE0;
                    color: #FFFFFF;
                    padding: 4px 12px;
                    border-radius: 6px;
                    font-family: 'SF Mono', 'Cascadia Code', monospace;
                    font-size: 0.8rem;
                }

                .path-input {
                    background: #FFFFFF;
                    border: 2px solid #D1C4E9;
                    border-radius: 8px;
                    padding: 10px 16px;
                    font-family: 'SF Mono', 'Cascadia Code', monospace;
                    font-size: 0.85rem;
                    color: #333;
                    width: 460px;
                    max-width: 70vw;
                    outline: none;
                    transition: border-color 0.2s;
                }
                .path-input:focus { border-color: #7B2FE0; }
                .path-input::placeholder { color: #B0BEC5; font-size: 0.78rem; }

                .scan-btn {
                    background: #7B2FE0;
                    color: #FFFFFF;
                    border: none;
                    padding: 18px 52px;
                    font-size: 1.1rem;
                    font-weight: 700;
                    border-radius: 12px;
                    cursor: pointer;
                    transition: all 0.3s;
                    box-shadow: 0 4px 20px rgba(123, 47, 224, 0.4);
                    text-transform: uppercase;
                    letter-spacing: 1.5px;
                    position: relative;
                    overflow: hidden;
                }

                .scan-btn:hover {
                    background: #6B21D1;
                    transform: translateY(-2px);
                    box-shadow: 0 8px 32px rgba(123, 47, 224, 0.5);
                }

                .scan-btn:active { transform: translateY(0); }
                .scan-btn.loading { pointer-events: none; opacity: 0.85; }
                .scan-btn .btn-text { transition: opacity 0.2s; }
                .scan-btn.loading .btn-text { opacity: 0; }
                .spinner { display: none; position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); }
                .scan-btn.loading .spinner { display: block; }
                .spinner::after {
                    content: ''; display: block; width: 24px; height: 24px;
                    border: 3px solid rgba(255,255,255,0.3); border-top-color: #FFFFFF;
                    border-radius: 50%; animation: spin 0.8s linear infinite;
                }
                @keyframes spin { to { transform: rotate(360deg); } }

                .status-text {
                    margin-top: 20px;
                    font-size: 0.85rem;
                    color: #7B2FE0;
                    min-height: 24px;
                    font-weight: 500;
                }

                @media (max-width: 768px) {
                    body { flex-direction: column; }
                    .left-panel, .right-panel { width: 100%; }
                    .left-panel { padding: 40px 30px; min-height: 40vh; }
                    .right-panel { padding: 40px 20px; }
                    .features { grid-template-columns: repeat(2, 1fr); gap: 12px; }
                    .left-panel h1 { font-size: 2rem; }
                }
            </style>
        </head>
        <body>
            <div class="left-panel">
                <div class="left-content">
                    <div class="shield-icon">🛡️</div>
                    <h1>SecureForge<br>Security Scanner</h1>
                    <p class="subtitle">
                        Automated vulnerability detection across source code, dependencies,
                        containers, and infrastructure configs — with prioritized, actionable reporting.
                    </p>
                </div>
            </div>

            <div class="right-panel">
                <div class="features">
                    <div class="feature">
                        <div class="icon-circle">💻</div>
                        <div class="name">Source Code</div>
                    </div>
                    <div class="feature">
                        <div class="icon-circle">📦</div>
                        <div class="name">Dependencies</div>
                    </div>
                    <div class="feature">
                        <div class="icon-circle">🐳</div>
                        <div class="name">Containers</div>
                    </div>
                    <div class="feature">
                        <div class="icon-circle">☁️</div>
                        <div class="name">Infrastructure</div>
                    </div>
                </div>

                <div class="target-info">
                    📁 Target:
                    <input type="text" id="targetPath" class="path-input" placeholder="Local path or Git URL (https://gitlab.../repo)" />
                </div>

                <button class="scan-btn" id="scanBtn" onclick="runScan()">
                    <span class="btn-text">🔍 Run Security Checks</span>
                    <span class="spinner"></span>
                </button>

                <div class="status-text" id="status"></div>
            </div>

            <script>
                async function runScan() {
                    var btn = document.getElementById('scanBtn');
                    var status = document.getElementById('status');
                    var targetPath = document.getElementById('targetPath').value.trim();
                    if (!targetPath) {
                        status.textContent = '⚠️ Please enter a project path to scan.';
                        status.style.color = '#E65100';
                        return;
                    }
                    btn.classList.add('loading');
                    status.style.color = '#7B2FE0';
                    var isGit = /^(https?:\\/\\/|git@)/.test(targetPath) || targetPath.endsWith('.git');
                    status.textContent = isGit
                        ? '⏳ Cloning repository and running security scan... (this may take a moment)'
                        : '⏳ Running security scan on ' + targetPath + '...';
                    try {
                        var res = await fetch('/api/scan', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ target: targetPath })
                        });
                        if (!res.ok) throw new Error('Scan failed with status ' + res.status);
                        var html = await res.text();
                        status.textContent = '✅ Scan complete! Loading dashboard...';
                        setTimeout(function() { document.open(); document.write(html); document.close(); }, 600);
                    } catch (err) {
                        btn.classList.remove('loading');
                        status.textContent = '❌ Error: ' + err.message;
                        status.style.color = '#D32F2F';
                    }
                }
            </script>
        </body>
        </html>
        """;
    }
}
