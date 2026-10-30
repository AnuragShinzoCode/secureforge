package com.kiro.security;

import com.kiro.security.core.*;
import com.kiro.security.reporters.ReportGenerator;
import com.kiro.security.scanners.*;
import com.kiro.security.web.WebServer;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * 🛡️ Kiro Security Agent — CLI entry point.
 * Orchestrates the full scan-to-report pipeline.
 */
@Command(
        name = "kiro-scan",
        description = "🛡️ Kiro Security Agent — Automated vulnerability scanning and reporting",
        version = "1.0.0",
        mixinStandardHelpOptions = true
)
public class KiroSecurityAgent implements Callable<Integer> {

    @Option(names = {"-t", "--target"}, description = "Target project directory to scan", defaultValue = "./sample-project")
    private Path target;

    @Option(names = {"-o", "--output"}, description = "Output directory for reports", defaultValue = "./reports")
    private Path output;

    @Option(names = {"-w", "--web"}, description = "Launch web UI dashboard", defaultValue = "false")
    private boolean web;

    @Option(names = {"-p", "--port"}, description = "Port for web UI", defaultValue = "8765")
    private int port;

    @Override
    public Integer call() throws Exception {
        Path targetDir = target.toAbsolutePath().normalize();
        Path outputDir = output.toAbsolutePath().normalize();

        // Web UI mode
        if (web) {
            WebServer server = new WebServer(port, targetDir);
            server.start();
            // Keep the process alive
            Thread.currentThread().join();
            return 0;
        }

        // CLI mode — run scan directly
        System.out.println();
        System.out.println("🛡️  ╔═══════════════════════════════════════════════╗");
        System.out.println("   ║            SecureForge (Java)                 ║");
        System.out.println("   ║  Automated Vulnerability Detection & Reporting ║");
        System.out.println("   ╚═══════════════════════════════════════════════╝");

        // 1. Build engine with all scanner plugins
        ScannerEngine engine = new ScannerEngine();
        engine.register(new SourceCodeScanner())
              .register(new DependencyScanner())
              .register(new ContainerScanner())
              .register(new InfraScanner());

        // 2. Run all scans
        ScannerResult scanResult = engine.run(targetDir);

        // 3. Score and prioritise findings
        List<Finding> scoredFindings = ScoringEngine.prioritise(scanResult.findings());
        ScoringEngine.SummaryStats stats = ScoringEngine.generateSummaryStats(scoredFindings);

        // 4. Generate reports
        ReportGenerator reporter = new ReportGenerator();
        reporter.printConsoleSummary(stats);

        ReportGenerator.ReportPaths paths = reporter.generate(scanResult, scoredFindings, stats, outputDir);

        System.out.printf("📄 Markdown report: %s%n", paths.mdPath());
        System.out.printf("📊 JSON report:     %s%n", paths.jsonPath());
        System.out.printf("🖥️  Dashboard:       %s%n%n", paths.dashboardPath());

        // 5. Exit code based on findings
        if (stats.bySeverity().getOrDefault("critical", 0) > 0) return 2;
        if (stats.bySeverity().getOrDefault("high", 0) > 0) return 1;
        return 0;
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new KiroSecurityAgent()).execute(args);
        System.exit(exitCode);
    }
}
