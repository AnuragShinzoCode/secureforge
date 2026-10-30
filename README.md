# 🛡️ SecureForge

**An automated security scanning agent** that detects vulnerabilities across source code,
dependencies, containers, and infrastructure configs — in a single scan-to-report pipeline.

Point it at a local path or a Git repository URL, and it clones, scans, scores, and
visualizes the results in seconds.

---

## ✨ Features

- **🔍 Source Code Analysis** — SQL injection, XSS, hardcoded secrets, weak crypto (MD5/SHA1),
  command injection, path traversal, eval/JNDI, unsafe deserialization, XXE, disabled TLS,
  CORS wildcards. Supports JavaScript, TypeScript, Python, Java, Go, Ruby, PHP, C#.
- **📦 Dependency Scanning** — Known CVEs in npm (`package.json`), pip (`requirements.txt`),
  and Maven (`pom.xml`) — including Log4Shell, Spring, Jackson, SnakeYAML, Commons Text.
- **🐳 Container Security** — Dockerfile & docker-compose checks: running as root, secrets in
  ENV, exposed ports, privileged mode, Docker socket mounts.
- **☁️ Infrastructure Configs** — Terraform, CloudFormation, and Kubernetes: open security
  groups, unencrypted storage, public access, wildcard IAM.
- **📊 Smart Prioritization** — Every finding scored 0–100 (severity × business impact ×
  confidence × category) and grouped into SLA tiers with actionable remediation guidance.
- **🌐 Web Dashboard** — Interactive UI with charts, a drill-down file tree, and a ranked
  findings table. Exports to HTML, JSON, and Markdown.
- **🔌 Pluggable Architecture** — Add new scanners or rules with zero engine changes.

---

## 🚀 Quick Start

### Prerequisites
- **Java 21+** ([download from Adoptium](https://adoptium.net/))
- **Maven 3.9+** (to build from source)

### Build

```bash
cd security-scanner-java
mvn clean package
```

This produces a self-contained fat JAR at `target/kiro-security-agent-1.0.0.jar`.

### Run — Web Dashboard

```bash
java -jar target/kiro-security-agent-1.0.0.jar --web
```

Then open **http://localhost:8765**, paste a local path or Git URL, and click
**Run Security Checks**.

### Run — Command Line

```bash
java -jar target/kiro-security-agent-1.0.0.jar --target /path/to/project --output ./reports
```

#### Exit codes (for CI/CD gates)

| Code | Meaning |
|------|---------|
| `0` | No high or critical findings |
| `1` | High severity findings detected |
| `2` | Critical severity findings detected |
| `3` | Scan error |

---

## 🏗️ Architecture

```
ScannerEngine        → registers & orchestrates all scanner plugins
 └── BaseScanner     → common plugin interface
      ├── SourceCodeScanner
      ├── DependencyScanner
      ├── ContainerScanner
      └── InfraScanner
ScoringEngine        → composite risk scoring & prioritization
ReportGenerator      → Markdown + JSON output
DashboardGenerator   → interactive HTML dashboard
WebServer            → embedded web UI + Git-clone support
```

Each scanner is a self-contained plugin. Adding a new check is as simple as implementing
`BaseScanner` or adding a `ScanRule` — no engine changes required.

---

## 🧪 Try It

A deliberately vulnerable `sample-project/` is included for testing:

```bash
java -jar security-scanner-java/target/kiro-security-agent-1.0.0.jar \
     --target ./sample-project --output ./reports
```

---

## 🗺️ Roadmap

- Auto-remediation (suggest & apply fixes)
- CI/CD gate integration
- Continuous monitoring dashboards
- Live CVE feeds (OSV / NVD)

---

## 📄 License

Released under the MIT License. See [LICENSE](LICENSE).
