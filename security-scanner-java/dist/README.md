# 🛡️ SecureForge

**Automated security scanning agent** — detect vulnerabilities across source code,
dependencies, containers, and infrastructure configs, with prioritized, actionable reports.

This is a self-contained tool. The only requirement is **Java 21 or later**.

---

## 1. Prerequisites

Check if you have Java 21+:

```bash
java --version
```

If not installed, download a free build from [Adoptium](https://adoptium.net/) (Temurin 21).

---

## 2. What's in this package

| File | Purpose |
|------|---------|
| `secureforge.jar` | The entire tool (self-contained fat JAR) |
| `run-web.sh` / `run-web.bat` | Launch the interactive web dashboard |
| `scan.sh` / `scan.bat` | Run a one-off scan from the command line |
| `README.md` | This file |

---

## 3. Option A — Web Dashboard (recommended)

Launch the UI, then paste any project path and click **Run Security Checks**.

**macOS / Linux:**
```bash
./run-web.sh
```

**Windows:**
```bat
run-web.bat
```

Then open **http://localhost:8765** in your browser.

To use a different port:
```bash
./run-web.sh 9000
```

---

## 4. Option B — Command Line (for CI/CD or scripting)

Scan a project and write Markdown + JSON + HTML reports to a folder.

**macOS / Linux:**
```bash
./scan.sh /path/to/your/project ./reports
```

**Windows:**
```bat
scan.bat C:\path\to\your\project .\reports
```

Or run the JAR directly:
```bash
java -jar secureforge.jar --target /path/to/project --output ./reports
```

### Exit codes (useful for CI/CD gates)

| Code | Meaning |
|------|---------|
| `0` | No high or critical findings |
| `1` | High severity findings detected |
| `2` | Critical severity findings detected |
| `3` | Scan error |

Example CI gate (fail the build on critical findings):
```bash
java -jar secureforge.jar --target . --output ./reports
if [ $? -ge 2 ]; then echo "Critical vulnerabilities found"; exit 1; fi
```

---

## 5. What it scans

| Category | Detects |
|----------|---------|
| **Source Code** | SQL injection, XSS, hardcoded secrets, weak crypto (MD5/SHA1), command injection, path traversal, eval/JNDI, unsafe deserialization, XXE, disabled TLS, CORS wildcards |
| **Dependencies** | Known CVEs in npm (`package.json`), pip (`requirements.txt`), and Maven (`pom.xml`) — Log4Shell, Spring, Jackson, SnakeYAML, Commons Text, and more |
| **Containers** | Dockerfile & docker-compose — running as root, secrets in ENV, exposed ports, privileged mode, Docker socket mounts |
| **Infrastructure** | Terraform, CloudFormation, Kubernetes — open security groups, unencrypted storage, public access, wildcard IAM |

Supported source languages: JavaScript, TypeScript, Python, Java, Go, Ruby, PHP, C#.

---

## 6. Reports

Each scan produces three outputs in the output folder:

- `security-dashboard-latest.html` — visual dashboard (charts + file tree + table)
- `security-report-latest.json` — machine-readable, for integration
- `security-report-latest.md` — human-readable summary

Findings are scored 0–100 (severity × business impact × confidence × category)
and grouped into SLA tiers (Critical = 24h, High = 1 week, Medium = 2 weeks, Low = 1 month).

---

## 7. Support & contributions

To add a new vulnerability rule or CVE, update the scanner classes and rebuild.
Contact the SecureForge team to contribute rules or report issues.

*SecureForge — Scan. Prioritize. Secure.*
