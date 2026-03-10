# PHP Security Scanner

A local PHP secure code review tool (SAST) built in Go. Zero external dependencies.

```
╔══════════════════════════════════════════════════╗
║   PHP Security Scanner v2.0.0                    ║
║   OWASP Top 10 + Taint Analysis SAST Tool       ║
║   109+ Detection Rules | 25+ Categories          ║
╚══════════════════════════════════════════════════╝
```

## Features

- **109+ detection rules** covering 25+ vulnerability categories
- **Intraprocedural taint tracking** — traces user input from source to sink
- **4 output formats** — Terminal (color-coded), HTML, JSON, SARIF
- **Sanitizer-aware** — recognizes `htmlspecialchars()`, `prepared statements`, WordPress escaping functions, etc.
- **Confidence scoring** — High / Medium / Low confidence for every finding
- **Rule deduplication** — consolidates overlapping regex + taint findings
- **Flow visualization** — displays full taint path (source → assignment → sink) in all reports
- **Semgrep rule import** — convert Semgrep YAML rules to scanner format
- **Baseline comparison** — track only new findings between scans
- **Framework detection** — Laravel, WordPress, Symfony, CodeIgniter, CakePHP
- **Concurrent scanning** — parallel file processing with configurable workers
- **Project config file** — `.php-scanner.json` for per-project settings
- **Inline suppression** — `// nosec` comments to mark intentional patterns
- **CI/CD ready** — SARIF output for GitHub Code Scanning, exit codes for build gates
- **Zero dependencies** — pure Go standard library, single binary

## Requirements

| Requirement | Version |
|-------------|---------|
| **Go** | 1.21 or later |
| **Git** | Any (to clone) |

That's it. No pip, npm, composer, or any package manager needed.

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/professor-13/php-security-scanner.git
cd php-security-scanner

# 2. Build
go build -o php-security-scanner .      # Linux/macOS
go build -o php-security-scanner.exe .  # Windows

# 3. Scan
./php-security-scanner /path/to/php/project
```

## Installation

See **[INSTALLATION.txt](INSTALLATION.txt)** for detailed step-by-step instructions including:
- Go installation for Windows, macOS, and Linux
- Building from source
- Global installation
- CI/CD integration setup

### Install Go

**Windows:** `winget install GoLang.Go`

**macOS:** `brew install go`

**Linux:** `sudo apt install golang-go` or download from [go.dev/dl](https://go.dev/dl/)

## Usage

```bash
# Basic scan
./php-security-scanner ./src

# Show only high/critical findings
./php-security-scanner -s high ./src

# Exclude vendor directories
./php-security-scanner -e "vendor/*,node_modules/*,test/*" ./src

# Generate all report formats
./php-security-scanner --json --sarif -o ./results ./src

# Scan a single file
./php-security-scanner ./path/to/file.php
```

### All CLI Flags

```
Output Flags:
  -o, --output string        Output directory for reports (default "./report")
      --no-html              Skip HTML report generation
      --json                 Also output JSON report
      --sarif                Also output SARIF report (GitHub/CI/CD integration)

Analysis Flags:
  -s, --severity string      Minimum severity: critical, high, medium, low, info
  -e, --exclude string       Comma-separated glob patterns to exclude
      --rules-dir string     Directory containing custom JSON rule files
      --disable-rule string  Comma-separated rule IDs to disable
      --context-lines int    Lines of context before/after findings (default 3)
      --concurrency int      Number of parallel workers, 0=auto (default 0)
      --show-suppressed      Include // nosec suppressed findings in output

Baseline Flags:
      --baseline string      Compare against baseline file (show only new findings)
      --save-baseline string Save current scan as baseline to this path

Utility Flags:
      --init-config          Create a default .php-scanner.json config
      --init-rules           Create an example custom-rules.json file
      --version              Show version and exit
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No critical or high severity findings |
| `1` | Critical or high severity findings detected |
| `2` | Scanner error |

## Vulnerability Categories

| Category | CWE | Rules |
|----------|-----|-------|
| SQL Injection | CWE-89 | SQL-001 to SQL-008 |
| Cross-Site Scripting (XSS) | CWE-79 | XSS-001 to XSS-007 |
| Command Injection | CWE-78/94 | CMD-001 to CMD-009 |
| File Inclusion (LFI/RFI) | CWE-98 | FI-001 to FI-003 |
| Path Traversal | CWE-22 | PT-001 to PT-007 |
| Insecure Deserialization | CWE-502 | DESER-001 to DESER-003 |
| SSRF | CWE-918 | SSRF-001 to SSRF-004 |
| Weak Cryptography | CWE-327/328/330 | CRYPTO-001 to CRYPTO-008 |
| Hardcoded Credentials | CWE-798 | AUTH-001 to AUTH-015 |
| Information Disclosure | CWE-200/209 | INFO-001 to INFO-007 |
| File Upload | CWE-434 | UPLOAD-001 to UPLOAD-004 |
| CSRF | CWE-352 | CSRF-001 to CSRF-002 |
| Open Redirect | CWE-601 | REDIR-001 to REDIR-002 |
| XXE | CWE-611 | XXE-001 to XXE-005 |
| Insecure Configuration | CWE-16/384 | CONFIG-001 to CONFIG-007 |
| Type Juggling | CWE-1025 | TYPE-001 to TYPE-003 |
| Header Injection | CWE-113 | HEADER-001 to HEADER-002 |
| Log Injection | CWE-117 | LOG-001 to LOG-002 |
| LDAP Injection | CWE-90 | LDAP-001 to LDAP-002 |
| XPath Injection | CWE-643 | XPATH-001 |
| Race Condition (TOCTOU) | CWE-367 | RACE-001 |
| Insecure Transport | CWE-319/295 | HTTP-001 to HTTP-003 |
| Regex DoS (ReDoS) | CWE-1333 | REDOS-001 |
| Email Injection | CWE-93 | EMAIL-001 |
| Session Fixation | CWE-384 | SESSION-001 |
| Unsafe Object Creation | CWE-470 | OBJ-001 to OBJ-002 |

## Taint Tracking

The scanner performs intraprocedural taint analysis to trace user input (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`) through variable assignments to dangerous sinks (`mysqli_query()`, `echo`, `exec()`, etc.).

Taint findings include full flow traces:

```
[SOURCE] L83   $cid = $_POST["cid"];                              ($cid)
  ->  [ASSIGN] L84   $sql = "SELECT * FROM ... WHERE id='$cid'";  ($sql)
  ->  [ SINK ] L85   $result = mysqli_query($con, $sql);           ($sql)
```

## Configuration

Create a project config file:

```bash
./php-security-scanner --init-config
```

This creates `.php-scanner.json`:

```json
{
  "min_severity": "low",
  "exclude_patterns": ["vendor/*", "node_modules/*"],
  "output_dir": "./report",
  "disabled_rules": [],
  "concurrency": 0,
  "context_lines": 3
}
```

CLI flags always take priority over config file values.

## Semgrep Rule Import

Convert existing Semgrep YAML rules to the scanner's JSON format:

```bash
# Import from a single file
./php-security-scanner import-semgrep ./rules/php-sqli.yaml

# Import from a directory
./php-security-scanner import-semgrep ./semgrep-rules/php/

# Use imported rules
./php-security-scanner --rules-dir . ./src
```

Only PHP rules are imported; other languages are automatically skipped.

## CI/CD Integration

### GitHub Actions

```yaml
name: PHP Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'
      - name: Build scanner
        run: |
          git clone https://github.com/professor-13/php-security-scanner.git /tmp/scanner
          cd /tmp/scanner && go build -o /usr/local/bin/php-security-scanner .
      - name: Run scan
        run: php-security-scanner --sarif -s high -e "vendor/*" .
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: report/php-security-report.sarif
```

### Baseline for PRs

```bash
# On main branch: save baseline
./php-security-scanner --save-baseline baseline.json ./src

# On PR: show only new findings
./php-security-scanner --baseline baseline.json ./src
```

## Project Structure

```
php-security-scanner/
  main.go                      # CLI entry point, flag parsing, subcommands
  go.mod                       # Go module (zero external dependencies)
  scanner/
    models.go                  # Data types (Finding, Rule, ScanConfig, FlowStep)
    scanner.go                 # Core scanning engine, taint integration, dedup
    rules.go                   # 86 built-in OWASP detection rules
    rules_extra.go             # 23 additional rules (type juggling, LDAP, etc.)
    taint.go                   # Intraprocedural taint tracking engine
    sanitizers.go              # Sanitizer detection (50+ PHP functions)
    framework.go               # Framework detection (Laravel, WordPress, etc.)
    config.go                  # Project config file (.php-scanner.json)
    cache.go                   # File content caching
    yaml_loader.go             # Custom YAML rule loader
    semgrep_importer.go        # Semgrep YAML rule importer & converter
  reporter/
    terminal.go                # Color-coded terminal output with flow traces
    html.go                    # Interactive HTML report + JSON export
    sarif.go                   # SARIF v2.1.0 output with CodeFlows
  testdata/                    # Sample vulnerable PHP projects for testing
```

## License

This project is open source. See the repository for license details.
