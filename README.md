# mycop

AI Code Security Scanner — detect and auto-fix vulnerabilities in AI-generated code.

[![CI](https://github.com/AbdumajidRashidov/mycop/actions/workflows/ci.yml/badge.svg)](https://github.com/AbdumajidRashidov/mycop/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

mycop scans Python, JavaScript, and TypeScript codebases for security vulnerabilities using pattern matching, AST analysis, and optional AI-powered explanations and auto-fix. It ships with 20 built-in security rules covering OWASP Top 10 categories.

## Installation

```bash
cargo install mycop
```

Or build from source:

```bash
git clone https://github.com/AbdumajidRashidov/mycop.git
cd mycop
cargo install --path .
```

## Quick Start

```bash
# Scan current directory
mycop scan .

# Auto-fix all vulnerabilities using AI
mycop fix .

# Deep AI security review of a single file
mycop review src/auth.py

# List all security rules
mycop rules list
```

## Commands

### `mycop scan`

Scan files for security vulnerabilities.

```bash
mycop scan .                              # Scan current directory
mycop scan src/ lib/                      # Scan specific directories
mycop scan --severity high                # Only report high/critical
mycop scan --format json                  # JSON output
mycop scan --format sarif                 # SARIF output (for IDE integration)
mycop scan --explain                      # AI-powered explanations
mycop scan --diff                         # Only scan git-changed files
mycop scan --fix                          # Auto-fix (same as `mycop fix`)
```

Exit code 1 if critical or high severity findings are detected.

### `mycop fix`

Auto-fix security vulnerabilities using AI. Groups all findings per file, sends the entire file to an AI provider, and writes back the fixed version.

```bash
mycop fix .                               # Fix all files
mycop fix src/auth.py                     # Fix specific file
mycop fix . --severity high               # Only fix high/critical
mycop fix . --dry-run                     # Show diffs without writing
mycop fix . --ai-provider anthropic       # Force specific AI provider
mycop fix . --diff                        # Only fix git-changed files
```

### `mycop review`

Deep AI-powered security review of a single file. Goes beyond rule matching to find logic flaws, race conditions, and architectural issues.

```bash
mycop review src/server.ts
mycop review app.py --ai-provider openai
```

### `mycop init`

Create a `.scanrc.yml` configuration file in the current directory.

```bash
mycop init
```

### `mycop rules list`

List all available security rules.

```bash
mycop rules list                          # All rules
mycop rules list --language python        # Python rules only
mycop rules list --severity high          # High/critical rules only
```

### `mycop deps check`

Check dependencies for issues (hallucinated packages).

```bash
mycop deps check .
mycop deps check requirements.txt
```

## AI Providers

mycop auto-detects available AI providers in this order:

1. **Claude CLI** — `claude` command installed
2. **Anthropic API** — `ANTHROPIC_API_KEY` environment variable
3. **OpenAI API** — `OPENAI_API_KEY` environment variable
4. **Ollama** — local Ollama server running on port 11434
5. **Rule-based** — offline fallback using fix hints from rules

Override with `--ai-provider`:

```bash
mycop scan . --explain --ai-provider anthropic
mycop fix . --ai-provider ollama
```

## Configuration

Create a `.scanrc.yml` (or `.mycop.yml`) in your project root:

```yaml
# File patterns to ignore (glob syntax)
ignore:
  - "**/*_test.py"
  - "**/test_*.py"
  - "**/*.test.js"
  - "**/*.spec.ts"
  - "**/node_modules/**"
  - "**/venv/**"

# Minimum severity level: critical, high, medium, low
min_severity: medium

# AI provider override: claude-cli, anthropic, openai, ollama, none
# ai_provider: anthropic
```

CLI flags always take priority over config file values.

## Security Rules

20 built-in rules covering:

| Category | Python | JavaScript |
|----------|--------|------------|
| SQL Injection (CWE-89) | PY-SEC-001 | — |
| Command Injection (CWE-78) | PY-SEC-002 | — |
| Hardcoded Secrets (CWE-798) | PY-SEC-003 | JS-SEC-004 |
| Insecure Random (CWE-330) | PY-SEC-004 | JS-SEC-005 |
| Eval/Exec Injection (CWE-95) | PY-SEC-005 | JS-SEC-002 |
| Path Traversal (CWE-22) | PY-SEC-006 | JS-SEC-006 |
| Insecure Deserialization (CWE-502) | PY-SEC-007 | JS-SEC-009 |
| Missing Auth (CWE-862) | PY-SEC-008 | — |
| XSS (CWE-79) | PY-SEC-009 | JS-SEC-001, JS-SEC-010 |
| Log Injection (CWE-117) | PY-SEC-010 | — |
| Prototype Pollution (CWE-1321) | — | JS-SEC-003 |
| SSRF (CWE-918) | — | JS-SEC-007 |
| NoSQL Injection (CWE-943) | — | JS-SEC-008 |

## Output Formats

- **Terminal** — colored output with code context (default)
- **JSON** — structured JSON for tool integration
- **SARIF** — Static Analysis Results Interchange Format for IDE/CI integration

## CI/CD Integration

```yaml
# GitHub Actions
- name: Security scan
  run: |
    cargo install mycop
    mycop scan . --format sarif > results.sarif

# Exit code 1 on high/critical findings
- name: Security gate
  run: mycop scan . --severity high
```

## License

MIT
