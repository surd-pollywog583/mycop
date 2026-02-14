# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Inline ignore comments (`# mycop-ignore:RULE-ID` / `// mycop-ignore:RULE-ID`)
- `--fail-on` flag for explicit exit code control
- Enhanced `mycop init` with project type detection
- GitHub Action for CI integration
- Pre-commit hook support
- Homebrew formula
- Docker image
- VS Code extension (preview)
- Comprehensive unit and integration test suite

## [0.1.0] - 2025-06-01

### Added
- Initial release
- 20 embedded security rules (10 Python, 10 JavaScript/TypeScript)
- OWASP Top 10 coverage with CWE mappings
- 5 AI backends: Claude CLI, Anthropic API, OpenAI API, Ollama, rule-based fallback
- AST (tree-sitter) + regex pattern matching
- Agentic auto-fix: AI rewrites entire files to fix all vulnerabilities
- Deep AI security review (`mycop review`)
- Terminal, JSON, and SARIF output formats
- Git diff scanning mode (`--diff`)
- `.scanrc.yml` / `.mycop.yml` configuration
- Severity filtering (`--severity`)
- Parallel file scanning with Rayon
