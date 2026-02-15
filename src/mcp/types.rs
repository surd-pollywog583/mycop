use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ---- Scan Tool ----

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScanParams {
    /// Files or directories to scan (absolute paths)
    pub paths: Vec<String>,
    /// Minimum severity to report: "critical", "high", "medium", "low", "info"
    #[serde(default)]
    pub severity: Option<String>,
    /// Only scan files changed in git diff
    #[serde(default)]
    pub diff: Option<bool>,
    /// Maximum number of findings to return (default: 50)
    #[serde(default)]
    pub max_results: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub total_findings: usize,
    pub files_scanned: usize,
    pub rules_loaded: usize,
    pub findings: Vec<FindingOutput>,
}

#[derive(Debug, Serialize)]
pub struct FindingOutput {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub matched_text: String,
    pub message: String,
    pub description: String,
    pub fix_hint: Option<String>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub references: Vec<String>,
    pub context_before: Vec<String>,
    pub context_after: Vec<String>,
}

// ---- List Rules Tool ----

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListRulesParams {
    /// Filter by language: "python", "javascript"
    #[serde(default)]
    pub language: Option<String>,
    /// Filter by minimum severity: "critical", "high", "medium", "low"
    #[serde(default)]
    pub severity: Option<String>,
    /// Search term to filter rules by name, id, or description
    #[serde(default)]
    pub search: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListRulesResult {
    pub total: usize,
    pub rules: Vec<RuleOutput>,
}

#[derive(Debug, Serialize)]
pub struct RuleOutput {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub language: String,
    pub description: String,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub fix_hint: Option<String>,
    pub references: Vec<String>,
}

// ---- Explain Finding Tool ----

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExplainFindingParams {
    /// The file path containing the vulnerability
    pub file: String,
    /// The line number of the finding
    pub line: usize,
    /// The rule ID (e.g., "PY-SEC-001")
    pub rule_id: String,
    /// Override AI provider: "claude-cli", "anthropic", "openai", "ollama", "none"
    #[serde(default)]
    pub ai_provider: Option<String>,
}

// ---- Fix Tool ----

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FixParams {
    /// File path to fix
    pub file: String,
    /// Minimum severity to fix: "critical", "high", "medium", "low"
    #[serde(default)]
    pub severity: Option<String>,
    /// If true, return the diff without writing changes (default: true)
    #[serde(default = "default_true")]
    pub dry_run: bool,
    /// Override AI provider
    #[serde(default)]
    pub ai_provider: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct FixResult {
    pub file: String,
    pub vulnerabilities_found: usize,
    pub fixed: bool,
    pub diff: Option<String>,
    pub fixed_content: Option<String>,
    pub remaining_vulnerabilities: usize,
}

// ---- Review Tool ----

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReviewParams {
    /// File path to review
    pub file: String,
    /// Override AI provider
    #[serde(default)]
    pub ai_provider: Option<String>,
}

// ---- Check Deps Tool ----

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CheckDepsParams {
    /// Path to project directory, requirements.txt, or package.json
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct CheckDepsResult {
    pub files_checked: Vec<String>,
    pub python_packages: Vec<String>,
    pub npm_packages: Vec<String>,
    pub npm_dev_packages: Vec<String>,
}
