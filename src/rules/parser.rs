use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub language: String,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub owasp: Option<String>,
    pub description: String,
    pub pattern: Pattern,
    pub message: String,
    #[serde(default)]
    pub fix_hint: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn ordinal(&self) -> u8 {
        match self {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Pattern {
    #[serde(rename = "type")]
    pub pattern_type: PatternType,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub regex: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PatternType {
    Ast,
    Regex,
}

/// Parse a single YAML rule file
pub fn parse_rule_file(path: &Path) -> Result<Rule> {
    let content = std::fs::read_to_string(path)?;
    let rule: Rule = serde_yaml::from_str(&content)?;
    Ok(rule)
}

/// Parse all YAML rule files in a directory
pub fn parse_rules_dir(dir: &Path) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();

    if !dir.exists() {
        return Ok(rules);
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("yml")
            || path.extension().and_then(|e| e.to_str()) == Some("yaml")
        {
            match parse_rule_file(&path) {
                Ok(rule) => rules.push(rule),
                Err(e) => eprintln!("Warning: failed to parse rule {}: {}", path.display(), e),
            }
        }
    }

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rule_yaml() {
        let yaml = r#"
id: TEST-001
name: test-rule
severity: high
language: python
description: "Test rule"
pattern:
  type: regex
  regex:
    - "eval\\("
message: "Do not use eval"
"#;
        let rule: Rule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.id, "TEST-001");
        assert_eq!(rule.severity, Severity::High);
        assert_eq!(rule.pattern.pattern_type, PatternType::Regex);
        assert_eq!(rule.pattern.regex.len(), 1);
        assert!(rule.cwe.is_none());
        assert!(rule.fix_hint.is_none());
    }

    #[test]
    fn test_parse_rule_with_all_fields() {
        let yaml = r#"
id: TEST-002
name: full-rule
severity: critical
language: javascript
cwe: CWE-79
owasp: "A07:2021"
description: "Full test rule"
pattern:
  type: ast
  query: "(call_expression)"
  regex:
    - "innerHTML"
message: "XSS risk"
fix_hint: "Use textContent"
references:
  - "https://example.com"
"#;
        let rule: Rule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.id, "TEST-002");
        assert_eq!(rule.severity, Severity::Critical);
        assert_eq!(rule.cwe, Some("CWE-79".to_string()));
        assert_eq!(rule.owasp, Some("A07:2021".to_string()));
        assert_eq!(rule.fix_hint, Some("Use textContent".to_string()));
        assert_eq!(rule.references.len(), 1);
        assert_eq!(rule.pattern.pattern_type, PatternType::Ast);
        assert!(rule.pattern.query.is_some());
    }

    #[test]
    fn test_severity_labels() {
        assert_eq!(Severity::Critical.label(), "CRITICAL");
        assert_eq!(Severity::High.label(), "HIGH");
        assert_eq!(Severity::Medium.label(), "MEDIUM");
        assert_eq!(Severity::Low.label(), "LOW");
        assert_eq!(Severity::Info.label(), "INFO");
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", Severity::Critical), "CRITICAL");
        assert_eq!(format!("{}", Severity::Low), "LOW");
    }

    #[test]
    fn test_parse_invalid_yaml_errors() {
        let yaml = "this is not valid: [";
        let result: Result<Rule, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }
}
