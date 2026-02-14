use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ScanConfig {
    /// File patterns to ignore (glob syntax)
    #[serde(default)]
    pub ignore: Vec<String>,

    /// Minimum severity to report: critical, high, medium, low
    #[serde(default)]
    pub min_severity: Option<String>,

    /// AI provider override: claude-cli, anthropic, openai, ollama, none
    #[serde(default)]
    pub ai_provider: Option<String>,

    /// Minimum severity to fail (exit code 1): critical, high, medium, low
    #[serde(default)]
    pub fail_on: Option<String>,
}

impl ScanConfig {
    /// Load config from .scanrc.yml in the given directory
    pub fn load(dir: &Path) -> Result<Option<Self>> {
        let candidates = vec![
            dir.join(".scanrc.yml"),
            dir.join(".scanrc.yaml"),
            dir.join(".mycop.yml"),
        ];

        for path in candidates {
            if path.exists() {
                let content = std::fs::read_to_string(&path)?;
                let config: ScanConfig = serde_yaml::from_str(&content)?;
                return Ok(Some(config));
            }
        }

        Ok(None)
    }

    /// Generate a default .scanrc.yml content
    #[allow(dead_code)]
    pub fn default_content() -> &'static str {
        r#"# mycop configuration file
# See https://github.com/AbdumajidRashidov/mycop for documentation

# File patterns to ignore (glob syntax)
ignore:
  - "**/*_test.py"
  - "**/test_*.py"
  - "**/*.test.js"
  - "**/*.spec.ts"
  - "**/node_modules/**"
  - "**/__pycache__/**"
  - "**/venv/**"

# Minimum severity level: critical, high, medium, low
# min_severity: medium

# Minimum severity to cause non-zero exit: critical, high, medium, low
# fail_on: high

# AI provider override: claude-cli, anthropic, openai, ollama, none
# ai_provider: null  # auto-detect
"#
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_missing_config() {
        let dir = std::env::temp_dir().join("mycop_test_nonexistent_dir_12345");
        let result = ScanConfig::load(&dir).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_valid_config() {
        let yaml = r#"
ignore:
  - "**/*.test.js"
  - "**/node_modules/**"
min_severity: high
ai_provider: anthropic
"#;
        let config: ScanConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.ignore.len(), 2);
        assert_eq!(config.min_severity, Some("high".to_string()));
        assert_eq!(config.ai_provider, Some("anthropic".to_string()));
    }

    #[test]
    fn test_default_content_is_valid_yaml() {
        let content = ScanConfig::default_content();
        let result: Result<ScanConfig, _> = serde_yaml::from_str(content);
        assert!(result.is_ok());
        let config = result.unwrap();
        assert!(!config.ignore.is_empty());
    }

    #[test]
    fn test_empty_config() {
        let yaml = "{}";
        let config: ScanConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.ignore.is_empty());
        assert!(config.min_severity.is_none());
        assert!(config.ai_provider.is_none());
        assert!(config.fail_on.is_none());
    }

    #[test]
    fn test_config_with_fail_on() {
        let yaml = r#"
fail_on: critical
min_severity: low
"#;
        let config: ScanConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.fail_on, Some("critical".to_string()));
        assert_eq!(config.min_severity, Some("low".to_string()));
    }

    #[test]
    fn test_config_ignores_unknown_fields() {
        let yaml = r#"
ignore: []
unknown_field: true
"#;
        let result: Result<ScanConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_alt_filename() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".mycop.yml"), "ignore:\n  - \"*.test\"\n").unwrap();
        let config = ScanConfig::load(dir.path()).unwrap();
        assert!(config.is_some());
        assert_eq!(config.unwrap().ignore, vec!["*.test"]);
    }
}
