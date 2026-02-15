use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;

use crate::rules::parser::{self, Rule};
use crate::scanner::language::Language;

/// Embedded rule YAML files compiled into the binary
static EMBEDDED_RULES: &[(&str, &str)] = &[
    // Python rules
    (
        "python",
        include_str!("../../rules/python/sql-injection.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/os-command-injection.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/hardcoded-secrets.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/insecure-random.yml"),
    ),
    ("python", include_str!("../../rules/python/eval-exec.yml")),
    (
        "python",
        include_str!("../../rules/python/path-traversal.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/insecure-deserialization.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/missing-auth.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/xss-template.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/log-injection.yml"),
    ),
    // Python rules (011-050)
    ("python", include_str!("../../rules/python/ssrf.yml")),
    ("python", include_str!("../../rules/python/xxe-parsing.yml")),
    (
        "python",
        include_str!("../../rules/python/ldap-injection.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/template-injection.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/header-injection.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/xpath-injection.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/weak-hash-md5.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/weak-hash-sha1.yml"),
    ),
    ("python", include_str!("../../rules/python/weak-cipher.yml")),
    ("python", include_str!("../../rules/python/ecb-mode.yml")),
    (
        "python",
        include_str!("../../rules/python/hardcoded-iv.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/insecure-tls.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/jwt-none-algorithm.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/weak-password-hash.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/session-fixation.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/missing-hsts.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/open-redirect.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/cors-misconfiguration.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/mass-assignment.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/idor-pattern.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/debug-mode-enabled.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/stack-trace-exposure.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/sensitive-data-logging.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/hardcoded-connection-string.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/arbitrary-file-upload.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/tempfile-insecure.yml"),
    ),
    ("python", include_str!("../../rules/python/zipslip.yml")),
    (
        "python",
        include_str!("../../rules/python/unencrypted-socket.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/dns-resolution-user-input.yml"),
    ),
    ("python", include_str!("../../rules/python/bare-except.yml")),
    (
        "python",
        include_str!("../../rules/python/assert-for-auth.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/django-raw-sql.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/flask-secret-key.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/django-safe-string.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/subprocess-user-input.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/timing-attack.yml"),
    ),
    ("python", include_str!("../../rules/python/redos.yml")),
    ("python", include_str!("../../rules/python/toctou.yml")),
    (
        "python",
        include_str!("../../rules/python/unsafe-import.yml"),
    ),
    (
        "python",
        include_str!("../../rules/python/shell-true-list.yml"),
    ),
    // JavaScript rules
    (
        "javascript",
        include_str!("../../rules/javascript/xss-innerhtml.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/eval-injection.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/prototype-pollution.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/hardcoded-secrets.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/insecure-random.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/path-traversal.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/ssrf.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/nosql-injection.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/insecure-deserialization.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/dangerouslysetinnerhtml.yml"),
    ),
    // JavaScript rules (011-050)
    (
        "javascript",
        include_str!("../../rules/javascript/sql-injection.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/xxe-parsing.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/template-injection.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/header-injection.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/ldap-injection.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/command-injection.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/weak-hash-md5.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/weak-hash-sha1.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/weak-cipher.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/ecb-mode.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/insecure-tls.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/createcipher-deprecated.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/jwt-none-algorithm.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/insecure-cookie.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/session-secret-weak.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/missing-helmet.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/open-redirect.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/cors-misconfiguration.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/idor-pattern.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/mass-assignment.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/debug-mode-enabled.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/error-info-leak.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/sensitive-data-exposure.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/hardcoded-connection-string.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/arbitrary-file-upload.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/directory-listing.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/zipslip.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/unencrypted-request.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/websocket-no-origin.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/empty-catch.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/react-ref-dom-manipulation.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/express-no-rate-limit.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/express-trust-proxy.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/react-unsafe-lifecycle.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/nextjs-ssr-secrets.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/timing-attack.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/redos.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/toctou.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/dynamic-require.yml"),
    ),
    (
        "javascript",
        include_str!("../../rules/javascript/postmessage-no-origin.yml"),
    ),
    // Go rules
    ("go", include_str!("../../rules/go/sql-injection.yml")),
    ("go", include_str!("../../rules/go/command-injection.yml")),
    ("go", include_str!("../../rules/go/hardcoded-secrets.yml")),
    ("go", include_str!("../../rules/go/insecure-random.yml")),
    ("go", include_str!("../../rules/go/path-traversal.yml")),
    ("go", include_str!("../../rules/go/ssrf.yml")),
    ("go", include_str!("../../rules/go/xss-template.yml")),
    ("go", include_str!("../../rules/go/unsafe-reflect.yml")),
    (
        "go",
        include_str!("../../rules/go/hardcoded-credentials.yml"),
    ),
    ("go", include_str!("../../rules/go/tls-insecure-skip.yml")),
    ("go", include_str!("../../rules/go/weak-hash-md5.yml")),
    ("go", include_str!("../../rules/go/weak-hash-sha1.yml")),
    ("go", include_str!("../../rules/go/weak-cipher.yml")),
    ("go", include_str!("../../rules/go/ecb-mode.yml")),
    ("go", include_str!("../../rules/go/hardcoded-iv.yml")),
    ("go", include_str!("../../rules/go/unhandled-error.yml")),
    ("go", include_str!("../../rules/go/defer-in-loop.yml")),
    ("go", include_str!("../../rules/go/unsafe-pointer.yml")),
    ("go", include_str!("../../rules/go/cgo-injection.yml")),
    ("go", include_str!("../../rules/go/open-redirect.yml")),
    ("go", include_str!("../../rules/go/cors-wildcard.yml")),
    ("go", include_str!("../../rules/go/jwt-none-alg.yml")),
    ("go", include_str!("../../rules/go/missing-csrf.yml")),
    ("go", include_str!("../../rules/go/debug-mode.yml")),
    ("go", include_str!("../../rules/go/error-info-leak.yml")),
    ("go", include_str!("../../rules/go/sensitive-logging.yml")),
    ("go", include_str!("../../rules/go/file-permissions.yml")),
    ("go", include_str!("../../rules/go/race-condition.yml")),
    ("go", include_str!("../../rules/go/goroutine-leak.yml")),
    ("go", include_str!("../../rules/go/template-injection.yml")),
    ("go", include_str!("../../rules/go/xxe-parsing.yml")),
    (
        "go",
        include_str!("../../rules/go/insecure-deserialization.yml"),
    ),
    (
        "go",
        include_str!("../../rules/go/yaml-unmarshal-unsafe.yml"),
    ),
    (
        "go",
        include_str!("../../rules/go/hardcoded-connection-string.yml"),
    ),
    (
        "go",
        include_str!("../../rules/go/unvalidated-redirect.yml"),
    ),
    ("go", include_str!("../../rules/go/zip-slip.yml")),
    ("go", include_str!("../../rules/go/missing-tls.yml")),
    (
        "go",
        include_str!("../../rules/go/http-serve-no-timeout.yml"),
    ),
    ("go", include_str!("../../rules/go/sql-string-concat.yml")),
    ("go", include_str!("../../rules/go/nosql-injection.yml")),
    ("go", include_str!("../../rules/go/ldap-injection.yml")),
    ("go", include_str!("../../rules/go/regex-dos.yml")),
    ("go", include_str!("../../rules/go/mass-assignment.yml")),
    ("go", include_str!("../../rules/go/timing-attack.yml")),
    (
        "go",
        include_str!("../../rules/go/gin-no-trusted-proxies.yml"),
    ),
    ("go", include_str!("../../rules/go/grpc-no-tls.yml")),
    ("go", include_str!("../../rules/go/filepath-clean.yml")),
    ("go", include_str!("../../rules/go/integer-overflow.yml")),
    ("go", include_str!("../../rules/go/dns-rebinding.yml")),
    ("go", include_str!("../../rules/go/unescaped-html.yml")),
    // Java rules
    ("java", include_str!("../../rules/java/sql-injection.yml")),
    (
        "java",
        include_str!("../../rules/java/command-injection.yml"),
    ),
    (
        "java",
        include_str!("../../rules/java/hardcoded-secrets.yml"),
    ),
    ("java", include_str!("../../rules/java/insecure-random.yml")),
    ("java", include_str!("../../rules/java/path-traversal.yml")),
    ("java", include_str!("../../rules/java/xxe-parsing.yml")),
    ("java", include_str!("../../rules/java/xss-servlet.yml")),
    (
        "java",
        include_str!("../../rules/java/insecure-deserialization.yml"),
    ),
    ("java", include_str!("../../rules/java/ssrf.yml")),
    ("java", include_str!("../../rules/java/ldap-injection.yml")),
    ("java", include_str!("../../rules/java/weak-hash-md5.yml")),
    ("java", include_str!("../../rules/java/weak-hash-sha1.yml")),
    ("java", include_str!("../../rules/java/weak-cipher-des.yml")),
    ("java", include_str!("../../rules/java/ecb-mode.yml")),
    ("java", include_str!("../../rules/java/hardcoded-iv.yml")),
    ("java", include_str!("../../rules/java/insecure-tls.yml")),
    ("java", include_str!("../../rules/java/jwt-none-alg.yml")),
    ("java", include_str!("../../rules/java/open-redirect.yml")),
    ("java", include_str!("../../rules/java/cors-wildcard.yml")),
    ("java", include_str!("../../rules/java/csrf-disabled.yml")),
    ("java", include_str!("../../rules/java/debug-mode.yml")),
    ("java", include_str!("../../rules/java/error-info-leak.yml")),
    (
        "java",
        include_str!("../../rules/java/sensitive-logging.yml"),
    ),
    (
        "java",
        include_str!("../../rules/java/hardcoded-credentials.yml"),
    ),
    (
        "java",
        include_str!("../../rules/java/hardcoded-connection-string.yml"),
    ),
    ("java", include_str!("../../rules/java/eval-expression.yml")),
    (
        "java",
        include_str!("../../rules/java/template-injection.yml"),
    ),
    ("java", include_str!("../../rules/java/xpath-injection.yml")),
    (
        "java",
        include_str!("../../rules/java/header-injection.yml"),
    ),
    ("java", include_str!("../../rules/java/mass-assignment.yml")),
    (
        "java",
        include_str!("../../rules/java/file-upload-unrestricted.yml"),
    ),
    ("java", include_str!("../../rules/java/zip-slip.yml")),
    (
        "java",
        include_str!("../../rules/java/insecure-temp-file.yml"),
    ),
    ("java", include_str!("../../rules/java/regex-dos.yml")),
    ("java", include_str!("../../rules/java/timing-attack.yml")),
    ("java", include_str!("../../rules/java/empty-catch.yml")),
    ("java", include_str!("../../rules/java/nosql-injection.yml")),
    (
        "java",
        include_str!("../../rules/java/spring-actuator-exposed.yml"),
    ),
    (
        "java",
        include_str!("../../rules/java/spring-sql-injection.yml"),
    ),
    ("java", include_str!("../../rules/java/spring-xss.yml")),
    (
        "java",
        include_str!("../../rules/java/hibernate-injection.yml"),
    ),
    (
        "java",
        include_str!("../../rules/java/unsafe-reflection.yml"),
    ),
    ("java", include_str!("../../rules/java/runtime-exec.yml")),
    ("java", include_str!("../../rules/java/trust-all-certs.yml")),
    (
        "java",
        include_str!("../../rules/java/weak-password-hash.yml"),
    ),
    (
        "java",
        include_str!("../../rules/java/session-fixation.yml"),
    ),
    (
        "java",
        include_str!("../../rules/java/unencrypted-socket.yml"),
    ),
    ("java", include_str!("../../rules/java/log-injection.yml")),
    ("java", include_str!("../../rules/java/idor.yml")),
    (
        "java",
        include_str!("../../rules/java/spring-security-disabled.yml"),
    ),
];

pub struct RuleRegistry {
    rules: HashMap<String, Vec<Rule>>, // language -> rules
}

impl RuleRegistry {
    /// Load rules from a directory containing language subdirectories
    pub fn load(rules_dir: &Path) -> Result<Self> {
        let mut rules: HashMap<String, Vec<Rule>> = HashMap::new();

        if !rules_dir.exists() {
            return Ok(Self { rules });
        }

        for entry in std::fs::read_dir(rules_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let lang_name = entry.file_name().to_string_lossy().to_string();
                let lang_rules = parser::parse_rules_dir(&entry.path())?;
                if !lang_rules.is_empty() {
                    rules.insert(lang_name, lang_rules);
                }
            }
        }

        Ok(Self { rules })
    }

    /// Load embedded rules (compiled into the binary) plus any external rules
    pub fn load_default() -> Result<Self> {
        let mut registry = Self::load_embedded()?;

        // Also check for additional rules on disk (project-local or user config)
        let extra_dirs = vec![
            std::env::current_dir().unwrap_or_default().join("rules"),
            std::env::current_dir()
                .unwrap_or_default()
                .join(".mycop-rules"),
            dirs_rules_path(),
        ];

        // Collect existing rule IDs to avoid duplicates
        let existing_ids: std::collections::HashSet<String> = registry
            .rules
            .values()
            .flat_map(|rules| rules.iter().map(|r| r.id.clone()))
            .collect();

        for dir in extra_dirs {
            if dir.exists() {
                if let Ok(extra) = Self::load(&dir) {
                    for (lang, rules) in extra.rules {
                        let new_rules: Vec<Rule> = rules
                            .into_iter()
                            .filter(|r| !existing_ids.contains(&r.id))
                            .collect();
                        if !new_rules.is_empty() {
                            registry.rules.entry(lang).or_default().extend(new_rules);
                        }
                    }
                }
            }
        }

        Ok(registry)
    }

    /// Load only the embedded (compiled-in) rules
    pub(crate) fn load_embedded() -> Result<Self> {
        let mut rules: HashMap<String, Vec<Rule>> = HashMap::new();

        for (lang, yaml_content) in EMBEDDED_RULES {
            match serde_yaml::from_str::<Rule>(yaml_content) {
                Ok(rule) => {
                    rules.entry(lang.to_string()).or_default().push(rule);
                }
                Err(e) => {
                    eprintln!("Warning: failed to parse embedded rule for {}: {}", lang, e);
                }
            }
        }

        Ok(Self { rules })
    }

    /// Get rules for a specific language
    pub fn rules_for_language(&self, language: &Language) -> Vec<&Rule> {
        let lang_key = language.rule_dir().to_string();
        self.rules
            .get(&lang_key)
            .map(|rules| rules.iter().collect())
            .unwrap_or_default()
    }

    /// Get all rules
    pub fn all_rules(&self) -> Vec<&Rule> {
        self.rules.values().flat_map(|rules| rules.iter()).collect()
    }

    /// Get count of loaded rules
    pub fn rule_count(&self) -> usize {
        self.rules.values().map(|r| r.len()).sum()
    }
}

fn dirs_rules_path() -> std::path::PathBuf {
    if let Some(config_dir) = dirs_config_path() {
        config_dir.join("rules")
    } else {
        std::path::PathBuf::from("rules")
    }
}

fn dirs_config_path() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| std::path::PathBuf::from(h).join(".config").join("mycop"))
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var("XDG_CONFIG_HOME")
            .or_else(|_| std::env::var("HOME").map(|h| format!("{}/.config", h)))
            .ok()
            .map(|h| std::path::PathBuf::from(h).join("mycop"))
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA")
            .ok()
            .map(|h| std::path::PathBuf::from(h).join("mycop"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_embedded_rules() {
        let registry = RuleRegistry::load_embedded().unwrap();
        assert!(
            registry.rule_count() >= 200,
            "Expected at least 200 embedded rules, got {}",
            registry.rule_count()
        );
    }

    #[test]
    fn test_rules_for_language_python() {
        let registry = RuleRegistry::load_embedded().unwrap();
        let py_rules = registry.rules_for_language(&Language::Python);
        assert!(
            py_rules.len() >= 50,
            "Expected at least 50 Python rules, got {}",
            py_rules.len()
        );
    }

    #[test]
    fn test_rules_for_language_javascript() {
        let registry = RuleRegistry::load_embedded().unwrap();
        let js_rules = registry.rules_for_language(&Language::JavaScript);
        assert!(
            js_rules.len() >= 50,
            "Expected at least 50 JavaScript rules, got {}",
            js_rules.len()
        );
    }

    #[test]
    fn test_typescript_uses_javascript_rules() {
        let registry = RuleRegistry::load_embedded().unwrap();
        let ts_rules = registry.rules_for_language(&Language::TypeScript);
        let js_rules = registry.rules_for_language(&Language::JavaScript);
        assert_eq!(ts_rules.len(), js_rules.len());
    }

    #[test]
    fn test_rules_for_language_go() {
        let registry = RuleRegistry::load_embedded().unwrap();
        let go_rules = registry.rules_for_language(&Language::Go);
        assert!(
            go_rules.len() >= 50,
            "Expected at least 50 Go rules, got {}",
            go_rules.len()
        );
    }

    #[test]
    fn test_rules_for_language_java() {
        let registry = RuleRegistry::load_embedded().unwrap();
        let java_rules = registry.rules_for_language(&Language::Java);
        assert!(
            java_rules.len() >= 50,
            "Expected at least 50 Java rules, got {}",
            java_rules.len()
        );
    }

    #[test]
    fn test_all_rules() {
        let registry = RuleRegistry::load_embedded().unwrap();
        let all = registry.all_rules();
        assert_eq!(all.len(), registry.rule_count());
    }

    #[test]
    fn test_load_nonexistent_dir() {
        let registry = RuleRegistry::load(Path::new("/nonexistent/path/12345")).unwrap();
        assert_eq!(registry.rule_count(), 0);
    }
}
