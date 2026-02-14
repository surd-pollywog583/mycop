use serde_json::json;
use std::collections::HashMap;

use crate::reporter::Reporter;
use crate::rules::matcher::Finding;
use crate::rules::parser::Severity;

pub struct SarifReporter;

impl Default for SarifReporter {
    fn default() -> Self {
        Self
    }
}

impl SarifReporter {
    pub fn new() -> Self {
        Self
    }
}

impl Reporter for SarifReporter {
    fn report(
        &self,
        findings: &[Finding],
        _ai_results: &HashMap<usize, String>,
    ) -> anyhow::Result<String> {
        let rules: Vec<serde_json::Value> = collect_unique_rules(findings);

        let results: Vec<serde_json::Value> = findings
            .iter()
            .map(|f| {
                json!({
                    "ruleId": f.rule_id,
                    "level": severity_to_sarif_level(&f.severity),
                    "message": {
                        "text": f.message
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": f.file.display().to_string()
                                },
                                "region": {
                                    "startLine": f.line,
                                    "startColumn": f.column
                                }
                            }
                        }
                    ]
                })
            })
            .collect();

        let sarif = json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "mycop",
                            "version": env!("CARGO_PKG_VERSION"),
                            "informationUri": "https://github.com/AbdumajidRashidov/mycop",
                            "rules": rules
                        }
                    },
                    "results": results
                }
            ]
        });

        let json_str = serde_json::to_string_pretty(&sarif)?;
        println!("{}", json_str);
        Ok(json_str)
    }
}

fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn collect_unique_rules(findings: &[Finding]) -> Vec<serde_json::Value> {
    let mut seen = std::collections::HashSet::new();
    let mut rules = Vec::new();

    for f in findings {
        if seen.insert(f.rule_id.clone()) {
            let mut rule = json!({
                "id": f.rule_id,
                "name": f.rule_name,
                "shortDescription": {
                    "text": f.message.clone()
                },
                "fullDescription": {
                    "text": f.description.clone()
                },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(&f.severity)
                }
            });

            if let Some(ref cwe) = f.cwe {
                rule["properties"] = json!({
                    "tags": [cwe]
                });
            }

            rules.push(rule);
        }
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::matcher::Finding;
    use std::path::PathBuf;

    fn make_finding(rule_id: &str, severity: Severity) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            rule_name: "test-rule".to_string(),
            severity,
            file: PathBuf::from("test.py"),
            line: 10,
            column: 1,
            matched_text: "eval(input)".to_string(),
            context_before: vec![],
            context_after: vec![],
            message: "Dangerous eval".to_string(),
            fix_hint: None,
            cwe: Some("CWE-95".to_string()),
            owasp: None,
            description: "Eval injection".to_string(),
            references: vec![],
        }
    }

    #[test]
    fn test_sarif_schema_structure() {
        let findings = vec![make_finding("PY-SEC-005", Severity::High)];
        let ai_results = HashMap::new();
        let reporter = SarifReporter::new();
        let result = reporter.report(&findings, &ai_results).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(parsed["version"], "2.1.0");
        assert!(parsed["runs"].is_array());
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "mycop");
        assert!(parsed["runs"][0]["results"].is_array());
        assert_eq!(parsed["runs"][0]["results"][0]["ruleId"], "PY-SEC-005");
        assert_eq!(parsed["runs"][0]["results"][0]["level"], "error");
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(severity_to_sarif_level(&Severity::Critical), "error");
        assert_eq!(severity_to_sarif_level(&Severity::High), "error");
        assert_eq!(severity_to_sarif_level(&Severity::Medium), "warning");
        assert_eq!(severity_to_sarif_level(&Severity::Low), "note");
        assert_eq!(severity_to_sarif_level(&Severity::Info), "note");
    }
}
