use serde_json::json;
use std::collections::HashMap;

use crate::reporter::Reporter;
use crate::rules::matcher::Finding;

pub struct JsonReporter;

impl Default for JsonReporter {
    fn default() -> Self {
        Self
    }
}

impl JsonReporter {
    pub fn new() -> Self {
        Self
    }
}

impl Reporter for JsonReporter {
    fn report(
        &self,
        findings: &[Finding],
        ai_results: &HashMap<usize, String>,
    ) -> anyhow::Result<String> {
        let findings_json: Vec<serde_json::Value> = findings
            .iter()
            .enumerate()
            .map(|(idx, f)| {
                let mut obj = json!({
                    "ruleId": f.rule_id,
                    "ruleName": f.rule_name,
                    "severity": f.severity.label(),
                    "file": f.file.display().to_string(),
                    "line": f.line,
                    "column": f.column,
                    "matchedText": f.matched_text,
                    "message": f.message,
                    "description": f.description,
                });

                if let Some(ref cwe) = f.cwe {
                    obj["cwe"] = json!(cwe);
                }
                if let Some(ref owasp) = f.owasp {
                    obj["owasp"] = json!(owasp);
                }
                if let Some(ref hint) = f.fix_hint {
                    obj["fixHint"] = json!(hint);
                }
                if !f.references.is_empty() {
                    obj["references"] = json!(f.references);
                }
                if let Some(ai_text) = ai_results.get(&idx) {
                    obj["aiExplanation"] = json!(ai_text);
                }

                obj
            })
            .collect();

        let output = json!({
            "version": env!("CARGO_PKG_VERSION"),
            "totalFindings": findings.len(),
            "findings": findings_json,
        });

        let json_str = serde_json::to_string_pretty(&output)?;
        println!("{}", json_str);
        Ok(json_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::parser::Severity;
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
            fix_hint: Some("Use ast.literal_eval".to_string()),
            cwe: Some("CWE-95".to_string()),
            owasp: None,
            description: "Eval injection".to_string(),
            references: vec![],
        }
    }

    #[test]
    fn test_json_output_structure() {
        let findings = vec![make_finding("PY-SEC-005", Severity::High)];
        let ai_results = HashMap::new();
        let reporter = JsonReporter::new();
        let result = reporter.report(&findings, &ai_results).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(parsed["totalFindings"], 1);
        assert!(parsed["version"].is_string());
        assert!(parsed["findings"].is_array());
        assert_eq!(parsed["findings"][0]["ruleId"], "PY-SEC-005");
        assert_eq!(parsed["findings"][0]["severity"], "HIGH");
        assert_eq!(parsed["findings"][0]["cwe"], "CWE-95");
    }

    #[test]
    fn test_json_empty_findings() {
        let findings = vec![];
        let ai_results = HashMap::new();
        let reporter = JsonReporter::new();
        let result = reporter.report(&findings, &ai_results).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(parsed["totalFindings"], 0);
        assert_eq!(parsed["findings"].as_array().unwrap().len(), 0);
    }
}
