use anyhow::Result;
use regex::Regex;
use std::path::{Path, PathBuf};
use streaming_iterator::StreamingIterator;

use crate::rules::parser::{PatternType, Rule, Severity};
use crate::scanner::language::Language;

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub matched_text: String,
    pub context_before: Vec<String>,
    pub context_after: Vec<String>,
    pub message: String,
    pub fix_hint: Option<String>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub description: String,
    pub references: Vec<String>,
}

/// Match a rule against file content and return findings
pub fn match_rule(
    rule: &Rule,
    content: &str,
    file_path: &Path,
    _language: &Language,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    // Try AST query first if available
    if rule.pattern.pattern_type == PatternType::Ast {
        if let Some(ref query_str) = rule.pattern.query {
            let ast_findings =
                match_ast_query(rule, content, file_path, _language, query_str, &lines);
            if let Ok(af) = ast_findings {
                findings.extend(af);
            }
        }
    }

    // Always try regex patterns (either as primary or as supplement to AST)
    for pattern_str in &rule.pattern.regex {
        match Regex::new(pattern_str) {
            Ok(re) => {
                for (line_idx, line) in lines.iter().enumerate() {
                    if let Some(m) = re.find(line) {
                        // Avoid duplicates if AST already found this line
                        let already_found = findings
                            .iter()
                            .any(|f: &Finding| f.line == line_idx + 1 && f.rule_id == rule.id);
                        if already_found {
                            continue;
                        }

                        let context_before = get_context_lines(&lines, line_idx, 2, true);
                        let context_after = get_context_lines(&lines, line_idx, 2, false);

                        findings.push(Finding {
                            rule_id: rule.id.clone(),
                            rule_name: rule.name.clone(),
                            severity: rule.severity.clone(),
                            file: file_path.to_path_buf(),
                            line: line_idx + 1,
                            column: m.start() + 1,
                            matched_text: m.as_str().to_string(),
                            context_before,
                            context_after,
                            message: rule.message.clone(),
                            fix_hint: rule.fix_hint.clone(),
                            cwe: rule.cwe.clone(),
                            owasp: rule.owasp.clone(),
                            description: rule.description.clone(),
                            references: rule.references.clone(),
                        });
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: invalid regex pattern in rule {}: {}", rule.id, e);
            }
        }
    }

    // Filter out findings with inline ignore comments
    findings.retain(|f| {
        let line_idx = f.line.saturating_sub(1);
        if line_idx < lines.len() {
            !is_ignored_by_comment(&lines, line_idx, &f.rule_id)
        } else {
            true
        }
    });

    Ok(findings)
}

/// Check if a finding should be ignored due to inline ignore comments.
/// Supports:
///   # mycop-ignore:RULE-ID     (Python comment on same or previous line)
///   // mycop-ignore:RULE-ID    (JS/TS comment on same or previous line)
///   # mycop-ignore              (suppress all rules for this line)
///   // mycop-ignore             (suppress all rules for this line)
///   # mycop-ignore:ID1,ID2     (suppress multiple specific rules)
fn is_ignored_by_comment(lines: &[&str], line_idx: usize, rule_id: &str) -> bool {
    let check_line = |line: &str| -> bool {
        if let Some(pos) = line.find("mycop-ignore") {
            let before = line[..pos].trim_end();
            if !(before.ends_with('#') || before.ends_with("//")) {
                return false;
            }
            let after = &line[pos + "mycop-ignore".len()..];
            // mycop-ignore (no colon) = suppress all rules
            if after.is_empty()
                || after.starts_with(' ')
                || after.starts_with('\t')
                || after.starts_with('\r')
            {
                return true;
            }
            // mycop-ignore:RULE-ID or mycop-ignore:ID1,ID2
            if let Some(rest) = after.strip_prefix(':') {
                let ids: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
                return ids.contains(&rule_id);
            }
        }
        false
    };

    // Check same line
    if check_line(lines[line_idx]) {
        return true;
    }
    // Check previous line
    if line_idx > 0 && check_line(lines[line_idx - 1]) {
        return true;
    }
    false
}

fn match_ast_query(
    rule: &Rule,
    content: &str,
    file_path: &Path,
    language: &Language,
    query_str: &str,
    lines: &[&str],
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let ts_language = match language {
        Language::Python => tree_sitter_python::LANGUAGE,
        Language::JavaScript => tree_sitter_javascript::LANGUAGE,
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT,
        Language::Go => tree_sitter_go::LANGUAGE,
        Language::Java => tree_sitter_java::LANGUAGE,
    };

    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&ts_language.into())?;

    let tree = parser
        .parse(content, None)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse AST for {}", file_path.display()))?;

    let ts_lang: tree_sitter::Language = ts_language.into();
    match tree_sitter::Query::new(&ts_lang, query_str) {
        Ok(query) => {
            let mut cursor = tree_sitter::QueryCursor::new();
            let mut matches = cursor.matches(&query, tree.root_node(), content.as_bytes());

            while let Some(m) = {
                matches.advance();
                matches.get()
            } {
                if let Some(capture) = m.captures.first() {
                    let node = capture.node;
                    let start = node.start_position();
                    let line_idx = start.row;
                    let matched_text = node.utf8_text(content.as_bytes()).unwrap_or("").to_string();

                    let context_before = get_context_lines(lines, line_idx, 2, true);
                    let context_after = get_context_lines(lines, line_idx, 2, false);

                    findings.push(Finding {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        severity: rule.severity.clone(),
                        file: file_path.to_path_buf(),
                        line: line_idx + 1,
                        column: start.column + 1,
                        matched_text,
                        context_before,
                        context_after,
                        message: rule.message.clone(),
                        fix_hint: rule.fix_hint.clone(),
                        cwe: rule.cwe.clone(),
                        owasp: rule.owasp.clone(),
                        description: rule.description.clone(),
                        references: rule.references.clone(),
                    });
                }
            }
        }
        Err(e) => {
            // AST query failed, will fall back to regex
            eprintln!(
                "Warning: AST query failed for rule {} ({}), using regex fallback: {}",
                rule.id, rule.name, e
            );
        }
    }

    Ok(findings)
}

fn get_context_lines(lines: &[&str], current: usize, count: usize, before: bool) -> Vec<String> {
    let mut result = Vec::new();
    if before {
        let start = current.saturating_sub(count);
        for line in lines.iter().take(current).skip(start) {
            result.push(line.to_string());
        }
    } else {
        let end = (current + count + 1).min(lines.len());
        for line in lines.iter().take(end).skip(current + 1) {
            result.push(line.to_string());
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::parser::{Pattern, PatternType, Rule, Severity};

    fn make_regex_rule(id: &str, patterns: Vec<&str>) -> Rule {
        Rule {
            id: id.to_string(),
            name: "test-rule".to_string(),
            severity: Severity::High,
            language: "python".to_string(),
            cwe: None,
            owasp: None,
            description: "test".to_string(),
            pattern: Pattern {
                pattern_type: PatternType::Regex,
                query: None,
                regex: patterns.into_iter().map(String::from).collect(),
            },
            message: "test message".to_string(),
            fix_hint: None,
            references: vec![],
        }
    }

    #[test]
    fn test_match_rule_finds_eval() {
        let rule = make_regex_rule("TEST-001", vec![r"eval\("]);
        let content = "x = 1\nresult = eval(user_input)\ny = 2\n";
        let findings = match_rule(&rule, content, Path::new("test.py"), &Language::Python).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[0].rule_id, "TEST-001");
    }

    #[test]
    fn test_match_rule_no_match() {
        let rule = make_regex_rule("TEST-001", vec![r"eval\("]);
        let content = "x = 1\ny = 2\n";
        let findings = match_rule(&rule, content, Path::new("test.py"), &Language::Python).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_match_rule_multiple_matches() {
        let rule = make_regex_rule("TEST-001", vec![r"eval\("]);
        let content = "eval(a)\nfoo()\neval(b)\n";
        let findings = match_rule(&rule, content, Path::new("test.py"), &Language::Python).unwrap();
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_finding_fields_populated() {
        let mut rule = make_regex_rule("TEST-001", vec![r"eval\("]);
        rule.cwe = Some("CWE-95".to_string());
        rule.fix_hint = Some("Use ast.literal_eval".to_string());
        let content = "result = eval(x)\n";
        let findings = match_rule(&rule, content, Path::new("app.py"), &Language::Python).unwrap();
        assert_eq!(findings[0].cwe, Some("CWE-95".to_string()));
        assert_eq!(
            findings[0].fix_hint,
            Some("Use ast.literal_eval".to_string())
        );
        assert_eq!(findings[0].file, PathBuf::from("app.py"));
    }

    #[test]
    fn test_context_lines_before() {
        let lines = vec!["line1", "line2", "line3", "line4", "line5"];
        let before = get_context_lines(&lines, 2, 2, true);
        assert_eq!(before, vec!["line1", "line2"]);
    }

    #[test]
    fn test_context_lines_after() {
        let lines = vec!["line1", "line2", "line3", "line4", "line5"];
        let after = get_context_lines(&lines, 2, 2, false);
        assert_eq!(after, vec!["line4", "line5"]);
    }

    #[test]
    fn test_context_lines_at_boundaries() {
        let lines = vec!["only"];
        let before = get_context_lines(&lines, 0, 2, true);
        assert!(before.is_empty());
        let after = get_context_lines(&lines, 0, 2, false);
        assert!(after.is_empty());
    }

    #[test]
    fn test_is_ignored_by_comment_python() {
        let lines = vec!["# mycop-ignore:PY-SEC-001", "eval(user_input)"];
        assert!(is_ignored_by_comment(&lines, 1, "PY-SEC-001"));
        assert!(!is_ignored_by_comment(&lines, 1, "PY-SEC-002"));
    }

    #[test]
    fn test_is_ignored_by_comment_js_same_line() {
        let lines = vec!["eval(x); // mycop-ignore:JS-SEC-002"];
        assert!(is_ignored_by_comment(&lines, 0, "JS-SEC-002"));
    }

    #[test]
    fn test_is_ignored_all_rules() {
        let lines = vec!["eval(x) # mycop-ignore"];
        assert!(is_ignored_by_comment(&lines, 0, "ANY-RULE-ID"));
    }

    #[test]
    fn test_is_ignored_multi_rule() {
        let lines = vec!["# mycop-ignore:PY-SEC-001,PY-SEC-003", "eval(code)"];
        assert!(is_ignored_by_comment(&lines, 1, "PY-SEC-001"));
        assert!(is_ignored_by_comment(&lines, 1, "PY-SEC-003"));
        assert!(!is_ignored_by_comment(&lines, 1, "PY-SEC-002"));
    }
}
