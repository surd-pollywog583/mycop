use crate::rules::matcher::Finding;
use crate::rules::parser::Rule;

use super::types::{FindingOutput, RuleOutput};

pub fn finding_to_output(finding: &Finding) -> FindingOutput {
    FindingOutput {
        rule_id: finding.rule_id.clone(),
        rule_name: finding.rule_name.clone(),
        severity: finding.severity.label().to_string(),
        file: finding.file.display().to_string(),
        line: finding.line,
        column: finding.column,
        matched_text: finding.matched_text.clone(),
        message: finding.message.clone(),
        description: finding.description.clone(),
        fix_hint: finding.fix_hint.clone(),
        cwe: finding.cwe.clone(),
        owasp: finding.owasp.clone(),
        references: finding.references.clone(),
        context_before: finding.context_before.clone(),
        context_after: finding.context_after.clone(),
    }
}

pub fn rule_to_output(rule: &Rule) -> RuleOutput {
    RuleOutput {
        id: rule.id.clone(),
        name: rule.name.clone(),
        severity: rule.severity.label().to_string(),
        language: rule.language.clone(),
        description: rule.description.clone(),
        cwe: rule.cwe.clone(),
        owasp: rule.owasp.clone(),
        fix_hint: rule.fix_hint.clone(),
        references: rule.references.clone(),
    }
}
