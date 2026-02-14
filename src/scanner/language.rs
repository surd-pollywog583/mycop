use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Language {
    Python,
    JavaScript,
    TypeScript,
}

impl Language {
    pub fn from_extension(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?;
        match ext {
            "py" | "pyw" => Some(Language::Python),
            "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
            "ts" | "tsx" | "mts" | "cts" => Some(Language::TypeScript),
            _ => None,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Language::Python => "python",
            Language::JavaScript => "javascript",
            Language::TypeScript => "typescript",
        }
    }

    pub fn rule_dir(&self) -> &str {
        match self {
            Language::Python => "python",
            Language::JavaScript | Language::TypeScript => "javascript",
        }
    }
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_extensions() {
        assert_eq!(
            Language::from_extension(Path::new("a.py")),
            Some(Language::Python)
        );
        assert_eq!(
            Language::from_extension(Path::new("a.pyw")),
            Some(Language::Python)
        );
    }

    #[test]
    fn test_javascript_extensions() {
        for ext in &["js", "jsx", "mjs", "cjs"] {
            let p = format!("file.{}", ext);
            assert_eq!(
                Language::from_extension(Path::new(&p)),
                Some(Language::JavaScript),
                "Failed for extension: {}",
                ext
            );
        }
    }

    #[test]
    fn test_typescript_extensions() {
        for ext in &["ts", "tsx", "mts", "cts"] {
            let p = format!("file.{}", ext);
            assert_eq!(
                Language::from_extension(Path::new(&p)),
                Some(Language::TypeScript),
                "Failed for extension: {}",
                ext
            );
        }
    }

    #[test]
    fn test_unsupported_extensions() {
        assert_eq!(Language::from_extension(Path::new("file.rs")), None);
        assert_eq!(Language::from_extension(Path::new("file.go")), None);
        assert_eq!(Language::from_extension(Path::new("file")), None);
    }

    #[test]
    fn test_rule_dir_mapping() {
        assert_eq!(Language::Python.rule_dir(), "python");
        assert_eq!(Language::JavaScript.rule_dir(), "javascript");
        assert_eq!(Language::TypeScript.rule_dir(), "javascript");
    }
}
