use std::fs;
use std::path::{Path, PathBuf};
use syn::visit::Visit;
use walkdir::WalkDir;

const RELATIVE_SCAN_DIRS: &[&str] = &[
    "src",
    "asupersync-browser-core/src",
    "asupersync-macros/src",
    "asupersync-tokio-compat/src",
    "asupersync-wasm/src",
    "conformance/src",
    "franken_kernel/src",
    "franken_evidence/src",
    "franken_decision/src",
    "frankenlab/src",
    "drop_unwrap_finder/src",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    filepath: String,
    detail: String,
}

impl Finding {
    fn new(filepath: &str, detail: impl Into<String>) -> Self {
        Self {
            filepath: filepath.to_string(),
            detail: detail.into(),
        }
    }
}

struct DropVisitor<'a> {
    filepath: &'a str,
    findings: &'a mut Vec<Finding>,
}

impl<'ast, 'a> Visit<'ast> for DropVisitor<'a> {
    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        if let Some((_, path, _)) = &i.trait_
            && let Some(segment) = path.segments.last()
            && segment.ident == "Drop"
        {
            let mut unwrap_visitor = UnwrapVisitor {
                filepath: self.filepath,
                findings: self.findings,
            };
            unwrap_visitor.visit_item_impl(i);
        }
        syn::visit::visit_item_impl(self, i);
    }
}

struct UnwrapVisitor<'a> {
    filepath: &'a str,
    findings: &'a mut Vec<Finding>,
}

impl<'ast, 'a> Visit<'ast> for UnwrapVisitor<'a> {
    fn visit_expr_method_call(&mut self, i: &'ast syn::ExprMethodCall) {
        let method_name = i.method.to_string();
        if matches!(method_name.as_str(), "unwrap" | "expect") {
            self.findings
                .push(Finding::new(self.filepath, format!("has {method_name}")));
        }
        syn::visit::visit_expr_method_call(self, i);
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        if m.path.is_ident("unwrap") || m.path.is_ident("expect") || m.path.is_ident("panic") {
            let macro_name = m
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .unwrap_or_else(|| "<unknown>".to_string());
            self.findings.push(Finding::new(
                self.filepath,
                format!("has macro {macro_name}"),
            ));
        }
        syn::visit::visit_macro(self, m);
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("drop_unwrap_finder must live under the workspace root")
        .to_path_buf()
}

fn dirs_to_check() -> Vec<PathBuf> {
    let root = workspace_root();
    RELATIVE_SCAN_DIRS
        .iter()
        .map(|relative| root.join(relative))
        .collect()
}

fn is_rust_source(path: &Path) -> bool {
    path.extension().and_then(|s| s.to_str()) == Some("rs")
}

fn is_ignored_test_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    path_str.contains("/tests/") || path_str.contains("/test_") || path_str.contains("tests.rs")
}

fn collect_drop_findings(filepath: &str, content: &str) -> Result<Vec<Finding>, syn::Error> {
    let file = syn::parse_file(content)?;
    let mut findings = Vec::new();
    let mut visitor = DropVisitor {
        filepath,
        findings: &mut findings,
    };
    visitor.visit_file(&file);
    Ok(findings)
}

fn main() {
    for dir in dirs_to_check() {
        if !dir.exists() {
            continue;
        }

        for entry in WalkDir::new(dir) {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            if !is_rust_source(path) || is_ignored_test_path(path) {
                continue;
            }

            let path_str = path.to_string_lossy();
            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            match collect_drop_findings(&path_str, &content) {
                Ok(findings) => {
                    for finding in findings {
                        println!("{}: {}", finding.filepath, finding.detail);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to parse {}: {}", path_str, e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RELATIVE_SCAN_DIRS, collect_drop_findings, dirs_to_check, workspace_root};

    #[test]
    fn dirs_to_check_are_workspace_relative() {
        let root = workspace_root();
        let dirs = dirs_to_check();

        for (dir, relative) in dirs.iter().zip(RELATIVE_SCAN_DIRS) {
            assert_eq!(dir, &root.join(relative));
            assert!(
                dir.exists(),
                "{relative} scan root should resolve from the workspace root"
            );
        }
    }

    #[test]
    fn flags_exact_unwrap_and_expect_in_drop_only() {
        let source = r#"
            struct NeedsDrop;

            impl Drop for NeedsDrop {
                fn drop(&mut self) {
                    let value = Some(1_u32);
                    let _ = value.expect("must exist");
                    panic!("cleanup panic");
                }
            }
        "#;

        let findings = collect_drop_findings("sample.rs", source).expect("parse test source");
        let details: Vec<_> = findings
            .iter()
            .map(|finding| finding.detail.as_str())
            .collect();

        assert_eq!(details, vec!["has expect", "has macro panic"]);
    }

    #[test]
    fn does_not_flag_substring_methods_or_non_drop_code() {
        let source = r#"
            struct NeedsDrop;
            struct Plain;

            impl Drop for NeedsDrop {
                fn drop(&mut self) {
                    let value = Some(1_u32);
                    let _ = value.unwrap_or(7);
                    helper.expecting();
                }
            }

            impl Plain {
                fn work(&self) {
                    let value = Some(2_u32);
                    let _ = value.unwrap();
                    let _ = value.expect("outside drop");
                }
            }
        "#;

        let findings = collect_drop_findings("sample.rs", source).expect("parse test source");
        assert!(
            findings.is_empty(),
            "substring methods and non-Drop code should not be reported: {findings:?}"
        );
    }
}
