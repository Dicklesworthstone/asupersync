//! ATP Test Plan Contract Enforcement
//!
//! This test ensures that the ATP test contract and coverage ledger remain
//! synchronized with the actual codebase. It validates that all ATP modules
//! are documented in the ledger and that test requirements are enforced.
//!
//! NOTE: This test validates documentation and test infrastructure without
//! requiring the main crate to compile, making it safe to run even during
//! development when ATP modules may have compilation errors.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

const COVERAGE_LEDGER_MD: &str = include_str!("../docs/atp_coverage_ledger.md");
const ATP_TEST_CONTRACT_MD: &str = include_str!("../docs/atp_test_contract.md");

/// Test that all ATP modules are tracked in the coverage ledger
#[test]
fn test_atp_modules_are_tracked_in_ledger() {
    let atp_modules = discover_atp_modules();
    let ledger_modules = parse_ledger_modules();

    // Check that all discovered modules are in the ledger
    for module in &atp_modules {
        assert!(
            ledger_modules.contains(module),
            "ATP module '{}' is not tracked in docs/atp_coverage_ledger.md. \
             Please add it to the appropriate section with PLANNED status.",
            module
        );
    }

    // Check that ledger doesn't reference non-existent modules
    for module in &ledger_modules {
        if !atp_modules.contains(module) {
            eprintln!(
                "Warning: Ledger references module '{}' which was not found in codebase. \
                 Consider updating the ledger.",
                module
            );
        }
    }
}

/// Test that critical path modules have explicit test requirements
#[test]
fn test_critical_path_modules_have_test_requirements() {
    let critical_modules = vec![
        "src/atp/object.rs",
        "src/atp/manifest.rs",
        "src/atp/verifier.rs",
        "src/net/atp/protocol.rs",
        "src/atp/sdk.rs",
    ];

    for module in critical_modules {
        assert!(
            COVERAGE_LEDGER_MD.contains(module),
            "Critical path module '{}' must be tracked in coverage ledger",
            module
        );

        // Verify the module has a complete test requirements row
        let module_line = COVERAGE_LEDGER_MD
            .lines()
            .find(|line| line.contains(module))
            .unwrap_or_else(|| panic!("Could not find module '{}' in ledger", module));

        // Check that the row has all required columns
        let pipe_count = module_line.matches('|').count();
        assert!(
            pipe_count >= 9, // Module | Status | Unit | Property | Metamorphic | Edge | Error | Cancel | Leak | Notes
            "Module '{}' is missing test requirement columns in ledger. Expected 10+ columns, found {}",
            module,
            pipe_count + 1
        );
    }
}

/// Test that the test contract document exists and has required sections
#[test]
fn test_contract_document_completeness() {
    let required_sections = vec![
        "Test Classification",
        "Unit Tests",
        "Property Tests",
        "Metamorphic Tests",
        "Integration Tests",
        "Lab Tests",
        "Test Requirements by Module Type",
        "Quality Gates",
        "Integration with Release Process",
    ];

    for section in required_sections {
        assert!(
            ATP_TEST_CONTRACT_MD.contains(section),
            "Test contract must contain '{}' section",
            section
        );
    }
}

/// Test that module test files follow naming conventions
#[test]
fn test_module_test_naming_conventions() {
    let atp_modules = discover_atp_modules();

    for module_path in atp_modules {
        // Convert module path to expected test file name
        // src/atp/object.rs -> tests/atp_object_test.rs
        // src/net/atp/protocol.rs -> tests/net_atp_protocol_test.rs
        let test_name = module_path
            .replace("src/", "")
            .replace(".rs", "_test.rs")
            .replace('/', "_");
        let expected_test_path = format!("tests/{}", test_name);

        // For now, we just check that if a test file exists, it follows the convention
        // In the future, this could be made stricter to require test files
        if Path::new(&expected_test_path).exists() {
            let test_content = fs::read_to_string(&expected_test_path)
                .unwrap_or_else(|_| panic!("Could not read test file {}", expected_test_path));

            // Basic validation that it looks like a proper test file
            assert!(
                test_content.contains("#[test]") || test_content.contains("#[cfg(test)]"),
                "Test file '{}' must contain test functions",
                expected_test_path
            );
        }
    }
}

/// Test that test configuration follows requirements
#[test]
fn test_configuration_requirements() {
    // Check that Cargo.toml has appropriate test dependencies
    let cargo_content = fs::read_to_string("Cargo.toml").expect("Could not read Cargo.toml");

    // Should have dev-dependencies section for test-only crates
    assert!(
        cargo_content.contains("[dev-dependencies]"),
        "Cargo.toml should have [dev-dependencies] section for test infrastructure"
    );

    // Check for common test framework dependencies
    let dev_deps_section = cargo_content
        .split("[dev-dependencies]")
        .nth(1)
        .unwrap_or("")
        .split("\n[")
        .next()
        .unwrap_or("");

    // Verify we have property testing capability
    if !dev_deps_section.contains("proptest") && !dev_deps_section.contains("quickcheck") {
        eprintln!(
            "Warning: Consider adding property test framework (proptest/quickcheck) \
             to [dev-dependencies] for ATP property testing requirements"
        );
    }
}

/// Discover all ATP-related Rust modules in the codebase
fn discover_atp_modules() -> HashSet<String> {
    let mut modules = HashSet::new();

    // Scan src/atp/ directory recursively
    scan_directory_recursive("src/atp", &mut modules);

    // Scan src/net/atp/ directory recursively
    scan_directory_recursive("src/net/atp", &mut modules);

    // Scan CLI ATP modules
    if let Ok(entries) = fs::read_dir("src/cli") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name.starts_with("atp_")
                    && Path::new(file_name)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
                {
                    if let Some(path_str) = path.to_str() {
                        modules.insert(path_str.to_string());
                    }
                }
            }
        }
    }

    modules
}

/// Recursively scan directory for Rust files
fn scan_directory_recursive(dir: &str, modules: &mut HashSet<String>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(path_str) = path.to_str() {
                    scan_directory_recursive(path_str, modules);
                }
            } else if path.extension().is_some_and(|s| s == "rs") {
                if let Some(path_str) = path.to_str() {
                    modules.insert(path_str.to_string());
                }
            }
        }
    }
}

/// Parse module names from the coverage ledger
fn parse_ledger_modules() -> HashSet<String> {
    let mut modules = HashSet::new();

    for line in COVERAGE_LEDGER_MD.lines() {
        // Look for table rows that start with | and contain src/
        if line.starts_with('|') && line.contains("src/") {
            // Extract the module path from the first column
            if let Some(first_col) = line.split('|').nth(1) {
                let module_path = first_col
                    .trim()
                    .trim_start_matches('`')
                    .trim_end_matches('`');
                if module_path.starts_with("src/")
                    && Path::new(module_path)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
                {
                    modules.insert(module_path.to_string());
                }
            }
        }
    }

    modules
}

/// Test helper to validate test file structure
#[cfg(test)]
#[allow(dead_code)]
mod test_helpers {
    use super::*;

    /// Validate that a test file meets ATP requirements
    pub fn validate_atp_test_file(file_path: &str) -> Result<(), String> {
        let content = fs::read_to_string(file_path)
            .map_err(|e| format!("Could not read {}: {}", file_path, e))?;

        // Check for required test types
        let has_unit_tests = content.contains("#[test]");

        if !has_unit_tests {
            return Err("Test file must contain unit tests (#[test])".to_string());
        }

        // Check for documentation
        if !content.contains("//!") && !content.contains("///") {
            return Err("Test file should have module or function documentation".to_string());
        }

        Ok(())
    }

    /// Extract test statistics from a test file
    pub fn extract_test_stats(file_path: &str) -> TestStats {
        let content = fs::read_to_string(file_path).unwrap_or_default();

        TestStats {
            unit_test_count: content.matches("#[test]").count(),
            property_test_count: content.matches("proptest!").count()
                + content.matches("quickcheck!").count(),
            error_test_count: content.matches("should_panic").count(),
            async_test_count: content.matches("async fn test_").count(),
        }
    }
}

#[derive(Debug, Default)]
pub struct TestStats {
    pub unit_test_count: usize,
    pub property_test_count: usize,
    pub error_test_count: usize,
    pub async_test_count: usize,
}
