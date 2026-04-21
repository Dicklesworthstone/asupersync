#![allow(warnings)]
#![allow(clippy::all)]
//! Golden File Management for RaptorQ RFC 6330 Conformance Testing
//!
//! Implements Pattern 2 (Golden File Testing) with UPDATE_GOLDENS workflow
//! for complex RaptorQ outputs that are correct once verified, then frozen
//! as regression tests.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Golden file manager with UPDATE_GOLDENS workflow
#[allow(dead_code)]
pub struct GoldenFileManager {
    base_path: PathBuf,
    update_mode: bool,
}

#[allow(dead_code)]

impl GoldenFileManager {
    /// Create new golden file manager
    #[allow(dead_code)]
    pub fn new() -> Self {
        let base_path = PathBuf::from("tests/conformance/raptorq_rfc6330/golden/fixtures");
        let update_mode = env::var("UPDATE_GOLDENS").is_ok();

        Self { base_path, update_mode }
    }

    /// Create manager with custom base path
    #[allow(dead_code)]
    pub fn with_base_path<P: Into<PathBuf>>(base_path: P) -> Self {
        let base_path = base_path.into();
        let update_mode = env::var("UPDATE_GOLDENS").is_ok();

        Self { base_path, update_mode }
    }

    /// Assert binary data matches golden file
    #[allow(dead_code)]
    pub fn assert_golden_binary(&self, test_name: &str, category: &str, actual: &[u8]) {
        let golden_path = self.golden_path(category, test_name, "golden");

        if self.update_mode {
            self.update_golden_file(&golden_path, actual);
            eprintln!("UPDATED golden: {}", golden_path.display());
            return;
        }

        let expected = self.read_golden_file(&golden_path);
        if actual != expected {
            self.handle_mismatch(test_name, &golden_path, actual, &expected);
        }
    }

    /// Assert structured data matches golden file (JSON format)
    #[allow(dead_code)]
    pub fn assert_golden_json<T>(&self, test_name: &str, category: &str, actual: &T)
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        let actual_json = serde_json::to_string_pretty(actual)
            .expect("Failed to serialize actual data to JSON");

        let golden_path = self.golden_path(category, test_name, "json");

        if self.update_mode {
            self.update_golden_file(&golden_path, actual_json.as_bytes());
            eprintln!("UPDATED golden: {}", golden_path.display());
            return;
        }

        let expected_json = String::from_utf8_lossy(&self.read_golden_file(&golden_path));
        let expected: T = serde_json::from_str(&expected_json)
            .expect("Failed to deserialize golden file");

        if actual != &expected {
            self.handle_json_mismatch(test_name, &golden_path, &actual_json, &expected_json);
        }
    }

    /// Assert hex-encoded data matches golden file
    #[allow(dead_code)]
    pub fn assert_golden_hex(&self, test_name: &str, category: &str, actual: &[u8]) {
        let actual_hex = hex::encode(actual);
        let golden_path = self.golden_path(category, test_name, "hex");

        if self.update_mode {
            self.update_golden_file(&golden_path, actual_hex.as_bytes());
            eprintln!("UPDATED golden: {}", golden_path.display());
            return;
        }

        let expected_hex = String::from_utf8_lossy(&self.read_golden_file(&golden_path));
        if actual_hex != expected_hex {
            panic!(
                "Golden hex mismatch for {test_name}\n\
                 Expected: {expected_hex}\n\
                 Actual:   {actual_hex}\n\
                 Golden:   {}",
                golden_path.display()
            );
        }
    }

    /// Generate golden file path for test
    #[allow(dead_code)]
    fn golden_path(&self, category: &str, test_name: &str, extension: &str) -> PathBuf {
        self.base_path
            .join(category)
            .join(format!("{}.{}", test_name, extension))
    }

    /// Read golden file with error handling
    #[allow(dead_code)]
    fn read_golden_file(&self, path: &Path) -> Vec<u8> {
        fs::read(path).unwrap_or_else(|_| {
            panic!(
                "Golden file not found: {}\n\
                 Run with UPDATE_GOLDENS=1 to create it",
                path.display()
            )
        })
    }

    /// Update golden file safely
    #[allow(dead_code)]
    fn update_golden_file(&self, path: &Path, content: &[u8]) {
        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .unwrap_or_else(|e| panic!("Failed to create directory {}: {}", parent.display(), e));
        }

        fs::write(path, content)
            .unwrap_or_else(|e| panic!("Failed to write golden file {}: {}", path.display(), e));
    }

    /// Handle binary data mismatch
    #[allow(dead_code)]
    fn handle_mismatch(&self, test_name: &str, golden_path: &Path, actual: &[u8], expected: &[u8]) {
        // Write actual output for debugging
        let actual_path = golden_path.with_extension("actual");
        fs::write(&actual_path, actual)
            .unwrap_or_else(|e| eprintln!("Warning: Failed to write actual file: {}", e));

        panic!(
            "GOLDEN MISMATCH: {test_name}\n\
             Expected {} bytes, got {} bytes\n\
             Golden:  {}\n\
             Actual:  {}\n\
             \n\
             To update: UPDATE_GOLDENS=1 cargo test {test_name}\n\
             To diff:   xxd {} && xxd {}",
            expected.len(),
            actual.len(),
            golden_path.display(),
            actual_path.display(),
            golden_path.display(),
            actual_path.display(),
        );
    }

    /// Handle JSON data mismatch
    #[allow(dead_code)]
    fn handle_json_mismatch(&self, test_name: &str, golden_path: &Path, actual: &str, expected: &str) {
        let actual_path = golden_path.with_extension("actual.json");
        fs::write(&actual_path, actual)
            .unwrap_or_else(|e| eprintln!("Warning: Failed to write actual file: {}", e));

        panic!(
            "GOLDEN JSON MISMATCH: {test_name}\n\
             Golden:  {}\n\
             Actual:  {}\n\
             \n\
             To update: UPDATE_GOLDENS=1 cargo test {test_name}\n\
             To diff:   diff {} {}",
            golden_path.display(),
            actual_path.display(),
            golden_path.display(),
            actual_path.display(),
        );
    }
}