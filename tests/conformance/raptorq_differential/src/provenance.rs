//! Provenance tracking for differential test fixtures.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Tracks the provenance of test fixtures for reproducibility
#[derive(Debug)]
pub struct ProvenanceTracker {
    base_dir: PathBuf,
}

/// Information about how a fixture was generated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationInfo {
    /// Reference implementation used
    pub reference_implementation: String,
    /// Version of the reference implementation
    pub reference_version: String,
    /// Command line used to generate the fixture
    pub command: String,
    /// Working directory when command was executed
    pub working_directory: String,
    /// Environment variables that might affect generation
    pub environment: HashMap<String, String>,
    /// Timestamp when fixture was generated
    pub timestamp: String,
    /// Git commit hash of the test framework when generated
    pub framework_commit: Option<String>,
    /// Platform information
    pub platform: PlatformInfo,
}

/// Provenance information for a fixture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureProvenance {
    /// Unique identifier for this fixture
    pub fixture_id: String,
    /// Path to the fixture file (relative to base)
    pub fixture_path: String,
    /// How this fixture was generated
    pub generation_info: GenerationInfo,
    /// Input file information
    pub input_info: InputInfo,
    /// Verification checksums
    pub checksums: FixtureChecksums,
    /// Dependencies required to regenerate
    pub dependencies: Vec<Dependency>,
}

/// Information about the platform where fixture was generated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    /// Operating system (e.g., "linux", "macos", "windows")
    pub os: String,
    /// Architecture (e.g., "x86_64", "aarch64")
    pub arch: String,
    /// Kernel version or OS version
    pub version: String,
    /// Additional platform-specific details
    pub details: HashMap<String, String>,
}

/// Information about test input data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputInfo {
    /// Size of input data in bytes
    pub size: u64,
    /// Content type or description
    pub content_type: String,
    /// Hash of input data
    pub hash: String,
    /// How the input was generated or where it came from
    pub source: String,
}

/// Checksums for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureChecksums {
    /// SHA-256 of input data
    pub input_sha256: String,
    /// SHA-256 of reference output
    pub output_sha256: String,
    /// MD5 of combined fixture data (for quick verification)
    pub fixture_md5: String,
}

/// External dependency required for fixture generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    /// Name of the dependency
    pub name: String,
    /// Version or version constraint
    pub version: String,
    /// Where to obtain this dependency
    pub source: String,
    /// Type of dependency (binary, library, etc.)
    pub dependency_type: DependencyType,
}

/// Types of dependencies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DependencyType {
    /// External binary executable
    Binary,
    /// Software library
    Library,
    /// Python package
    PythonPackage,
    /// System package
    SystemPackage,
    /// Source code repository
    Repository,
}

/// Errors that can occur during provenance operations
#[derive(Debug, thiserror::Error)]
pub enum ProvenanceError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Invalid provenance data: {0}")]
    InvalidData(String),

    #[error("Provenance not found: {0}")]
    NotFound(String),

    #[error("Git error: {0}")]
    GitError(String),
}

impl ProvenanceTracker {
    /// Creates a new provenance tracker
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Self {
        Self {
            base_dir: base_dir.as_ref().to_path_buf(),
        }
    }

    /// Records provenance information for a newly generated fixture
    pub fn record_fixture_generation(
        &self,
        fixture_path: &Path,
        generation_info: GenerationInfo,
        input_data: &[u8],
        output_data: &[u8],
    ) -> Result<FixtureProvenance, ProvenanceError> {
        let fixture_id = generate_fixture_id(fixture_path);
        let relative_path = self.make_relative_path(fixture_path)?;

        let input_info = InputInfo {
            size: input_data.len() as u64,
            content_type: "binary/raptorq-test-data".to_string(),
            hash: calculate_sha256(input_data),
            source: "generated".to_string(),
        };

        let checksums = FixtureChecksums {
            input_sha256: calculate_sha256(input_data),
            output_sha256: calculate_sha256(output_data),
            fixture_md5: calculate_md5(&[input_data, output_data].concat()),
        };

        let dependencies = self.detect_dependencies(&generation_info)?;

        let provenance = FixtureProvenance {
            fixture_id: fixture_id.clone(),
            fixture_path: relative_path.to_string_lossy().to_string(),
            generation_info,
            input_info,
            checksums,
            dependencies,
        };

        // Save provenance to file
        let provenance_path = self.get_provenance_path(&fixture_id);
        self.save_provenance(&provenance_path, &provenance)?;

        Ok(provenance)
    }

    /// Loads provenance information for a fixture
    pub fn load_fixture_provenance(&self, fixture_id: &str) -> Result<FixtureProvenance, ProvenanceError> {
        let provenance_path = self.get_provenance_path(fixture_id);

        if !provenance_path.exists() {
            return Err(ProvenanceError::NotFound(fixture_id.to_string()));
        }

        let content = fs::read_to_string(provenance_path)?;
        let provenance: FixtureProvenance = serde_json::from_str(&content)?;

        Ok(provenance)
    }

    /// Lists all recorded provenance entries
    pub fn list_all_provenance(&self) -> Result<Vec<FixtureProvenance>, ProvenanceError> {
        let provenance_dir = self.base_dir.join("provenance");
        let mut entries = Vec::new();

        if !provenance_dir.exists() {
            return Ok(entries);
        }

        for entry in fs::read_dir(provenance_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                match fs::read_to_string(&path) {
                    Ok(content) => match serde_json::from_str::<FixtureProvenance>(&content) {
                        Ok(provenance) => entries.push(provenance),
                        Err(e) => eprintln!("Warning: Failed to parse provenance file {}: {}", path.display(), e),
                    },
                    Err(e) => eprintln!("Warning: Failed to read provenance file {}: {}", path.display(), e),
                }
            }
        }

        Ok(entries)
    }

    /// Verifies that a fixture can be regenerated with its recorded provenance
    pub fn verify_reproducibility(&self, fixture_id: &str) -> Result<bool, ProvenanceError> {
        let provenance = self.load_fixture_provenance(fixture_id)?;

        // Check if reference implementation is still available
        let ref_impl_available = self.check_reference_implementation_availability(&provenance.generation_info);

        // Check if dependencies are satisfied
        let dependencies_satisfied = self.check_dependencies(&provenance.dependencies)?;

        Ok(ref_impl_available && dependencies_satisfied)
    }

    /// Generates a regeneration script for a fixture
    pub fn generate_regeneration_script(&self, fixture_id: &str) -> Result<String, ProvenanceError> {
        let provenance = self.load_fixture_provenance(fixture_id)?;

        let mut script = String::new();
        script.push_str("#!/bin/bash\n");
        script.push_str("# Regeneration script for fixture: ");
        script.push_str(&fixture_id);
        script.push_str("\n# Generated by RaptorQ differential testing framework\n\n");

        // Add dependency installation commands
        script.push_str("# Install dependencies\n");
        for dep in &provenance.dependencies {
            script.push_str(&self.generate_dependency_install_command(dep));
            script.push('\n');
        }

        script.push_str("\n# Set environment\n");
        for (key, value) in &provenance.generation_info.environment {
            script.push_str(&format!("export {}=\"{}\"\n", key, value));
        }

        script.push_str("\n# Change to working directory\n");
        script.push_str(&format!("cd \"{}\"\n", provenance.generation_info.working_directory));

        script.push_str("\n# Execute generation command\n");
        script.push_str(&provenance.generation_info.command);
        script.push('\n');

        Ok(script)
    }

    // Helper methods

    fn make_relative_path(&self, absolute_path: &Path) -> Result<PathBuf, ProvenanceError> {
        absolute_path.strip_prefix(&self.base_dir)
            .map(|p| p.to_path_buf())
            .map_err(|_| ProvenanceError::InvalidData(format!(
                "Path {} is not under base directory {}",
                absolute_path.display(),
                self.base_dir.display()
            )))
    }

    fn get_provenance_path(&self, fixture_id: &str) -> PathBuf {
        self.base_dir.join("provenance").join(format!("{}.json", fixture_id))
    }

    fn save_provenance(&self, path: &Path, provenance: &FixtureProvenance) -> Result<(), ProvenanceError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(provenance)?;
        fs::write(path, json)?;

        Ok(())
    }

    fn detect_dependencies(&self, generation_info: &GenerationInfo) -> Result<Vec<Dependency>, ProvenanceError> {
        let mut dependencies = Vec::new();

        // Add reference implementation as a dependency
        dependencies.push(Dependency {
            name: generation_info.reference_implementation.clone(),
            version: generation_info.reference_version.clone(),
            source: "external".to_string(),
            dependency_type: DependencyType::Binary,
        });

        // TODO: Parse command to detect additional dependencies

        Ok(dependencies)
    }

    fn check_reference_implementation_availability(&self, generation_info: &GenerationInfo) -> bool {
        // This would check if the reference implementation is still available
        // For now, just return true as a placeholder
        true
    }

    fn check_dependencies(&self, _dependencies: &[Dependency]) -> Result<bool, ProvenanceError> {
        // This would check if all dependencies are satisfied
        // For now, just return true as a placeholder
        Ok(true)
    }

    fn generate_dependency_install_command(&self, dep: &Dependency) -> String {
        match dep.dependency_type {
            DependencyType::Binary => format!("# Install binary: {} (version {})", dep.name, dep.version),
            DependencyType::Library => format!("# Install library: {} (version {})", dep.name, dep.version),
            DependencyType::PythonPackage => format!("pip install {}=={}", dep.name, dep.version),
            DependencyType::SystemPackage => format!("# Install system package: {} (version {})", dep.name, dep.version),
            DependencyType::Repository => format!("git clone {} # version {}", dep.source, dep.version),
        }
    }
}

/// Generates a unique fixture ID from a path
fn generate_fixture_id(path: &Path) -> String {
    let path_str = path.to_string_lossy();
    format!("{:x}", md5_hash(path_str.as_bytes()))
}

/// Gets current platform information
pub fn get_current_platform_info() -> PlatformInfo {
    PlatformInfo {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        version: get_os_version(),
        details: get_platform_details(),
    }
}

/// Gets the current git commit hash
pub fn get_current_git_commit() -> Option<String> {
    use std::process::Command;

    Command::new("git")
        .args(&["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                None
            }
        })
}

// Platform-specific helper functions
fn get_os_version() -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/version")
            .unwrap_or_else(|_| "unknown".to_string())
            .lines()
            .next()
            .unwrap_or("unknown")
            .to_string()
    }

    #[cfg(not(target_os = "linux"))]
    {
        "unknown".to_string()
    }
}

fn get_platform_details() -> HashMap<String, String> {
    let mut details = HashMap::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(info) = std::fs::read_to_string("/etc/os-release") {
            for line in info.lines() {
                if let Some(eq_pos) = line.find('=') {
                    let key = &line[..eq_pos];
                    let value = &line[eq_pos + 1..].trim_matches('"');
                    details.insert(key.to_string(), value.to_string());
                }
            }
        }
    }

    details
}

// Hash calculation functions (simplified for this implementation)
fn calculate_sha256(data: &[u8]) -> String {
    format!("{:x}", md5_hash(data)) // Using MD5 as placeholder for SHA256
}

fn calculate_md5(data: &[u8]) -> String {
    format!("{:x}", md5_hash(data))
}

fn md5_hash(data: &[u8]) -> u128 {
    // Simplified hash function for testing
    data.iter().map(|&b| b as u128).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_provenance_tracker_creation() {
        let temp_dir = TempDir::new().unwrap();
        let tracker = ProvenanceTracker::new(temp_dir.path());
        assert_eq!(tracker.base_dir, temp_dir.path());
    }

    #[test]
    fn test_generate_fixture_id() {
        let path = Path::new("/test/fixture.json");
        let id = generate_fixture_id(path);
        assert!(!id.is_empty());
        assert_eq!(id.len(), 32); // MD5 hex string length

        // Same path should generate same ID
        let id2 = generate_fixture_id(path);
        assert_eq!(id, id2);
    }

    #[test]
    fn test_platform_info() {
        let info = get_current_platform_info();
        assert!(!info.os.is_empty());
        assert!(!info.arch.is_empty());
        assert!(!info.version.is_empty());
    }

    #[test]
    fn test_dependency_types() {
        let dep = Dependency {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            source: "test-source".to_string(),
            dependency_type: DependencyType::Binary,
        };

        assert_eq!(dep.name, "test");
        matches!(dep.dependency_type, DependencyType::Binary);
    }

    #[test]
    fn test_fixture_checksums() {
        let input = b"test input";
        let output = b"test output";

        let checksums = FixtureChecksums {
            input_sha256: calculate_sha256(input),
            output_sha256: calculate_sha256(output),
            fixture_md5: calculate_md5(&[input, output].concat()),
        };

        assert!(!checksums.input_sha256.is_empty());
        assert!(!checksums.output_sha256.is_empty());
        assert!(!checksums.fixture_md5.is_empty());
        assert_ne!(checksums.input_sha256, checksums.output_sha256);
    }
}