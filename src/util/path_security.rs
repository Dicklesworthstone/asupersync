//! Secure path validation utilities for preventing directory traversal attacks.
//!
//! This module provides path canonicalization and bounds checking to ensure
//! user-supplied paths cannot escape intended directories or access sensitive
//! system files.
//!
//! # Security Model
//!
//! 1. **Canonicalization**: All paths are canonicalized to resolve ".." and "." components
//! 2. **Bounds checking**: Canonical paths must stay within allowed directories
//! 3. **Fail-safe**: Invalid or suspicious paths are rejected with clear error messages
//! 4. **Audit trail**: Security violations are logged for monitoring
//!
//! # Example
//!
//! ```ignore
//! use asupersync::util::path_security::{SecurePath, PathSecurityError};
//!
//! // Create a secure path validator with allowed base directory
//! let secure_path = SecurePath::new("/app/data")?;
//!
//! // Validate a user-supplied path
//! let validated = secure_path.validate_path("configs/app.toml")?;
//! assert_eq!(validated.as_path(), Path::new("/app/data/configs/app.toml"));
//!
//! // This would fail with PathTraversalAttempt error
//! let result = secure_path.validate_path("../../etc/passwd");
//! assert!(result.is_err());
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors that can occur during path security validation.
#[derive(Error, Debug)]
pub enum PathSecurityError {
    /// Path contains directory traversal attempts (e.g., "../../../etc/passwd").
    #[error("Path traversal attempt detected: {path}")]
    PathTraversalAttempt { path: String },

    /// Path canonicalization failed due to I/O error.
    #[error("Failed to canonicalize path {path}: {source}")]
    CanonicalizationFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Canonical path is outside the allowed bounds.
    #[error("Path {path} is outside allowed bounds {allowed_base}")]
    OutsideAllowedBounds { path: String, allowed_base: String },

    /// Base directory does not exist or is not accessible.
    #[error("Base directory {base} is not accessible: {source}")]
    BaseDirectoryInaccessible {
        base: String,
        #[source]
        source: std::io::Error,
    },

    /// Path is empty or contains null bytes.
    #[error("Invalid path: {reason}")]
    InvalidPath { reason: String },
}

/// A validated and canonicalized secure path.
#[derive(Debug, Clone)]
pub struct ValidatedPath {
    /// The canonicalized path that has been validated as safe.
    canonical_path: PathBuf,
    /// The original user-supplied path for audit purposes.
    original_path: String,
}

impl ValidatedPath {
    /// Get the validated canonical path.
    pub fn as_path(&self) -> &Path {
        &self.canonical_path
    }

    /// Get the validated canonical path as PathBuf.
    pub fn to_path_buf(&self) -> PathBuf {
        self.canonical_path.clone()
    }

    /// Get the original user-supplied path for audit/logging.
    pub fn original_path(&self) -> &str {
        &self.original_path
    }
}

/// Secure path validator that prevents directory traversal attacks.
#[derive(Debug, Clone)]
pub struct SecurePath {
    /// The canonicalized base directory that constrains all validated paths.
    allowed_base: PathBuf,
}

impl SecurePath {
    /// Create a new secure path validator with the given base directory.
    ///
    /// The base directory must exist and be accessible. All validated paths
    /// will be constrained to stay within this directory tree.
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self, PathSecurityError> {
        let base_path = base_dir.as_ref();

        // Canonicalize the base directory to ensure it's absolute and resolved
        let allowed_base =
            base_path
                .canonicalize()
                .map_err(|e| PathSecurityError::BaseDirectoryInaccessible {
                    base: base_path.display().to_string(),
                    source: e,
                })?;

        Ok(Self { allowed_base })
    }

    /// Validate a user-supplied path to ensure it's safe for file operations.
    ///
    /// This method performs the following security checks:
    /// 1. Validates the path is not empty and contains no null bytes
    /// 2. Joins the path with the allowed base directory
    /// 3. Canonicalizes the result to resolve any ".." or "." components
    /// 4. Verifies the canonical path stays within the allowed base
    ///
    /// Returns a `ValidatedPath` if the path is safe, or an error if validation fails.
    pub fn validate_path<P: AsRef<Path>>(
        &self,
        user_path: P,
    ) -> Result<ValidatedPath, PathSecurityError> {
        let user_path_ref = user_path.as_ref();
        let user_path_str = user_path_ref.to_string_lossy().to_string();

        // Check for empty path or null bytes
        if user_path_str.is_empty() {
            return Err(PathSecurityError::InvalidPath {
                reason: "Path is empty".to_string(),
            });
        }

        if user_path_str.contains('\0') {
            return Err(PathSecurityError::InvalidPath {
                reason: "Path contains null bytes".to_string(),
            });
        }

        // Pre-check for obvious traversal attempts before canonicalization
        if user_path_str.contains("..") {
            // This is a preliminary check; canonicalization will be the final arbiter
            #[cfg(feature = "tracing-integration")]
            tracing::warn!(
                "Potential path traversal attempt detected: {}",
                user_path_str
            );
        }

        // Join with the allowed base directory
        let joined_path = self.allowed_base.join(user_path_ref);

        // Canonicalize to resolve any ".." or "." components
        let canonical_path = match joined_path.canonicalize() {
            Ok(path) => path,
            Err(e) => {
                // If canonicalization fails, it could be because the path doesn't exist yet
                // Try to canonicalize the parent directory and append the filename
                if let Some(parent) = joined_path.parent() {
                    if let Some(filename) = joined_path.file_name() {
                        match parent.canonicalize() {
                            Ok(canonical_parent) => canonical_parent.join(filename),
                            Err(_) => {
                                return Err(PathSecurityError::CanonicalizationFailed {
                                    path: user_path_str,
                                    source: e,
                                });
                            }
                        }
                    } else {
                        return Err(PathSecurityError::CanonicalizationFailed {
                            path: user_path_str,
                            source: e,
                        });
                    }
                } else {
                    return Err(PathSecurityError::CanonicalizationFailed {
                        path: user_path_str,
                        source: e,
                    });
                }
            }
        };

        // Verify the canonical path is within the allowed bounds
        if !canonical_path.starts_with(&self.allowed_base) {
            return Err(PathSecurityError::OutsideAllowedBounds {
                path: canonical_path.display().to_string(),
                allowed_base: self.allowed_base.display().to_string(),
            });
        }

        // Log successful validation for audit purposes
        #[cfg(feature = "tracing-integration")]
        tracing::debug!(
            "Path validation successful: {} -> {}",
            user_path_str,
            canonical_path.display()
        );

        Ok(ValidatedPath {
            canonical_path,
            original_path: user_path_str,
        })
    }

    /// Get the base directory for this secure path validator.
    pub fn base_directory(&self) -> &Path {
        &self.allowed_base
    }
}

/// Secure wrapper functions for common file operations.
impl SecurePath {
    /// Securely read a file to a string with path validation.
    pub fn read_to_string<P: AsRef<Path>>(
        &self,
        user_path: P,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let validated = self.validate_path(user_path)?;
        let content = fs::read_to_string(validated.as_path())?;
        Ok(content)
    }

    /// Securely write a string to a file with path validation.
    pub fn write_string<P: AsRef<Path>, C: AsRef<str>>(
        &self,
        user_path: P,
        content: C,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let validated = self.validate_path(user_path)?;

        // Ensure parent directory exists
        if let Some(parent) = validated.as_path().parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(validated.as_path(), content.as_ref())?;
        Ok(())
    }

    /// Securely read file bytes with path validation.
    pub fn read_bytes<P: AsRef<Path>>(
        &self,
        user_path: P,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let validated = self.validate_path(user_path)?;
        let bytes = fs::read(validated.as_path())?;
        Ok(bytes)
    }

    /// Securely write bytes to a file with path validation.
    pub fn write_bytes<P: AsRef<Path>, B: AsRef<[u8]>>(
        &self,
        user_path: P,
        bytes: B,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let validated = self.validate_path(user_path)?;

        // Ensure parent directory exists
        if let Some(parent) = validated.as_path().parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(validated.as_path(), bytes.as_ref())?;
        Ok(())
    }

    /// Securely copy a file with source and destination path validation.
    pub fn copy_file<P1: AsRef<Path>, P2: AsRef<Path>>(
        &self,
        src: P1,
        dst: P2,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let validated_src = self.validate_path(src)?;
        let validated_dst = self.validate_path(dst)?;

        // Ensure destination parent directory exists
        if let Some(parent) = validated_dst.as_path().parent() {
            fs::create_dir_all(parent)?;
        }

        let bytes_copied = fs::copy(validated_src.as_path(), validated_dst.as_path())?;
        Ok(bytes_copied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_secure_path_creation() {
        let temp_dir = TempDir::new().unwrap();
        let secure_path = SecurePath::new(temp_dir.path()).unwrap();
        assert_eq!(
            secure_path.base_directory(),
            temp_dir.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn test_invalid_base_directory() {
        let result = SecurePath::new("/nonexistent/directory");
        assert!(result.is_err());
        match result.unwrap_err() {
            PathSecurityError::BaseDirectoryInaccessible { .. } => (),
            other => panic!("Expected BaseDirectoryInaccessible, got {:?}", other),
        }
    }

    #[test]
    fn test_valid_path_validation() {
        let temp_dir = TempDir::new().unwrap();
        let secure_path = SecurePath::new(temp_dir.path()).unwrap();

        let validated = secure_path.validate_path("configs/app.toml").unwrap();
        let expected = temp_dir
            .path()
            .canonicalize()
            .unwrap()
            .join("configs/app.toml");
        assert_eq!(validated.as_path(), expected);
        assert_eq!(validated.original_path(), "configs/app.toml");
    }

    #[test]
    fn test_path_traversal_attack() {
        let temp_dir = TempDir::new().unwrap();
        let secure_path = SecurePath::new(temp_dir.path()).unwrap();

        let result = secure_path.validate_path("../../etc/passwd");
        assert!(result.is_err());
        match result.unwrap_err() {
            PathSecurityError::OutsideAllowedBounds { .. } => (),
            other => panic!("Expected OutsideAllowedBounds, got {:?}", other),
        }
    }

    #[test]
    fn test_empty_path() {
        let temp_dir = TempDir::new().unwrap();
        let secure_path = SecurePath::new(temp_dir.path()).unwrap();

        let result = secure_path.validate_path("");
        assert!(result.is_err());
        match result.unwrap_err() {
            PathSecurityError::InvalidPath { .. } => (),
            other => panic!("Expected InvalidPath, got {:?}", other),
        }
    }

    #[test]
    fn test_null_byte_path() {
        let temp_dir = TempDir::new().unwrap();
        let secure_path = SecurePath::new(temp_dir.path()).unwrap();

        let result = secure_path.validate_path("file\0.txt");
        assert!(result.is_err());
        match result.unwrap_err() {
            PathSecurityError::InvalidPath { .. } => (),
            other => panic!("Expected InvalidPath, got {:?}", other),
        }
    }

    #[test]
    fn test_secure_file_operations() {
        let temp_dir = TempDir::new().unwrap();
        let secure_path = SecurePath::new(temp_dir.path()).unwrap();

        // Test write and read
        let content = "Hello, secure world!";
        secure_path.write_string("test.txt", content).unwrap();
        let read_content = secure_path.read_to_string("test.txt").unwrap();
        assert_eq!(read_content, content);

        // Test bytes operations
        let bytes = b"Binary data";
        secure_path.write_bytes("binary.dat", bytes).unwrap();
        let read_bytes = secure_path.read_bytes("binary.dat").unwrap();
        assert_eq!(read_bytes, bytes);
    }

    #[test]
    fn test_secure_copy_operation() {
        let temp_dir = TempDir::new().unwrap();
        let secure_path = SecurePath::new(temp_dir.path()).unwrap();

        // Create source file
        let content = "File to copy";
        secure_path.write_string("source.txt", content).unwrap();

        // Copy file
        let bytes_copied = secure_path
            .copy_file("source.txt", "destination.txt")
            .unwrap();
        assert!(bytes_copied > 0);

        // Verify copy
        let copied_content = secure_path.read_to_string("destination.txt").unwrap();
        assert_eq!(copied_content, content);
    }

    #[test]
    fn test_directory_creation() {
        let temp_dir = TempDir::new().unwrap();
        let secure_path = SecurePath::new(temp_dir.path()).unwrap();

        // Writing to nested path should create directories
        secure_path
            .write_string("nested/dirs/file.txt", "content")
            .unwrap();

        // Verify the file was created
        let content = secure_path.read_to_string("nested/dirs/file.txt").unwrap();
        assert_eq!(content, "content");
    }
}
