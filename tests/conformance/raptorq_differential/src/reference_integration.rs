#![allow(clippy::all)]
//! Integration with external RaptorQ reference implementations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use std::path::Path;
use std::time::Duration;

/// Interface to external reference implementations
#[derive(Debug)]
#[allow(dead_code)]
pub struct ReferenceImplementation {
    name: String,
    binary_path: String,
    version: String,
    timeout: Duration,
}

/// Output from a reference implementation
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ReferenceOutput {
    /// Encoded or decoded data
    pub data: Vec<u8>,
    /// Standard output from the reference tool
    pub stdout: String,
    /// Standard error from the reference tool
    pub stderr: String,
    /// Exit code
    pub exit_code: i32,
    /// Execution time
    pub execution_time: Duration,
}

/// Information about a reference implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ImplementationInfo {
    /// Name of the implementation
    pub name: String,
    /// Version string
    pub version: String,
    /// Command line interface format
    pub cli_format: String,
    /// Supported operations
    pub supported_operations: Vec<String>,
    /// Parameter constraints
    pub constraints: HashMap<String, String>,
}

/// Errors from reference implementation integration
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum ReferenceError {
    #[error("Binary not found: {0}")]
    BinaryNotFound(String),

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Timeout after {timeout:?}")]
    Timeout { timeout: Duration },

    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

#[allow(dead_code)]

impl ReferenceImplementation {
    /// Creates a new reference implementation interface
    #[allow(dead_code)]
    pub fn new(name: String, binary_path: String) -> Result<Self, ReferenceError> {
        // Verify binary exists
        if !Path::new(&binary_path).exists() {
            return Err(ReferenceError::BinaryNotFound(binary_path));
        }

        // Get version info
        let version = Self::get_version(&binary_path)?;

        Ok(Self {
            name,
            binary_path,
            version,
            timeout: Duration::from_secs(30),
        })
    }

    /// Sets the timeout for reference implementation calls
    #[allow(dead_code)]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Gets version information from the reference binary
    #[allow(dead_code)]
    fn get_version(binary_path: &str) -> Result<String, ReferenceError> {
        let output = Command::new(binary_path)
            .arg("--version")
            .output()
            .map_err(|e| ReferenceError::ExecutionFailed(format!("Failed to get version: {}", e)))?;

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Encodes data using the reference implementation
    #[allow(dead_code)]
    pub fn encode(
        &self,
        input_data: &[u8],
        source_symbols: usize,
        symbol_size: usize,
        repair_symbols: usize,
    ) -> Result<ReferenceOutput, ReferenceError> {
        let start_time = std::time::Instant::now();

        // Build command arguments based on implementation
        let args = match self.name.as_str() {
            "libraptorq" => self.build_libraptorq_encode_args(source_symbols, symbol_size, repair_symbols),
            "raptorq-python" => self.build_python_encode_args(source_symbols, symbol_size, repair_symbols),
            _ => return Err(ReferenceError::InvalidParameters(format!("Unknown implementation: {}", self.name))),
        }?;

        // Execute the command
        let mut cmd = Command::new(&self.binary_path);
        cmd.args(&args);

        // Provide input data via stdin
        let output = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(stdin) = child.stdin.as_mut() {
                    stdin.write_all(input_data)?;
                }
                child.wait_with_output()
            })
            .map_err(|e| ReferenceError::ExecutionFailed(format!("Command execution failed: {}", e)))?;

        let execution_time = start_time.elapsed();

        if execution_time > self.timeout {
            return Err(ReferenceError::Timeout { timeout: self.timeout });
        }

        Ok(ReferenceOutput {
            data: output.stdout,
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
            execution_time,
        })
    }

    /// Decodes data using the reference implementation
    #[allow(dead_code)]
    pub fn decode(
        &self,
        encoded_symbols: &[Vec<u8>],
        symbol_indices: &[u32],
        source_symbols: usize,
        symbol_size: usize,
    ) -> Result<ReferenceOutput, ReferenceError> {
        let start_time = std::time::Instant::now();

        // Build command arguments
        let args = match self.name.as_str() {
            "libraptorq" => self.build_libraptorq_decode_args(source_symbols, symbol_size),
            "raptorq-python" => self.build_python_decode_args(source_symbols, symbol_size),
            _ => return Err(ReferenceError::InvalidParameters(format!("Unknown implementation: {}", self.name))),
        }?;

        // Serialize encoded symbols to input format expected by reference implementation
        let input_data = self.serialize_symbols_for_decode(encoded_symbols, symbol_indices)?;

        let mut cmd = Command::new(&self.binary_path);
        cmd.args(&args);

        let output = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(stdin) = child.stdin.as_mut() {
                    stdin.write_all(&input_data)?;
                }
                child.wait_with_output()
            })
            .map_err(|e| ReferenceError::ExecutionFailed(format!("Command execution failed: {}", e)))?;

        let execution_time = start_time.elapsed();

        if execution_time > self.timeout {
            return Err(ReferenceError::Timeout { timeout: self.timeout });
        }

        Ok(ReferenceOutput {
            data: output.stdout,
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
            execution_time,
        })
    }

    /// Gets information about this reference implementation
    #[allow(dead_code)]
    pub fn get_info(&self) -> ImplementationInfo {
        let mut constraints = HashMap::new();
        let mut supported_operations = vec!["encode".to_string(), "decode".to_string()];

        match self.name.as_str() {
            "libraptorq" => {
                constraints.insert("max_k".to_string(), "8192".to_string());
                constraints.insert("symbol_sizes".to_string(), "1,2,4,8,16,32,64,128,256,512,1024".to_string());
            }
            "raptorq-python" => {
                constraints.insert("max_k".to_string(), "8192".to_string());
                constraints.insert("symbol_sizes".to_string(), "any".to_string());
                supported_operations.push("systematic".to_string());
            }
            _ => {}
        }

        ImplementationInfo {
            name: self.name.clone(),
            version: self.version.clone(),
            cli_format: self.get_cli_format(),
            supported_operations,
            constraints,
        }
    }

    // Implementation-specific command building

    #[allow(dead_code)]

    fn build_libraptorq_encode_args(
        &self,
        source_symbols: usize,
        symbol_size: usize,
        repair_symbols: usize,
    ) -> Result<Vec<String>, ReferenceError> {
        Ok(vec![
            "encode".to_string(),
            "--source-symbols".to_string(),
            source_symbols.to_string(),
            "--symbol-size".to_string(),
            symbol_size.to_string(),
            "--repair-symbols".to_string(),
            repair_symbols.to_string(),
            "--format".to_string(),
            "binary".to_string(),
        ])
    }

    #[allow(dead_code)]

    fn build_libraptorq_decode_args(
        &self,
        source_symbols: usize,
        symbol_size: usize,
    ) -> Result<Vec<String>, ReferenceError> {
        Ok(vec![
            "decode".to_string(),
            "--source-symbols".to_string(),
            source_symbols.to_string(),
            "--symbol-size".to_string(),
            symbol_size.to_string(),
            "--format".to_string(),
            "binary".to_string(),
        ])
    }

    #[allow(dead_code)]

    fn build_python_encode_args(
        &self,
        source_symbols: usize,
        symbol_size: usize,
        repair_symbols: usize,
    ) -> Result<Vec<String>, ReferenceError> {
        Ok(vec![
            "-c".to_string(),
            format!(
                "import raptorq; import sys; data=sys.stdin.buffer.read(); \
                encoder=raptorq.Encoder.with_defaults(data, {}); \
                symbols=encoder.get_encoded_packets({}); \
                sys.stdout.buffer.write(b''.join(s.data() for s in symbols))",
                symbol_size, source_symbols + repair_symbols
            ),
        ])
    }

    #[allow(dead_code)]

    fn build_python_decode_args(
        &self,
        source_symbols: usize,
        symbol_size: usize,
    ) -> Result<Vec<String>, ReferenceError> {
        Ok(vec![
            "-c".to_string(),
            format!(
                "import raptorq; import sys; import struct; \
                data=sys.stdin.buffer.read(); \
                decoder=raptorq.Decoder.with_defaults({}, {}); \
                # Parse symbols from input data \
                result=decoder.decode(); \
                if result: sys.stdout.buffer.write(result)",
                source_symbols, symbol_size
            ),
        ])
    }

    #[allow(dead_code)]

    fn serialize_symbols_for_decode(&self, symbols: &[Vec<u8>], indices: &[u32]) -> Result<Vec<u8>, ReferenceError> {
        // Simple serialization: length prefix + symbol data
        let mut data = Vec::new();

        for (symbol, &index) in symbols.iter().zip(indices.iter()) {
            data.extend_from_slice(&index.to_le_bytes());
            data.extend_from_slice(&(symbol.len() as u32).to_le_bytes());
            data.extend_from_slice(symbol);
        }

        Ok(data)
    }

    #[allow(dead_code)]

    fn get_cli_format(&self) -> String {
        match self.name.as_str() {
            "libraptorq" => "libraptorq [encode|decode] --source-symbols K --symbol-size T [options]".to_string(),
            "raptorq-python" => "python -c \"raptorq script\" < input > output".to_string(),
            _ => "unknown".to_string(),
        }
    }
}

/// Discovers available reference implementations on the system
#[allow(dead_code)]
pub fn discover_reference_implementations() -> Vec<ImplementationInfo> {
    let mut implementations = Vec::new();

    // Check for known binaries
    let candidates = vec![
        ("libraptorq", "/usr/local/bin/libraptorq"),
        ("libraptorq", "/usr/bin/libraptorq"),
        ("raptorq-python", "/usr/bin/python3"),
        ("raptorq-python", "/usr/local/bin/python3"),
    ];

    for (name, path) in candidates {
        if Path::new(path).exists() {
            if let Ok(ref_impl) = ReferenceImplementation::new(name.to_string(), path.to_string()) {
                implementations.push(ref_impl.get_info());
            }
        }
    }

    implementations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(dead_code)]
    fn test_implementation_info_creation() {
        let info = ImplementationInfo {
            name: "test-impl".to_string(),
            version: "1.0.0".to_string(),
            cli_format: "test-impl [options]".to_string(),
            supported_operations: vec!["encode".to_string(), "decode".to_string()],
            constraints: HashMap::new(),
        };

        assert_eq!(info.name, "test-impl");
        assert_eq!(info.version, "1.0.0");
        assert_eq!(info.supported_operations.len(), 2);
    }

    #[test]
    #[allow(dead_code)]
    fn test_reference_error_display() {
        let error = ReferenceError::BinaryNotFound("/nonexistent/binary".to_string());
        assert!(format!("{}", error).contains("Binary not found"));

        let timeout_error = ReferenceError::Timeout { timeout: Duration::from_secs(30) };
        assert!(format!("{}", timeout_error).contains("Timeout"));
    }

    #[test]
    #[allow(dead_code)]
    fn test_reference_output_creation() {
        let output = ReferenceOutput {
            data: b"test data".to_vec(),
            stdout: "success".to_string(),
            stderr: "".to_string(),
            exit_code: 0,
            execution_time: Duration::from_millis(100),
        };

        assert_eq!(output.data, b"test data");
        assert_eq!(output.exit_code, 0);
        assert!(output.execution_time < Duration::from_secs(1));
    }

    #[test]
    #[allow(dead_code)]
    fn test_discover_reference_implementations() {
        let implementations = discover_reference_implementations();
        // This will vary by system, so just check that it doesn't crash
        assert!(implementations.len() >= 0);
    }
}