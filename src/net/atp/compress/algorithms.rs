//! Compression algorithm implementations for ATP-C4.
//!
//! This module provides the core compression algorithm implementations
//! with consistent interfaces and error handling.

use super::CompressionError;
use crate::atp::manifest::CompressionAlgorithm;
#[cfg(feature = "compression")]
use std::io::{Read, Write};

/// Algorithm-specific compression parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct CompressionParams {
    /// Algorithm to use.
    pub algorithm: CompressionAlgorithm,
    /// Compression level.
    pub level: u8,
    /// Expected compression ratio.
    pub expected_ratio: Option<f32>,
    /// Maximum output size to prevent bombs.
    pub max_output_size: Option<u64>,
}

/// Algorithm registry for compression implementations.
pub struct AlgorithmRegistry;

impl AlgorithmRegistry {
    /// Get default parameters for an algorithm.
    pub fn default_params(algorithm: CompressionAlgorithm) -> CompressionParams {
        match algorithm {
            CompressionAlgorithm::None => CompressionParams {
                algorithm,
                level: 0,
                expected_ratio: Some(1.0),
                max_output_size: None,
            },
            CompressionAlgorithm::Lz4 => CompressionParams {
                algorithm,
                level: 1,
                expected_ratio: Some(0.6),
                max_output_size: None,
            },
            CompressionAlgorithm::Gzip => CompressionParams {
                algorithm,
                level: 6,
                expected_ratio: Some(0.5),
                max_output_size: None,
            },
            CompressionAlgorithm::Brotli => CompressionParams {
                algorithm,
                level: 6,
                expected_ratio: Some(0.4),
                max_output_size: None,
            },
        }
    }

    /// Check if algorithm is supported in this build.
    pub fn is_supported(algorithm: CompressionAlgorithm) -> bool {
        match algorithm {
            CompressionAlgorithm::None => true,
            CompressionAlgorithm::Lz4 => true,
            CompressionAlgorithm::Gzip => true,
            CompressionAlgorithm::Brotli => cfg!(feature = "compression"),
        }
    }

    /// Get compression performance characteristics.
    pub fn performance_profile(algorithm: CompressionAlgorithm) -> PerformanceProfile {
        match algorithm {
            CompressionAlgorithm::None => PerformanceProfile {
                compression_speed: CompressionSpeed::VeryFast,
                decompression_speed: CompressionSpeed::VeryFast,
                compression_ratio: CompressionRatio::None,
                cpu_usage: CpuUsage::VeryLow,
            },
            CompressionAlgorithm::Lz4 => PerformanceProfile {
                compression_speed: CompressionSpeed::VeryFast,
                decompression_speed: CompressionSpeed::VeryFast,
                compression_ratio: CompressionRatio::Low,
                cpu_usage: CpuUsage::Low,
            },
            CompressionAlgorithm::Gzip => PerformanceProfile {
                compression_speed: CompressionSpeed::Medium,
                decompression_speed: CompressionSpeed::Fast,
                compression_ratio: CompressionRatio::Medium,
                cpu_usage: CpuUsage::Medium,
            },
            CompressionAlgorithm::Brotli => PerformanceProfile {
                compression_speed: CompressionSpeed::Slow,
                decompression_speed: CompressionSpeed::Fast,
                compression_ratio: CompressionRatio::High,
                cpu_usage: CpuUsage::High,
            },
        }
    }
}

/// Compression performance profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerformanceProfile {
    /// Compression speed characteristic.
    pub compression_speed: CompressionSpeed,
    /// Decompression speed characteristic.
    pub decompression_speed: CompressionSpeed,
    /// Compression ratio characteristic.
    pub compression_ratio: CompressionRatio,
    /// CPU usage characteristic.
    pub cpu_usage: CpuUsage,
}

/// Compression speed categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompressionSpeed {
    /// Very fast compression.
    VeryFast,
    /// Fast compression.
    Fast,
    /// Medium compression.
    Medium,
    /// Slow compression.
    Slow,
    /// Very slow compression.
    VerySlow,
}

/// Compression ratio categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompressionRatio {
    /// No compression.
    None,
    /// Low compression ratio.
    Low,
    /// Medium compression ratio.
    Medium,
    /// High compression ratio.
    High,
    /// Very high compression ratio.
    VeryHigh,
}

/// CPU usage categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CpuUsage {
    /// Very low CPU usage.
    VeryLow,
    /// Low CPU usage.
    Low,
    /// Medium CPU usage.
    Medium,
    /// High CPU usage.
    High,
    /// Very high CPU usage.
    VeryHigh,
}

/// Compression algorithm adapter.
pub trait CompressionAdapter {
    /// Compress data with given parameters.
    fn compress(
        &self,
        data: &[u8],
        params: &CompressionParams,
    ) -> Result<Vec<u8>, CompressionError>;

    /// Decompress data with given parameters.
    fn decompress(
        &self,
        data: &[u8],
        params: &CompressionParams,
        expected_size: u64,
    ) -> Result<Vec<u8>, CompressionError>;

    /// Validate parameters for this algorithm.
    fn validate_params(&self, params: &CompressionParams) -> Result<(), CompressionError>;
}

/// LZ4 compression adapter.
pub struct Lz4Adapter;

impl CompressionAdapter for Lz4Adapter {
    fn compress(
        &self,
        data: &[u8],
        _params: &CompressionParams,
    ) -> Result<Vec<u8>, CompressionError> {
        lz4_flex::compress_prepend_size(data)
            .map_err(|e| CompressionError::CompressionFailed(e.to_string()))
    }

    fn decompress(
        &self,
        data: &[u8],
        _params: &CompressionParams,
        expected_size: u64,
    ) -> Result<Vec<u8>, CompressionError> {
        let decompressed = lz4_flex::decompress_size_prepended(data)
            .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;

        if decompressed.len() != expected_size as usize {
            return Err(CompressionError::DecompressionFailed(
                "size mismatch after decompression".to_string(),
            ));
        }

        Ok(decompressed)
    }

    fn validate_params(&self, params: &CompressionParams) -> Result<(), CompressionError> {
        if !matches!(params.algorithm, CompressionAlgorithm::Lz4) {
            return Err(CompressionError::PolicyViolation(
                "LZ4 adapter requires LZ4 algorithm".to_string(),
            ));
        }
        Ok(())
    }
}

/// Gzip compression adapter.
pub struct GzipAdapter;

impl CompressionAdapter for GzipAdapter {
    fn compress(
        &self,
        data: &[u8],
        params: &CompressionParams,
    ) -> Result<Vec<u8>, CompressionError> {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(params.level.into()));
        encoder
            .write_all(data)
            .map_err(|e| CompressionError::CompressionFailed(e.to_string()))?;

        encoder
            .finish()
            .map_err(|e| CompressionError::CompressionFailed(e.to_string()))
    }

    fn decompress(
        &self,
        data: &[u8],
        _params: &CompressionParams,
        expected_size: u64,
    ) -> Result<Vec<u8>, CompressionError> {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::with_capacity(expected_size as usize);

        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;

        if decompressed.len() != expected_size as usize {
            return Err(CompressionError::DecompressionFailed(
                "size mismatch after decompression".to_string(),
            ));
        }

        Ok(decompressed)
    }

    fn validate_params(&self, params: &CompressionParams) -> Result<(), CompressionError> {
        if !matches!(params.algorithm, CompressionAlgorithm::Gzip) {
            return Err(CompressionError::PolicyViolation(
                "Gzip adapter requires Gzip algorithm".to_string(),
            ));
        }

        if params.level > 9 {
            return Err(CompressionError::PolicyViolation(
                "Gzip level must be 0-9".to_string(),
            ));
        }

        Ok(())
    }
}

/// Brotli compression adapter.
pub struct BrotliAdapter;

impl CompressionAdapter for BrotliAdapter {
    fn compress(
        &self,
        data: &[u8],
        params: &CompressionParams,
    ) -> Result<Vec<u8>, CompressionError> {
        self.validate_params(params)?;

        #[cfg(feature = "compression")]
        {
            let quality = u32::from(params.level.min(11));
            let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, quality, 22);
            encoder
                .write_all(data)
                .map_err(|e| CompressionError::CompressionFailed(e.to_string()))?;
            encoder
                .flush()
                .map_err(|e| CompressionError::CompressionFailed(e.to_string()))?;
            Ok(encoder.into_inner())
        }

        #[cfg(not(feature = "compression"))]
        {
            let _ = data;
            Err(CompressionError::UnsupportedAlgorithm(
                CompressionAlgorithm::Brotli,
            ))
        }
    }

    fn decompress(
        &self,
        data: &[u8],
        params: &CompressionParams,
        expected_size: u64,
    ) -> Result<Vec<u8>, CompressionError> {
        self.validate_params(params)?;

        #[cfg(feature = "compression")]
        {
            let expected_size = usize::try_from(expected_size).map_err(|_| {
                CompressionError::DecompressionFailed(
                    "expected size does not fit usize".to_string(),
                )
            })?;
            let mut decoder = brotli::Decompressor::new(data, 4096);
            let mut decompressed = Vec::with_capacity(expected_size);
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;

            if decompressed.len() != expected_size {
                return Err(CompressionError::DecompressionFailed(
                    "size mismatch after decompression".to_string(),
                ));
            }

            Ok(decompressed)
        }

        #[cfg(not(feature = "compression"))]
        {
            let _ = data;
            let _ = expected_size;
            Err(CompressionError::UnsupportedAlgorithm(
                CompressionAlgorithm::Brotli,
            ))
        }
    }

    fn validate_params(&self, params: &CompressionParams) -> Result<(), CompressionError> {
        if !matches!(params.algorithm, CompressionAlgorithm::Brotli) {
            return Err(CompressionError::PolicyViolation(
                "Brotli adapter requires Brotli algorithm".to_string(),
            ));
        }

        if params.level > 11 {
            return Err(CompressionError::PolicyViolation(
                "Brotli level must be 0-11".to_string(),
            ));
        }

        if !Self::brotli_available() {
            return Err(CompressionError::UnsupportedAlgorithm(
                CompressionAlgorithm::Brotli,
            ));
        }

        Ok(())
    }
}

impl BrotliAdapter {
    fn brotli_available() -> bool {
        cfg!(feature = "compression")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_support() {
        assert!(AlgorithmRegistry::is_supported(CompressionAlgorithm::None));
        assert!(AlgorithmRegistry::is_supported(CompressionAlgorithm::Lz4));
        assert!(AlgorithmRegistry::is_supported(CompressionAlgorithm::Gzip));
        assert_eq!(
            AlgorithmRegistry::is_supported(CompressionAlgorithm::Brotli),
            cfg!(feature = "compression")
        );
    }

    #[test]
    fn test_performance_profiles() {
        let lz4_profile = AlgorithmRegistry::performance_profile(CompressionAlgorithm::Lz4);
        assert_eq!(lz4_profile.compression_speed, CompressionSpeed::VeryFast);
        assert_eq!(lz4_profile.cpu_usage, CpuUsage::Low);

        let gzip_profile = AlgorithmRegistry::performance_profile(CompressionAlgorithm::Gzip);
        assert_eq!(gzip_profile.compression_ratio, CompressionRatio::Medium);
    }

    #[test]
    fn test_lz4_adapter() {
        let adapter = Lz4Adapter;
        let params = AlgorithmRegistry::default_params(CompressionAlgorithm::Lz4);

        assert!(adapter.validate_params(&params).is_ok());

        let test_data = b"Hello, world! This is a test for LZ4 compression.";
        let compressed = adapter.compress(test_data, &params).unwrap();
        let decompressed = adapter
            .decompress(&compressed, &params, test_data.len() as u64)
            .unwrap();

        assert_eq!(decompressed, test_data);
    }

    #[test]
    fn test_gzip_adapter() {
        let adapter = GzipAdapter;
        let params = AlgorithmRegistry::default_params(CompressionAlgorithm::Gzip);

        assert!(adapter.validate_params(&params).is_ok());

        let test_data = b"Hello, world! This is a test for Gzip compression.";
        let compressed = adapter.compress(test_data, &params).unwrap();
        let decompressed = adapter
            .decompress(&compressed, &params, test_data.len() as u64)
            .unwrap();

        assert_eq!(decompressed, test_data);
    }

    #[test]
    #[cfg(feature = "compression")]
    fn test_brotli_adapter() {
        let adapter = BrotliAdapter;
        let params = AlgorithmRegistry::default_params(CompressionAlgorithm::Brotli);

        assert!(adapter.validate_params(&params).is_ok());

        let test_data =
            b"Hello, world! Brotli benefits from repeated repeated repeated transfer metadata.";
        let compressed = adapter.compress(test_data, &params).unwrap();
        let decompressed = adapter
            .decompress(&compressed, &params, test_data.len() as u64)
            .unwrap();

        assert_eq!(decompressed, test_data);
    }

    #[test]
    #[cfg(not(feature = "compression"))]
    fn test_brotli_adapter_reports_unsupported_without_feature() {
        let adapter = BrotliAdapter;
        let params = AlgorithmRegistry::default_params(CompressionAlgorithm::Brotli);

        assert!(matches!(
            adapter.validate_params(&params),
            Err(CompressionError::UnsupportedAlgorithm(
                CompressionAlgorithm::Brotli
            ))
        ));
    }
}
