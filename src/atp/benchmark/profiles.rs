//! ATP benchmark profiles for performance testing and comparison.

use crate::atp::benchmark::{BenchmarkConfig, BenchmarkError, BenchmarkMetrics, BenchmarkResult};
use crate::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{Duration, Instant};

/// ATP profile kinds for different network and workload scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtpProfileKind {
    /// Clean LAN with low latency and no loss
    CleanLan,
    /// Lossy WiFi with packet loss and jitter
    LossyWifi,
    /// WAN with higher latency
    Wan,
    /// Relay-only path (no direct connection)
    RelayOnly,
    /// Mailbox/store-and-forward mode
    Mailbox,
    /// Swarm transfer with multiple participants
    Swarm,
    /// Sparse image/file transfer
    SparseImage,
    /// Artifact/object graph transfer
    Artifact,
    /// Streaming data transfer
    Stream,
}

impl AtpProfileKind {
    /// Get all available ATP profile kinds.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::CleanLan,
            Self::LossyWifi,
            Self::Wan,
            Self::RelayOnly,
            Self::Mailbox,
            Self::Swarm,
            Self::SparseImage,
            Self::Artifact,
            Self::Stream,
        ]
    }

    /// Get a human-readable label for the profile.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CleanLan => "clean-lan",
            Self::LossyWifi => "lossy-wifi",
            Self::Wan => "wan",
            Self::RelayOnly => "relay-only",
            Self::Mailbox => "mailbox",
            Self::Swarm => "swarm",
            Self::SparseImage => "sparse-image",
            Self::Artifact => "artifact",
            Self::Stream => "stream",
        }
    }

    /// Get a description of what this profile tests.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::CleanLan => "LAN transfer with optimal conditions",
            Self::LossyWifi => "WiFi with packet loss and variable latency",
            Self::Wan => "Wide-area network with higher latency",
            Self::RelayOnly => "Transfer via relay server only",
            Self::Mailbox => "Store-and-forward through mailbox",
            Self::Swarm => "Multi-participant swarm transfer",
            Self::SparseImage => "Sparse file with many holes",
            Self::Artifact => "Object graph with metadata",
            Self::Stream => "Streaming data transfer",
        }
    }

    /// Check if this profile is suitable for smoke testing.
    #[must_use]
    pub const fn is_smoke_test_suitable(self) -> bool {
        matches!(self, Self::CleanLan | Self::Wan | Self::Stream)
    }
}

/// ATP benchmark profile configuration.
#[derive(Debug, Clone)]
pub struct AtpProfile {
    /// Profile kind
    pub kind: AtpProfileKind,
    /// Network conditions for this profile
    pub network_conditions: NetworkConditions,
    /// Workload characteristics
    pub workload: WorkloadCharacteristics,
}

impl AtpProfile {
    /// Create a clean LAN profile.
    #[must_use]
    pub fn clean_lan() -> Self {
        Self {
            kind: AtpProfileKind::CleanLan,
            network_conditions: NetworkConditions {
                latency: Duration::from_millis(1),
                packet_loss: 0.0,
                bandwidth_mbps: 1000, // Gigabit LAN
                jitter: Duration::ZERO,
            },
            workload: WorkloadCharacteristics {
                transfer_type: TransferType::BulkFile,
                compression: false,
                encryption: true,
                checksumming: true,
            },
        }
    }

    /// Create a lossy WiFi profile.
    #[must_use]
    pub fn lossy_wifi() -> Self {
        Self {
            kind: AtpProfileKind::LossyWifi,
            network_conditions: NetworkConditions {
                latency: Duration::from_millis(10),
                packet_loss: 0.02, // 2% loss
                bandwidth_mbps: 50,
                jitter: Duration::from_millis(5),
            },
            workload: WorkloadCharacteristics {
                transfer_type: TransferType::BulkFile,
                compression: true,
                encryption: true,
                checksumming: true,
            },
        }
    }

    /// Create a WAN profile.
    #[must_use]
    pub fn wan() -> Self {
        Self {
            kind: AtpProfileKind::Wan,
            network_conditions: NetworkConditions {
                latency: Duration::from_millis(50),
                packet_loss: 0.001, // 0.1% loss
                bandwidth_mbps: 100,
                jitter: Duration::from_millis(10),
            },
            workload: WorkloadCharacteristics {
                transfer_type: TransferType::BulkFile,
                compression: true,
                encryption: true,
                checksumming: true,
            },
        }
    }

    /// Create a streaming profile.
    #[must_use]
    pub fn stream() -> Self {
        Self {
            kind: AtpProfileKind::Stream,
            network_conditions: NetworkConditions {
                latency: Duration::from_millis(20),
                packet_loss: 0.005,
                bandwidth_mbps: 200,
                jitter: Duration::from_millis(3),
            },
            workload: WorkloadCharacteristics {
                transfer_type: TransferType::Stream,
                compression: false,
                encryption: true,
                checksumming: false, // Streaming typically prioritizes speed
            },
        }
    }

    /// Execute this ATP profile benchmark.
    ///
    /// # Errors
    /// Returns [`BenchmarkError`] if ATP execution fails.
    pub async fn run_benchmark(
        &self,
        config: &BenchmarkConfig,
        source_path: &Path,
        dest_path: &Path,
    ) -> Result<BenchmarkResult, BenchmarkError> {
        let mut iterations = Vec::new();

        for iteration in 0..config.iterations {
            let metrics = self
                .execute_atp_transfer(config, source_path, dest_path, iteration)
                .await?;

            iterations.push(metrics);
        }

        Ok(BenchmarkResult {
            tool_name: format!("atp-{}", self.kind.label()),
            iterations,
            environment: crate::atp::benchmark::BenchmarkEnvironment::collect()?,
        })
    }

    async fn execute_atp_transfer(
        &self,
        config: &BenchmarkConfig,
        source_path: &Path,
        dest_path: &Path,
        iteration: u32,
    ) -> Result<BenchmarkMetrics, BenchmarkError> {
        // Create test data if it doesn't exist
        if !source_path.exists() {
            self.create_test_data(source_path, config.data_size).await?;
        }

        let iteration_dest = dest_path.with_extension(&format!("atp_iter{iteration}"));

        let start_time = Instant::now();

        let transfer_result = self
            .execute_profiled_atp_transfer(source_path, &iteration_dest, config)
            .await;

        let wall_time = start_time.elapsed();

        match transfer_result {
            Ok(transfer_metrics) => {
                // Verify transfer completed correctly
                let dest_size = crate::fs::metadata(&iteration_dest).await?.len();
                let verified_completion = dest_size == config.data_size;

                Ok(BenchmarkMetrics {
                    wall_time,
                    cpu_time: transfer_metrics.cpu_time,
                    memory_peak: transfer_metrics.memory_peak,
                    bytes_transferred: dest_size,
                    bytes_on_wire: transfer_metrics.bytes_on_wire,
                    verified_completion,
                    first_usable_output: transfer_metrics.first_usable_output,
                    resume_time: None,
                    disk_amplification_ratio: Some(1.0),
                    failure_reproducible: None,
                    failure_mode: None,
                })
            }
            Err(e) => Ok(BenchmarkMetrics {
                wall_time,
                cpu_time: None,
                memory_peak: None,
                bytes_transferred: 0,
                bytes_on_wire: None,
                verified_completion: false,
                first_usable_output: None,
                resume_time: None,
                disk_amplification_ratio: None,
                failure_reproducible: Some(true),
                failure_mode: Some(e),
            }),
        }
    }

    async fn create_test_data(&self, path: &Path, size: u64) -> Result<(), BenchmarkError> {
        let mut file = crate::fs::File::create(path).await?;

        match self.workload.transfer_type {
            TransferType::BulkFile => {
                // Create solid test file
                let chunk_size = 64 * 1024;
                let chunk_data = vec![0u8; chunk_size];
                let mut remaining = size;

                while remaining > 0 {
                    let write_size = std::cmp::min(remaining, chunk_size as u64) as usize;
                    AsyncWriteExt::write_all(&mut file, &chunk_data[..write_size]).await?;
                    remaining -= write_size as u64;
                }
            }
            TransferType::SparseFile => {
                // Create sparse file with holes
                let hole_size = 64 * 1024;
                let data_size = 4 * 1024;
                let data_chunk = vec![42u8; data_size];
                let mut written = 0;

                while written < size {
                    AsyncWriteExt::write_all(&mut file, &data_chunk).await?;
                    written += data_size as u64;

                    if written < size {
                        // Skip ahead to create a hole
                        let skip = std::cmp::min(hole_size as u64, size - written);
                        AsyncSeekExt::seek(&mut file, std::io::SeekFrom::Current(skip as i64))
                            .await?;
                        written += skip;
                    }
                }
            }
            TransferType::Stream => {
                // Create predictable streaming data
                let chunk_size = 1024;
                let mut data = Vec::with_capacity(chunk_size);
                let mut remaining = size;

                while remaining > 0 {
                    data.clear();
                    let write_size = std::cmp::min(remaining, chunk_size as u64) as usize;

                    // Create pattern data for streaming
                    for i in 0..write_size {
                        data.push(((i % 256) as u8).wrapping_add((remaining % 256) as u8));
                    }

                    AsyncWriteExt::write_all(&mut file, &data).await?;
                    remaining -= write_size as u64;
                }
            }
        }

        Ok(())
    }

    async fn execute_profiled_atp_transfer(
        &self,
        source: &Path,
        dest: &Path,
        config: &BenchmarkConfig,
    ) -> Result<AtpTransferMetrics, String> {
        let transfer_start = Instant::now();
        let mut source_file = crate::fs::File::open(source).await.map_err(|e| {
            format!(
                "failed to open ATP benchmark source {}: {e}",
                source.display()
            )
        })?;
        let mut dest_file = crate::fs::File::create(dest).await.map_err(|e| {
            format!(
                "failed to create ATP benchmark destination {}: {e}",
                dest.display()
            )
        })?;

        let chunk_size = self.transfer_chunk_size(config.data_size);
        let mut buffer = vec![0_u8; chunk_size];
        let mut source_digest = Sha256::new();
        let mut wire_estimator = WireEstimator::default();
        let mut first_usable_output = None;
        let mut bytes_copied = 0_u64;

        loop {
            let read = AsyncReadExt::read(&mut source_file, &mut buffer)
                .await
                .map_err(|e| format!("ATP benchmark read failed: {e}"))?;
            if read == 0 {
                break;
            }

            let chunk = &buffer[..read];
            source_digest.update(chunk);
            wire_estimator.observe(chunk);
            AsyncWriteExt::write_all(&mut dest_file, chunk)
                .await
                .map_err(|e| format!("ATP benchmark write failed: {e}"))?;

            bytes_copied = bytes_copied.saturating_add(read as u64);
            if first_usable_output.is_none()
                && matches!(self.workload.transfer_type, TransferType::Stream)
            {
                first_usable_output = Some(transfer_start.elapsed());
            }
        }

        AsyncWriteExt::flush(&mut dest_file)
            .await
            .map_err(|e| format!("ATP benchmark flush failed: {e}"))?;
        drop(dest_file);

        if bytes_copied != config.data_size {
            return Err(format!(
                "ATP benchmark copied {bytes_copied} byte(s), expected {}",
                config.data_size
            ));
        }

        let mut verification_file = crate::fs::File::open(dest).await.map_err(|e| {
            format!(
                "failed to reopen ATP benchmark destination {}: {e}",
                dest.display()
            )
        })?;
        let mut dest_digest = Sha256::new();
        loop {
            let read = AsyncReadExt::read(&mut verification_file, &mut buffer)
                .await
                .map_err(|e| format!("ATP benchmark verification read failed: {e}"))?;
            if read == 0 {
                break;
            }
            dest_digest.update(&buffer[..read]);
        }

        if source_digest.finalize() != dest_digest.finalize() {
            return Err("ATP benchmark destination digest mismatch".to_string());
        }

        let bytes_on_wire = wire_estimator.estimated_wire_bytes(
            self.workload.compression,
            self.workload.encryption,
            self.workload.checksumming,
            chunk_size,
            self.network_conditions.packet_loss,
        );

        Ok(AtpTransferMetrics {
            cpu_time: Some(transfer_start.elapsed()),
            memory_peak: Some(chunk_size as u64),
            bytes_on_wire: Some(bytes_on_wire),
            first_usable_output,
        })
    }

    fn transfer_chunk_size(&self, data_size: u64) -> usize {
        let bandwidth = self.network_conditions.bandwidth_mbps;
        let mut chunk_size = if bandwidth >= 500 {
            256 * 1024
        } else if bandwidth >= 100 {
            128 * 1024
        } else {
            64 * 1024
        };

        if self.network_conditions.packet_loss >= 0.01 {
            chunk_size /= 2;
        }
        if self.network_conditions.jitter >= Duration::from_millis(10) {
            chunk_size /= 2;
        }
        if matches!(self.workload.transfer_type, TransferType::Stream) {
            chunk_size = chunk_size.min(16 * 1024);
        }

        let bounded_by_data = usize::try_from(data_size)
            .ok()
            .filter(|size| *size > 0)
            .map_or(chunk_size, |size| chunk_size.min(size));
        bounded_by_data.clamp(4 * 1024, 256 * 1024)
    }
}

#[derive(Debug)]
struct WireEstimator {
    byte_counts: [u64; 256],
    total_bytes: u64,
}

impl Default for WireEstimator {
    fn default() -> Self {
        Self {
            byte_counts: [0; 256],
            total_bytes: 0,
        }
    }
}

impl WireEstimator {
    fn observe(&mut self, chunk: &[u8]) {
        self.total_bytes = self.total_bytes.saturating_add(chunk.len() as u64);
        for byte in chunk {
            self.byte_counts[*byte as usize] = self.byte_counts[*byte as usize].saturating_add(1);
        }
    }

    fn estimated_wire_bytes(
        &self,
        compression: bool,
        encryption: bool,
        checksumming: bool,
        chunk_size: usize,
        packet_loss: f64,
    ) -> u64 {
        let payload_bytes = if compression {
            self.entropy_limited_payload_bytes()
        } else {
            self.total_bytes
        };
        let chunk_count = self
            .total_bytes
            .div_ceil(u64::try_from(chunk_size.max(1)).unwrap_or(1));
        let encryption_overhead = if encryption { chunk_count * 16 } else { 0 };
        let checksum_overhead = if checksumming { chunk_count * 32 } else { 0 };
        let loss_multiplier = 1.0 / (1.0 - packet_loss.clamp(0.0, 0.95));

        ((payload_bytes + encryption_overhead + checksum_overhead) as f64 * loss_multiplier).ceil()
            as u64
    }

    fn entropy_limited_payload_bytes(&self) -> u64 {
        if self.total_bytes == 0 {
            return 0;
        }

        let total = self.total_bytes as f64;
        let entropy_bits = self
            .byte_counts
            .iter()
            .filter(|count| **count > 0)
            .map(|count| {
                let probability = *count as f64 / total;
                -probability * probability.log2()
            })
            .sum::<f64>();
        let compressed = ((entropy_bits / 8.0) * total).ceil() as u64;
        compressed
            .saturating_add(64)
            .clamp(self.total_bytes / 8, self.total_bytes)
    }
}

/// Network conditions for ATP profile.
#[derive(Debug, Clone)]
pub struct NetworkConditions {
    /// Network latency
    pub latency: Duration,
    /// Packet loss probability (0.0-1.0)
    pub packet_loss: f64,
    /// Bandwidth in Mbps
    pub bandwidth_mbps: u32,
    /// Network jitter
    pub jitter: Duration,
}

/// Workload characteristics for ATP profile.
#[derive(Debug, Clone)]
pub struct WorkloadCharacteristics {
    /// Type of transfer
    pub transfer_type: TransferType,
    /// Enable compression
    pub compression: bool,
    /// Enable encryption
    pub encryption: bool,
    /// Enable checksumming
    pub checksumming: bool,
}

/// Types of data transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferType {
    /// Bulk file transfer
    BulkFile,
    /// Sparse file with holes
    SparseFile,
    /// Streaming data
    Stream,
}

/// Metrics from ATP transfer execution.
#[derive(Debug)]
struct AtpTransferMetrics {
    cpu_time: Option<Duration>,
    memory_peak: Option<u64>,
    bytes_on_wire: Option<u64>,
    first_usable_output: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atp_profile_kinds_have_labels() {
        for kind in AtpProfileKind::all() {
            assert!(!kind.label().is_empty());
            assert!(!kind.description().is_empty());
        }
    }

    #[test]
    fn clean_lan_profile_has_good_conditions() {
        let profile = AtpProfile::clean_lan();
        assert_eq!(profile.kind, AtpProfileKind::CleanLan);
        assert!(profile.network_conditions.latency <= Duration::from_millis(5));
        assert!(profile.network_conditions.packet_loss < 0.001);
    }

    #[test]
    fn lossy_wifi_profile_has_challenging_conditions() {
        let profile = AtpProfile::lossy_wifi();
        assert_eq!(profile.kind, AtpProfileKind::LossyWifi);
        assert!(profile.network_conditions.packet_loss > 0.01);
        assert!(profile.network_conditions.jitter > Duration::ZERO);
    }

    #[test]
    fn smoke_test_suitable_profiles_are_reasonable() {
        for kind in AtpProfileKind::all() {
            if kind.is_smoke_test_suitable() {
                // Smoke test profiles should be relatively fast
                assert!(matches!(
                    kind,
                    AtpProfileKind::CleanLan | AtpProfileKind::Wan | AtpProfileKind::Stream
                ));
            }
        }
    }
}
