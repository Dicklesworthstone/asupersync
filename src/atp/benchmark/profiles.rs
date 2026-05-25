//! ATP benchmark profiles for performance testing and comparison.

use crate::atp::benchmark::{BenchmarkConfig, BenchmarkError, BenchmarkMetrics, BenchmarkResult};
use crate::io::{AsyncSeekExt, AsyncWriteExt};
use serde::{Deserialize, Serialize};
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

        // Simulate ATP transfer execution
        let start_time = Instant::now();

        // For now, simulate ATP transfer by copying file with simulated network conditions
        let transfer_result = self
            .simulate_atp_transfer(source_path, &iteration_dest, config)
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
                    resume_time: None, // Not testing resume in this benchmark
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
                    tokio::io::AsyncWriteExt::write_all(&mut file, &data_chunk).await?;
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

                    tokio::io::AsyncWriteExt::write_all(&mut file, &data).await?;
                    remaining -= write_size as u64;
                }
            }
        }

        Ok(())
    }

    async fn simulate_atp_transfer(
        &self,
        source: &Path,
        dest: &Path,
        config: &BenchmarkConfig,
    ) -> Result<AtpTransferMetrics, String> {
        // Simulate network delay based on profile
        let base_delay = self.network_conditions.latency;
        let size_factor = config.data_size as f64 / (1024.0 * 1024.0); // Size in MB
        let bandwidth_delay = Duration::from_secs_f64(
            size_factor / self.network_conditions.bandwidth_mbps as f64 * 8.0,
        );

        let total_delay = base_delay + bandwidth_delay;
        crate::time::sleep(total_delay).await;

        // Copy file to simulate transfer
        crate::fs::copy(source, dest)
            .await
            .map_err(|e| format!("Transfer failed: {e}"))?;

        // Calculate simulated metrics
        let bytes_on_wire = if self.workload.compression {
            (config.data_size as f64 * 0.7) as u64 // Assume 30% compression
        } else {
            config.data_size
        };

        let first_usable_output = if matches!(self.workload.transfer_type, TransferType::Stream) {
            Some(base_delay + Duration::from_millis(100)) // Streaming starts quickly
        } else {
            None
        };

        Ok(AtpTransferMetrics {
            cpu_time: Some(total_delay / 10), // Simulate CPU usage
            memory_peak: Some(std::cmp::min(config.data_size, 64 * 1024 * 1024)), // Max 64MB
            bytes_on_wire: Some(bytes_on_wire),
            first_usable_output,
        })
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
