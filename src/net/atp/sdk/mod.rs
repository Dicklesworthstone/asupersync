//! ATP SDK - High-level APIs for object, tree, stream, and buffer movement.
//!
//! Provides the programmatic API that gives users the simple write(really_big_buffer)
//! experience without bypassing ATP correctness. SDK APIs are Cx-first and support
//! native Asupersync semantics.
//!
//! Key design principles:
//! - Public async/effectful APIs take &Cx first and preserve explicit capability boundaries
//! - APIs preserve Outcome or equivalent structured failure until a documented policy boundary
//! - SDK can run in-process without atpd and can also delegate to atpd with the same semantics
//! - Cancellation-correct with proper obligation tracking
//! - Deterministic replay and structured logging support

use crate::net::atp::protocol::PeerId;
use serde::{Deserialize, Serialize};

pub mod diagnostics;
pub mod object;
pub mod session;
pub mod stream;
pub mod transfer;

pub use diagnostics::*;
pub use object::*;
pub use session::*;
pub use stream::*;
pub use transfer::*;

/// High-level ATP SDK client for object graph transfers.
#[derive(Debug, Clone)]
pub struct AtpSdk {
    /// SDK execution mode.
    mode: SdkMode,
    /// Default session configuration.
    default_config: SessionConfig,
    /// Transfer policy defaults.
    transfer_policy: TransferPolicy,
}

/// SDK execution mode determines how transfers are executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdkMode {
    /// Run transfers in-process using native ATP implementation.
    InProcess,
    /// Delegate transfers to atpd daemon.
    DaemonDelegated {
        /// Daemon endpoint.
        daemon_endpoint: String,
        /// Authentication token for daemon.
        auth_token: Option<String>,
    },
}

/// Session configuration for ATP connections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Local peer identity.
    pub local_peer: PeerId,
    /// Session timeout in milliseconds.
    pub session_timeout_ms: u64,
    /// Enable compression during transfers.
    pub enable_compression: bool,
    /// Enable repair symbols for error correction.
    pub enable_repair: bool,
    /// Enable resume/checkpoint functionality.
    pub enable_resume: bool,
    /// Maximum concurrent transfers per session.
    pub max_concurrent_transfers: u32,
    /// Buffer size for streaming operations.
    pub stream_buffer_size: usize,
}

/// Transfer policy controls transfer behavior and limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferPolicy {
    /// Maximum transfer size in bytes.
    pub max_transfer_size_bytes: u64,
    /// Maximum chunk size in bytes.
    pub max_chunk_size_bytes: u32,
    /// Transfer timeout in milliseconds.
    pub transfer_timeout_ms: u64,
    /// Enable automatic retry on recoverable failures.
    pub enable_auto_retry: bool,
    /// Maximum retry attempts.
    pub max_retry_attempts: u32,
    /// Backoff strategy for retries.
    pub retry_backoff_ms: u64,
    /// Progress reporting interval in milliseconds.
    pub progress_report_interval_ms: u64,
}

/// Transfer handle for tracking and controlling ongoing transfers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransferId(pub String);

impl TransferId {
    /// Create a new transfer ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Generate a unique transfer ID.
    #[must_use]
    pub fn generate() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        Self(format!("atp_transfer_{:016x}", id))
    }

    /// Get the raw transfer ID string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TransferId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Transfer progress information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransferProgress {
    /// Transfer identifier.
    pub transfer_id: TransferId,
    /// Bytes transferred so far.
    pub bytes_transferred: u64,
    /// Total bytes to transfer.
    pub total_bytes: u64,
    /// Transfer speed in bytes per second.
    pub speed_bytes_per_sec: u64,
    /// Estimated time remaining in milliseconds.
    pub eta_ms: Option<u64>,
    /// Current transfer phase.
    pub phase: TransferPhase,
    /// Number of active paths.
    pub active_paths: u32,
    /// Repair symbols in use.
    pub repair_symbols_active: bool,
}

/// Phase of the transfer process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferPhase {
    /// Initializing transfer session.
    Initializing,
    /// Discovering paths to peer.
    PathDiscovery,
    /// Negotiating session parameters.
    SessionNegotiation,
    /// Transferring manifest metadata.
    ManifestTransfer,
    /// Transferring object data.
    DataTransfer,
    /// Verifying transferred data.
    Verification,
    /// Finalizing and cleanup.
    Finalization,
    /// Transfer completed successfully.
    Completed,
    /// Transfer failed.
    Failed,
    /// Transfer was cancelled.
    Cancelled,
}

impl TransferProgress {
    /// Calculate progress percentage (0.0 to 100.0).
    #[must_use]
    pub fn progress_percent(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        (self.bytes_transferred as f64 / self.total_bytes as f64) * 100.0
    }

    /// Check if transfer is complete.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(
            self.phase,
            TransferPhase::Completed | TransferPhase::Failed | TransferPhase::Cancelled
        )
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            local_peer: PeerId::from_label("default_local_peer"),
            session_timeout_ms: 30000,
            enable_compression: true,
            enable_repair: true,
            enable_resume: true,
            max_concurrent_transfers: 10,
            stream_buffer_size: 64 * 1024, // 64KB
        }
    }
}

impl Default for TransferPolicy {
    fn default() -> Self {
        Self {
            max_transfer_size_bytes: 10 * 1024 * 1024 * 1024, // 10GB
            max_chunk_size_bytes: 1024 * 1024,                // 1MB
            transfer_timeout_ms: 300000,                      // 5 minutes
            enable_auto_retry: true,
            max_retry_attempts: 3,
            retry_backoff_ms: 1000,
            progress_report_interval_ms: 1000,
        }
    }
}

impl AtpSdk {
    /// Create a new ATP SDK instance in in-process mode.
    #[must_use]
    pub fn new_in_process(config: SessionConfig) -> Self {
        Self {
            mode: SdkMode::InProcess,
            default_config: config,
            transfer_policy: TransferPolicy::default(),
        }
    }

    /// Create a new ATP SDK instance in daemon-delegated mode.
    #[must_use]
    pub fn new_daemon_delegated(
        config: SessionConfig,
        daemon_endpoint: String,
        auth_token: Option<String>,
    ) -> Self {
        Self {
            mode: SdkMode::DaemonDelegated {
                daemon_endpoint,
                auth_token,
            },
            default_config: config,
            transfer_policy: TransferPolicy::default(),
        }
    }

    /// Configure transfer policy for this SDK instance.
    #[must_use]
    pub fn with_transfer_policy(mut self, policy: TransferPolicy) -> Self {
        self.transfer_policy = policy;
        self
    }

    /// Get the current SDK mode.
    #[must_use]
    pub const fn mode(&self) -> &SdkMode {
        &self.mode
    }

    /// Get the default session configuration.
    #[must_use]
    pub const fn default_config(&self) -> &SessionConfig {
        &self.default_config
    }

    /// Get the transfer policy.
    #[must_use]
    pub const fn transfer_policy(&self) -> &TransferPolicy {
        &self.transfer_policy
    }
}
