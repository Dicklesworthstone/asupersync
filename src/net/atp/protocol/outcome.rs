//! ATP-specific Outcome taxonomy with error codes and idempotency keys.
//!
//! This module extends the base Outcome type with ATP-specific error classification,
//! stable error codes, and idempotency semantics for transfer operations.

use crate::types::cancel::CancelReason;
use crate::types::outcome::Outcome;
use serde::{Deserialize, Serialize};
use std::fmt;

// For IdempotencyKey generation - use a simple approach without external deps
mod rand_simple {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub fn random<T>() -> T
    where
        T: Default + From<f64>,
    {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let mut hasher = DefaultHasher::new();
        (counter, time).hash(&mut hasher);
        let hash = hasher.finish();

        // Convert to f64 in range [0.0, 1.0)
        let normalized = (hash as f64) / (u64::MAX as f64);
        T::from(normalized)
    }
}

/// ATP error taxonomy with stable codes for different failure domains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtpError {
    /// Transport layer failures (TCP, QUIC, UDP).
    Transport(TransportError),
    /// Protocol frame parsing and validation errors.
    Protocol(ProtocolError),
    /// Authentication and authorization failures.
    Auth(AuthError),
    /// Local disk and filesystem errors.
    Disk(DiskError),
    /// Manifest validation and structure errors.
    Manifest(ManifestError),
    /// RaptorQ repair and FEC errors.
    Repair(RepairError),
    /// Path discovery and routing errors.
    Path(PathError),
    /// Policy and capability violations.
    Policy(PolicyError),
    /// Relay service errors.
    Relay(RelayError),
    /// Mailbox storage errors.
    Mailbox(MailboxError),
    /// Daemon lifecycle and coordination errors.
    Daemon(DaemonError),
    /// Adapter integration errors (H3, WebTransport, MASQUE).
    Adapter(AdapterError),
    /// Platform and OS-specific errors.
    Platform(PlatformError),
}

impl AtpError {
    /// Get the stable error code for this error.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Transport(e) => e.code(),
            Self::Protocol(e) => e.code(),
            Self::Auth(e) => e.code(),
            Self::Disk(e) => e.code(),
            Self::Manifest(e) => e.code(),
            Self::Repair(e) => e.code(),
            Self::Path(e) => e.code(),
            Self::Policy(e) => e.code(),
            Self::Relay(e) => e.code(),
            Self::Mailbox(e) => e.code(),
            Self::Daemon(e) => e.code(),
            Self::Adapter(e) => e.code(),
            Self::Platform(e) => e.code(),
        }
    }

    /// Get the error domain for classification.
    #[must_use]
    pub const fn domain(&self) -> &'static str {
        match self {
            Self::Transport(_) => "transport",
            Self::Protocol(_) => "protocol",
            Self::Auth(_) => "auth",
            Self::Disk(_) => "disk",
            Self::Manifest(_) => "manifest",
            Self::Repair(_) => "repair",
            Self::Path(_) => "path",
            Self::Policy(_) => "policy",
            Self::Relay(_) => "relay",
            Self::Mailbox(_) => "mailbox",
            Self::Daemon(_) => "daemon",
            Self::Adapter(_) => "adapter",
            Self::Platform(_) => "platform",
        }
    }

    /// Whether this error is retryable with backoff.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Transport(e) => e.is_retryable(),
            Self::Protocol(e) => e.is_retryable(),
            Self::Auth(e) => e.is_retryable(),
            Self::Disk(e) => e.is_retryable(),
            Self::Manifest(e) => e.is_retryable(),
            Self::Repair(e) => e.is_retryable(),
            Self::Path(e) => e.is_retryable(),
            Self::Policy(e) => e.is_retryable(),
            Self::Relay(e) => e.is_retryable(),
            Self::Mailbox(e) => e.is_retryable(),
            Self::Daemon(e) => e.is_retryable(),
            Self::Adapter(e) => e.is_retryable(),
            Self::Platform(e) => e.is_retryable(),
        }
    }
}

impl fmt::Display for AtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::Protocol(e) => write!(f, "protocol: {e}"),
            Self::Auth(e) => write!(f, "auth: {e}"),
            Self::Disk(e) => write!(f, "disk: {e}"),
            Self::Manifest(e) => write!(f, "manifest: {e}"),
            Self::Repair(e) => write!(f, "repair: {e}"),
            Self::Path(e) => write!(f, "path: {e}"),
            Self::Policy(e) => write!(f, "policy: {e}"),
            Self::Relay(e) => write!(f, "relay: {e}"),
            Self::Mailbox(e) => write!(f, "mailbox: {e}"),
            Self::Daemon(e) => write!(f, "daemon: {e}"),
            Self::Adapter(e) => write!(f, "adapter: {e}"),
            Self::Platform(e) => write!(f, "platform: {e}"),
        }
    }
}

impl std::error::Error for AtpError {}

// Transport layer errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportError {
    ConnectionRefused,
    ConnectionReset,
    ConnectionTimeout,
    QuicHandshakeFailed,
    QuicStreamError,
    UdpSendError,
    TlsError,
    NetworkUnreachable,
}

impl TransportError {
    const fn code(&self) -> &'static str {
        match self {
            Self::ConnectionRefused => "transport_connection_refused",
            Self::ConnectionReset => "transport_connection_reset",
            Self::ConnectionTimeout => "transport_connection_timeout",
            Self::QuicHandshakeFailed => "transport_quic_handshake_failed",
            Self::QuicStreamError => "transport_quic_stream_error",
            Self::UdpSendError => "transport_udp_send_error",
            Self::TlsError => "transport_tls_error",
            Self::NetworkUnreachable => "transport_network_unreachable",
        }
    }

    const fn is_retryable(&self) -> bool {
        match self {
            Self::ConnectionRefused | Self::ConnectionTimeout | Self::NetworkUnreachable => true,
            Self::ConnectionReset | Self::QuicStreamError | Self::UdpSendError => true,
            Self::QuicHandshakeFailed | Self::TlsError => false,
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionRefused => write!(f, "connection refused"),
            Self::ConnectionReset => write!(f, "connection reset"),
            Self::ConnectionTimeout => write!(f, "connection timeout"),
            Self::QuicHandshakeFailed => write!(f, "QUIC handshake failed"),
            Self::QuicStreamError => write!(f, "QUIC stream error"),
            Self::UdpSendError => write!(f, "UDP send error"),
            Self::TlsError => write!(f, "TLS error"),
            Self::NetworkUnreachable => write!(f, "network unreachable"),
        }
    }
}

// Protocol layer errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolError {
    InvalidFrameType,
    MalformedFrame,
    ProtocolVersionMismatch,
    InvalidVarInt,
    UnexpectedFrame,
    FrameTooLarge,
    SessionStateMismatch,
}

impl ProtocolError {
    const fn code(&self) -> &'static str {
        match self {
            Self::InvalidFrameType => "protocol_invalid_frame_type",
            Self::MalformedFrame => "protocol_malformed_frame",
            Self::ProtocolVersionMismatch => "protocol_version_mismatch",
            Self::InvalidVarInt => "protocol_invalid_varint",
            Self::UnexpectedFrame => "protocol_unexpected_frame",
            Self::FrameTooLarge => "protocol_frame_too_large",
            Self::SessionStateMismatch => "protocol_session_state_mismatch",
        }
    }

    const fn is_retryable(&self) -> bool {
        match self {
            Self::InvalidFrameType | Self::MalformedFrame | Self::InvalidVarInt => false,
            Self::ProtocolVersionMismatch => false,
            Self::UnexpectedFrame => true, // May be transient race
            Self::FrameTooLarge => false,
            Self::SessionStateMismatch => true, // May recover with state sync
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFrameType => write!(f, "invalid frame type"),
            Self::MalformedFrame => write!(f, "malformed frame"),
            Self::ProtocolVersionMismatch => write!(f, "protocol version mismatch"),
            Self::InvalidVarInt => write!(f, "invalid varint encoding"),
            Self::UnexpectedFrame => write!(f, "unexpected frame in current state"),
            Self::FrameTooLarge => write!(f, "frame exceeds size limit"),
            Self::SessionStateMismatch => write!(f, "session state mismatch"),
        }
    }
}

// Authentication errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthError {
    InvalidSignature,
    GrantExpired,
    GrantRevoked,
    InsufficientCapabilities,
    PeerNotTrusted,
    ReplayedNonce,
    InvalidCertificate,
}

impl AuthError {
    const fn code(&self) -> &'static str {
        match self {
            Self::InvalidSignature => "auth_invalid_signature",
            Self::GrantExpired => "auth_grant_expired",
            Self::GrantRevoked => "auth_grant_revoked",
            Self::InsufficientCapabilities => "auth_insufficient_capabilities",
            Self::PeerNotTrusted => "auth_peer_not_trusted",
            Self::ReplayedNonce => "auth_replayed_nonce",
            Self::InvalidCertificate => "auth_invalid_certificate",
        }
    }

    const fn is_retryable(&self) -> bool {
        match self {
            Self::InvalidSignature | Self::ReplayedNonce | Self::InvalidCertificate => false,
            Self::GrantExpired => true, // May be refreshed
            Self::GrantRevoked | Self::InsufficientCapabilities | Self::PeerNotTrusted => false,
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::GrantExpired => write!(f, "capability grant expired"),
            Self::GrantRevoked => write!(f, "capability grant revoked"),
            Self::InsufficientCapabilities => write!(f, "insufficient capabilities"),
            Self::PeerNotTrusted => write!(f, "peer not trusted"),
            Self::ReplayedNonce => write!(f, "replayed nonce detected"),
            Self::InvalidCertificate => write!(f, "invalid certificate"),
        }
    }
}

// Disk and storage errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiskError {
    InsufficientSpace,
    PermissionDenied,
    FileNotFound,
    DirectoryNotFound,
    IoError,
    CorruptedData,
    QuotaExceeded,
}

impl DiskError {
    const fn code(&self) -> &'static str {
        match self {
            Self::InsufficientSpace => "disk_insufficient_space",
            Self::PermissionDenied => "disk_permission_denied",
            Self::FileNotFound => "disk_file_not_found",
            Self::DirectoryNotFound => "disk_directory_not_found",
            Self::IoError => "disk_io_error",
            Self::CorruptedData => "disk_corrupted_data",
            Self::QuotaExceeded => "disk_quota_exceeded",
        }
    }

    const fn is_retryable(&self) -> bool {
        match self {
            Self::InsufficientSpace | Self::QuotaExceeded => true, // Space may be freed
            Self::PermissionDenied => false,
            Self::FileNotFound | Self::DirectoryNotFound => false,
            Self::IoError => true, // May be transient
            Self::CorruptedData => false,
        }
    }
}

impl fmt::Display for DiskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientSpace => write!(f, "insufficient disk space"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::FileNotFound => write!(f, "file not found"),
            Self::DirectoryNotFound => write!(f, "directory not found"),
            Self::IoError => write!(f, "I/O error"),
            Self::CorruptedData => write!(f, "corrupted data detected"),
            Self::QuotaExceeded => write!(f, "disk quota exceeded"),
        }
    }
}

// Manifest errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestError {
    InvalidFormat,
    UnsupportedVersion,
    MissingRequiredField,
    HashMismatch,
    CircularReference,
    ObjectNotFound,
}

impl ManifestError {
    const fn code(&self) -> &'static str {
        match self {
            Self::InvalidFormat => "manifest_invalid_format",
            Self::UnsupportedVersion => "manifest_unsupported_version",
            Self::MissingRequiredField => "manifest_missing_required_field",
            Self::HashMismatch => "manifest_hash_mismatch",
            Self::CircularReference => "manifest_circular_reference",
            Self::ObjectNotFound => "manifest_object_not_found",
        }
    }

    const fn is_retryable(&self) -> bool {
        match self {
            Self::InvalidFormat | Self::UnsupportedVersion | Self::MissingRequiredField => false,
            Self::HashMismatch | Self::CircularReference => false,
            Self::ObjectNotFound => true, // Object may be retrieved
        }
    }
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "invalid manifest format"),
            Self::UnsupportedVersion => write!(f, "unsupported manifest version"),
            Self::MissingRequiredField => write!(f, "missing required manifest field"),
            Self::HashMismatch => write!(f, "manifest hash mismatch"),
            Self::CircularReference => write!(f, "circular reference in manifest"),
            Self::ObjectNotFound => write!(f, "object not found in manifest"),
        }
    }
}

// Repair errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepairError {
    InsufficientSymbols,
    DecodeFailure,
    InvalidSourceBlock,
    MissingRepairSymbol,
    CorruptedSymbol,
    UnsupportedCodec,
}

impl RepairError {
    const fn code(&self) -> &'static str {
        match self {
            Self::InsufficientSymbols => "repair_insufficient_symbols",
            Self::DecodeFailure => "repair_decode_failure",
            Self::InvalidSourceBlock => "repair_invalid_source_block",
            Self::MissingRepairSymbol => "repair_missing_repair_symbol",
            Self::CorruptedSymbol => "repair_corrupted_symbol",
            Self::UnsupportedCodec => "repair_unsupported_codec",
        }
    }

    const fn is_retryable(&self) -> bool {
        match self {
            Self::InsufficientSymbols => true, // More symbols may arrive
            Self::DecodeFailure => true,       // May be transient
            Self::InvalidSourceBlock => false,
            Self::MissingRepairSymbol => true, // Symbol may be retrieved
            Self::CorruptedSymbol => true,     // Symbol may be re-fetched
            Self::UnsupportedCodec => false,
        }
    }
}

impl fmt::Display for RepairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientSymbols => write!(f, "insufficient repair symbols"),
            Self::DecodeFailure => write!(f, "RaptorQ decode failure"),
            Self::InvalidSourceBlock => write!(f, "invalid source block"),
            Self::MissingRepairSymbol => write!(f, "missing repair symbol"),
            Self::CorruptedSymbol => write!(f, "corrupted repair symbol"),
            Self::UnsupportedCodec => write!(f, "unsupported repair codec"),
        }
    }
}

// Path errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathError {
    NoAvailablePaths,
    PathValidationFailed,
    NatTraversalFailed,
    RelayUnavailable,
    StunTimeout,
    PathRaceTimeout,
}

impl PathError {
    const fn code(&self) -> &'static str {
        match self {
            Self::NoAvailablePaths => "path_no_available_paths",
            Self::PathValidationFailed => "path_validation_failed",
            Self::NatTraversalFailed => "path_nat_traversal_failed",
            Self::RelayUnavailable => "path_relay_unavailable",
            Self::StunTimeout => "path_stun_timeout",
            Self::PathRaceTimeout => "path_race_timeout",
        }
    }

    const fn is_retryable(&self) -> bool {
        match self {
            Self::NoAvailablePaths => true, // Paths may become available
            Self::PathValidationFailed => true,
            Self::NatTraversalFailed => true,
            Self::RelayUnavailable => true, // Relay may come online
            Self::StunTimeout => true,
            Self::PathRaceTimeout => true,
        }
    }
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAvailablePaths => write!(f, "no available paths"),
            Self::PathValidationFailed => write!(f, "path validation failed"),
            Self::NatTraversalFailed => write!(f, "NAT traversal failed"),
            Self::RelayUnavailable => write!(f, "relay unavailable"),
            Self::StunTimeout => write!(f, "STUN timeout"),
            Self::PathRaceTimeout => write!(f, "path race timeout"),
        }
    }
}

// Policy errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyError {
    CapabilityDenied,
    ResourceQuotaExceeded,
    TransferSizeExceeded,
    RateLimitExceeded,
    RegionRestriction,
    FeatureDisabled,
}

impl PolicyError {
    const fn code(&self) -> &'static str {
        match self {
            Self::CapabilityDenied => "policy_capability_denied",
            Self::ResourceQuotaExceeded => "policy_resource_quota_exceeded",
            Self::TransferSizeExceeded => "policy_transfer_size_exceeded",
            Self::RateLimitExceeded => "policy_rate_limit_exceeded",
            Self::RegionRestriction => "policy_region_restriction",
            Self::FeatureDisabled => "policy_feature_disabled",
        }
    }

    const fn is_retryable(&self) -> bool {
        match self {
            Self::CapabilityDenied => false,
            Self::ResourceQuotaExceeded => true, // Quota may reset
            Self::TransferSizeExceeded => false,
            Self::RateLimitExceeded => true, // Rate limit may reset
            Self::RegionRestriction => false,
            Self::FeatureDisabled => false,
        }
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityDenied => write!(f, "capability denied"),
            Self::ResourceQuotaExceeded => write!(f, "resource quota exceeded"),
            Self::TransferSizeExceeded => write!(f, "transfer size exceeded"),
            Self::RateLimitExceeded => write!(f, "rate limit exceeded"),
            Self::RegionRestriction => write!(f, "region restriction"),
            Self::FeatureDisabled => write!(f, "feature disabled"),
        }
    }
}

// Relay errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayError {
    RelayOffline,
    RelayOverloaded,
    InvalidRelayCredentials,
    RelayTimeout,
    RelayProtocolMismatch,
}

impl RelayError {
    const fn code(&self) -> &'static str {
        match self {
            Self::RelayOffline => "relay_offline",
            Self::RelayOverloaded => "relay_overloaded",
            Self::InvalidRelayCredentials => "relay_invalid_credentials",
            Self::RelayTimeout => "relay_timeout",
            Self::RelayProtocolMismatch => "relay_protocol_mismatch",
        }
    }

    const fn is_retryable(&self) -> bool {
        match self {
            Self::RelayOffline => true, // Relay may come online
            Self::RelayOverloaded => true,
            Self::InvalidRelayCredentials => false,
            Self::RelayTimeout => true,
            Self::RelayProtocolMismatch => false,
        }
    }
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelayOffline => write!(f, "relay offline"),
            Self::RelayOverloaded => write!(f, "relay overloaded"),
            Self::InvalidRelayCredentials => write!(f, "invalid relay credentials"),
            Self::RelayTimeout => write!(f, "relay timeout"),
            Self::RelayProtocolMismatch => write!(f, "relay protocol mismatch"),
        }
    }
}

// Mailbox errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MailboxError {
    MailboxFull,
    MessageTooLarge,
    MailboxUnavailable,
    InvalidMailboxCredentials,
    MessageExpired,
}

impl MailboxError {
    const fn code(&self) -> &'static str {
        match self {
            Self::MailboxFull => "mailbox_full",
            Self::MessageTooLarge => "mailbox_message_too_large",
            Self::MailboxUnavailable => "mailbox_unavailable",
            Self::InvalidMailboxCredentials => "mailbox_invalid_credentials",
            Self::MessageExpired => "mailbox_message_expired",
        }
    }

    const fn is_retryable(&self) -> bool {
        match self {
            Self::MailboxFull => true, // Space may be freed
            Self::MessageTooLarge => false,
            Self::MailboxUnavailable => true,
            Self::InvalidMailboxCredentials => false,
            Self::MessageExpired => false,
        }
    }
}

impl fmt::Display for MailboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MailboxFull => write!(f, "mailbox full"),
            Self::MessageTooLarge => write!(f, "message too large for mailbox"),
            Self::MailboxUnavailable => write!(f, "mailbox unavailable"),
            Self::InvalidMailboxCredentials => write!(f, "invalid mailbox credentials"),
            Self::MessageExpired => write!(f, "message expired in mailbox"),
        }
    }
}

// Daemon errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaemonError {
    DaemonOffline,
    DaemonRestarting,
    ConfigurationError,
    ServiceUnavailable,
    InternalError,
}

impl DaemonError {
    const fn code(&self) -> &'static str {
        match self {
            Self::DaemonOffline => "daemon_offline",
            Self::DaemonRestarting => "daemon_restarting",
            Self::ConfigurationError => "daemon_configuration_error",
            Self::ServiceUnavailable => "daemon_service_unavailable",
            Self::InternalError => "daemon_internal_error",
        }
    }

    const fn is_retryable(&self) -> bool {
        match self {
            Self::DaemonOffline => true, // May come online
            Self::DaemonRestarting => true,
            Self::ConfigurationError => false,
            Self::ServiceUnavailable => true,
            Self::InternalError => true, // May be transient
        }
    }
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DaemonOffline => write!(f, "daemon offline"),
            Self::DaemonRestarting => write!(f, "daemon restarting"),
            Self::ConfigurationError => write!(f, "daemon configuration error"),
            Self::ServiceUnavailable => write!(f, "daemon service unavailable"),
            Self::InternalError => write!(f, "daemon internal error"),
        }
    }
}

// Adapter errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterError {
    UnsupportedProtocol,
    AdapterOffline,
    ProtocolMismatch,
    AdapterOverloaded,
    InvalidAdapterConfig,
}

impl AdapterError {
    const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedProtocol => "adapter_unsupported_protocol",
            Self::AdapterOffline => "adapter_offline",
            Self::ProtocolMismatch => "adapter_protocol_mismatch",
            Self::AdapterOverloaded => "adapter_overloaded",
            Self::InvalidAdapterConfig => "adapter_invalid_config",
        }
    }

    const fn is_retryable(&self) -> bool {
        match self {
            Self::UnsupportedProtocol => false,
            Self::AdapterOffline => true, // May come online
            Self::ProtocolMismatch => false,
            Self::AdapterOverloaded => true,
            Self::InvalidAdapterConfig => false,
        }
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProtocol => write!(f, "unsupported protocol"),
            Self::AdapterOffline => write!(f, "adapter offline"),
            Self::ProtocolMismatch => write!(f, "adapter protocol mismatch"),
            Self::AdapterOverloaded => write!(f, "adapter overloaded"),
            Self::InvalidAdapterConfig => write!(f, "invalid adapter configuration"),
        }
    }
}

// Platform errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlatformError {
    OutOfMemory,
    ProcessLimitExceeded,
    SystemShutdown,
    ResourceTemporarilyUnavailable,
    OperatingSystemError,
}

impl PlatformError {
    const fn code(&self) -> &'static str {
        match self {
            Self::OutOfMemory => "platform_out_of_memory",
            Self::ProcessLimitExceeded => "platform_process_limit_exceeded",
            Self::SystemShutdown => "platform_system_shutdown",
            Self::ResourceTemporarilyUnavailable => "platform_resource_temporarily_unavailable",
            Self::OperatingSystemError => "platform_operating_system_error",
        }
    }

    const fn is_retryable(&self) -> bool {
        match self {
            Self::OutOfMemory => true, // Memory may be freed
            Self::ProcessLimitExceeded => true,
            Self::SystemShutdown => false,
            Self::ResourceTemporarilyUnavailable => true,
            Self::OperatingSystemError => true, // May be transient
        }
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::ProcessLimitExceeded => write!(f, "process limit exceeded"),
            Self::SystemShutdown => write!(f, "system shutdown"),
            Self::ResourceTemporarilyUnavailable => write!(f, "resource temporarily unavailable"),
            Self::OperatingSystemError => write!(f, "operating system error"),
        }
    }
}

/// Cancellation reasons specific to ATP operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtpCancelReason {
    /// User explicitly cancelled the transfer.
    UserCancel(String),
    /// Operation timed out.
    Timeout,
    /// System shutdown initiated.
    Shutdown,
    /// Fail-fast due to early error detection.
    FailFast(String),
    /// Parent operation was cancelled.
    ParentCancel,
    /// Lost the path race to a better path.
    PathRaceLost,
    /// Repair decoding was abandoned.
    RepairDecodeAbandoned,
    /// Daemon restart interrupted the operation.
    DaemonRestart,
    /// Resource budget exhausted.
    ResourceBudgetExhausted(String),
}

impl AtpCancelReason {
    /// Get the stable reason code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UserCancel(_) => "cancel_user",
            Self::Timeout => "cancel_timeout",
            Self::Shutdown => "cancel_shutdown",
            Self::FailFast(_) => "cancel_fail_fast",
            Self::ParentCancel => "cancel_parent",
            Self::PathRaceLost => "cancel_path_race_lost",
            Self::RepairDecodeAbandoned => "cancel_repair_decode_abandoned",
            Self::DaemonRestart => "cancel_daemon_restart",
            Self::ResourceBudgetExhausted(_) => "cancel_resource_budget_exhausted",
        }
    }

    /// Get the severity for ordering cancellation reasons.
    #[must_use]
    pub const fn severity(&self) -> u8 {
        match self {
            Self::UserCancel(_) => 1,
            Self::Timeout => 2,
            Self::FailFast(_) => 3,
            Self::ParentCancel => 4,
            Self::PathRaceLost => 5,
            Self::RepairDecodeAbandoned => 6,
            Self::ResourceBudgetExhausted(_) => 7,
            Self::DaemonRestart => 8,
            Self::Shutdown => 9, // Highest severity
        }
    }

    /// Convert to base CancelReason.
    #[must_use]
    pub fn to_base_reason(&self) -> CancelReason {
        match self {
            Self::UserCancel(_) => CancelReason::user("user cancel"),
            Self::Timeout => CancelReason::timeout(),
            Self::Shutdown => CancelReason::shutdown(),
            Self::FailFast(_) => CancelReason::fail_fast().with_message("fail-fast"),
            Self::ParentCancel => CancelReason::linked_exit(),
            Self::PathRaceLost => CancelReason::user("path race lost"),
            Self::RepairDecodeAbandoned => CancelReason::user("repair decode abandoned"),
            Self::DaemonRestart => CancelReason::user("daemon restart"),
            Self::ResourceBudgetExhausted(_) => {
                CancelReason::timeout().with_message("resource budget exhausted")
            }
        }
    }
}

impl fmt::Display for AtpCancelReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserCancel(msg) => write!(f, "user cancel: {msg}"),
            Self::Timeout => write!(f, "timeout"),
            Self::Shutdown => write!(f, "shutdown"),
            Self::FailFast(msg) => write!(f, "fail-fast: {msg}"),
            Self::ParentCancel => write!(f, "parent cancelled"),
            Self::PathRaceLost => write!(f, "path race lost"),
            Self::RepairDecodeAbandoned => write!(f, "repair decode abandoned"),
            Self::DaemonRestart => write!(f, "daemon restart"),
            Self::ResourceBudgetExhausted(msg) => write!(f, "resource budget exhausted: {msg}"),
        }
    }
}

/// ATP-specific Outcome type with rich error taxonomy.
pub type AtpOutcome<T> = Outcome<T, AtpError>;

/// Convenience constructors for ATP outcomes.
impl<T> AtpOutcome<T> {
    /// Create a transport error outcome.
    #[must_use]
    pub fn transport_error(error: TransportError) -> Self {
        Outcome::err(AtpError::Transport(error))
    }

    /// Create a protocol error outcome.
    #[must_use]
    pub fn protocol_error(error: ProtocolError) -> Self {
        Outcome::err(AtpError::Protocol(error))
    }

    /// Create an auth error outcome.
    #[must_use]
    pub fn auth_error(error: AuthError) -> Self {
        Outcome::err(AtpError::Auth(error))
    }

    /// Create a disk error outcome.
    #[must_use]
    pub fn disk_error(error: DiskError) -> Self {
        Outcome::err(AtpError::Disk(error))
    }

    /// Create an ATP cancellation outcome.
    #[must_use]
    pub fn atp_cancelled(reason: AtpCancelReason) -> Self {
        Outcome::cancelled(reason.to_base_reason())
    }
}

// Idempotency key system for ATP operations
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Idempotency key for ensuring safe retries and duplicate detection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Create a new idempotency key from a string.
    #[must_use]
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// Generate an idempotency key from hashable input.
    #[must_use]
    pub fn generate<T: Hash>(input: T) -> Self {
        let mut hasher = DefaultHasher::new();
        input.hash(&mut hasher);
        Self(format!("atp_{:016x}", hasher.finish()))
    }

    /// Get the raw key value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Create an idempotency key for an offer operation.
    #[must_use]
    pub fn offer(manifest_hash: &[u8], peer_id: &str, timestamp_nanos: u64) -> Self {
        Self::generate(("offer", manifest_hash, peer_id, timestamp_nanos))
    }

    /// Create an idempotency key for an accept operation.
    #[must_use]
    pub fn accept(offer_key: &IdempotencyKey, peer_id: &str, timestamp_nanos: u64) -> Self {
        Self::generate(("accept", offer_key.as_str(), peer_id, timestamp_nanos))
    }

    /// Create an idempotency key for a chunk transfer operation.
    #[must_use]
    pub fn chunk(transfer_id: &str, chunk_index: u32, attempt: u32) -> Self {
        Self::generate(("chunk", transfer_id, chunk_index, attempt))
    }

    /// Create an idempotency key for a repair group operation.
    #[must_use]
    pub fn repair_group(source_block_id: &str, repair_generation: u32, peer_id: &str) -> Self {
        Self::generate(("repair_group", source_block_id, repair_generation, peer_id))
    }

    /// Create an idempotency key for a commit operation.
    #[must_use]
    pub fn commit(transfer_id: &str, final_hash: &[u8], timestamp_nanos: u64) -> Self {
        Self::generate(("commit", transfer_id, final_hash, timestamp_nanos))
    }

    /// Create an idempotency key for a mailbox store operation.
    #[must_use]
    pub fn mailbox_store(mailbox_id: &str, message_hash: &[u8], sequence: u64) -> Self {
        Self::generate(("mailbox_store", mailbox_id, message_hash, sequence))
    }

    /// Create an idempotency key for a capability grant operation.
    #[must_use]
    pub fn grant(issuer_id: &str, subject_id: &str, capability_hash: &[u8], expiry: u64) -> Self {
        Self::generate(("grant", issuer_id, subject_id, capability_hash, expiry))
    }

    /// Create an idempotency key for a relay reservation operation.
    #[must_use]
    pub fn relay_reservation(
        relay_id: &str,
        client_id: &str,
        bandwidth: u64,
        duration: u64,
    ) -> Self {
        Self::generate((
            "relay_reservation",
            relay_id,
            client_id,
            bandwidth,
            duration,
        ))
    }

    /// Create an idempotency key for a resume journal entry.
    #[must_use]
    pub fn resume_journal(transfer_id: &str, checkpoint_hash: &[u8], sequence: u64) -> Self {
        Self::generate(("resume_journal", transfer_id, checkpoint_hash, sequence))
    }

    /// Create an idempotency key for a final proof operation.
    #[must_use]
    pub fn final_proof(transfer_id: &str, proof_hash: &[u8], verifier_id: &str) -> Self {
        Self::generate(("final_proof", transfer_id, proof_hash, verifier_id))
    }
}

impl fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for IdempotencyKey {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for IdempotencyKey {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

/// Transfer transcript for audit and replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferTranscript {
    /// Transfer identifier.
    pub transfer_id: String,
    /// Idempotency key for the transfer.
    pub idempotency_key: IdempotencyKey,
    /// Manifest hash being transferred.
    pub manifest_hash: Vec<u8>,
    /// Peer involved in the transfer.
    pub peer_id: String,
    /// Transfer start timestamp (nanoseconds since Unix epoch).
    pub start_time_nanos: u64,
    /// Transfer completion timestamp (nanoseconds since Unix epoch).
    pub end_time_nanos: Option<u64>,
    /// Outcome classification.
    pub outcome_class: OutcomeClass,
    /// Retry attempt number (0 for initial attempt).
    pub retry_attempt: u32,
    /// Cancellation source if applicable.
    pub cancellation_source: Option<AtpCancelReason>,
    /// User-facing message identifier for UI correlation.
    pub user_message_id: Option<String>,
    /// Replay pointer for deterministic replay.
    pub replay_pointer: Option<String>,
    /// Transfer size in bytes.
    pub transfer_size_bytes: u64,
    /// Chunks successfully transferred.
    pub chunks_completed: u32,
    /// Total chunks in transfer.
    pub total_chunks: u32,
    /// Repair groups used.
    pub repair_groups_used: u32,
    /// Paths attempted during transfer.
    pub paths_attempted: Vec<String>,
    /// Final error code if transfer failed.
    pub error_code: Option<String>,
}

impl TransferTranscript {
    /// Create a new transfer transcript.
    #[must_use]
    pub fn new(
        transfer_id: String,
        idempotency_key: IdempotencyKey,
        manifest_hash: Vec<u8>,
        peer_id: String,
        start_time_nanos: u64,
        transfer_size_bytes: u64,
        total_chunks: u32,
    ) -> Self {
        Self {
            transfer_id,
            idempotency_key,
            manifest_hash,
            peer_id,
            start_time_nanos,
            end_time_nanos: None,
            outcome_class: OutcomeClass::Pending,
            retry_attempt: 0,
            cancellation_source: None,
            user_message_id: None,
            replay_pointer: None,
            transfer_size_bytes,
            chunks_completed: 0,
            total_chunks,
            repair_groups_used: 0,
            paths_attempted: Vec::new(),
            error_code: None,
        }
    }

    /// Mark the transfer as completed with the given outcome.
    pub fn complete(&mut self, outcome: &AtpOutcome<()>, end_time_nanos: u64) {
        self.end_time_nanos = Some(end_time_nanos);
        self.outcome_class = OutcomeClass::from_outcome(outcome);

        if let Outcome::Err(error) = outcome {
            self.error_code = Some(error.code().to_string());
        }

        if let Outcome::Cancelled(reason) = outcome {
            // Try to extract ATP-specific cancel reason
            if let Some(message) = reason.message() {
                if let Some(atp_reason) = Self::parse_atp_cancel_reason(message) {
                    self.cancellation_source = Some(atp_reason);
                }
            }
        }
    }

    /// Add a path attempt to the transcript.
    pub fn add_path_attempt(&mut self, path: String) {
        self.paths_attempted.push(path);
    }

    /// Update chunk progress.
    pub fn update_chunks_completed(&mut self, completed: u32) {
        self.chunks_completed = completed;
    }

    /// Increment repair groups used.
    pub fn increment_repair_groups(&mut self) {
        self.repair_groups_used += 1;
    }

    /// Set the retry attempt number.
    pub fn set_retry_attempt(&mut self, attempt: u32) {
        self.retry_attempt = attempt;
    }

    /// Set user-facing message ID.
    pub fn set_user_message_id(&mut self, message_id: String) {
        self.user_message_id = Some(message_id);
    }

    /// Set replay pointer for deterministic replay.
    pub fn set_replay_pointer(&mut self, pointer: String) {
        self.replay_pointer = Some(pointer);
    }

    /// Get progress percentage (0-100).
    #[must_use]
    pub fn progress_percent(&self) -> f64 {
        if self.total_chunks == 0 {
            return 0.0;
        }
        (f64::from(self.chunks_completed) / f64::from(self.total_chunks)) * 100.0
    }

    /// Get transfer duration in nanoseconds.
    #[must_use]
    pub fn duration_nanos(&self) -> Option<u64> {
        self.end_time_nanos
            .map(|end| end.saturating_sub(self.start_time_nanos))
    }

    /// Check if transfer is complete.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(
            self.outcome_class,
            OutcomeClass::Success | OutcomeClass::Error | OutcomeClass::Cancelled
        )
    }

    // Helper to parse ATP cancel reasons from message strings
    fn parse_atp_cancel_reason(message: &str) -> Option<AtpCancelReason> {
        if message.contains("timeout") {
            Some(AtpCancelReason::Timeout)
        } else if message.contains("shutdown") {
            Some(AtpCancelReason::Shutdown)
        } else if message.contains("user") {
            Some(AtpCancelReason::UserCancel(message.to_string()))
        } else if message.contains("path race") {
            Some(AtpCancelReason::PathRaceLost)
        } else if message.contains("repair decode") {
            Some(AtpCancelReason::RepairDecodeAbandoned)
        } else if message.contains("daemon restart") {
            Some(AtpCancelReason::DaemonRestart)
        } else if message.contains("fail-fast") {
            Some(AtpCancelReason::FailFast(message.to_string()))
        } else if message.contains("parent") {
            Some(AtpCancelReason::ParentCancel)
        } else if message.contains("resource budget") {
            Some(AtpCancelReason::ResourceBudgetExhausted(
                message.to_string(),
            ))
        } else {
            None
        }
    }
}

/// Classification of outcomes for analysis and retry logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutcomeClass {
    /// Operation is still in progress.
    Pending,
    /// Operation completed successfully.
    Success,
    /// Operation failed with an error.
    Error,
    /// Operation was cancelled.
    Cancelled,
    /// Operation panicked.
    Panicked,
}

impl OutcomeClass {
    /// Extract outcome class from an ATP outcome.
    #[must_use]
    pub fn from_outcome<T>(outcome: &AtpOutcome<T>) -> Self {
        match outcome {
            Outcome::Ok(_) => Self::Success,
            Outcome::Err(_) => Self::Error,
            Outcome::Cancelled(_) => Self::Cancelled,
            Outcome::Panicked(_) => Self::Panicked,
        }
    }

    /// Check if the outcome indicates a retryable state.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Error | Self::Cancelled)
    }

    /// Get the severity for outcome ordering.
    #[must_use]
    pub const fn severity(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Pending => 1,
            Self::Cancelled => 2,
            Self::Error => 3,
            Self::Panicked => 4, // Highest severity
        }
    }
}

impl fmt::Display for OutcomeClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Success => write!(f, "success"),
            Self::Error => write!(f, "error"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::Panicked => write!(f, "panicked"),
        }
    }
}

/// Retry semantics and bounds for ATP operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts.
    pub max_attempts: u32,
    /// Base delay between retries in milliseconds.
    pub base_delay_ms: u64,
    /// Maximum delay between retries in milliseconds.
    pub max_delay_ms: u64,
    /// Backoff multiplier for exponential backoff.
    pub backoff_multiplier: f64,
    /// Jitter percentage (0-100) to avoid thundering herd.
    pub jitter_percent: u8,
    /// Whether to retry on cancelled operations.
    pub retry_on_cancel: bool,
    /// Operation-specific retry conditions.
    pub retry_conditions: Vec<RetryCondition>,
}

impl RetryPolicy {
    /// Default retry policy for transfer operations.
    #[must_use]
    pub fn default_transfer() -> Self {
        Self {
            max_attempts: 3,
            base_delay_ms: 1000,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
            jitter_percent: 10,
            retry_on_cancel: false,
            retry_conditions: vec![
                RetryCondition::ErrorClass(vec!["transport".to_string(), "path".to_string()]),
                RetryCondition::ErrorCode(vec!["repair_insufficient_symbols".to_string()]),
            ],
        }
    }

    /// Aggressive retry policy for high-value transfers.
    #[must_use]
    pub fn aggressive() -> Self {
        Self {
            max_attempts: 7,
            base_delay_ms: 500,
            max_delay_ms: 60000,
            backoff_multiplier: 1.5,
            jitter_percent: 20,
            retry_on_cancel: true,
            retry_conditions: vec![
                RetryCondition::ErrorClass(vec![
                    "transport".to_string(),
                    "path".to_string(),
                    "repair".to_string(),
                ]),
                RetryCondition::AlwaysRetry,
            ],
        }
    }

    /// Conservative retry policy for low-priority operations.
    #[must_use]
    pub fn conservative() -> Self {
        Self {
            max_attempts: 2,
            base_delay_ms: 2000,
            max_delay_ms: 10000,
            backoff_multiplier: 3.0,
            jitter_percent: 5,
            retry_on_cancel: false,
            retry_conditions: vec![RetryCondition::ErrorClass(vec!["transport".to_string()])],
        }
    }

    /// Check if an outcome should be retried based on this policy.
    #[must_use]
    pub fn should_retry<T>(&self, outcome: &AtpOutcome<T>, attempt: u32) -> bool {
        if attempt >= self.max_attempts {
            return false;
        }

        match outcome {
            Outcome::Ok(_) => false,
            Outcome::Panicked(_) => false,
            Outcome::Cancelled(_) => self.retry_on_cancel,
            Outcome::Err(error) => {
                if !error.is_retryable() {
                    return false;
                }

                self.retry_conditions
                    .iter()
                    .any(|condition| condition.matches(error))
            }
        }
    }

    /// Calculate the delay for the next retry attempt.
    #[must_use]
    pub fn delay_for_attempt(&self, attempt: u32) -> u64 {
        let base_delay = self.base_delay_ms as f64;
        let multiplier = self
            .backoff_multiplier
            .powi(attempt.saturating_sub(1).cast_signed());
        let delay = base_delay * multiplier;
        let delay = delay.min(self.max_delay_ms as f64) as u64;

        // Apply jitter
        if self.jitter_percent > 0 {
            let jitter = delay as f64 * f64::from(self.jitter_percent) / 100.0;
            let jitter_amount = (jitter * (rand_simple::random::<f64>() * 2.0 - 1.0)) as i64;
            delay.saturating_add_signed(jitter_amount)
        } else {
            delay
        }
    }
}

/// Conditions under which an operation should be retried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetryCondition {
    /// Retry on specific error codes.
    ErrorCode(Vec<String>),
    /// Retry on specific error classes (domains).
    ErrorClass(Vec<String>),
    /// Retry on errors marked as retryable.
    RetryableErrors,
    /// Always retry (use with caution).
    AlwaysRetry,
    /// Never retry.
    NeverRetry,
}

impl RetryCondition {
    /// Check if this condition matches the given error.
    #[must_use]
    pub fn matches(&self, error: &AtpError) -> bool {
        match self {
            Self::ErrorCode(codes) => codes.contains(&error.code().to_string()),
            Self::ErrorClass(classes) => classes.contains(&error.domain().to_string()),
            Self::RetryableErrors => error.is_retryable(),
            Self::AlwaysRetry => true,
            Self::NeverRetry => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(
            TransportError::ConnectionTimeout.code(),
            "transport_connection_timeout"
        );
        assert_eq!(AuthError::GrantExpired.code(), "auth_grant_expired");
        assert_eq!(
            RepairError::InsufficientSymbols.code(),
            "repair_insufficient_symbols"
        );
    }

    #[test]
    fn retryable_classification() {
        assert!(TransportError::ConnectionTimeout.is_retryable());
        assert!(!AuthError::InvalidSignature.is_retryable());
        assert!(RepairError::MissingRepairSymbol.is_retryable());
        assert!(!ManifestError::InvalidFormat.is_retryable());
    }

    #[test]
    fn cancel_reason_severity_ordering() {
        let user = AtpCancelReason::UserCancel("test".to_string());
        let shutdown = AtpCancelReason::Shutdown;
        let timeout = AtpCancelReason::Timeout;

        assert!(user.severity() < timeout.severity());
        assert!(timeout.severity() < shutdown.severity());
    }

    #[test]
    fn atp_outcome_constructors() {
        let outcome: AtpOutcome<()> =
            AtpOutcome::transport_error(TransportError::ConnectionTimeout);
        assert!(outcome.is_err());

        let outcome: AtpOutcome<()> = AtpOutcome::atp_cancelled(AtpCancelReason::Timeout);
        assert!(outcome.is_cancelled());
    }

    #[test]
    fn idempotency_key_generation() {
        let key1 = IdempotencyKey::generate("test_input");
        let key2 = IdempotencyKey::generate("test_input");
        let key3 = IdempotencyKey::generate("different_input");

        // Same input should generate same key
        assert_eq!(key1, key2);
        // Different input should generate different key
        assert_ne!(key1, key3);

        // Keys should be prefixed with "atp_"
        assert!(key1.as_str().starts_with("atp_"));
    }

    #[test]
    fn idempotency_key_typed_constructors() {
        let manifest_hash = b"test_manifest_hash";
        let peer_id = "peer123";
        let timestamp = 1000000000;

        let offer_key = IdempotencyKey::offer(manifest_hash, peer_id, timestamp);
        let accept_key = IdempotencyKey::accept(&offer_key, peer_id, timestamp);
        let chunk_key = IdempotencyKey::chunk("transfer123", 42, 1);

        assert!(offer_key.as_str().starts_with("atp_"));
        assert!(accept_key.as_str().starts_with("atp_"));
        assert!(chunk_key.as_str().starts_with("atp_"));

        // Keys should be deterministic for same inputs
        let offer_key2 = IdempotencyKey::offer(manifest_hash, peer_id, timestamp);
        assert_eq!(offer_key, offer_key2);
    }

    #[test]
    fn transfer_transcript_lifecycle() {
        let key = IdempotencyKey::new("test_key");
        let mut transcript = TransferTranscript::new(
            "transfer123".to_string(),
            key.clone(),
            vec![1, 2, 3, 4],
            "peer456".to_string(),
            1000000000,
            1024,
            10,
        );

        assert_eq!(transcript.transfer_id, "transfer123");
        assert_eq!(transcript.idempotency_key, key);
        assert_eq!(transcript.outcome_class, OutcomeClass::Pending);
        assert!(!transcript.is_complete());

        // Test progress tracking
        transcript.update_chunks_completed(5);
        assert_eq!(transcript.progress_percent(), 50.0);

        // Test completion
        let success_outcome = AtpOutcome::ok(());
        transcript.complete(&success_outcome, 2000000000);

        assert_eq!(transcript.outcome_class, OutcomeClass::Success);
        assert!(transcript.is_complete());
        assert_eq!(transcript.duration_nanos(), Some(1000000000));
    }

    #[test]
    fn transfer_transcript_error_handling() {
        let key = IdempotencyKey::new("error_test");
        let mut transcript = TransferTranscript::new(
            "transfer_error".to_string(),
            key,
            vec![],
            "peer".to_string(),
            0,
            100,
            1,
        );

        let error_outcome = AtpOutcome::transport_error(TransportError::ConnectionTimeout);
        transcript.complete(&error_outcome, 1000);

        assert_eq!(transcript.outcome_class, OutcomeClass::Error);
        assert_eq!(
            transcript.error_code,
            Some("transport_connection_timeout".to_string())
        );
    }

    #[test]
    fn retry_policy_should_retry_logic() {
        let policy = RetryPolicy::default_transfer();

        // Should not retry on success
        let success = AtpOutcome::ok(());
        assert!(!policy.should_retry(&success, 1));

        // Should retry on retryable transport error within max attempts
        let retryable_error: AtpOutcome<()> =
            AtpOutcome::transport_error(TransportError::ConnectionTimeout);
        assert!(policy.should_retry(&retryable_error, 1));
        assert!(policy.should_retry(&retryable_error, 2));
        assert!(!policy.should_retry(&retryable_error, 3)); // At max attempts

        // Should not retry on non-retryable error
        let non_retryable: AtpOutcome<()> = AtpOutcome::auth_error(AuthError::InvalidSignature);
        assert!(!policy.should_retry(&non_retryable, 1));
    }

    #[test]
    fn retry_policy_delay_calculation() {
        let policy = RetryPolicy {
            max_attempts: 5,
            base_delay_ms: 1000,
            max_delay_ms: 10000,
            backoff_multiplier: 2.0,
            jitter_percent: 0, // No jitter for deterministic test
            retry_on_cancel: false,
            retry_conditions: vec![RetryCondition::RetryableErrors],
        };

        let delay1 = policy.delay_for_attempt(1);
        let delay2 = policy.delay_for_attempt(2);
        let delay3 = policy.delay_for_attempt(3);

        assert_eq!(delay1, 1000); // Base delay
        assert_eq!(delay2, 2000); // Base * 2^1
        assert_eq!(delay3, 4000); // Base * 2^2

        // Test max delay clamping
        let delay_high = policy.delay_for_attempt(10);
        assert!(delay_high <= 10000);
    }

    #[test]
    fn retry_condition_matching() {
        let transport_error = AtpError::Transport(TransportError::ConnectionTimeout);
        let auth_error = AtpError::Auth(AuthError::InvalidSignature);

        let code_condition =
            RetryCondition::ErrorCode(vec!["transport_connection_timeout".to_string()]);
        assert!(code_condition.matches(&transport_error));
        assert!(!code_condition.matches(&auth_error));

        let class_condition = RetryCondition::ErrorClass(vec!["transport".to_string()]);
        assert!(class_condition.matches(&transport_error));
        assert!(!class_condition.matches(&auth_error));

        let retryable_condition = RetryCondition::RetryableErrors;
        assert!(retryable_condition.matches(&transport_error)); // Retryable
        assert!(!retryable_condition.matches(&auth_error)); // Not retryable

        let always_condition = RetryCondition::AlwaysRetry;
        assert!(always_condition.matches(&transport_error));
        assert!(always_condition.matches(&auth_error));

        let never_condition = RetryCondition::NeverRetry;
        assert!(!never_condition.matches(&transport_error));
        assert!(!never_condition.matches(&auth_error));
    }

    #[test]
    fn outcome_class_from_outcome() {
        let success: AtpOutcome<()> = AtpOutcome::ok(());
        assert_eq!(OutcomeClass::from_outcome(&success), OutcomeClass::Success);

        let error: AtpOutcome<()> = AtpOutcome::transport_error(TransportError::ConnectionTimeout);
        assert_eq!(OutcomeClass::from_outcome(&error), OutcomeClass::Error);

        let cancelled: AtpOutcome<()> = AtpOutcome::atp_cancelled(AtpCancelReason::Timeout);
        assert_eq!(
            OutcomeClass::from_outcome(&cancelled),
            OutcomeClass::Cancelled
        );

        // Test retryable classification
        assert!(OutcomeClass::Error.is_retryable());
        assert!(OutcomeClass::Cancelled.is_retryable());
        assert!(!OutcomeClass::Success.is_retryable());
        assert!(!OutcomeClass::Panicked.is_retryable());
    }

    #[test]
    fn idempotency_key_all_operation_types() {
        // Test all the specific key generators
        let manifest_hash = b"manifest";
        let peer_id = "peer";
        let timestamp = 123456789;

        let offer_key = IdempotencyKey::offer(manifest_hash, peer_id, timestamp);
        let accept_key = IdempotencyKey::accept(&offer_key, peer_id, timestamp);
        let chunk_key = IdempotencyKey::chunk("transfer", 1, 1);
        let repair_key = IdempotencyKey::repair_group("block", 1, peer_id);
        let commit_key = IdempotencyKey::commit("transfer", b"hash", timestamp);
        let mailbox_key = IdempotencyKey::mailbox_store("mailbox", b"msg", 1);
        let grant_key = IdempotencyKey::grant("issuer", "subject", b"cap", timestamp);
        let relay_key = IdempotencyKey::relay_reservation("relay", "client", 1000, 3600);
        let journal_key = IdempotencyKey::resume_journal("transfer", b"checkpoint", 1);
        let proof_key = IdempotencyKey::final_proof("transfer", b"proof", "verifier");

        // All keys should be unique
        let keys = vec![
            offer_key,
            accept_key,
            chunk_key,
            repair_key,
            commit_key,
            mailbox_key,
            grant_key,
            relay_key,
            journal_key,
            proof_key,
        ];

        for (i, key1) in keys.iter().enumerate() {
            for (j, key2) in keys.iter().enumerate() {
                if i != j {
                    assert_ne!(key1, key2, "Keys should be unique");
                }
            }
        }
    }
}
