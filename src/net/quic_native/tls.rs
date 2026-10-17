//! QUIC-TLS/key-phase state machine.
//!
//! This module models QUIC crypto-level progression, packet-protection
//! provider boundaries, and key updates without coupling QUIC protocol state to
//! a specific cryptographic backend.

use sha2::{Digest, Sha256};
#[cfg(any(test, feature = "test-internals", feature = "tls"))]
use std::collections::BTreeMap;
use std::fmt;
#[cfg(feature = "tls")]
use std::sync::Arc;

/// QUIC crypto level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CryptoLevel {
    /// Initial keys.
    Initial,
    /// Handshake keys.
    Handshake,
    /// Application (1-RTT) keys.
    OneRtt,
}

/// QUIC packet number space used for packet-protection key lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PacketProtectionSpace {
    /// Initial packet number space.
    Initial,
    /// Handshake packet number space.
    Handshake,
    /// 0-RTT application packet number space.
    ZeroRtt,
    /// 1-RTT application packet number space.
    OneRtt,
}

impl PacketProtectionSpace {
    /// Stable lowercase label for logs and proof artifacts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Handshake => "handshake",
            Self::ZeroRtt => "zero_rtt",
            Self::OneRtt => "one_rtt",
        }
    }

    #[cfg(any(test, feature = "test-internals", feature = "tls"))]
    const fn code(self) -> u8 {
        match self {
            Self::Initial => 0,
            Self::Handshake => 1,
            Self::ZeroRtt => 2,
            Self::OneRtt => 3,
        }
    }

    /// Crypto level associated with this packet number space.
    #[must_use]
    pub const fn crypto_level(self) -> CryptoLevel {
        match self {
            Self::Initial => CryptoLevel::Initial,
            Self::Handshake => CryptoLevel::Handshake,
            Self::ZeroRtt | Self::OneRtt => CryptoLevel::OneRtt,
        }
    }
}

/// Result event from processing a key-update signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUpdateEvent {
    /// No change was required.
    NoChange,
    /// A new local key phase was scheduled.
    LocalUpdateScheduled {
        /// Next key phase bit.
        next_phase: bool,
        /// Key generation number.
        generation: u64,
    },
    /// Peer moved to a new key phase.
    RemoteUpdateAccepted {
        /// Accepted peer key phase bit.
        new_phase: bool,
        /// Peer generation number.
        generation: u64,
    },
}

/// TLS/key-phase state machine errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicTlsError {
    /// Operation requires handshake confirmation.
    HandshakeNotConfirmed,
    /// A client connection reached handshake confirmation without verifying the
    /// server's certificate chain against configured roots. The native QUIC TLS
    /// path performs no certificate exchange/verification, so client connections
    /// fail closed here rather than accepting an unauthenticated server identity
    /// (MITM exposure). A verifying handshake must record success via
    /// `NativeQuicConnection::record_verified_server_identity` before confirming.
    ServerCertificateUnverified,
    /// Invalid crypto-level transition.
    InvalidTransition {
        /// Current crypto level.
        from: CryptoLevel,
        /// Requested level.
        to: CryptoLevel,
    },
    /// Peer key-phase value is stale.
    StalePeerKeyPhase(bool),
    /// Packet-protection keys have not been installed for a packet space/phase.
    MissingKeys {
        /// Packet number space.
        space: PacketProtectionSpace,
        /// Requested key phase bit.
        key_phase: bool,
    },
    /// Server identity verification was configured with no trust anchors.
    ServerIdentityRootStoreEmpty,
    /// Peer did not present a certificate chain.
    ServerCertificateChainEmpty,
    /// Configured DNS name was not valid for WebPKI verification.
    InvalidServerName,
    /// rustls/WebPKI rejected the server certificate chain.
    ServerCertificateRejected {
        /// Stable, redaction-safe rejection reason.
        code: &'static str,
    },
    /// Packet-protection keys were already discarded for this packet space.
    KeyDiscarded {
        /// Packet number space.
        space: PacketProtectionSpace,
    },
    /// Protected packet authentication tag did not verify.
    BadPacketTag {
        /// Packet number space.
        space: PacketProtectionSpace,
    },
    /// Protected packet used a key phase that is inconsistent with installed keys.
    WrongKeyPhase {
        /// Packet number space.
        space: PacketProtectionSpace,
        /// Expected key phase.
        expected: bool,
        /// Observed key phase.
        observed: bool,
    },
    /// Handshake transcript digest did not match provider state.
    TranscriptMismatch {
        /// Expected transcript hash.
        expected: TranscriptHash,
        /// Actual transcript hash.
        actual: TranscriptHash,
    },
    /// Header-protection sample is too short for the provider.
    HeaderProtectionSampleTooShort {
        /// Observed sample length.
        len: usize,
        /// Minimum required sample length.
        min: usize,
    },
    /// Provider reported a deterministic, redacted failure.
    CryptoProviderFailure {
        /// Provider kind.
        provider: &'static str,
        /// Stable failure code.
        code: &'static str,
    },
}

impl fmt::Display for QuicTlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HandshakeNotConfirmed => write!(f, "handshake not confirmed"),
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid crypto transition: {from:?} -> {to:?}")
            }
            Self::StalePeerKeyPhase(phase) => write!(f, "stale peer key phase: {phase}"),
            Self::MissingKeys { space, key_phase } => {
                write!(
                    f,
                    "missing packet protection keys: space={}, key_phase={key_phase}",
                    space.as_str()
                )
            }
            Self::ServerIdentityRootStoreEmpty => {
                write!(f, "server identity root store is empty")
            }
            Self::ServerCertificateChainEmpty => {
                write!(f, "server certificate chain is empty")
            }
            Self::InvalidServerName => {
                write!(f, "invalid server name for certificate verification")
            }
            Self::ServerCertificateRejected { code } => {
                write!(f, "server certificate rejected: code={code}")
            }
            Self::KeyDiscarded { space } => {
                write!(
                    f,
                    "packet protection keys discarded: space={}",
                    space.as_str()
                )
            }
            Self::BadPacketTag { space } => {
                write!(f, "packet authentication failed: space={}", space.as_str())
            }
            Self::WrongKeyPhase {
                space,
                expected,
                observed,
            } => write!(
                f,
                "wrong packet key phase: space={}, expected={expected}, observed={observed}",
                space.as_str()
            ),
            Self::TranscriptMismatch { expected, actual } => write!(
                f,
                "handshake transcript mismatch: expected={}, actual={}",
                expected.short_hex(),
                actual.short_hex()
            ),
            Self::HeaderProtectionSampleTooShort { len, min } => write!(
                f,
                "header protection sample too short: len={len}, min={min}"
            ),
            Self::CryptoProviderFailure { provider, code } => {
                write!(
                    f,
                    "crypto provider failure: provider={provider}, code={code}"
                )
            }
            Self::ServerCertificateUnverified => write!(
                f,
                "server certificate chain was not verified against configured roots"
            ),
        }
    }
}

impl std::error::Error for QuicTlsError {}

impl QuicTlsError {
    /// Stable machine-readable failure code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::HandshakeNotConfirmed => "handshake_not_confirmed",
            Self::InvalidTransition { .. } => "invalid_transition",
            Self::StalePeerKeyPhase(_) => "stale_peer_key_phase",
            Self::MissingKeys { .. } => "missing_keys",
            Self::ServerIdentityRootStoreEmpty => "server_identity_root_store_empty",
            Self::ServerCertificateChainEmpty => "server_certificate_chain_empty",
            Self::InvalidServerName => "invalid_server_name",
            Self::ServerCertificateRejected { code } => code,
            Self::KeyDiscarded { .. } => "key_discarded",
            Self::BadPacketTag { .. } => "bad_packet_tag",
            Self::WrongKeyPhase { .. } => "wrong_key_phase",
            Self::TranscriptMismatch { .. } => "transcript_mismatch",
            Self::HeaderProtectionSampleTooShort { .. } => "header_sample_too_short",
            Self::CryptoProviderFailure { code, .. } => code,
            Self::ServerCertificateUnverified => "server_certificate_unverified",
        }
    }
}

#[cfg(feature = "tls")]
fn server_identity_failure(code: &'static str) -> QuicTlsError {
    match code {
        "server_identity_root_store_empty" => QuicTlsError::ServerIdentityRootStoreEmpty,
        "server_certificate_chain_empty" => QuicTlsError::ServerCertificateChainEmpty,
        "invalid_server_name" => QuicTlsError::InvalidServerName,
        code => QuicTlsError::ServerCertificateRejected { code },
    }
}

/// Redaction-safe receipt for a successful server identity verification.
#[cfg(feature = "tls")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicServerIdentityVerification {
    /// Number of certificates supplied by the peer, leaf first.
    pub chain_len: usize,
    /// Number of trust anchors in the configured root store.
    pub root_count: usize,
}

/// rustls/WebPKI-backed verifier for native QUIC server identities.
///
/// This type verifies the peer's X.509 server certificate chain against an
/// explicit root store and hostname before the connection records the
/// server-identity gate. It deliberately exposes no insecure skip-verify path.
#[cfg(feature = "tls")]
#[derive(Debug, Clone)]
pub struct QuicServerIdentityVerifier {
    verifier: Arc<rustls::client::WebPkiServerVerifier>,
    root_count: usize,
}

#[cfg(feature = "tls")]
impl QuicServerIdentityVerifier {
    /// Construct a verifier from an explicit root store.
    pub fn from_root_store(root_store: crate::tls::RootCertStore) -> Result<Self, QuicTlsError> {
        let root_count = root_store.len();
        if root_count == 0 {
            return Err(server_identity_failure("server_identity_root_store_empty"));
        }
        // Resolve the provider like every other asupersync TLS configuration;
        // plain `WebPkiServerVerifier::builder` would use rustls's process
        // default, and panic when there is none.
        let provider = crate::tls::resolve_crypto_provider(None).map_err(|_| {
            QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-server-identity",
                code: "crypto_provider_unavailable",
            }
        })?;
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(root_store.into_inner()),
            provider,
        )
        .build()
        .map_err(|_| server_identity_failure("server_identity_verifier_build_failed"))?;
        Ok(Self {
            verifier,
            root_count,
        })
    }

    /// Verify a presented server chain against the configured roots and name.
    pub fn verify_server_chain(
        &self,
        hostname: &str,
        presented_chain: crate::tls::CertificateChain,
        now: rustls_pki_types::UnixTime,
    ) -> Result<QuicServerIdentityVerification, QuicTlsError> {
        use rustls::client::danger::ServerCertVerifier;

        let certs = presented_chain.into_inner();
        let (leaf, intermediates) = certs
            .split_first()
            .ok_or_else(|| server_identity_failure("server_certificate_chain_empty"))?;
        let server_name = rustls_pki_types::ServerName::try_from(hostname.to_string())
            .map_err(|_| server_identity_failure("invalid_server_name"))?;
        self.verifier
            .verify_server_cert(leaf, intermediates, &server_name, &[], now)
            .map_err(map_server_cert_verification_error)?;
        Ok(QuicServerIdentityVerification {
            chain_len: certs.len(),
            root_count: self.root_count,
        })
    }
}

#[cfg(feature = "tls")]
fn map_server_cert_verification_error(err: rustls::Error) -> QuicTlsError {
    let code = match err {
        rustls::Error::InvalidCertificate(_) => "server_certificate_invalid",
        rustls::Error::NoCertificatesPresented => "server_certificate_chain_empty",
        rustls::Error::UnsupportedNameType => "server_certificate_unsupported_name",
        rustls::Error::InvalidMessage(_) => "server_certificate_bad_encoding",
        rustls::Error::General(_) => "server_certificate_general_failure",
        _ => "server_certificate_rejected",
    };
    server_identity_failure(code)
}

/// Redaction-safe transcript hash used by provider proofs and errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TranscriptHash([u8; 32]);

impl TranscriptHash {
    /// Construct from raw hash bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow raw hash bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Short lowercase hex prefix safe for logs.
    #[must_use]
    pub fn short_hex(self) -> String {
        let mut out = String::with_capacity(16);
        for byte in &self.0[..8] {
            use std::fmt::Write as _;
            let _ = write!(&mut out, "{byte:02x}");
        }
        out
    }
}

/// Canonical QUIC handshake transcript accumulator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicHandshakeTranscript {
    digest: TranscriptHash,
    entries: u64,
}

impl Default for QuicHandshakeTranscript {
    fn default() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"asupersync/quic-handshake-transcript/v1");
        Self {
            digest: TranscriptHash::from_bytes(hasher.finalize().into()),
            entries: 0,
        }
    }
}

impl QuicHandshakeTranscript {
    /// Create an empty canonical transcript.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a labeled handshake message.
    pub fn record(&mut self, label: &str, payload: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(b"asupersync/quic-handshake-transcript/record/v1");
        hasher.update(self.digest.as_bytes());
        hasher.update(self.entries.to_be_bytes());
        hasher.update(label.len().to_be_bytes());
        hasher.update(label.as_bytes());
        hasher.update(payload.len().to_be_bytes());
        hasher.update(payload);
        self.digest = TranscriptHash::from_bytes(hasher.finalize().into());
        self.entries += 1;
    }

    /// Current transcript hash.
    #[must_use]
    pub const fn digest(&self) -> TranscriptHash {
        self.digest
    }

    /// Number of recorded transcript entries.
    #[must_use]
    pub const fn entries(&self) -> u64 {
        self.entries
    }
}

/// Installed packet-protection key metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionKeySnapshot {
    /// Packet number space.
    pub space: PacketProtectionSpace,
    /// QUIC key phase bit.
    pub key_phase: bool,
    /// Key generation for this space/phase.
    pub generation: u64,
    /// Redacted key identifier for logs/proofs.
    pub key_id: [u8; 16],
    /// Transcript hash bound to the key derivation.
    pub transcript_hash: TranscriptHash,
}

/// Packet-protection request.
#[derive(Debug, Clone, Copy)]
pub struct PacketProtectionRequest<'a> {
    /// Packet number space.
    pub space: PacketProtectionSpace,
    /// QUIC key phase bit.
    pub key_phase: bool,
    /// Packet number.
    pub packet_number: u64,
    /// Header bytes authenticated but not encrypted.
    pub associated_data: &'a [u8],
    /// Payload bytes to protect.
    pub payload: &'a [u8],
}

/// Protected packet output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedPacket {
    /// Packet number space.
    pub space: PacketProtectionSpace,
    /// QUIC key phase bit.
    pub key_phase: bool,
    /// Packet number.
    pub packet_number: u64,
    /// Protected payload.
    pub ciphertext: Vec<u8>,
    /// Authentication tag.
    pub tag: [u8; 16],
    /// Redaction-safe provider proof.
    pub proof: ProtectionProof,
}

/// Unprotected packet output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnprotectedPacket {
    /// Packet number space.
    pub space: PacketProtectionSpace,
    /// QUIC key phase bit.
    pub key_phase: bool,
    /// Packet number.
    pub packet_number: u64,
    /// Plain payload.
    pub plaintext: Vec<u8>,
    /// Redaction-safe provider proof.
    pub proof: ProtectionProof,
}

/// Header-protection mask output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderProtectionMask {
    /// QUIC header-protection mask bytes.
    pub bytes: [u8; 5],
}

/// Redaction-safe proof emitted by provider operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionProof {
    /// Provider kind.
    pub provider_kind: &'static str,
    /// Packet number space.
    pub space: PacketProtectionSpace,
    /// QUIC key phase bit.
    pub key_phase: bool,
    /// Key generation.
    pub generation: u64,
    /// Transcript hash bound to this operation.
    pub transcript_hash: TranscriptHash,
    /// Optional stable failure code.
    pub failure_code: Option<&'static str>,
}

impl ProtectionProof {
    #[cfg(any(test, feature = "test-internals", feature = "tls"))]
    fn success(provider_kind: &'static str, key: &ProtectionKeySnapshot) -> Self {
        Self {
            provider_kind,
            space: key.space,
            key_phase: key.key_phase,
            generation: key.generation,
            transcript_hash: key.transcript_hash,
            failure_code: None,
        }
    }
}

/// Provider boundary for QUIC packet protection.
pub trait QuicPacketProtectionProvider {
    /// Stable provider kind for redacted logs.
    fn provider_kind(&self) -> &'static str;

    /// Clone a read-only provider snapshot for parallel packet unprotection.
    ///
    /// Packet protection keys are immutable for a given key phase, so providers
    /// that can cheaply share those keys may return a clone here. Stateful
    /// lifecycle operations (derive/update/discard) still require the canonical
    /// mutable provider owned by the connection.
    fn clone_for_parallel_unprotect(
        &self,
    ) -> Option<Box<dyn QuicPacketProtectionProvider + Send + Sync>> {
        None
    }

    /// Redaction-safe AEAD/provider metadata for performance diagnosis.
    fn aead_provider_profile(&self) -> QuicAeadProviderProfile {
        QuicAeadProviderProfile::unknown(self.provider_kind())
    }

    /// Derive and install packet-protection keys for a packet number space.
    fn derive_keys(
        &mut self,
        space: PacketProtectionSpace,
        transcript: &QuicHandshakeTranscript,
        secret_seed: &[u8],
    ) -> Result<ProtectionKeySnapshot, QuicTlsError>;

    /// Verify the provider's transcript binding.
    fn verify_transcript(&self, expected: TranscriptHash) -> Result<(), QuicTlsError>;

    /// Return installed key metadata for a space/phase.
    fn key_snapshot(
        &self,
        space: PacketProtectionSpace,
        key_phase: bool,
    ) -> Result<ProtectionKeySnapshot, QuicTlsError>;

    /// Protect a packet payload.
    fn protect_packet(
        &mut self,
        request: PacketProtectionRequest<'_>,
    ) -> Result<ProtectedPacket, QuicTlsError>;

    /// Authenticate and decrypt a protected packet.
    fn unprotect_packet(
        &mut self,
        packet: &ProtectedPacket,
        associated_data: &[u8],
    ) -> Result<UnprotectedPacket, QuicTlsError>;

    /// Authenticate and decrypt a protected packet in place.
    ///
    /// `packet_data` is the full received datagram: `header || ciphertext ||
    /// tag`, with the header occupying `packet_data[..header_len]` and serving
    /// as the associated data. On success the plaintext occupies
    /// `packet_data[header_len..header_len + returned_len]` and the returned
    /// length is the plaintext length (`packet_data.len() - header_len -
    /// tag_len`).
    ///
    /// The default implementation routes through [`Self::unprotect_packet`]
    /// (one ciphertext copy in, one plaintext copy back), so existing
    /// providers stay correct; providers with an in-place AEAD override this
    /// to decrypt with zero copies.
    fn unprotect_packet_in_place(
        &mut self,
        space: PacketProtectionSpace,
        key_phase: bool,
        packet_number: u64,
        packet_data: &mut [u8],
        header_len: usize,
    ) -> Result<usize, QuicTlsError> {
        const TAG_LEN: usize = 16;
        if packet_data.len() < header_len + TAG_LEN {
            return Err(QuicTlsError::CryptoProviderFailure {
                provider: self.provider_kind(),
                code: "packet_too_short_for_in_place_unprotect",
            });
        }
        let body = &packet_data[header_len..];
        let tag_offset = body.len() - TAG_LEN;
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&body[tag_offset..]);
        let protected = ProtectedPacket {
            space,
            key_phase,
            packet_number,
            ciphertext: body[..tag_offset].to_vec(),
            tag,
            proof: ProtectionProof {
                provider_kind: self.provider_kind(),
                space,
                key_phase,
                generation: 0,
                transcript_hash: TranscriptHash::from_bytes([0u8; 32]),
                failure_code: None,
            },
        };
        let associated_data = packet_data[..header_len].to_vec();
        let unprotected = self.unprotect_packet(&protected, &associated_data)?;
        let plaintext_len = unprotected.plaintext.len();
        packet_data[header_len..header_len + plaintext_len].copy_from_slice(&unprotected.plaintext);
        Ok(plaintext_len)
    }

    /// Produce QUIC header-protection mask bytes for **protecting** an
    /// outgoing header (RFC 9001 §5.4), i.e. with this endpoint's own
    /// header-protection key for `space`.
    ///
    /// `bytes[0]` is applied to the first byte (low four bits of a long
    /// header, low five of a short header) and `bytes[1..]` to the
    /// packet-number bytes; see
    /// [`crate::net::quic_core::apply_header_protection`].
    fn header_protection_mask(
        &self,
        space: PacketProtectionSpace,
        sample: &[u8],
    ) -> Result<HeaderProtectionMask, QuicTlsError>;

    /// Produce QUIC header-protection mask bytes for **removing** protection
    /// from a received header.
    ///
    /// This uses the *peer's* header-protection key for `space` (RFC 9001
    /// §5.4.1 applies the sender's key on both ends).
    ///
    /// Providers whose keys are direction-symmetric (the deterministic lab
    /// provider) inherit this default; a TLS-derived provider must override
    /// it, or every received header would be unmasked with the wrong key.
    fn header_protection_mask_remote(
        &self,
        space: PacketProtectionSpace,
        sample: &[u8],
    ) -> Result<HeaderProtectionMask, QuicTlsError> {
        self.header_protection_mask(space, sample)
    }

    /// Derive and install the next key phase.
    fn update_key(
        &mut self,
        space: PacketProtectionSpace,
        next_phase: bool,
    ) -> Result<ProtectionKeySnapshot, QuicTlsError>;

    /// Discard keys for a packet number space.
    fn discard_keys(&mut self, space: PacketProtectionSpace) -> Result<(), QuicTlsError>;
}

/// Runtime CPU features relevant to AES-GCM packet protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicAeadHardwareProfile {
    /// Whether the current CPU reports AES block-cipher instructions.
    pub aes: bool,
    /// Whether the current CPU reports carry-less multiply instructions used by
    /// GHASH in fast AES-GCM implementations.
    pub ghash: bool,
    /// Human-readable probe family for traces.
    pub probe: &'static str,
}

impl QuicAeadHardwareProfile {
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            aes: false,
            ghash: false,
            probe: "not-probed",
        }
    }

    #[must_use]
    pub fn detect() -> Self {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            return Self {
                aes: std::is_x86_feature_detected!("aes"),
                ghash: std::is_x86_feature_detected!("pclmulqdq"),
                probe: "x86-aes-pclmulqdq",
            };
        }

        #[cfg(target_arch = "aarch64")]
        {
            return Self {
                aes: std::arch::is_aarch64_feature_detected!("aes"),
                ghash: std::arch::is_aarch64_feature_detected!("pmull"),
                probe: "aarch64-aes-pmull",
            };
        }

        #[allow(unreachable_code)]
        Self::unknown()
    }

    #[must_use]
    pub const fn aes_gcm_capable(self) -> bool {
        self.aes && self.ghash
    }
}

/// Redaction-safe QUIC packet-protection provider profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicAeadProviderProfile {
    /// Stable provider kind.
    pub provider_kind: &'static str,
    /// Concrete crypto backend selected by the provider.
    pub backend: &'static str,
    /// TLS cipher suite supplying the QUIC AEAD.
    pub tls_cipher_suite: &'static str,
    /// QUIC AEAD algorithm used for packet protection.
    pub quic_aead: &'static str,
    /// Runtime hardware feature probe for AES-GCM acceleration.
    pub hardware: QuicAeadHardwareProfile,
}

impl QuicAeadProviderProfile {
    #[must_use]
    pub fn rustls_ring_aes_128_gcm() -> Self {
        Self {
            provider_kind: "rustls-quic-ring",
            backend: "rustls/ring",
            tls_cipher_suite: "TLS13_AES_128_GCM_SHA256",
            quic_aead: "AES-128-GCM",
            hardware: QuicAeadHardwareProfile::detect(),
        }
    }

    #[must_use]
    pub const fn deterministic() -> Self {
        Self {
            provider_kind: "deterministic-lab",
            backend: "deterministic-test-provider",
            tls_cipher_suite: "none",
            quic_aead: "deterministic-xor-tag",
            hardware: QuicAeadHardwareProfile::unknown(),
        }
    }

    #[must_use]
    pub const fn unknown(provider_kind: &'static str) -> Self {
        Self {
            provider_kind,
            backend: "unknown",
            tls_cipher_suite: "unknown",
            quic_aead: "unknown",
            hardware: QuicAeadHardwareProfile::unknown(),
        }
    }
}

/// Local QUIC endpoint side for the rustls packet-protection provider.
#[cfg(feature = "tls")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustlsQuicProviderSide {
    /// Client endpoint.
    Client,
    /// Server endpoint.
    Server,
}

#[cfg(feature = "tls")]
impl RustlsQuicProviderSide {
    const fn code(self) -> u8 {
        match self {
            Self::Client => 0,
            Self::Server => 1,
        }
    }
}

#[cfg(feature = "tls")]
impl From<RustlsQuicProviderSide> for rustls::Side {
    fn from(side: RustlsQuicProviderSide) -> Self {
        match side {
            RustlsQuicProviderSide::Client => Self::Client,
            RustlsQuicProviderSide::Server => Self::Server,
        }
    }
}

#[cfg(feature = "tls")]
#[derive(Clone)]
struct RustlsDirectionalKeys {
    header: Arc<dyn rustls::quic::HeaderProtectionKey>,
    packet: Arc<dyn rustls::quic::PacketKey>,
}

#[cfg(feature = "tls")]
#[derive(Clone)]
struct RustlsProtectionKeys {
    local: RustlsDirectionalKeys,
    remote: RustlsDirectionalKeys,
}

#[cfg(feature = "tls")]
#[derive(Clone)]
struct RustlsKeySlot {
    snapshot: ProtectionKeySnapshot,
    keys: RustlsProtectionKeys,
    discarded: bool,
}

/// rustls-backed QUIC packet-protection provider.
///
/// This adapter is intentionally narrow: `quic_native` owns packet-space,
/// key-phase, lifecycle, and proof state, while rustls owns TLS 1.3 QUIC key
/// derivation plus AEAD/header-protection primitive operations. It is not an
/// external QUIC implementation; it is the internal crypto-provider boundary
/// required by the native QUIC endpoint.
#[cfg(feature = "tls")]
#[derive(Clone)]
pub struct RustlsQuicCryptoProvider {
    version: rustls::quic::Version,
    side: RustlsQuicProviderSide,
    suite: rustls::quic::Suite,
    transcript_hash: TranscriptHash,
    keys: BTreeMap<(PacketProtectionSpace, bool), RustlsKeySlot>,
    next_1rtt: Option<rustls::quic::Secrets>,
}

#[cfg(feature = "tls")]
impl RustlsQuicCryptoProvider {
    /// Construct a QUIC v1 provider using the AES-128-GCM initial suite of the
    /// resolved rustls crypto provider (ring when `tls` links it; see the
    /// `crate::tls` module documentation).
    pub fn new_v1(side: RustlsQuicProviderSide) -> Result<Self, QuicTlsError> {
        let provider = crate::tls::resolve_crypto_provider(None).map_err(|_| {
            QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-ring",
                code: "crypto_provider_unavailable",
            }
        })?;
        let suite = provider
            .cipher_suites
            .iter()
            .find_map(|candidate| match (candidate.suite(), candidate.tls13()) {
                (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(suite)) => suite.quic_suite(),
                _ => None,
            })
            .ok_or(QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-ring",
                code: "missing_initial_suite",
            })?;
        Ok(Self::with_initial_suite(
            rustls::quic::Version::V1,
            side,
            suite,
        ))
    }

    /// Construct with an explicit rustls QUIC version and initial suite.
    #[must_use]
    pub fn with_initial_suite(
        version: rustls::quic::Version,
        side: RustlsQuicProviderSide,
        suite: rustls::quic::Suite,
    ) -> Self {
        Self {
            version,
            side,
            suite,
            transcript_hash: QuicHandshakeTranscript::new().digest(),
            keys: BTreeMap::new(),
            next_1rtt: None,
        }
    }

    /// Install rustls handshake or 1-RTT key material emitted by
    /// `rustls::quic::Connection::write_hs`.
    pub fn install_key_change(
        &mut self,
        key_change: rustls::quic::KeyChange,
        transcript: &QuicHandshakeTranscript,
    ) -> Result<ProtectionKeySnapshot, QuicTlsError> {
        self.transcript_hash = transcript.digest();
        match key_change {
            rustls::quic::KeyChange::Handshake { keys } => {
                Ok(self.insert_keys(PacketProtectionSpace::Handshake, false, 0, keys))
            }
            rustls::quic::KeyChange::OneRtt { keys, next } => {
                self.next_1rtt = Some(next);
                Ok(self.insert_keys(PacketProtectionSpace::OneRtt, false, 0, keys))
            }
        }
    }

    /// Retry may select a zero-length CID (RFC 9000 §17.2.5). Preserve the
    /// public initial-derivation input checks while allowing that wire case.
    pub(crate) fn install_retry_initial_keys(
        &mut self,
        dcid: &[u8],
        transcript: &QuicHandshakeTranscript,
    ) {
        self.transcript_hash = transcript.digest();
        let keys = self.suite.keys(dcid, self.side.into(), self.version);
        self.insert_keys(PacketProtectionSpace::Initial, false, 0, keys);
    }

    fn insert_keys(
        &mut self,
        space: PacketProtectionSpace,
        key_phase: bool,
        generation: u64,
        keys: rustls::quic::Keys,
    ) -> ProtectionKeySnapshot {
        self.insert_protection_keys(space, key_phase, generation, rustls_keys_from_full(keys))
    }

    fn insert_protection_keys(
        &mut self,
        space: PacketProtectionSpace,
        key_phase: bool,
        generation: u64,
        keys: RustlsProtectionKeys,
    ) -> ProtectionKeySnapshot {
        let snapshot = ProtectionKeySnapshot {
            space,
            key_phase,
            generation,
            key_id: derive_rustls_key_id(
                self.side,
                self.version,
                space,
                key_phase,
                generation,
                self.transcript_hash,
            ),
            transcript_hash: self.transcript_hash,
        };
        self.keys.insert(
            (space, key_phase),
            RustlsKeySlot {
                snapshot: snapshot.clone(),
                keys,
                discarded: false,
            },
        );
        snapshot
    }

    fn installed_key(
        &self,
        space: PacketProtectionSpace,
        key_phase: bool,
    ) -> Result<&RustlsKeySlot, QuicTlsError> {
        if let Some(slot) = self.keys.get(&(space, key_phase)) {
            if slot.discarded {
                return Err(QuicTlsError::KeyDiscarded { space });
            }
            return Ok(slot);
        }

        for ((candidate_space, candidate_phase), slot) in &self.keys {
            if *candidate_space == space && !slot.discarded {
                return Err(QuicTlsError::WrongKeyPhase {
                    space,
                    expected: *candidate_phase,
                    observed: key_phase,
                });
            }
        }

        Err(QuicTlsError::MissingKeys { space, key_phase })
    }

    fn installed_any_phase(
        &self,
        space: PacketProtectionSpace,
    ) -> Result<&RustlsKeySlot, QuicTlsError> {
        self.keys
            .iter()
            .filter(|((candidate_space, _), slot)| *candidate_space == space && !slot.discarded)
            .max_by_key(|(_, slot)| slot.snapshot.generation)
            .map(|(_, slot)| slot)
            .ok_or(QuicTlsError::MissingKeys {
                space,
                key_phase: false,
            })
    }
}

#[cfg(feature = "tls")]
impl QuicPacketProtectionProvider for RustlsQuicCryptoProvider {
    fn provider_kind(&self) -> &'static str {
        "rustls-quic-ring"
    }

    fn clone_for_parallel_unprotect(
        &self,
    ) -> Option<Box<dyn QuicPacketProtectionProvider + Send + Sync>> {
        Some(Box::new(self.clone()))
    }

    fn aead_provider_profile(&self) -> QuicAeadProviderProfile {
        QuicAeadProviderProfile::rustls_ring_aes_128_gcm()
    }

    fn derive_keys(
        &mut self,
        space: PacketProtectionSpace,
        transcript: &QuicHandshakeTranscript,
        secret_seed: &[u8],
    ) -> Result<ProtectionKeySnapshot, QuicTlsError> {
        self.transcript_hash = transcript.digest();
        match space {
            PacketProtectionSpace::Initial => {
                if secret_seed.is_empty() {
                    return Err(QuicTlsError::CryptoProviderFailure {
                        provider: self.provider_kind(),
                        code: "empty_initial_dcid",
                    });
                }
                let keys = self.suite.keys(secret_seed, self.side.into(), self.version);
                Ok(self.insert_keys(PacketProtectionSpace::Initial, false, 0, keys))
            }
            PacketProtectionSpace::Handshake
            | PacketProtectionSpace::ZeroRtt
            | PacketProtectionSpace::OneRtt => {
                self.key_snapshot(space, false)
                    .map_err(|_| QuicTlsError::CryptoProviderFailure {
                        provider: self.provider_kind(),
                        code: "rustls_key_change_required",
                    })
            }
        }
    }

    fn verify_transcript(&self, expected: TranscriptHash) -> Result<(), QuicTlsError> {
        if self.transcript_hash == expected {
            Ok(())
        } else {
            Err(QuicTlsError::TranscriptMismatch {
                expected,
                actual: self.transcript_hash,
            })
        }
    }

    fn key_snapshot(
        &self,
        space: PacketProtectionSpace,
        key_phase: bool,
    ) -> Result<ProtectionKeySnapshot, QuicTlsError> {
        Ok(self.installed_key(space, key_phase)?.snapshot.clone())
    }

    fn protect_packet(
        &mut self,
        request: PacketProtectionRequest<'_>,
    ) -> Result<ProtectedPacket, QuicTlsError> {
        let slot = self.installed_key(request.space, request.key_phase)?;
        let mut ciphertext = request.payload.to_vec();
        let tag = slot
            .keys
            .local
            .packet
            .encrypt_in_place(
                request.packet_number,
                request.associated_data,
                &mut ciphertext,
            )
            .map_err(|_| QuicTlsError::CryptoProviderFailure {
                provider: self.provider_kind(),
                code: "rustls_encrypt_error",
            })?;
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(tag.as_ref());
        Ok(ProtectedPacket {
            space: request.space,
            key_phase: request.key_phase,
            packet_number: request.packet_number,
            ciphertext,
            tag: tag_bytes,
            proof: ProtectionProof::success(self.provider_kind(), &slot.snapshot),
        })
    }

    fn unprotect_packet(
        &mut self,
        packet: &ProtectedPacket,
        associated_data: &[u8],
    ) -> Result<UnprotectedPacket, QuicTlsError> {
        let slot = self.installed_key(packet.space, packet.key_phase)?;
        let mut payload_and_tag = Vec::with_capacity(packet.ciphertext.len() + packet.tag.len());
        payload_and_tag.extend_from_slice(&packet.ciphertext);
        payload_and_tag.extend_from_slice(&packet.tag);
        let plaintext = slot
            .keys
            .remote
            .packet
            .decrypt_in_place(packet.packet_number, associated_data, &mut payload_and_tag)
            .map_err(|_| QuicTlsError::BadPacketTag {
                space: packet.space,
            })?
            .to_vec();
        Ok(UnprotectedPacket {
            space: packet.space,
            key_phase: packet.key_phase,
            packet_number: packet.packet_number,
            plaintext,
            proof: ProtectionProof::success(self.provider_kind(), &slot.snapshot),
        })
    }

    fn unprotect_packet_in_place(
        &mut self,
        space: PacketProtectionSpace,
        key_phase: bool,
        packet_number: u64,
        packet_data: &mut [u8],
        header_len: usize,
    ) -> Result<usize, QuicTlsError> {
        const TAG_LEN: usize = 16;
        if packet_data.len() < header_len + TAG_LEN {
            return Err(QuicTlsError::CryptoProviderFailure {
                provider: self.provider_kind(),
                code: "packet_too_short_for_in_place_unprotect",
            });
        }
        let slot = self.installed_key(space, key_phase)?;
        let (header, payload_and_tag) = packet_data.split_at_mut(header_len);
        let plaintext_len = slot
            .keys
            .remote
            .packet
            .decrypt_in_place(packet_number, header, payload_and_tag)
            .map_err(|_| QuicTlsError::BadPacketTag { space })?
            .len();
        Ok(plaintext_len)
    }

    fn header_protection_mask(
        &self,
        space: PacketProtectionSpace,
        sample: &[u8],
    ) -> Result<HeaderProtectionMask, QuicTlsError> {
        let slot = self.installed_any_phase(space)?;
        rustls_header_protection_mask(
            self.provider_kind(),
            slot.keys.local.header.as_ref(),
            space,
            sample,
        )
    }

    fn header_protection_mask_remote(
        &self,
        space: PacketProtectionSpace,
        sample: &[u8],
    ) -> Result<HeaderProtectionMask, QuicTlsError> {
        let slot = self.installed_any_phase(space)?;
        rustls_header_protection_mask(
            self.provider_kind(),
            slot.keys.remote.header.as_ref(),
            space,
            sample,
        )
    }

    fn update_key(
        &mut self,
        space: PacketProtectionSpace,
        next_phase: bool,
    ) -> Result<ProtectionKeySnapshot, QuicTlsError> {
        if space != PacketProtectionSpace::OneRtt {
            return Err(QuicTlsError::CryptoProviderFailure {
                provider: self.provider_kind(),
                code: "rustls_key_update_requires_1rtt",
            });
        }
        let current = self.installed_any_phase(space)?;
        if current.snapshot.key_phase == next_phase {
            return Err(QuicTlsError::WrongKeyPhase {
                space,
                expected: !current.snapshot.key_phase,
                observed: next_phase,
            });
        }
        let generation = current.snapshot.generation + 1;
        let local_header = Arc::clone(&current.keys.local.header);
        let remote_header = Arc::clone(&current.keys.remote.header);
        let next = self
            .next_1rtt
            .as_mut()
            .ok_or(QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-ring",
                code: "rustls_next_secret_missing",
            })?;
        let packet_keys = next.next_packet_keys();
        let updated_keys = RustlsProtectionKeys {
            local: RustlsDirectionalKeys {
                header: local_header,
                packet: Arc::from(packet_keys.local),
            },
            remote: RustlsDirectionalKeys {
                header: remote_header,
                packet: Arc::from(packet_keys.remote),
            },
        };
        Ok(self.insert_protection_keys(space, next_phase, generation, updated_keys))
    }

    fn discard_keys(&mut self, space: PacketProtectionSpace) -> Result<(), QuicTlsError> {
        let mut discarded = false;
        for ((candidate_space, _), slot) in &mut self.keys {
            if *candidate_space == space {
                slot.discarded = true;
                discarded = true;
            }
        }
        if discarded {
            Ok(())
        } else {
            Err(QuicTlsError::MissingKeys {
                space,
                key_phase: false,
            })
        }
    }
}

/// Recover the 5-byte RFC 9001 §5.4 header-protection mask from a rustls
/// header-protection key.
///
/// rustls exposes the mask only through its apply routine, which XORs the
/// first byte's low bits and as many packet-number bytes as the *unmasked*
/// first byte's length bits announce. Seeding a first byte whose length bits
/// say "4-byte packet number" (`0x83` long / `0x43` short) and a zero packet
/// number therefore recovers the whole mask: `bytes[0]` holds the masked low
/// bits (the only bits ever applied to a real header) and `bytes[1..5]` the
/// packet-number mask. Seeding `0x80`/`0x40` instead would announce a 1-byte
/// packet number and leave `bytes[2..5]` zero.
#[cfg(feature = "tls")]
fn rustls_header_protection_mask(
    provider: &'static str,
    key: &dyn rustls::quic::HeaderProtectionKey,
    space: PacketProtectionSpace,
    sample: &[u8],
) -> Result<HeaderProtectionMask, QuicTlsError> {
    let min = key.sample_len();
    if sample.len() < min {
        return Err(QuicTlsError::HeaderProtectionSampleTooShort {
            len: sample.len(),
            min,
        });
    }

    let seed = match space {
        PacketProtectionSpace::Initial
        | PacketProtectionSpace::Handshake
        | PacketProtectionSpace::ZeroRtt => 0x83,
        PacketProtectionSpace::OneRtt => 0x43,
    };
    let mut first = seed;
    let mut packet_number = [0u8; 4];
    key.encrypt_in_place(&sample[..min], &mut first, &mut packet_number)
        .map_err(|_| QuicTlsError::CryptoProviderFailure {
            provider,
            code: "rustls_header_protection_error",
        })?;

    let mut bytes = [0u8; 5];
    bytes[0] = first ^ seed;
    bytes[1..].copy_from_slice(&packet_number);
    Ok(HeaderProtectionMask { bytes })
}

#[cfg(feature = "tls")]
fn rustls_keys_from_full(keys: rustls::quic::Keys) -> RustlsProtectionKeys {
    RustlsProtectionKeys {
        local: RustlsDirectionalKeys {
            header: Arc::from(keys.local.header),
            packet: Arc::from(keys.local.packet),
        },
        remote: RustlsDirectionalKeys {
            header: Arc::from(keys.remote.header),
            packet: Arc::from(keys.remote.packet),
        },
    }
}

#[cfg(feature = "tls")]
fn derive_rustls_key_id(
    side: RustlsQuicProviderSide,
    version: rustls::quic::Version,
    space: PacketProtectionSpace,
    key_phase: bool,
    generation: u64,
    transcript_hash: TranscriptHash,
) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync/rustls-quic-protection-key-id/v1");
    hasher.update([side.code()]);
    hasher.update([rustls_version_code(version)]);
    hasher.update([space.code()]);
    hasher.update([u8::from(key_phase)]);
    hasher.update(generation.to_be_bytes());
    hasher.update(transcript_hash.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

#[cfg(feature = "tls")]
fn rustls_version_code(version: rustls::quic::Version) -> u8 {
    match version {
        rustls::quic::Version::V1Draft => 0,
        rustls::quic::Version::V1 => 1,
        rustls::quic::Version::V2 => 2,
        _ => 255,
    }
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone)]
struct DeterministicKeySlot {
    snapshot: ProtectionKeySnapshot,
    secret: [u8; 32],
    discarded: bool,
}

/// Deterministic provider for lab, unit, and e2e contract tests.
///
/// This provider is not a production secrecy provider. It exists so the QUIC
/// state machine can prove provider lifecycle, transcript binding, key update,
/// header protection, and fail-closed behavior without importing an external
/// QUIC implementation.
#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone)]
pub struct DeterministicQuicCryptoProvider {
    transcript_hash: TranscriptHash,
    keys: BTreeMap<(PacketProtectionSpace, bool), DeterministicKeySlot>,
}

#[cfg(any(test, feature = "test-internals"))]
impl Default for DeterministicQuicCryptoProvider {
    fn default() -> Self {
        Self {
            transcript_hash: QuicHandshakeTranscript::new().digest(),
            keys: BTreeMap::new(),
        }
    }
}

#[cfg(any(test, feature = "test-internals"))]
impl DeterministicQuicCryptoProvider {
    /// Construct an empty deterministic provider.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn installed_key(
        &self,
        space: PacketProtectionSpace,
        key_phase: bool,
    ) -> Result<&DeterministicKeySlot, QuicTlsError> {
        if let Some(slot) = self.keys.get(&(space, key_phase)) {
            if slot.discarded {
                return Err(QuicTlsError::KeyDiscarded { space });
            }
            return Ok(slot);
        }

        for ((candidate_space, candidate_phase), slot) in &self.keys {
            if *candidate_space == space && !slot.discarded {
                return Err(QuicTlsError::WrongKeyPhase {
                    space,
                    expected: *candidate_phase,
                    observed: key_phase,
                });
            }
        }

        Err(QuicTlsError::MissingKeys { space, key_phase })
    }

    fn insert_key(
        &mut self,
        space: PacketProtectionSpace,
        key_phase: bool,
        generation: u64,
        secret_seed: &[u8],
        transcript_hash: TranscriptHash,
    ) -> ProtectionKeySnapshot {
        let secret = derive_secret(space, key_phase, generation, transcript_hash, secret_seed);
        let key_id = derive_key_id(&secret);
        let snapshot = ProtectionKeySnapshot {
            space,
            key_phase,
            generation,
            key_id,
            transcript_hash,
        };
        self.keys.insert(
            (space, key_phase),
            DeterministicKeySlot {
                snapshot: snapshot.clone(),
                secret,
                discarded: false,
            },
        );
        snapshot
    }
}

#[cfg(any(test, feature = "test-internals"))]
impl QuicPacketProtectionProvider for DeterministicQuicCryptoProvider {
    fn provider_kind(&self) -> &'static str {
        "deterministic-lab"
    }

    fn clone_for_parallel_unprotect(
        &self,
    ) -> Option<Box<dyn QuicPacketProtectionProvider + Send + Sync>> {
        Some(Box::new(self.clone()))
    }

    fn aead_provider_profile(&self) -> QuicAeadProviderProfile {
        QuicAeadProviderProfile::deterministic()
    }

    fn derive_keys(
        &mut self,
        space: PacketProtectionSpace,
        transcript: &QuicHandshakeTranscript,
        secret_seed: &[u8],
    ) -> Result<ProtectionKeySnapshot, QuicTlsError> {
        if secret_seed.is_empty() {
            return Err(QuicTlsError::CryptoProviderFailure {
                provider: self.provider_kind(),
                code: "empty_secret_seed",
            });
        }
        self.transcript_hash = transcript.digest();
        Ok(self.insert_key(space, false, 0, secret_seed, transcript.digest()))
    }

    fn verify_transcript(&self, expected: TranscriptHash) -> Result<(), QuicTlsError> {
        if self.transcript_hash == expected {
            Ok(())
        } else {
            Err(QuicTlsError::TranscriptMismatch {
                expected,
                actual: self.transcript_hash,
            })
        }
    }

    fn key_snapshot(
        &self,
        space: PacketProtectionSpace,
        key_phase: bool,
    ) -> Result<ProtectionKeySnapshot, QuicTlsError> {
        Ok(self.installed_key(space, key_phase)?.snapshot.clone())
    }

    fn protect_packet(
        &mut self,
        request: PacketProtectionRequest<'_>,
    ) -> Result<ProtectedPacket, QuicTlsError> {
        let slot = self.installed_key(request.space, request.key_phase)?;
        let ciphertext = apply_keystream(
            &slot.secret,
            request.packet_number,
            request.associated_data,
            request.payload,
        );
        let tag = compute_tag(
            &slot.secret,
            request.space,
            request.key_phase,
            request.packet_number,
            request.associated_data,
            &ciphertext,
        );
        Ok(ProtectedPacket {
            space: request.space,
            key_phase: request.key_phase,
            packet_number: request.packet_number,
            ciphertext,
            tag,
            proof: ProtectionProof::success(self.provider_kind(), &slot.snapshot),
        })
    }

    fn unprotect_packet(
        &mut self,
        packet: &ProtectedPacket,
        associated_data: &[u8],
    ) -> Result<UnprotectedPacket, QuicTlsError> {
        let slot = self.installed_key(packet.space, packet.key_phase)?;
        let expected = compute_tag(
            &slot.secret,
            packet.space,
            packet.key_phase,
            packet.packet_number,
            associated_data,
            &packet.ciphertext,
        );
        if expected != packet.tag {
            return Err(QuicTlsError::BadPacketTag {
                space: packet.space,
            });
        }
        let plaintext = apply_keystream(
            &slot.secret,
            packet.packet_number,
            associated_data,
            &packet.ciphertext,
        );
        Ok(UnprotectedPacket {
            space: packet.space,
            key_phase: packet.key_phase,
            packet_number: packet.packet_number,
            plaintext,
            proof: ProtectionProof::success(self.provider_kind(), &slot.snapshot),
        })
    }

    fn header_protection_mask(
        &self,
        space: PacketProtectionSpace,
        sample: &[u8],
    ) -> Result<HeaderProtectionMask, QuicTlsError> {
        const MIN_SAMPLE: usize = 16;
        if sample.len() < MIN_SAMPLE {
            return Err(QuicTlsError::HeaderProtectionSampleTooShort {
                len: sample.len(),
                min: MIN_SAMPLE,
            });
        }
        let slot = self.installed_key(space, false).or_else(|_| {
            self.keys
                .iter()
                .find(|((candidate_space, _), slot)| *candidate_space == space && !slot.discarded)
                .map(|(_, slot)| slot)
                .ok_or(QuicTlsError::MissingKeys {
                    space,
                    key_phase: false,
                })
        })?;
        let mut hasher = Sha256::new();
        hasher.update(b"asupersync/quic-header-protection/v1");
        hasher.update(slot.secret);
        hasher.update(space.code().to_be_bytes());
        hasher.update(sample);
        let digest: [u8; 32] = hasher.finalize().into();
        let mut bytes = [0u8; 5];
        bytes.copy_from_slice(&digest[..5]);
        Ok(HeaderProtectionMask { bytes })
    }

    fn update_key(
        &mut self,
        space: PacketProtectionSpace,
        next_phase: bool,
    ) -> Result<ProtectionKeySnapshot, QuicTlsError> {
        let current = self
            .keys
            .iter()
            .filter(|((candidate_space, _), slot)| *candidate_space == space && !slot.discarded)
            .max_by_key(|(_, slot)| slot.snapshot.generation)
            .map(|(_, slot)| slot.clone())
            .ok_or(QuicTlsError::MissingKeys {
                space,
                key_phase: next_phase,
            })?;
        let next_generation = current.snapshot.generation + 1;
        let next_secret = derive_secret(
            space,
            next_phase,
            next_generation,
            current.snapshot.transcript_hash,
            &current.secret,
        );
        let key_id = derive_key_id(&next_secret);
        let snapshot = ProtectionKeySnapshot {
            space,
            key_phase: next_phase,
            generation: next_generation,
            key_id,
            transcript_hash: current.snapshot.transcript_hash,
        };
        self.keys.insert(
            (space, next_phase),
            DeterministicKeySlot {
                snapshot: snapshot.clone(),
                secret: next_secret,
                discarded: false,
            },
        );
        Ok(snapshot)
    }

    fn discard_keys(&mut self, space: PacketProtectionSpace) -> Result<(), QuicTlsError> {
        let mut discarded = false;
        for ((candidate_space, _), slot) in &mut self.keys {
            if *candidate_space == space {
                slot.discarded = true;
                discarded = true;
            }
        }
        if discarded {
            Ok(())
        } else {
            Err(QuicTlsError::MissingKeys {
                space,
                key_phase: false,
            })
        }
    }
}

#[cfg(any(test, feature = "test-internals"))]
fn derive_secret(
    space: PacketProtectionSpace,
    key_phase: bool,
    generation: u64,
    transcript_hash: TranscriptHash,
    seed: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync/quic-protection-secret/v1");
    hasher.update([space.code()]);
    hasher.update([u8::from(key_phase)]);
    hasher.update(generation.to_be_bytes());
    hasher.update(transcript_hash.as_bytes());
    hasher.update(seed.len().to_be_bytes());
    hasher.update(seed);
    hasher.finalize().into()
}

#[cfg(any(test, feature = "test-internals"))]
fn derive_key_id(secret: &[u8; 32]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync/quic-protection-key-id/v1");
    hasher.update(secret);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

#[cfg(any(test, feature = "test-internals"))]
fn apply_keystream(secret: &[u8; 32], packet_number: u64, aad: &[u8], input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut counter = 0u64;
    while output.len() < input.len() {
        let mut hasher = Sha256::new();
        hasher.update(b"asupersync/quic-protection-keystream/v1");
        hasher.update(secret);
        hasher.update(packet_number.to_be_bytes());
        hasher.update(counter.to_be_bytes());
        hasher.update(aad.len().to_be_bytes());
        hasher.update(aad);
        let block: [u8; 32] = hasher.finalize().into();
        for byte in block {
            if output.len() == input.len() {
                break;
            }
            let idx = output.len();
            output.push(input[idx] ^ byte);
        }
        counter += 1;
    }
    output
}

#[cfg(any(test, feature = "test-internals"))]
fn compute_tag(
    secret: &[u8; 32],
    space: PacketProtectionSpace,
    key_phase: bool,
    packet_number: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync/quic-protection-tag/v1");
    hasher.update(secret);
    hasher.update([space.code()]);
    hasher.update([u8::from(key_phase)]);
    hasher.update(packet_number.to_be_bytes());
    hasher.update(aad.len().to_be_bytes());
    hasher.update(aad);
    hasher.update(ciphertext.len().to_be_bytes());
    hasher.update(ciphertext);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct KeyEpoch {
    phase: bool,
    generation: u64,
}

/// Native QUIC-TLS progression state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicTlsMachine {
    level: CryptoLevel,
    handshake_complete: bool,
    handshake_confirmed: bool,
    resumption_enabled: bool,
    local: KeyEpoch,
    remote: KeyEpoch,
    pending_local_update: bool,
    /// Lowest packet number attributed to the current remote key generation.
    /// A phase flip carrying a lower number is a reordered packet of a previous
    /// key phase (RFC 9001 §6.3), not a new peer key update.
    remote_gen_floor_pn: u64,
}

impl Default for QuicTlsMachine {
    fn default() -> Self {
        Self {
            level: CryptoLevel::Initial,
            handshake_complete: false,
            handshake_confirmed: false,
            resumption_enabled: false,
            local: KeyEpoch::default(),
            remote: KeyEpoch::default(),
            pending_local_update: false,
            remote_gen_floor_pn: 0,
        }
    }
}

impl QuicTlsMachine {
    /// Create a new TLS machine at `Initial`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current crypto level.
    #[must_use]
    pub fn level(&self) -> CryptoLevel {
        self.level
    }

    /// Whether authenticated TLS completion permits 1-RTT traffic.
    #[must_use]
    pub fn can_send_1rtt(&self) -> bool {
        self.level == CryptoLevel::OneRtt && self.handshake_complete
    }

    /// Whether the handshake has been confirmed (RFC 9001 §4.1.2). The ACK path
    /// uses this to decide when the peer's `max_ack_delay` clamp applies to RTT
    /// samples (RFC 9002 §5.3, asupersync-mc7m2r).
    #[must_use]
    pub fn handshake_confirmed(&self) -> bool {
        self.handshake_confirmed
    }

    /// Whether 0-RTT application-data packets are currently allowed.
    #[must_use]
    pub fn can_send_0rtt(&self) -> bool {
        self.level >= CryptoLevel::Handshake && !self.handshake_complete && self.resumption_enabled
    }

    /// Whether session resumption is enabled for this handshake.
    #[must_use]
    pub fn resumption_enabled(&self) -> bool {
        self.resumption_enabled
    }

    /// Enable session resumption/0-RTT mode for the current handshake.
    pub fn enable_resumption(&mut self) {
        self.resumption_enabled = true;
    }

    /// Disable session resumption/0-RTT mode.
    pub fn disable_resumption(&mut self) {
        self.resumption_enabled = false;
    }

    /// Current local key phase bit.
    #[must_use]
    pub fn local_key_phase(&self) -> bool {
        self.local.phase
    }

    /// Current remote key phase bit.
    #[must_use]
    pub fn remote_key_phase(&self) -> bool {
        self.remote.phase
    }

    /// Observe that Initial keys are available.
    ///
    /// The machine starts at `Initial`, so this is normally a no-op. Keeping it
    /// as an explicit transition lets conformance tests exercise the same
    /// monotonic transition guard used by later levels.
    pub fn on_initial_keys_available(&mut self) -> Result<(), QuicTlsError> {
        self.advance_to(CryptoLevel::Initial)
    }

    /// Transition to `Handshake` level.
    pub fn on_handshake_keys_available(&mut self) -> Result<(), QuicTlsError> {
        self.advance_to(CryptoLevel::Handshake)
    }

    /// Transition to `OneRtt` level (keys installed).
    pub fn on_1rtt_keys_available(&mut self) -> Result<(), QuicTlsError> {
        self.advance_to(CryptoLevel::OneRtt)
    }

    /// Allow application traffic after the authenticated TLS handshake completes.
    ///
    /// The connection owner must enforce its peer-identity gate before calling
    /// this; installing 1-RTT keys alone does not establish authentication.
    pub(crate) fn on_authenticated_handshake_complete(&mut self) -> Result<(), QuicTlsError> {
        if self.level != CryptoLevel::OneRtt {
            return Err(QuicTlsError::HandshakeNotConfirmed);
        }
        self.handshake_complete = true;
        Ok(())
    }

    /// Mark handshake as confirmed.
    pub fn on_handshake_confirmed(&mut self) -> Result<(), QuicTlsError> {
        self.on_authenticated_handshake_complete()?;
        self.handshake_confirmed = true;
        Ok(())
    }

    /// Request a local key update.
    pub fn request_local_key_update(&mut self) -> Result<KeyUpdateEvent, QuicTlsError> {
        if !self.handshake_confirmed {
            return Err(QuicTlsError::HandshakeNotConfirmed);
        }
        if self.pending_local_update {
            return Ok(KeyUpdateEvent::NoChange);
        }
        self.pending_local_update = true;
        Ok(KeyUpdateEvent::LocalUpdateScheduled {
            next_phase: !self.local.phase,
            generation: self.local.generation + 1,
        })
    }

    /// Commit the pending local key update after keys are installed.
    pub fn commit_local_key_update(&mut self) -> Result<KeyUpdateEvent, QuicTlsError> {
        if !self.pending_local_update {
            return Ok(KeyUpdateEvent::NoChange);
        }
        self.pending_local_update = false;
        self.local.phase = !self.local.phase;
        self.local.generation += 1;
        Ok(KeyUpdateEvent::LocalUpdateScheduled {
            next_phase: self.local.phase,
            generation: self.local.generation,
        })
    }

    /// Process peer key-phase bit from a protected packet.
    /// Process a peer key-phase bit observed on an authenticated 1-RTT packet,
    /// using the packet number to disambiguate a genuine key update from a
    /// delayed packet of the previous key phase (RFC 9001 §6.3).
    ///
    /// A phase flip is accepted as a new peer key update when `packet_number`
    /// is at least the lowest packet number attributed to the current remote
    /// generation; a lower number is a reordered packet from an earlier phase
    /// and yields [`QuicTlsError::StalePeerKeyPhase`]. Because QUIC key phases
    /// alternate, this accepts repeated bidirectional updates rather than only
    /// the first one. The live receive path invokes this only after the packet
    /// has decrypted under the new keys, so an accepted update is confirmed.
    pub fn on_peer_key_phase_pn(
        &mut self,
        phase: bool,
        packet_number: u64,
    ) -> Result<KeyUpdateEvent, QuicTlsError> {
        if !self.handshake_confirmed {
            return Err(QuicTlsError::HandshakeNotConfirmed);
        }
        if phase == self.remote.phase {
            return Ok(KeyUpdateEvent::NoChange);
        }
        if self.remote.generation > 0 && packet_number < self.remote_gen_floor_pn {
            return Err(QuicTlsError::StalePeerKeyPhase(phase));
        }
        self.remote.phase = phase;
        self.remote.generation += 1;
        self.remote_gen_floor_pn = packet_number;
        Ok(KeyUpdateEvent::RemoteUpdateAccepted {
            new_phase: self.remote.phase,
            generation: self.remote.generation,
        })
    }

    /// Whether a key-phase-flip packet would be accepted as a genuine new peer
    /// key update, without mutating any machine state.
    ///
    /// This is the non-committing predicate the live 1-RTT receive path uses to
    /// decide whether to install next-generation receive keys *before* running
    /// AEAD (the replay window permits decrypting a packet only once). It is
    /// `true` exactly when [`Self::on_peer_key_phase_pn`] would return
    /// [`KeyUpdateEvent::RemoteUpdateAccepted`]: the handshake is confirmed, the
    /// phase differs from the current remote phase, and `packet_number` is not
    /// below the floor of the current remote generation (a delayed
    /// previous-phase packet, which must be decrypted with the retained old keys
    /// rather than triggering a rotation) (RFC 9001 §6.3, asupersync-1bheeo).
    #[must_use]
    pub fn peer_key_phase_is_new_update(&self, phase: bool, packet_number: u64) -> bool {
        self.handshake_confirmed
            && phase != self.remote.phase
            && !(self.remote.generation > 0 && packet_number < self.remote_gen_floor_pn)
    }

    /// Process a peer key-phase bit without packet-number context.
    ///
    /// Equivalent to [`Self::on_peer_key_phase_pn`] evaluated at the current
    /// generation floor, so it accepts an alternating peer key update
    /// (RFC 9001 §6.3) without rejecting it as stale. The packet-number-aware
    /// form is preferred on the live receive path, where a delayed packet from
    /// the previous phase must be rejected as
    /// [`QuicTlsError::StalePeerKeyPhase`] instead of rotating backwards.
    pub fn on_peer_key_phase(&mut self, phase: bool) -> Result<KeyUpdateEvent, QuicTlsError> {
        self.on_peer_key_phase_pn(phase, self.remote_gen_floor_pn)
    }

    fn advance_to(&mut self, target: CryptoLevel) -> Result<(), QuicTlsError> {
        if target < self.level {
            return Err(QuicTlsError::InvalidTransition {
                from: self.level,
                to: target,
            });
        }
        if target > self.level {
            self.level = target;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tls_inline_tests.rs"]
mod tests;
