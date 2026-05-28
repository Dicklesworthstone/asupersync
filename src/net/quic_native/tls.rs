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
            Self::KeyDiscarded { .. } => "key_discarded",
            Self::BadPacketTag { .. } => "bad_packet_tag",
            Self::WrongKeyPhase { .. } => "wrong_key_phase",
            Self::TranscriptMismatch { .. } => "transcript_mismatch",
            Self::HeaderProtectionSampleTooShort { .. } => "header_sample_too_short",
            Self::CryptoProviderFailure { code, .. } => code,
        }
    }
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

    /// Produce QUIC header-protection mask bytes.
    fn header_protection_mask(
        &self,
        space: PacketProtectionSpace,
        sample: &[u8],
    ) -> Result<HeaderProtectionMask, QuicTlsError>;

    /// Derive and install the next key phase.
    fn update_key(
        &mut self,
        space: PacketProtectionSpace,
        next_phase: bool,
    ) -> Result<ProtectionKeySnapshot, QuicTlsError>;

    /// Discard keys for a packet number space.
    fn discard_keys(&mut self, space: PacketProtectionSpace) -> Result<(), QuicTlsError>;
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
struct RustlsDirectionalKeys {
    header: Arc<dyn rustls::quic::HeaderProtectionKey>,
    packet: Box<dyn rustls::quic::PacketKey>,
}

#[cfg(feature = "tls")]
struct RustlsProtectionKeys {
    local: RustlsDirectionalKeys,
    remote: RustlsDirectionalKeys,
}

#[cfg(feature = "tls")]
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
    /// Construct a QUIC v1 provider using rustls' ring-backed AES-128-GCM
    /// initial suite.
    pub fn new_v1(side: RustlsQuicProviderSide) -> Result<Self, QuicTlsError> {
        let provider = rustls::crypto::ring::default_provider();
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

    fn header_protection_mask(
        &self,
        space: PacketProtectionSpace,
        sample: &[u8],
    ) -> Result<HeaderProtectionMask, QuicTlsError> {
        let slot = self.installed_any_phase(space)?;
        let min = slot.keys.local.header.sample_len();
        if sample.len() < min {
            return Err(QuicTlsError::HeaderProtectionSampleTooShort {
                len: sample.len(),
                min,
            });
        }

        let mut first = match space {
            PacketProtectionSpace::Initial
            | PacketProtectionSpace::Handshake
            | PacketProtectionSpace::ZeroRtt => 0x80,
            PacketProtectionSpace::OneRtt => 0x40,
        };
        let original_first = first;
        let mut packet_number = [0u8; 4];
        slot.keys
            .local
            .header
            .encrypt_in_place(&sample[..min], &mut first, &mut packet_number)
            .map_err(|_| QuicTlsError::CryptoProviderFailure {
                provider: self.provider_kind(),
                code: "rustls_header_protection_error",
            })?;

        let mut bytes = [0u8; 5];
        bytes[0] = first ^ original_first;
        bytes[1..].copy_from_slice(&packet_number);
        Ok(HeaderProtectionMask { bytes })
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
                packet: packet_keys.local,
            },
            remote: RustlsDirectionalKeys {
                header: remote_header,
                packet: packet_keys.remote,
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

#[cfg(feature = "tls")]
fn rustls_keys_from_full(keys: rustls::quic::Keys) -> RustlsProtectionKeys {
    RustlsProtectionKeys {
        local: RustlsDirectionalKeys {
            header: Arc::from(keys.local.header),
            packet: keys.local.packet,
        },
        remote: RustlsDirectionalKeys {
            header: Arc::from(keys.remote.header),
            packet: keys.remote.packet,
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
    handshake_confirmed: bool,
    resumption_enabled: bool,
    local: KeyEpoch,
    remote: KeyEpoch,
    pending_local_update: bool,
}

impl Default for QuicTlsMachine {
    fn default() -> Self {
        Self {
            level: CryptoLevel::Initial,
            handshake_confirmed: false,
            resumption_enabled: false,
            local: KeyEpoch::default(),
            remote: KeyEpoch::default(),
            pending_local_update: false,
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

    /// Whether 1-RTT traffic is allowed.
    #[must_use]
    pub fn can_send_1rtt(&self) -> bool {
        self.level == CryptoLevel::OneRtt && self.handshake_confirmed
    }

    /// Whether 0-RTT application-data packets are currently allowed.
    #[must_use]
    pub fn can_send_0rtt(&self) -> bool {
        self.level >= CryptoLevel::Handshake && !self.handshake_confirmed && self.resumption_enabled
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

    /// Mark handshake as confirmed.
    pub fn on_handshake_confirmed(&mut self) -> Result<(), QuicTlsError> {
        if self.level != CryptoLevel::OneRtt {
            return Err(QuicTlsError::HandshakeNotConfirmed);
        }
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
    pub fn on_peer_key_phase(&mut self, phase: bool) -> Result<KeyUpdateEvent, QuicTlsError> {
        if !self.handshake_confirmed {
            return Err(QuicTlsError::HandshakeNotConfirmed);
        }
        if phase == self.remote.phase {
            return Ok(KeyUpdateEvent::NoChange);
        }
        if self.remote.generation > 0 && !phase {
            return Err(QuicTlsError::StalePeerKeyPhase(phase));
        }
        self.remote.phase = phase;
        self.remote.generation += 1;
        Ok(KeyUpdateEvent::RemoteUpdateAccepted {
            new_phase: self.remote.phase,
            generation: self.remote.generation,
        })
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn level_transitions_are_monotonic() {
        let mut m = QuicTlsMachine::new();
        assert_eq!(m.level(), CryptoLevel::Initial);
        m.on_handshake_keys_available().expect("handshake keys");
        assert_eq!(m.level(), CryptoLevel::Handshake);
        m.on_1rtt_keys_available().expect("1rtt keys");
        assert_eq!(m.level(), CryptoLevel::OneRtt);
        let err = m.advance_to(CryptoLevel::Initial).expect_err("must fail");
        assert_eq!(
            err,
            QuicTlsError::InvalidTransition {
                from: CryptoLevel::OneRtt,
                to: CryptoLevel::Initial
            }
        );
    }

    #[test]
    fn key_update_requires_confirmed_handshake() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        let err = m.request_local_key_update().expect_err("must fail");
        assert_eq!(err, QuicTlsError::HandshakeNotConfirmed);
    }

    #[test]
    fn local_key_update_flow() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");
        assert!(!m.local_key_phase());

        let scheduled = m.request_local_key_update().expect("schedule");
        assert_eq!(
            scheduled,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 1
            }
        );
        let committed = m.commit_local_key_update().expect("commit");
        assert_eq!(
            committed,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 1
            }
        );
        assert!(m.local_key_phase());
    }

    #[test]
    fn peer_key_phase_updates_are_applied() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        let evt = m.on_peer_key_phase(true).expect("peer update");
        assert_eq!(
            evt,
            KeyUpdateEvent::RemoteUpdateAccepted {
                new_phase: true,
                generation: 1
            }
        );
        assert!(m.remote_key_phase());
    }

    // --- gap-filling tests ---

    #[test]
    fn on_peer_key_phase_before_handshake_confirmed() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        // handshake NOT confirmed
        let err = m.on_peer_key_phase(true).expect_err("must fail");
        assert_eq!(err, QuicTlsError::HandshakeNotConfirmed);
    }

    #[test]
    fn on_peer_key_phase_same_phase_returns_no_change() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        // Remote phase starts at false; sending false again is same phase.
        let evt = m.on_peer_key_phase(false).expect("same phase");
        assert_eq!(evt, KeyUpdateEvent::NoChange);
        assert!(!m.remote_key_phase());
    }

    #[test]
    fn stale_peer_key_phase_rollback_is_rejected() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        let evt = m.on_peer_key_phase(true).expect("first update");
        assert_eq!(
            evt,
            KeyUpdateEvent::RemoteUpdateAccepted {
                new_phase: true,
                generation: 1,
            }
        );

        let err = m.on_peer_key_phase(false).expect_err("rollback must fail");
        assert_eq!(err, QuicTlsError::StalePeerKeyPhase(false));
        assert!(m.remote_key_phase());
        assert_eq!(m.remote.generation, 1);
    }

    #[test]
    fn double_request_local_key_update_is_idempotent() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        let first = m.request_local_key_update().expect("first request");
        assert_eq!(
            first,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 1,
            }
        );

        // Second request while the first is still pending returns NoChange.
        let second = m.request_local_key_update().expect("second request");
        assert_eq!(second, KeyUpdateEvent::NoChange);
    }

    #[test]
    fn commit_local_key_update_without_prior_request() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        // No request_local_key_update was issued.
        let evt = m.commit_local_key_update().expect("commit without request");
        assert_eq!(evt, KeyUpdateEvent::NoChange);
        // Phase and generation remain at defaults.
        assert!(!m.local_key_phase());
    }

    #[test]
    fn multiple_key_update_generations() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        m.on_1rtt_keys_available().expect("1rtt");
        m.on_handshake_confirmed().expect("confirmed");

        // Generation 0 -> 1
        m.request_local_key_update().expect("request gen1");
        m.commit_local_key_update().expect("commit gen1");
        assert!(m.local_key_phase()); // phase flipped to true
        assert_eq!(m.local.generation, 1);

        // Generation 1 -> 2
        let sched = m.request_local_key_update().expect("request gen2");
        assert_eq!(
            sched,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: false, // flips back
                generation: 2,
            }
        );
        let committed = m.commit_local_key_update().expect("commit gen2");
        assert_eq!(
            committed,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: false,
                generation: 2,
            }
        );
        assert!(!m.local_key_phase());
        assert_eq!(m.local.generation, 2);

        // Generation 2 -> 3
        let sched = m.request_local_key_update().expect("request gen3");
        assert_eq!(
            sched,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 3,
            }
        );
        let committed = m.commit_local_key_update().expect("commit gen3");
        assert_eq!(
            committed,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 3,
            }
        );
        assert!(m.local_key_phase());
        assert_eq!(m.local.generation, 3);
    }

    #[test]
    fn advance_to_skipping_handshake_level() {
        let mut m = QuicTlsMachine::new();
        assert_eq!(m.level(), CryptoLevel::Initial);

        // Skip directly from Initial to OneRtt.
        m.advance_to(CryptoLevel::OneRtt).expect("skip to 1rtt");
        assert_eq!(m.level(), CryptoLevel::OneRtt);

        // Going backwards must fail.
        let err = m
            .advance_to(CryptoLevel::Handshake)
            .expect_err("must fail backwards");
        assert_eq!(
            err,
            QuicTlsError::InvalidTransition {
                from: CryptoLevel::OneRtt,
                to: CryptoLevel::Handshake,
            }
        );
    }

    #[test]
    fn quic_tls_error_display_messages() {
        let e1 = QuicTlsError::HandshakeNotConfirmed;
        assert_eq!(e1.to_string(), "handshake not confirmed");

        let e2 = QuicTlsError::InvalidTransition {
            from: CryptoLevel::Handshake,
            to: CryptoLevel::Initial,
        };
        assert_eq!(
            e2.to_string(),
            "invalid crypto transition: Handshake -> Initial"
        );

        let e3 = QuicTlsError::StalePeerKeyPhase(true);
        assert_eq!(e3.to_string(), "stale peer key phase: true");

        let e4 = QuicTlsError::StalePeerKeyPhase(false);
        assert_eq!(e4.to_string(), "stale peer key phase: false");
    }

    #[test]
    fn crypto_level_ord_semantics() {
        assert!(CryptoLevel::Initial < CryptoLevel::Handshake);
        assert!(CryptoLevel::Handshake < CryptoLevel::OneRtt);
        assert!(CryptoLevel::Initial < CryptoLevel::OneRtt);

        // Verify ordering consistency with Ord trait.
        let mut levels = vec![
            CryptoLevel::OneRtt,
            CryptoLevel::Initial,
            CryptoLevel::Handshake,
        ];
        levels.sort();
        assert_eq!(
            levels,
            vec![
                CryptoLevel::Initial,
                CryptoLevel::Handshake,
                CryptoLevel::OneRtt,
            ]
        );
    }

    // =========================================================================
    // Wave 44 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn crypto_level_debug_clone_copy_eq() {
        let l = CryptoLevel::Initial;
        let copied = l;
        let cloned = l;
        assert_eq!(copied, cloned);
        assert_ne!(CryptoLevel::Initial, CryptoLevel::OneRtt);
        let dbg = format!("{l:?}");
        assert!(dbg.contains("Initial"), "{dbg}");
    }

    #[test]
    fn key_update_event_debug_clone_copy_eq() {
        let e1 = KeyUpdateEvent::NoChange;
        let e2 = KeyUpdateEvent::LocalUpdateScheduled {
            next_phase: true,
            generation: 1,
        };
        let e3 = KeyUpdateEvent::RemoteUpdateAccepted {
            new_phase: false,
            generation: 2,
        };
        assert!(format!("{e1:?}").contains("NoChange"));
        assert!(format!("{e2:?}").contains("LocalUpdateScheduled"));
        assert!(format!("{e3:?}").contains("RemoteUpdateAccepted"));
        let copied = e2;
        let cloned = e2;
        assert_eq!(copied, cloned);
        assert_ne!(e1, e2);
    }

    #[test]
    fn quic_tls_error_debug_clone_eq_display() {
        let e1 = QuicTlsError::HandshakeNotConfirmed;
        let e2 = QuicTlsError::InvalidTransition {
            from: CryptoLevel::Initial,
            to: CryptoLevel::OneRtt,
        };
        let e3 = QuicTlsError::StalePeerKeyPhase(true);

        assert!(format!("{e1:?}").contains("HandshakeNotConfirmed"));
        assert!(format!("{e1}").contains("handshake not confirmed"));
        assert!(format!("{e2}").contains("invalid crypto transition"));
        assert!(format!("{e3}").contains("stale peer key phase"));

        assert_eq!(e1.clone(), e1);
        assert_ne!(e1, e2);

        let err: &dyn std::error::Error = &e1;
        assert!(err.source().is_none());
    }

    #[test]
    fn quic_tls_machine_debug_clone_eq() {
        let m = QuicTlsMachine::new();
        let dbg = format!("{m:?}");
        assert!(dbg.contains("QuicTlsMachine"), "{dbg}");
        let cloned = m.clone();
        assert_eq!(m, cloned);
    }

    #[test]
    fn zero_rtt_requires_resumption_and_pre_confirmation_state() {
        let mut m = QuicTlsMachine::new();
        m.on_handshake_keys_available().expect("handshake");
        assert!(!m.can_send_0rtt());

        m.enable_resumption();
        assert!(m.resumption_enabled());
        assert!(m.can_send_0rtt());

        m.on_1rtt_keys_available().expect("1rtt");
        assert!(m.can_send_0rtt());

        m.on_handshake_confirmed().expect("confirmed");
        assert!(!m.can_send_0rtt());
        assert!(m.can_send_1rtt());

        m.disable_resumption();
        assert!(!m.resumption_enabled());
        assert!(!m.can_send_0rtt());
    }
}
