//! ATP-QUIC Packet Protection Integration
//!
//! This module integrates the QUIC packet protection provider with ATP's native QUIC
//! implementation, providing the crypto boundary that keeps ATP protocol state separate
//! from cryptographic primitive operations.

use crate::cx::Cx;
use crate::net::atp::protocol::outcome::{AtpError, AtpOutcome, AuthError, ProtocolError};
use crate::net::quic_native::tls::{
    HeaderProtectionMask, PacketProtectionRequest, PacketProtectionSpace, ProtectedPacket,
    ProtectionKeySnapshot, QuicAeadProviderProfile, QuicHandshakeTranscript,
    QuicPacketProtectionProvider, QuicTlsError, TranscriptHash, UnprotectedPacket,
};
use std::collections::{BTreeMap, BTreeSet};

const REPLAY_WINDOW_CAPACITY: usize = 1024;
const REPLAY_WINDOW_SPAN: u64 = REPLAY_WINDOW_CAPACITY as u64 - 1;

#[cfg(any(test, feature = "test-internals"))]
use crate::net::quic_native::tls::DeterministicQuicCryptoProvider;

#[cfg(feature = "tls")]
use crate::net::quic_native::tls::{RustlsQuicCryptoProvider, RustlsQuicProviderSide};
use crate::types::outcome::Outcome;

/// ATP packet protection configuration.
#[derive(Debug, Clone)]
pub struct AtpPacketProtectionConfig {
    /// Use deterministic provider for testing.
    pub use_deterministic: bool,
    /// Enable transcript verification.
    pub enable_transcript_verification: bool,
    /// Enable structured logging for proof artifacts.
    pub enable_proof_logging: bool,
    /// Provider-specific configuration options.
    pub provider_options: ProviderOptions,
}

impl Default for AtpPacketProtectionConfig {
    fn default() -> Self {
        Self {
            use_deterministic: false,
            enable_transcript_verification: true,
            enable_proof_logging: true,
            provider_options: ProviderOptions::default(),
        }
    }
}

/// Provider-specific configuration options.
#[derive(Debug, Clone)]
pub enum ProviderOptions {
    /// Rustls-based provider configuration.
    #[cfg(feature = "tls")]
    Rustls {
        /// Endpoint side (client or server).
        side: RustlsQuicProviderSide,
    },
    /// Deterministic provider for testing.
    Deterministic {
        /// Test scenario identifier.
        scenario: String,
    },
}

impl Default for ProviderOptions {
    fn default() -> Self {
        #[cfg(feature = "tls")]
        {
            Self::Rustls {
                side: RustlsQuicProviderSide::Client,
            }
        }
        #[cfg(not(feature = "tls"))]
        {
            Self::Deterministic {
                scenario: "default".to_string(),
            }
        }
    }
}

/// ATP wrapper around QUIC packet protection provider.
///
/// This provides the ATP-specific integration boundary between protocol state
/// and cryptographic operations, ensuring proper error handling, logging,
/// and structured concurrency semantics.
pub struct AtpPacketProtection {
    /// Underlying packet protection provider.
    provider: Box<dyn QuicPacketProtectionProvider + Send + Sync>,
    /// Configuration.
    config: AtpPacketProtectionConfig,
    /// Provider kind for logging.
    provider_kind: &'static str,
    /// One-shot provider profile trace guard for ATP_RQ_TRACE bench runs.
    provider_profile_traced: bool,
    /// Bounded accepted-packet windows by packet-number space. QUIC packet
    /// numbers must not be reused inside a space, including across key phases.
    accepted_packets: BTreeMap<PacketProtectionSpace, PacketReplayWindow>,
}

#[derive(Debug, Clone, Default)]
struct PacketReplayWindow {
    highest_seen: Option<u64>,
    seen: BTreeSet<u64>,
}

impl PacketReplayWindow {
    fn rejects(&self, packet_number: u64) -> bool {
        if self.seen.contains(&packet_number) {
            return true;
        }

        self.highest_seen
            .is_some_and(|highest| packet_number < highest.saturating_sub(REPLAY_WINDOW_SPAN))
    }

    fn accept(&mut self, packet_number: u64) {
        self.highest_seen = Some(
            self.highest_seen
                .map_or(packet_number, |highest| highest.max(packet_number)),
        );
        self.seen.insert(packet_number);
        self.prune();
    }

    fn prune(&mut self) {
        let Some(highest) = self.highest_seen else {
            return;
        };
        let floor = highest.saturating_sub(REPLAY_WINDOW_SPAN);

        while self
            .seen
            .iter()
            .next()
            .is_some_and(|oldest| *oldest < floor || self.seen.len() > REPLAY_WINDOW_CAPACITY)
        {
            let oldest = *self.seen.iter().next().expect("window not empty");
            self.seen.remove(&oldest);
        }
    }

    fn len(&self) -> usize {
        self.seen.len()
    }
}

impl AtpPacketProtection {
    /// Create a new ATP packet protection instance.
    pub fn new(config: AtpPacketProtectionConfig) -> AtpOutcome<Self> {
        let (provider, provider_kind): (
            Box<dyn QuicPacketProtectionProvider + Send + Sync>,
            &'static str,
        ) = if config.use_deterministic {
            #[cfg(any(test, feature = "test-internals"))]
            match &config.provider_options {
                ProviderOptions::Deterministic { .. } => {
                    let provider = DeterministicQuicCryptoProvider::new();
                    (Box::new(provider), "deterministic")
                }
                #[cfg(feature = "tls")]
                ProviderOptions::Rustls { .. } => {
                    let provider = DeterministicQuicCryptoProvider::new();
                    (Box::new(provider), "deterministic")
                }
            }
            #[cfg(not(any(test, feature = "test-internals")))]
            {
                // SECURITY: Deterministic crypto must never be used in production builds.
                panic!(
                    "Deterministic crypto provider requested in production build - this is a security vulnerability"
                );
            }
        } else {
            #[cfg(feature = "tls")]
            match &config.provider_options {
                ProviderOptions::Rustls { side } => match RustlsQuicCryptoProvider::new_v1(*side) {
                    Ok(provider) => (Box::new(provider), "rustls-quic-ring"),
                    Err(_) => {
                        return Outcome::err(AtpError::Protocol(
                            ProtocolError::SessionStateMismatch,
                        ));
                    }
                },
                #[cfg(any(test, feature = "test-internals"))]
                ProviderOptions::Deterministic { .. } => {
                    let provider = DeterministicQuicCryptoProvider::new();
                    (Box::new(provider), "deterministic")
                }
                #[cfg(not(any(test, feature = "test-internals")))]
                ProviderOptions::Deterministic { .. } => {
                    return Outcome::err(AtpError::Protocol(ProtocolError::SessionStateMismatch));
                }
            }
            #[cfg(all(not(feature = "tls"), any(test, feature = "test-internals")))]
            {
                match &config.provider_options {
                    ProviderOptions::Deterministic { .. } => {
                        let provider = DeterministicQuicCryptoProvider::new();
                        (Box::new(provider), "deterministic")
                    }
                }
            }
            #[cfg(all(not(feature = "tls"), not(any(test, feature = "test-internals"))))]
            {
                // SECURITY: Deterministic crypto must never be used in production builds.
                panic!(
                    "Deterministic crypto provider requested in production build - this is a security vulnerability"
                );
            }
        };

        #[allow(unreachable_code)]
        Outcome::ok(Self {
            provider,
            config,
            provider_kind,
            provider_profile_traced: false,
            accepted_packets: BTreeMap::new(),
        })
    }

    /// Get the provider kind for logging.
    pub fn provider_kind(&self) -> &'static str {
        self.provider_kind
    }

    /// Redaction-safe provider/cipher metadata for encrypted-path diagnosis.
    #[must_use]
    pub fn aead_provider_profile(&self) -> QuicAeadProviderProfile {
        self.provider.aead_provider_profile()
    }

    fn trace_provider_profile_once(&mut self, cx: &Cx, operation: &'static str) {
        if self.provider_profile_traced {
            return;
        }
        self.provider_profile_traced = true;

        let profile = self.aead_provider_profile();
        let hardware_aes = trace_bool(profile.hardware.aes);
        let hardware_ghash = trace_bool(profile.hardware.ghash);
        let hardware_aes_gcm_capable = trace_bool(profile.hardware.aes_gcm_capable());
        if cx.trace_buffer().is_some() {
            cx.trace_with_fields(
                "atp_quic.aead_provider",
                &[
                    ("operation", operation),
                    ("provider_kind", profile.provider_kind),
                    ("backend", profile.backend),
                    ("tls_cipher_suite", profile.tls_cipher_suite),
                    ("quic_aead", profile.quic_aead),
                    ("arch", std::env::consts::ARCH),
                    ("hardware_probe", profile.hardware.probe),
                    ("hardware_aes", hardware_aes),
                    ("hardware_ghash", hardware_ghash),
                    ("hardware_aes_gcm_capable", hardware_aes_gcm_capable),
                ],
            );
        }
    }

    /// Number of unique protected packets accepted by this boundary.
    #[must_use]
    pub fn accepted_packet_count(&self) -> usize {
        self.accepted_packets
            .values()
            .map(PacketReplayWindow::len)
            .sum()
    }

    /// Derive and install packet protection keys with ATP error handling.
    pub async fn derive_keys(
        &mut self,
        cx: &Cx,
        space: PacketProtectionSpace,
        transcript: &QuicHandshakeTranscript,
        secret_seed: &[u8],
    ) -> AtpOutcome<ProtectionKeySnapshot> {
        cx.trace(&format!("atp_packet_protection_derive_keys {:?}", space));

        let result: AtpOutcome<ProtectionKeySnapshot> = self
            .provider
            .derive_keys(space, transcript, secret_seed)
            .map_err(|e| self.map_tls_error(e))
            .into();

        if self.config.enable_proof_logging {
            match &result {
                Outcome::Ok(snapshot) => {
                    cx.trace(&format!(
                        "packet protection keys derived: space={:?} phase={} gen={}",
                        snapshot.space, snapshot.key_phase, snapshot.generation
                    ));
                }
                Outcome::Err(err) => {
                    cx.trace(&format!(
                        "packet protection key derivation failed: {:?}",
                        err
                    ));
                }
                Outcome::Cancelled(_) | Outcome::Panicked(_) => {}
            }
        }

        result
    }

    /// Verify transcript with ATP error handling.
    pub async fn verify_transcript(&self, cx: &Cx, expected: TranscriptHash) -> AtpOutcome<()> {
        if !self.config.enable_transcript_verification {
            return Outcome::ok(());
        }

        cx.trace("atp_packet_protection_verify_transcript");

        self.provider
            .verify_transcript(expected)
            .map_err(|e| self.map_tls_error(e))
            .into()
    }

    /// Protect a packet with ATP error handling on the current task.
    ///
    /// This is the synchronous primitive used by the hot QUIC send path when it
    /// has already assembled a batch of plaintext packets. It avoids building
    /// one async state machine per packet while preserving the public async
    /// wrapper below for existing callers.
    pub fn protect_packet_now(
        &mut self,
        cx: &Cx,
        request: PacketProtectionRequest<'_>,
    ) -> AtpOutcome<ProtectedPacket> {
        self.trace_provider_profile_once(cx, "protect");

        if cx.trace_buffer().is_some() {
            cx.trace_with_fields(
                "atp_packet_protection_protect",
                &[
                    ("space", &format!("{:?}", request.space)),
                    ("pn", &request.packet_number.to_string()),
                    ("phase", &request.key_phase.to_string()),
                ],
            );
        }

        let result: AtpOutcome<ProtectedPacket> = self
            .provider
            .protect_packet(request)
            .map_err(|e| self.map_tls_error(e))
            .into();

        if self.config.enable_proof_logging {
            match &result {
                Outcome::Ok(packet) => {
                    cx.trace(&format!(
                        "packet protected: space={:?} pn={} ciphertext_len={}",
                        packet.space,
                        packet.packet_number,
                        packet.ciphertext.len()
                    ));
                }
                Outcome::Err(err) => {
                    cx.trace(&format!("packet protection failed: {:?}", err));
                }
                Outcome::Cancelled(_) | Outcome::Panicked(_) => {}
            }
        }

        result
    }

    /// Protect a batch of packets with one ATP boundary call.
    ///
    /// Requests are processed in order, preserving packet-number order and
    /// failing closed on the first provider error. Packet protection does not
    /// mutate replay windows; anti-replay state is still updated only by
    /// [`Self::unprotect_packet`] after authentication succeeds.
    pub fn protect_packets(
        &mut self,
        cx: &Cx,
        requests: &[PacketProtectionRequest<'_>],
    ) -> AtpOutcome<Vec<ProtectedPacket>> {
        if cx.trace_buffer().is_some() {
            cx.trace_with_fields(
                "atp_packet_protection_protect_batch",
                &[("packets", &requests.len().to_string())],
            );
        }

        let mut protected = Vec::with_capacity(requests.len());
        for request in requests {
            match self.protect_packet_now(cx, *request) {
                Outcome::Ok(packet) => protected.push(packet),
                Outcome::Err(err) => return Outcome::Err(err),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        }
        Outcome::ok(protected)
    }

    /// Protect a packet with ATP error handling.
    pub async fn protect_packet(
        &mut self,
        cx: &Cx,
        request: PacketProtectionRequest<'_>,
    ) -> AtpOutcome<ProtectedPacket> {
        self.protect_packet_now(cx, request)
    }

    /// Unprotect a packet with ATP error handling.
    pub async fn unprotect_packet(
        &mut self,
        cx: &Cx,
        packet: &ProtectedPacket,
        associated_data: &[u8],
    ) -> AtpOutcome<UnprotectedPacket> {
        self.trace_provider_profile_once(cx, "unprotect");

        if self
            .accepted_packets
            .get(&packet.space)
            .is_some_and(|window| window.rejects(packet.packet_number))
        {
            if cx.trace_buffer().is_some() {
                cx.trace_with_fields(
                    "atp_packet_protection_replay_rejected",
                    &[
                        ("space", packet.space.as_str()),
                        ("pn", &packet.packet_number.to_string()),
                        ("phase", &packet.key_phase.to_string()),
                    ],
                );
            }
            return Outcome::err(AtpError::Auth(AuthError::ReplayedNonce));
        }

        if cx.trace_buffer().is_some() {
            cx.trace_with_fields(
                "atp_packet_protection_unprotect",
                &[
                    ("space", &format!("{:?}", packet.space)),
                    ("pn", &packet.packet_number.to_string()),
                    ("phase", &packet.key_phase.to_string()),
                ],
            );
        }

        let result: AtpOutcome<UnprotectedPacket> = self
            .provider
            .unprotect_packet(packet, associated_data)
            .map_err(|e| self.map_tls_error(e))
            .into();

        if let Outcome::Ok(_) = &result {
            self.accepted_packets
                .entry(packet.space)
                .or_default()
                .accept(packet.packet_number);
        }

        if self.config.enable_proof_logging {
            match &result {
                Outcome::Ok(unprotected) => {
                    cx.trace(&format!(
                        "packet unprotected: space={:?} pn={} payload_len={}",
                        packet.space,
                        packet.packet_number,
                        unprotected.plaintext.len()
                    ));
                }
                Outcome::Err(err) => {
                    cx.trace(&format!("packet unprotection failed: {:?}", err));
                }
                Outcome::Cancelled(_) | Outcome::Panicked(_) => {}
            }
        }

        result
    }

    /// Generate header protection mask with ATP error handling.
    pub async fn header_protection_mask(
        &self,
        cx: &Cx,
        space: PacketProtectionSpace,
        sample: &[u8],
    ) -> AtpOutcome<HeaderProtectionMask> {
        if cx.trace_buffer().is_some() {
            cx.trace_with_fields(
                "atp_packet_protection_header_mask",
                &[
                    ("space", &format!("{:?}", space)),
                    ("sample_len", &sample.len().to_string()),
                ],
            );
        }

        self.provider
            .header_protection_mask(space, sample)
            .map_err(|e| self.map_tls_error(e))
            .into()
    }

    /// Update keys for next phase with ATP error handling.
    pub async fn update_key(
        &mut self,
        cx: &Cx,
        space: PacketProtectionSpace,
        next_phase: bool,
    ) -> AtpOutcome<ProtectionKeySnapshot> {
        if cx.trace_buffer().is_some() {
            cx.trace_with_fields(
                "atp_packet_protection_update_key",
                &[
                    ("space", &format!("{:?}", space)),
                    ("phase", &next_phase.to_string()),
                ],
            );
        }

        let result: AtpOutcome<ProtectionKeySnapshot> = self
            .provider
            .update_key(space, next_phase)
            .map_err(|e| self.map_tls_error(e))
            .into();

        if self.config.enable_proof_logging {
            match &result {
                Outcome::Ok(snapshot) => {
                    cx.trace(&format!(
                        "key updated: space={:?} phase={} gen={}",
                        snapshot.space, snapshot.key_phase, snapshot.generation
                    ));
                }
                Outcome::Err(err) => {
                    cx.trace(&format!("key update failed: {:?}", err));
                }
                Outcome::Cancelled(_) | Outcome::Panicked(_) => {}
            }
        }

        result
    }

    /// Discard keys for a packet space with ATP error handling.
    pub async fn discard_keys(&mut self, cx: &Cx, space: PacketProtectionSpace) -> AtpOutcome<()> {
        cx.trace(&format!(
            "atp_packet_protection_discard_keys space={:?}",
            space
        ));

        self.provider
            .discard_keys(space)
            .map_err(|e| self.map_tls_error(e))
            .into()
    }

    /// Map QuicTlsError to AtpError with appropriate classification.
    fn map_tls_error(&self, error: QuicTlsError) -> AtpError {
        match error {
            QuicTlsError::HandshakeNotConfirmed
            | QuicTlsError::InvalidTransition { .. }
            | QuicTlsError::StalePeerKeyPhase(_)
            | QuicTlsError::ServerCertificateUnverified => {
                AtpError::Protocol(ProtocolError::SessionStateMismatch)
            }
            QuicTlsError::ServerIdentityRootStoreEmpty
            | QuicTlsError::ServerCertificateChainEmpty
            | QuicTlsError::InvalidServerName
            | QuicTlsError::ServerCertificateRejected { .. } => {
                AtpError::Auth(AuthError::InvalidCertificate)
            }
            QuicTlsError::MissingKeys { .. } | QuicTlsError::KeyDiscarded { .. } => {
                AtpError::Protocol(ProtocolError::UnexpectedFrame)
            }
            QuicTlsError::BadPacketTag { .. } | QuicTlsError::WrongKeyPhase { .. } => {
                AtpError::Protocol(ProtocolError::InvalidFrameType)
            }
            QuicTlsError::TranscriptMismatch { .. } => {
                AtpError::Protocol(ProtocolError::ProtocolVersionMismatch)
            }
            QuicTlsError::HeaderProtectionSampleTooShort { .. } => {
                AtpError::Protocol(ProtocolError::MalformedFrame)
            }
            QuicTlsError::CryptoProviderFailure { .. } => {
                AtpError::Protocol(ProtocolError::InvalidFrameType)
            }
        }
    }
}

/// Integration with ATP QUIC connection state.
impl AtpPacketProtection {
    /// Create client-side packet protection for ATP connections.
    pub fn new_client(use_deterministic: bool) -> AtpOutcome<Self> {
        let config = AtpPacketProtectionConfig {
            use_deterministic,
            enable_transcript_verification: true,
            enable_proof_logging: true,
            provider_options: if use_deterministic {
                ProviderOptions::Deterministic {
                    scenario: "atp-client".to_string(),
                }
            } else {
                #[cfg(feature = "tls")]
                {
                    ProviderOptions::Rustls {
                        side: RustlsQuicProviderSide::Client,
                    }
                }
                #[cfg(not(feature = "tls"))]
                {
                    ProviderOptions::Deterministic {
                        scenario: "atp-client".to_string(),
                    }
                }
            },
        };
        Self::new(config)
    }

    /// Create server-side packet protection for ATP connections.
    pub fn new_server(use_deterministic: bool) -> AtpOutcome<Self> {
        let config = AtpPacketProtectionConfig {
            use_deterministic,
            enable_transcript_verification: true,
            enable_proof_logging: true,
            provider_options: if use_deterministic {
                ProviderOptions::Deterministic {
                    scenario: "atp-server".to_string(),
                }
            } else {
                #[cfg(feature = "tls")]
                {
                    ProviderOptions::Rustls {
                        side: RustlsQuicProviderSide::Server,
                    }
                }
                #[cfg(not(feature = "tls"))]
                {
                    ProviderOptions::Deterministic {
                        scenario: "atp-server".to_string(),
                    }
                }
            },
        };
        Self::new(config)
    }

    /// Build packet protection around an already-established provider — e.g. the
    /// `RustlsQuicCryptoProvider` produced by a completed handshake, holding the
    /// derived Handshake/1-RTT keys. This hands the handshake-derived keys to the
    /// data plane without re-deriving them, which is how a real (wire-driven)
    /// handshake's keys reach `ConnectionRouter::install_packet_protection`.
    #[must_use]
    pub fn from_provider(
        provider: Box<dyn QuicPacketProtectionProvider + Send + Sync>,
        config: AtpPacketProtectionConfig,
    ) -> Self {
        let provider_kind = provider.provider_kind();
        Self {
            provider,
            config,
            provider_kind,
            provider_profile_traced: false,
            accepted_packets: BTreeMap::new(),
        }
    }
}

const fn trace_bool(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::{Bytes, BytesMut};
    use crate::cx::{Cx, cap};
    use crate::net::atp::protocol::quic_frames::QuicFrame;
    use crate::net::atp::protocol::varint::VarInt;
    use crate::trace::TraceBufferHandle;
    use crate::types::{Budget, RegionId, TaskId};

    fn test_cx() -> Cx<cap::All> {
        Cx::new(
            RegionId::new_for_test(0, 1),
            TaskId::testing_default(),
            Budget::INFINITE,
        )
    }

    fn encoded_application_payload() -> Vec<u8> {
        let mut payload = BytesMut::new();
        QuicFrame::Stream {
            stream_id: VarInt::from_u64_unchecked(0),
            offset: Some(VarInt::from_u64_unchecked(0)),
            data: Bytes::from_static(b"control-stream-bytes"),
            fin: false,
        }
        .encode(&mut payload)
        .expect("encode STREAM frame");
        QuicFrame::Datagram {
            data: Bytes::from_static(b"raptorq-symbol-datagram"),
        }
        .encode(&mut payload)
        .expect("encode DATAGRAM frame");
        payload.to_vec()
    }

    async fn deterministic_one_rtt_protection(
        cx: &Cx<cap::All>,
        seed: &'static [u8],
    ) -> AtpPacketProtection {
        let mut protection =
            AtpPacketProtection::new_client(true).expect("deterministic protection");
        let mut transcript = QuicHandshakeTranscript::new();
        transcript.record("client-finished", b"client");
        transcript.record("server-finished", b"server");
        let snapshot = protection
            .derive_keys(cx, PacketProtectionSpace::OneRtt, &transcript, seed)
            .await
            .expect("derive 1-rtt keys");
        assert_eq!(snapshot.space, PacketProtectionSpace::OneRtt);
        assert!(!snapshot.key_phase);
        protection
    }

    async fn deterministic_one_rtt_protection_with_logging(
        cx: &Cx<cap::All>,
        seed: &'static [u8],
        enable_proof_logging: bool,
    ) -> AtpPacketProtection {
        let mut protection = AtpPacketProtection::new(AtpPacketProtectionConfig {
            use_deterministic: true,
            enable_transcript_verification: true,
            enable_proof_logging,
            provider_options: ProviderOptions::Deterministic {
                scenario: "a4-packet-protection".to_string(),
            },
        })
        .expect("deterministic protection");
        let mut transcript = QuicHandshakeTranscript::new();
        transcript.record("client-finished", b"client");
        transcript.record("server-finished", b"server");
        protection
            .derive_keys(cx, PacketProtectionSpace::OneRtt, &transcript, seed)
            .await
            .expect("derive 1-rtt keys");
        protection
    }

    #[test]
    fn test_packet_protection_config_defaults() {
        let config = AtpPacketProtectionConfig::default();
        assert!(!config.use_deterministic);
        assert!(config.enable_transcript_verification);
        assert!(config.enable_proof_logging);
    }

    #[test]
    fn aead_provider_profile_identifies_deterministic_test_path() {
        let protection = AtpPacketProtection::new_client(true).expect("deterministic protection");
        let profile = protection.aead_provider_profile();

        assert_eq!(profile.provider_kind, "deterministic-lab");
        assert_eq!(profile.backend, "deterministic-test-provider");
        assert_eq!(profile.tls_cipher_suite, "none");
        assert_eq!(profile.quic_aead, "deterministic-xor-tag");
        assert!(!profile.hardware.aes_gcm_capable());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn rustls_aead_provider_profile_reports_aes_gcm_hardware_probe() {
        let protection = AtpPacketProtection::new_client(false).expect("rustls protection");
        let profile = protection.aead_provider_profile();

        assert_eq!(profile.provider_kind, "rustls-quic-ring");
        assert_eq!(profile.backend, "rustls/ring");
        assert_eq!(profile.tls_cipher_suite, "TLS13_AES_128_GCM_SHA256");
        assert_eq!(profile.quic_aead, "AES-128-GCM");
        assert_ne!(profile.hardware.probe, "not-probed");
    }

    #[test]
    fn test_deterministic_protection_lifecycle() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let protection =
                AtpPacketProtection::new_client(true).expect("deterministic protection");

            assert_eq!(protection.provider_kind(), "deterministic");

            // Test transcript verification
            let transcript = QuicHandshakeTranscript::new();
            protection
                .verify_transcript(&cx, transcript.digest())
                .await
                .expect("transcript verification");
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_rustls_protection_creation() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let client = AtpPacketProtection::new_client(false).expect("rustls client protection");
            let server = AtpPacketProtection::new_server(false).expect("rustls server protection");

            assert_eq!(client.provider_kind(), "rustls-quic-ring");
            assert_eq!(server.provider_kind(), "rustls-quic-ring");

            let profile = client.aead_provider_profile();
            assert_eq!(profile.provider_kind, "rustls-quic-ring");
            assert_eq!(profile.backend, "rustls/ring");
            assert_eq!(profile.tls_cipher_suite, "TLS13_AES_128_GCM_SHA256");
            assert_eq!(profile.quic_aead, "AES-128-GCM");
            assert!(!profile.hardware.probe.is_empty());

            // Test basic operations don't panic
            let transcript = QuicHandshakeTranscript::new();
            client
                .verify_transcript(&cx, transcript.digest())
                .await
                .expect("client transcript verification");
            server
                .verify_transcript(&cx, transcript.digest())
                .await
                .expect("server transcript verification");
        });
    }

    #[test]
    fn test_error_mapping() {
        futures_lite::future::block_on(async {
            let _cx = test_cx();
            let protection =
                AtpPacketProtection::new_client(true).expect("deterministic protection");

            // Test error mapping
            let tls_error = QuicTlsError::HandshakeNotConfirmed;
            let atp_error = protection.map_tls_error(tls_error);

            match atp_error {
                AtpError::Protocol(ProtocolError::SessionStateMismatch) => {
                    // Expected
                }
                _ => panic!("Unexpected error mapping: {:?}", atp_error),
            }
        });
    }

    #[test]
    fn replay_window_is_bounded_and_stale_packets_fail_closed() {
        let mut window = PacketReplayWindow::default();
        let packet_count = REPLAY_WINDOW_CAPACITY as u64 + 8;

        for packet_number in 0..packet_count {
            assert!(
                !window.rejects(packet_number),
                "fresh packet {packet_number} should be inside the replay window"
            );
            window.accept(packet_number);
        }

        assert!(window.len() <= REPLAY_WINDOW_CAPACITY);
        assert!(window.rejects(0), "stale packet below the window is closed");
        assert!(
            window.rejects(packet_count - 1),
            "duplicate packet number is closed"
        );
        assert!(
            !window.rejects(packet_count),
            "next packet number is still accepted"
        );
    }

    #[test]
    fn one_rtt_application_payload_roundtrips_and_replay_fails_closed() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let mut protection =
                deterministic_one_rtt_protection(&cx, b"one-rtt-roundtrip-seed").await;
            let payload = encoded_application_payload();
            let aad = b"short-header pn=41 key_phase=0";

            let protected = protection
                .protect_packet(
                    &cx,
                    PacketProtectionRequest {
                        space: PacketProtectionSpace::OneRtt,
                        key_phase: false,
                        packet_number: 41,
                        associated_data: aad,
                        payload: &payload,
                    },
                )
                .await
                .expect("protect 1-rtt app payload");

            assert_eq!(protected.space, PacketProtectionSpace::OneRtt);
            assert_ne!(
                protected.ciphertext, payload,
                "payload should be protected, not copied as plaintext"
            );

            let unprotected = protection
                .unprotect_packet(&cx, &protected, aad)
                .await
                .expect("unprotect 1-rtt app payload");
            assert_eq!(unprotected.plaintext, payload);
            assert_eq!(protection.accepted_packet_count(), 1);

            let replay = protection
                .unprotect_packet(&cx, &protected, aad)
                .await
                .expect_err("same packet number in same space must be rejected");
            assert_eq!(replay, AtpError::Auth(AuthError::ReplayedNonce));
            assert_eq!(protection.accepted_packet_count(), 1);
        });
    }

    #[test]
    fn protect_packets_batches_ordered_one_rtt_payloads() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let mut protection = deterministic_one_rtt_protection(&cx, b"one-rtt-batch-seed").await;
            let payloads = [
                encoded_application_payload(),
                b"second application payload".to_vec(),
                b"third application payload".to_vec(),
            ];
            let associated_data = [
                b"batch short header pn=100".as_slice(),
                b"batch short header pn=101".as_slice(),
                b"batch short header pn=102".as_slice(),
            ];
            let requests = [
                PacketProtectionRequest {
                    space: PacketProtectionSpace::OneRtt,
                    key_phase: false,
                    packet_number: 100,
                    associated_data: associated_data[0],
                    payload: &payloads[0],
                },
                PacketProtectionRequest {
                    space: PacketProtectionSpace::OneRtt,
                    key_phase: false,
                    packet_number: 101,
                    associated_data: associated_data[1],
                    payload: &payloads[1],
                },
                PacketProtectionRequest {
                    space: PacketProtectionSpace::OneRtt,
                    key_phase: false,
                    packet_number: 102,
                    associated_data: associated_data[2],
                    payload: &payloads[2],
                },
            ];

            let protected = protection
                .protect_packets(&cx, &requests)
                .expect("batch protects");

            assert_eq!(protected.len(), requests.len());
            assert_eq!(
                protection.accepted_packet_count(),
                0,
                "protecting packets must not mutate the receive replay window"
            );

            for (idx, packet) in protected.iter().enumerate() {
                assert_eq!(packet.packet_number, requests[idx].packet_number);
                assert_ne!(packet.ciphertext, payloads[idx]);
                let unprotected = protection
                    .unprotect_packet(&cx, packet, associated_data[idx])
                    .await
                    .expect("batched packet unprotects");
                assert_eq!(unprotected.plaintext, payloads[idx]);
            }
            assert_eq!(protection.accepted_packet_count(), requests.len());
        });
    }

    #[test]
    fn replay_guard_is_active_when_proof_logging_is_disabled() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let mut protection = deterministic_one_rtt_protection_with_logging(
                &cx,
                b"proof-logging-disabled-seed",
                false,
            )
            .await;
            let payload = encoded_application_payload();
            let aad = b"short-header pn=55 key_phase=0";
            let protected = protection
                .protect_packet(
                    &cx,
                    PacketProtectionRequest {
                        space: PacketProtectionSpace::OneRtt,
                        key_phase: false,
                        packet_number: 55,
                        associated_data: aad,
                        payload: &payload,
                    },
                )
                .await
                .expect("protect");
            protection
                .unprotect_packet(&cx, &protected, aad)
                .await
                .expect("first decrypt succeeds");
            let replay = protection
                .unprotect_packet(&cx, &protected, aad)
                .await
                .expect_err("proof logging must not gate anti-replay");
            assert_eq!(replay, AtpError::Auth(AuthError::ReplayedNonce));
        });
    }

    #[test]
    fn tampered_ciphertext_fails_closed_without_poisoning_replay_guard() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let mut protection = deterministic_one_rtt_protection(&cx, b"tamper-seed").await;
            let payload = encoded_application_payload();
            let aad = b"short-header pn=7 key_phase=0";
            let protected = protection
                .protect_packet(
                    &cx,
                    PacketProtectionRequest {
                        space: PacketProtectionSpace::OneRtt,
                        key_phase: false,
                        packet_number: 7,
                        associated_data: aad,
                        payload: &payload,
                    },
                )
                .await
                .expect("protect");

            let mut tampered = protected.clone();
            tampered.ciphertext[0] ^= 0x5a;
            let err = protection
                .unprotect_packet(&cx, &tampered, aad)
                .await
                .expect_err("tampered ciphertext must fail authentication");
            assert_eq!(
                err,
                AtpError::Protocol(ProtocolError::InvalidFrameType),
                "BadPacketTag maps to fail-closed protocol rejection"
            );
            assert_eq!(
                protection.accepted_packet_count(),
                0,
                "failed authentication must not poison replay state"
            );

            let unprotected = protection
                .unprotect_packet(&cx, &protected, aad)
                .await
                .expect("original packet still decrypts after tampered attempt");
            assert_eq!(unprotected.plaintext, payload);
            assert_eq!(protection.accepted_packet_count(), 1);
        });
    }

    #[test]
    fn header_protection_and_key_phase_update_are_covered() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let mut protection = deterministic_one_rtt_protection(&cx, b"key-phase-seed").await;
            let mask = protection
                .header_protection_mask(&cx, PacketProtectionSpace::OneRtt, b"1234567890abcdef")
                .await
                .expect("header mask");
            assert_ne!(mask.bytes, [0; 5]);

            let update = protection
                .update_key(&cx, PacketProtectionSpace::OneRtt, true)
                .await
                .expect("key update");
            assert!(update.key_phase);
            assert_eq!(update.generation, 1);

            let payload = encoded_application_payload();
            let protected = protection
                .protect_packet(
                    &cx,
                    PacketProtectionRequest {
                        space: PacketProtectionSpace::OneRtt,
                        key_phase: true,
                        packet_number: 9,
                        associated_data: b"short-header pn=9 key_phase=1",
                        payload: &payload,
                    },
                )
                .await
                .expect("protect updated phase");
            let unprotected = protection
                .unprotect_packet(&cx, &protected, b"short-header pn=9 key_phase=1")
                .await
                .expect("unprotect updated phase");
            assert_eq!(unprotected.plaintext, payload);
            assert!(unprotected.proof.key_phase);
            assert_eq!(unprotected.proof.generation, 1);
        });
    }

    #[test]
    fn packet_number_replay_is_rejected_across_key_phase() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let mut protection = deterministic_one_rtt_protection(&cx, b"phase-replay-seed").await;
            let payload = encoded_application_payload();
            let first = protection
                .protect_packet(
                    &cx,
                    PacketProtectionRequest {
                        space: PacketProtectionSpace::OneRtt,
                        key_phase: false,
                        packet_number: 12,
                        associated_data: b"pn=12 phase=0",
                        payload: &payload,
                    },
                )
                .await
                .expect("protect first phase");
            protection
                .unprotect_packet(&cx, &first, b"pn=12 phase=0")
                .await
                .expect("accept first phase packet");

            protection
                .update_key(&cx, PacketProtectionSpace::OneRtt, true)
                .await
                .expect("update phase");
            let second = protection
                .protect_packet(
                    &cx,
                    PacketProtectionRequest {
                        space: PacketProtectionSpace::OneRtt,
                        key_phase: true,
                        packet_number: 12,
                        associated_data: b"pn=12 phase=1",
                        payload: &payload,
                    },
                )
                .await
                .expect("protect reused packet number with new phase");
            let err = protection
                .unprotect_packet(&cx, &second, b"pn=12 phase=1")
                .await
                .expect_err("packet numbers cannot be reused inside a PN space");
            assert_eq!(err, AtpError::Auth(AuthError::ReplayedNonce));
        });
    }

    #[test]
    fn packet_protection_traces_are_redacted() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let trace = TraceBufferHandle::new(16);
            cx.set_trace_buffer(trace.clone());
            let secret_seed = b"super-secret-a4-seed";
            let sensitive_payload = b"ATP_QUIC_TRACE_SECRET_PAYLOAD";
            let mut protection = deterministic_one_rtt_protection(&cx, secret_seed).await;
            let protected = protection
                .protect_packet(
                    &cx,
                    PacketProtectionRequest {
                        space: PacketProtectionSpace::OneRtt,
                        key_phase: false,
                        packet_number: 31,
                        associated_data: b"trace-aad",
                        payload: sensitive_payload,
                    },
                )
                .await
                .expect("protect");
            protection
                .unprotect_packet(&cx, &protected, b"trace-aad")
                .await
                .expect("unprotect");
            let replay = protection
                .unprotect_packet(&cx, &protected, b"trace-aad")
                .await
                .expect_err("replay");
            assert_eq!(replay, AtpError::Auth(AuthError::ReplayedNonce));

            let rendered = trace
                .snapshot()
                .iter()
                .map(|event| format!("{:?}", event.data))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(rendered.contains("atp_packet_protection_protect"));
            assert!(rendered.contains("atp_packet_protection_unprotect"));
            assert!(rendered.contains("atp_packet_protection_replay_rejected"));
            assert!(
                !rendered.contains("super-secret-a4-seed"),
                "trace must not contain key seed material: {rendered}"
            );
            assert!(
                !rendered.contains("ATP_QUIC_TRACE_SECRET_PAYLOAD"),
                "trace must not contain plaintext payload material: {rendered}"
            );
        });
    }
}
