//! ATP-QUIC Packet Protection Integration
//!
//! This module integrates the QUIC packet protection provider with ATP's native QUIC
//! implementation, providing the crypto boundary that keeps ATP protocol state separate
//! from cryptographic primitive operations.

use crate::cx::Cx;
use crate::net::atp::protocol::outcome::{AtpError, AtpOutcome, ProtocolError};
use crate::net::quic_native::tls::{
    HeaderProtectionMask, PacketProtectionRequest, PacketProtectionSpace, ProtectedPacket,
    ProtectionKeySnapshot, QuicHandshakeTranscript, QuicPacketProtectionProvider, QuicTlsError,
    TranscriptHash, UnprotectedPacket,
};

#[cfg(test)]
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
}

impl AtpPacketProtection {
    /// Create a new ATP packet protection instance.
    pub fn new(config: AtpPacketProtectionConfig) -> AtpOutcome<Self> {
        let (provider, provider_kind): (
            Box<dyn QuicPacketProtectionProvider + Send + Sync>,
            &'static str,
        ) = if config.use_deterministic {
            #[cfg(test)]
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
            #[cfg(not(test))]
            {
                // SECURITY: Deterministic crypto must never be used in production builds
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
                #[cfg(test)]
                ProviderOptions::Deterministic { .. } => {
                    let provider = DeterministicQuicCryptoProvider::new();
                    (Box::new(provider), "deterministic")
                }
                #[cfg(not(test))]
                ProviderOptions::Deterministic { .. } => {
                    return Outcome::err(AtpError::Protocol(ProtocolError::SessionStateMismatch));
                }
            }
            #[cfg(all(not(feature = "tls"), test))]
            {
                match &config.provider_options {
                    ProviderOptions::Deterministic { .. } => {
                        let provider = DeterministicQuicCryptoProvider::new();
                        (Box::new(provider), "deterministic")
                    }
                }
            }
            #[cfg(all(not(feature = "tls"), not(test)))]
            {
                // SECURITY: Deterministic crypto must never be used in production builds
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
        })
    }

    /// Get the provider kind for logging.
    pub fn provider_kind(&self) -> &'static str {
        self.provider_kind
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

    /// Protect a packet with ATP error handling.
    pub async fn protect_packet(
        &mut self,
        cx: &Cx,
        request: PacketProtectionRequest<'_>,
    ) -> AtpOutcome<ProtectedPacket> {
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

    /// Unprotect a packet with ATP error handling.
    pub async fn unprotect_packet(
        &mut self,
        cx: &Cx,
        packet: &ProtectedPacket,
        associated_data: &[u8],
    ) -> AtpOutcome<UnprotectedPacket> {
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
            | QuicTlsError::StalePeerKeyPhase(_) => {
                AtpError::Protocol(ProtocolError::SessionStateMismatch)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::{Cx, cap};
    use crate::types::{Budget, RegionId, TaskId};

    fn test_cx() -> Cx<cap::All> {
        Cx::new(
            RegionId::testing_default(),
            TaskId::testing_default(),
            Budget::INFINITE,
        )
    }

    #[test]
    fn test_packet_protection_config_defaults() {
        let config = AtpPacketProtectionConfig::default();
        assert!(!config.use_deterministic);
        assert!(config.enable_transcript_verification);
        assert!(config.enable_proof_logging);
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
}
