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
const PARALLEL_UNPROTECT_MIN_PACKETS: usize = 4;
const PARALLEL_UNPROTECT_TARGET_CHUNK_PACKETS: usize = 8;

/// AEAD usage limits for the QUIC AES-128-GCM suite the rustls provider
/// selects (RFC 9001 §6.6). An endpoint MUST initiate a key update before
/// protecting more than `AEAD_CONFIDENTIALITY_LIMIT` packets under one key,
/// and MUST close the connection once `AEAD_INTEGRITY_LIMIT` packets have
/// failed authentication under one key.
pub(crate) const AEAD_CONFIDENTIALITY_LIMIT: u64 = 1 << 23;
pub(crate) const AEAD_INTEGRITY_LIMIT: u64 = 1 << 52;
/// Default soft threshold at which the send path initiates a key update:
/// seven-eighths of the confidentiality limit, leaving margin for the update
/// to be committed and for in-flight packets still riding the old key.
const DEFAULT_KEY_UPDATE_CONFIDENTIALITY_THRESHOLD: u64 =
    AEAD_CONFIDENTIALITY_LIMIT - (AEAD_CONFIDENTIALITY_LIMIT >> 3);

#[cfg(any(test, feature = "test-internals"))]
use crate::net::quic_native::tls::DeterministicQuicCryptoProvider;

#[cfg(feature = "tls")]
use crate::net::quic_native::tls::{RustlsQuicCryptoProvider, RustlsQuicProviderSide};
use crate::types::outcome::Outcome;

/// Packet-unprotection request borrowed by the batch receive hot path.
#[derive(Debug, Clone, Copy)]
pub struct PacketUnprotectionRequest<'a> {
    /// Protected packet to authenticate and decrypt.
    pub packet: &'a ProtectedPacket,
    /// Header bytes authenticated but not encrypted.
    pub associated_data: &'a [u8],
}

#[derive(Debug, Clone)]
struct OwnedPacketUnprotectionRequest {
    index: usize,
    packet: ProtectedPacket,
    associated_data: Vec<u8>,
}

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
    /// Packets protected under the current local send key, per space (RFC 9001
    /// §6.6 confidentiality accounting). Reset by [`Self::note_local_key_update`]
    /// once the send key has rotated to the next generation.
    protected_under_current_key: BTreeMap<PacketProtectionSpace, u64>,
    /// Authentication failures observed under the current receive key, per
    /// space (RFC 9001 §6.6 integrity accounting). Reset by
    /// [`Self::note_peer_key_update`] once the receive key has rotated.
    auth_failures_under_current_key: BTreeMap<PacketProtectionSpace, u64>,
    /// Soft threshold of protected packets after which the send path should
    /// initiate a key update. Defaults to
    /// [`DEFAULT_KEY_UPDATE_CONFIDENTIALITY_THRESHOLD`].
    key_update_confidentiality_threshold: u64,
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

fn packet_unprotect_parallel_width_for_cx(cx: &Cx, packets: usize) -> usize {
    if packets < PARALLEL_UNPROTECT_MIN_PACKETS {
        return 1;
    }
    let Some(pool) = cx.blocking_pool_handle() else {
        return 1;
    };
    let mut cap = pool.current_max_threads();
    if !pool.is_explicitly_sized() {
        // The runtime's default pool is sized for blocking I/O (up to 512
        // threads), not for CPUs (kpmoy5.1.15).
        cap = cap.min(host_cpu_parallelism());
    }
    let available_threads = cap.saturating_sub(pool.busy_threads()).max(1);
    let chunks_by_size = packets
        .div_ceil(PARALLEL_UNPROTECT_TARGET_CHUNK_PACKETS)
        .max(1);
    available_threads.min(chunks_by_size).max(1)
}

fn host_cpu_parallelism() -> usize {
    static CORES: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CORES
        .get_or_init(|| std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get))
}

fn unprotect_packet_chunk(
    mut provider: Box<dyn QuicPacketProtectionProvider + Send + Sync>,
    requests: Vec<OwnedPacketUnprotectionRequest>,
) -> Vec<(usize, AtpOutcome<UnprotectedPacket>)> {
    requests
        .into_iter()
        .map(|request| {
            let result = provider
                .unprotect_packet(&request.packet, &request.associated_data)
                .map_err(map_tls_error_to_atp)
                .into();
            (request.index, result)
        })
        .collect()
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
            protected_under_current_key: BTreeMap::new(),
            auth_failures_under_current_key: BTreeMap::new(),
            key_update_confidentiality_threshold: DEFAULT_KEY_UPDATE_CONFIDENTIALITY_THRESHOLD,
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

    /// Largest packet number authenticated so far in `space`.
    ///
    /// This is the reference a receiver reconstructs truncated packet numbers
    /// against (RFC 9000 §A.3). `None` until the first packet in that space
    /// authenticates.
    #[must_use]
    pub fn highest_accepted_packet_number(&self, space: PacketProtectionSpace) -> Option<u64> {
        self.accepted_packets
            .get(&space)
            .and_then(|window| window.highest_seen)
    }

    /// Packets protected under the current local send key in `space` (RFC 9001
    /// §6.6 confidentiality accounting).
    #[must_use]
    pub fn protected_packet_count(&self, space: PacketProtectionSpace) -> u64 {
        self.protected_under_current_key
            .get(&space)
            .copied()
            .unwrap_or(0)
    }

    /// Whether the send path should initiate a key update in `space`: the
    /// number of packets protected under the current key has reached the soft
    /// confidentiality threshold (RFC 9001 §6.6). The threshold sits below the
    /// hard [`Self::confidentiality_limit_reached`] limit so the rotation lands
    /// with margin.
    #[must_use]
    pub fn confidentiality_key_update_due(&self, space: PacketProtectionSpace) -> bool {
        self.protected_packet_count(space) >= self.key_update_confidentiality_threshold
    }

    /// Whether the hard confidentiality limit (RFC 9001 §6.6, `2^23` for
    /// AES-128-GCM) has been reached in `space`. Protecting a further packet
    /// under the same key is forbidden; a connection that cannot rotate MUST
    /// close.
    #[must_use]
    pub fn confidentiality_limit_reached(&self, space: PacketProtectionSpace) -> bool {
        self.protected_packet_count(space) >= AEAD_CONFIDENTIALITY_LIMIT
    }

    /// Authentication failures observed under the current receive key in
    /// `space` (RFC 9001 §6.6 integrity accounting).
    #[must_use]
    pub fn auth_failure_count(&self, space: PacketProtectionSpace) -> u64 {
        self.auth_failures_under_current_key
            .get(&space)
            .copied()
            .unwrap_or(0)
    }

    /// Whether the integrity limit (RFC 9001 §6.6, `2^52` for AES-128-GCM) has
    /// been reached in `space`. The connection MUST close.
    #[must_use]
    pub fn integrity_limit_reached(&self, space: PacketProtectionSpace) -> bool {
        self.auth_failure_count(space) >= AEAD_INTEGRITY_LIMIT
    }

    /// Reset the confidentiality counter for `space` after the local send key
    /// has rotated to the next generation.
    pub fn note_local_key_update(&mut self, space: PacketProtectionSpace) {
        self.protected_under_current_key.insert(space, 0);
    }

    /// Reset the integrity counter for `space` after the receive key has
    /// rotated to the next generation.
    pub fn note_peer_key_update(&mut self, space: PacketProtectionSpace) {
        self.auth_failures_under_current_key.insert(space, 0);
    }

    /// Advance the packet protection provider to the next key generation for
    /// `space`/`next_phase` on the current task.
    ///
    /// This is the synchronous counterpart to [`update_key`](Self::update_key):
    /// the QUIC 1-RTT flush and receive hot paths are synchronous and cannot
    /// await, so they install next-generation keys through this primitive. It
    /// performs no RFC 9001 §6.6 counter bookkeeping — callers reset the
    /// confidentiality counter with
    /// [`note_local_key_update`](Self::note_local_key_update) once they begin
    /// sending under the new key, and the integrity counter with
    /// [`note_peer_key_update`](Self::note_peer_key_update) once a received
    /// packet has authenticated under it (asupersync-1bheeo).
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub(crate) fn update_key_now(
        &mut self,
        cx: &Cx,
        space: PacketProtectionSpace,
        next_phase: bool,
    ) -> AtpOutcome<ProtectionKeySnapshot> {
        if cx.trace_buffer().is_some() {
            cx.trace_with_fields(
                "atp_packet_protection_update_key_now",
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
            if let Outcome::Ok(snapshot) = &result {
                cx.trace(&format!(
                    "key updated (sync): space={:?} phase={} gen={}",
                    snapshot.space, snapshot.key_phase, snapshot.generation
                ));
            }
        }

        result
    }

    /// Whether the next-generation keys for `space`/`key_phase` are already
    /// installed, derived purely from provider state so it can never fall out of
    /// sync with the send- and receive-side rotation paths.
    ///
    /// QUIC key phases alternate (`0 → 1 → 0 → …`) while the generation counter
    /// only increases, and each phase owns a single provider key slot. The
    /// next-generation keys for `key_phase` are therefore installed exactly when
    /// that phase's slot holds a strictly newer generation than the opposite
    /// phase's slot. This keeps [`ensure_next_gen_keys`](Self::ensure_next_gen_keys)
    /// idempotent across a rotation: a forged or duplicated key-phase-flip packet
    /// observes the already-newer generation and does not advance the
    /// bidirectional, single-shot rustls key ratchet a second time (which would
    /// desynchronize us from the peer) (RFC 9001 §6.3, asupersync-1bheeo).
    ///
    /// `key_phase` is the rotation **target** — the phase opposite the current
    /// one. Passing the current phase is meaningless (a rotation never targets
    /// the phase already in use) and the result is not defined for that misuse.
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    #[must_use]
    pub(crate) fn next_gen_keys_installed(
        &self,
        space: PacketProtectionSpace,
        key_phase: bool,
    ) -> bool {
        let Some(this_gen) = self
            .provider
            .key_snapshot(space, key_phase)
            .ok()
            .map(|snapshot| snapshot.generation)
        else {
            // The target phase has no keys yet: the next generation is not
            // installed.
            return false;
        };
        match self
            .provider
            .key_snapshot(space, !key_phase)
            .ok()
            .map(|snapshot| snapshot.generation)
        {
            Some(other_gen) => this_gen > other_gen,
            // The opposite (current) phase is absent: any keys under the target
            // phase are already the newest generation.
            None => true,
        }
    }

    /// Idempotently install next-generation keys for `space`/`key_phase`.
    ///
    /// Called by both the flush path (local-initiated update) and the receive
    /// path (peer-initiated update). Because the rustls key ratchet advances on
    /// every `update_key` call and drives both directions at once, this must run
    /// at most once per rotation;
    /// [`next_gen_keys_installed`](Self::next_gen_keys_installed) gates the
    /// ratchet so repeated candidate packets reuse the installed keys rather than
    /// desynchronizing from the peer (RFC 9001 §6.3, asupersync-1bheeo).
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub(crate) fn ensure_next_gen_keys(
        &mut self,
        cx: &Cx,
        space: PacketProtectionSpace,
        key_phase: bool,
    ) -> AtpOutcome<()> {
        if self.next_gen_keys_installed(space, key_phase) {
            return Outcome::ok(());
        }
        self.update_key_now(cx, space, key_phase).map(|_| ())
    }

    /// Override the soft key-update threshold. Tests exercise rotation without
    /// protecting millions of packets; production always uses the default.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn set_key_update_confidentiality_threshold(&mut self, threshold: u64) {
        self.key_update_confidentiality_threshold = threshold;
    }

    /// Preload the confidentiality counter so a test can reach the hard limit
    /// without protecting millions of packets.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn set_protected_packet_count_for_test(
        &mut self,
        space: PacketProtectionSpace,
        count: u64,
    ) {
        self.protected_under_current_key.insert(space, count);
    }

    /// Preload the integrity counter so a test can reach the hard limit without
    /// forging millions of packets.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn set_auth_failure_count_for_test(&mut self, space: PacketProtectionSpace, count: u64) {
        self.auth_failures_under_current_key.insert(space, count);
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

        // RFC 9001 §6.6: count packets protected under the current local key so
        // the send path can rotate before the AEAD confidentiality limit.
        if let Outcome::Ok(_) = &result {
            let counter = self
                .protected_under_current_key
                .entry(request.space)
                .or_default();
            *counter = counter.saturating_add(1);
        }

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

    /// Unprotect a packet with ATP error handling on the current task.
    ///
    /// This synchronous primitive is used by the hot receive path when it has
    /// already pulled a socket batch. It preserves the same anti-replay update
    /// point as the async wrapper: a packet number is accepted only after
    /// authentication succeeds.
    pub fn unprotect_packet_now(
        &mut self,
        cx: &Cx,
        packet: &ProtectedPacket,
        associated_data: &[u8],
    ) -> AtpOutcome<UnprotectedPacket> {
        self.unprotect_packet_inner(cx, packet, associated_data, true)
    }

    /// Authenticate retained Handshake traffic for recovery classification only.
    ///
    /// Duplicate ACKs must still be distinguishable from duplicate CRYPTO
    /// flights. This does not admit frames for delivery: the caller may only
    /// inspect them to decide whether a retained flight needs retransmission.
    /// Normal receive APIs continue rejecting replayed packet numbers.
    pub(crate) fn inspect_handshake_packet_now(
        &mut self,
        cx: &Cx,
        packet: &ProtectedPacket,
        associated_data: &[u8],
    ) -> AtpOutcome<UnprotectedPacket> {
        if packet.space != PacketProtectionSpace::Handshake {
            return Outcome::err(AtpError::Protocol(ProtocolError::SessionStateMismatch));
        }
        self.unprotect_packet_inner(cx, packet, associated_data, false)
    }

    fn unprotect_packet_inner(
        &mut self,
        cx: &Cx,
        packet: &ProtectedPacket,
        associated_data: &[u8],
        reject_replays: bool,
    ) -> AtpOutcome<UnprotectedPacket> {
        self.trace_provider_profile_once(cx, "unprotect");

        if reject_replays
            && self
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

        match &result {
            Outcome::Ok(_) => {
                self.accepted_packets
                    .entry(packet.space)
                    .or_default()
                    .accept(packet.packet_number);
            }
            // RFC 9001 §6.6 integrity accounting: a post-replay-screen
            // authentication failure counts toward the integrity limit for the
            // current receive key.
            Outcome::Err(_) => {
                let counter = self
                    .auth_failures_under_current_key
                    .entry(packet.space)
                    .or_default();
                *counter = counter.saturating_add(1);
            }
            Outcome::Cancelled(_) | Outcome::Panicked(_) => {}
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

    /// Authenticate and decrypt a received 1-RTT datagram in place.
    ///
    /// `packet_data` is the full datagram (`header || ciphertext || tag`) with
    /// the header in `packet_data[..header_len]` serving as associated data.
    /// On success the plaintext occupies
    /// `packet_data[header_len..header_len + returned_len]`.
    ///
    /// Anti-replay semantics are identical to [`Self::unprotect_packet_now`]:
    /// the packet number is screened against the accepted window first and
    /// accepted only after authentication succeeds.
    pub fn unprotect_one_rtt_in_place_now(
        &mut self,
        cx: &Cx,
        key_phase: bool,
        packet_number: u64,
        packet_data: &mut [u8],
        header_len: usize,
    ) -> AtpOutcome<usize> {
        let space = PacketProtectionSpace::OneRtt;
        self.trace_provider_profile_once(cx, "unprotect");

        if self
            .accepted_packets
            .get(&space)
            .is_some_and(|window| window.rejects(packet_number))
        {
            if cx.trace_buffer().is_some() {
                cx.trace_with_fields(
                    "atp_packet_protection_replay_rejected",
                    &[
                        ("space", space.as_str()),
                        ("pn", &packet_number.to_string()),
                        ("phase", &key_phase.to_string()),
                    ],
                );
            }
            return Outcome::err(AtpError::Auth(AuthError::ReplayedNonce));
        }

        let result: AtpOutcome<usize> = self
            .provider
            .unprotect_packet_in_place(space, key_phase, packet_number, packet_data, header_len)
            .map_err(|e| self.map_tls_error(e))
            .into();

        match &result {
            Outcome::Ok(_) => {
                self.accepted_packets
                    .entry(space)
                    .or_default()
                    .accept(packet_number);
            }
            // RFC 9001 §6.6 integrity accounting (see `unprotect_packet_now`).
            Outcome::Err(_) => {
                let counter = self
                    .auth_failures_under_current_key
                    .entry(space)
                    .or_default();
                *counter = counter.saturating_add(1);
            }
            Outcome::Cancelled(_) | Outcome::Panicked(_) => {}
        }

        if self.config.enable_proof_logging {
            match &result {
                Outcome::Ok(plaintext_len) => {
                    cx.trace(&format!(
                        "packet unprotected: space={space:?} pn={packet_number} payload_len={plaintext_len}"
                    ));
                }
                Outcome::Err(err) => {
                    cx.trace(&format!("packet unprotection failed: {err:?}"));
                }
                Outcome::Cancelled(_) | Outcome::Panicked(_) => {}
            }
        }

        result
    }

    /// Unprotect a batch of packets with one ATP boundary call.
    ///
    /// Requests are processed in order. Each result is independent so a stray,
    /// replayed, or undecryptable packet drops exactly as it did in the
    /// per-packet receive loop without preventing later packets in the socket
    /// batch from being considered.
    #[must_use]
    pub fn unprotect_packets(
        &mut self,
        cx: &Cx,
        requests: &[PacketUnprotectionRequest<'_>],
    ) -> Vec<AtpOutcome<UnprotectedPacket>> {
        if cx.trace_buffer().is_some() {
            cx.trace_with_fields(
                "atp_packet_protection_unprotect_batch",
                &[("packets", &requests.len().to_string())],
            );
        }

        requests
            .iter()
            .map(|request| self.unprotect_packet_now(cx, request.packet, request.associated_data))
            .collect()
    }

    /// Unprotect a packet batch across the receiver blocking pool when safe.
    ///
    /// Anti-replay state remains serialized in this wrapper: packet numbers are
    /// screened before dispatch, duplicate packet numbers within the same batch
    /// fall back to the serial path, and the accepted replay window is updated
    /// in receive order only after worker decrypts return successfully.
    pub async fn unprotect_packets_parallel(
        &mut self,
        cx: &Cx,
        requests: &[PacketUnprotectionRequest<'_>],
    ) -> Vec<AtpOutcome<UnprotectedPacket>> {
        let width = packet_unprotect_parallel_width_for_cx(cx, requests.len());
        if width <= 1 || self.provider.clone_for_parallel_unprotect().is_none() {
            return self.unprotect_packets(cx, requests);
        }

        if cx.trace_buffer().is_some() {
            cx.trace_with_fields(
                "atp_packet_protection_unprotect_batch_parallel",
                &[
                    ("packets", &requests.len().to_string()),
                    ("workers", &width.to_string()),
                ],
            );
        }

        let mut outcomes = Vec::with_capacity(requests.len());
        outcomes.resize_with(requests.len(), || None);
        let mut candidates = Vec::with_capacity(requests.len());
        let mut batch_seen = BTreeSet::new();

        for (index, request) in requests.iter().enumerate() {
            let key = (request.packet.space, request.packet.packet_number);
            if self
                .accepted_packets
                .get(&request.packet.space)
                .is_some_and(|window| window.rejects(request.packet.packet_number))
            {
                outcomes[index] = Some(Outcome::err(AtpError::Auth(AuthError::ReplayedNonce)));
                continue;
            }
            if !batch_seen.insert(key) {
                return self.unprotect_packets(cx, requests);
            }
            candidates.push(OwnedPacketUnprotectionRequest {
                index,
                packet: request.packet.clone(),
                associated_data: request.associated_data.to_vec(),
            });
        }

        if candidates.is_empty() {
            return outcomes
                .into_iter()
                .map(|outcome| outcome.expect("every request has a replay outcome"))
                .collect();
        }

        let chunk_len = candidates
            .len()
            .div_ceil(width)
            .max(PARALLEL_UNPROTECT_TARGET_CHUNK_PACKETS);
        let mut pending = Vec::new();
        for chunk in candidates.chunks(chunk_len) {
            let Some(provider) = self.provider.clone_for_parallel_unprotect() else {
                return self.unprotect_packets(cx, requests);
            };
            let chunk = chunk.to_vec();
            let inline_chunk = chunk.clone();
            match cx.spawn_blocking(move |_child| unprotect_packet_chunk(provider, chunk)) {
                Ok(handle) => pending.push(Ok(handle)),
                Err(_) => {
                    let Some(provider) = self.provider.clone_for_parallel_unprotect() else {
                        return self.unprotect_packets(cx, requests);
                    };
                    pending.push(Err(unprotect_packet_chunk(provider, inline_chunk)));
                }
            }
        }

        for pending_chunk in pending {
            let chunk_results = match pending_chunk {
                Ok(mut handle) => match handle.join(cx).await {
                    Ok(results) => results,
                    Err(_) => return self.unprotect_packets(cx, requests),
                },
                Err(results) => results,
            };
            for (index, outcome) in chunk_results {
                outcomes[index] = Some(outcome);
            }
        }

        let mut ordered = Vec::with_capacity(requests.len());
        for outcome in outcomes {
            let outcome = outcome.expect("every unprotect request has an outcome");
            match outcome {
                Outcome::Ok(unprotected) => {
                    let replay_window = self.accepted_packets.entry(unprotected.space).or_default();
                    if replay_window.rejects(unprotected.packet_number) {
                        ordered.push(Outcome::err(AtpError::Auth(AuthError::ReplayedNonce)));
                    } else {
                        replay_window.accept(unprotected.packet_number);
                        ordered.push(Outcome::ok(unprotected));
                    }
                }
                other => ordered.push(other),
            }
        }
        ordered
    }

    /// Unprotect a packet with ATP error handling.
    pub async fn unprotect_packet(
        &mut self,
        cx: &Cx,
        packet: &ProtectedPacket,
        associated_data: &[u8],
    ) -> AtpOutcome<UnprotectedPacket> {
        self.unprotect_packet_now(cx, packet, associated_data)
    }

    /// Header-protection mask for protecting an outgoing header (this
    /// endpoint's key), on the current task. See
    /// [`QuicPacketProtectionProvider::header_protection_mask`].
    pub fn header_protection_mask_now(
        &self,
        cx: &Cx,
        space: PacketProtectionSpace,
        sample: &[u8],
    ) -> AtpOutcome<HeaderProtectionMask> {
        self.trace_header_mask(cx, "atp_packet_protection_header_mask", space, sample);
        self.provider
            .header_protection_mask(space, sample)
            .map_err(|e| self.map_tls_error(e))
            .into()
    }

    /// Header-protection mask for removing protection from a received header
    /// (the peer's key), on the current task. See
    /// [`QuicPacketProtectionProvider::header_protection_mask_remote`].
    pub fn header_protection_mask_remote_now(
        &self,
        cx: &Cx,
        space: PacketProtectionSpace,
        sample: &[u8],
    ) -> AtpOutcome<HeaderProtectionMask> {
        self.trace_header_mask(
            cx,
            "atp_packet_protection_header_mask_remote",
            space,
            sample,
        );
        self.provider
            .header_protection_mask_remote(space, sample)
            .map_err(|e| self.map_tls_error(e))
            .into()
    }

    fn trace_header_mask(&self, cx: &Cx, event: &str, space: PacketProtectionSpace, sample: &[u8]) {
        if cx.trace_buffer().is_some() {
            cx.trace_with_fields(
                event,
                &[
                    ("space", &format!("{:?}", space)),
                    ("sample_len", &sample.len().to_string()),
                ],
            );
        }
    }

    /// Generate header protection mask with ATP error handling.
    pub async fn header_protection_mask(
        &self,
        cx: &Cx,
        space: PacketProtectionSpace,
        sample: &[u8],
    ) -> AtpOutcome<HeaderProtectionMask> {
        self.header_protection_mask_now(cx, space, sample)
    }

    /// Generate the peer-direction header protection mask with ATP error
    /// handling.
    pub async fn header_protection_mask_remote(
        &self,
        cx: &Cx,
        space: PacketProtectionSpace,
        sample: &[u8],
    ) -> AtpOutcome<HeaderProtectionMask> {
        self.header_protection_mask_remote_now(cx, space, sample)
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
        map_tls_error_to_atp(error)
    }
}

fn map_tls_error_to_atp(error: QuicTlsError) -> AtpError {
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
            protected_under_current_key: BTreeMap::new(),
            auth_failures_under_current_key: BTreeMap::new(),
            key_update_confidentiality_threshold: DEFAULT_KEY_UPDATE_CONFIDENTIALITY_THRESHOLD,
        }
    }
}

const fn trace_bool(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

#[cfg(test)]
#[path = "packet_protection_inline_tests.rs"]
mod tests;
