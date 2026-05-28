//! ATP session negotiation, capability grants, and feature selection.
//!
//! This module is deliberately a deterministic state-machine model before it is
//! connected to sockets, QUIC streams, daemon storage, or relay workers. ATP must
//! reject identity confusion, replayed nonces, feature downgrades that violate
//! policy, and capability/path/object escalation before any object bytes reach a
//! sparse writer, relay store, or mailbox.

use crate::atp::path::PathCandidateId;
use crate::net::atp::protocol::frames::{Frame, FrameError, FrameType, ProtocolVersion};
use crate::net::atp::protocol::transcript::{SessionTranscript, TranscriptHash};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

/// Stable ATP peer identity, normally `sha256(public_key)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PeerId([u8; 32]);

impl PeerId {
    const PUBLIC_KEY_DOMAIN: &'static [u8] = b"ATP-PEER-PUBLIC-KEY-V1\0";

    /// Construct a peer id from an already-hashed public identity.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derive the canonical peer id from public key material.
    pub fn from_public_key(public_key: &[u8]) -> Result<Self, PeerIdentityError> {
        if public_key.is_empty() {
            return Err(PeerIdentityError::EmptyPublicKey);
        }
        if public_key.iter().all(|byte| *byte == 0) {
            return Err(PeerIdentityError::AllZeroPublicKey);
        }

        let mut hasher = Sha256::new();
        hasher.update(Self::PUBLIC_KEY_DOMAIN);
        hasher.update((public_key.len() as u64).to_be_bytes());
        hasher.update(public_key);
        Ok(Self(hasher.finalize().into()))
    }

    /// Deterministically derive a test/local peer id from a label.
    #[must_use]
    pub fn from_label(label: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"ATP-PEER-ID-V1\x00");
        hasher.update(label.as_bytes());
        Self(hasher.finalize().into())
    }

    /// Deterministically derive a peer id for unit tests.
    #[cfg(test)]
    #[must_use]
    pub fn test(id: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"ATP-PEER-ID-TEST-V1\x00");
        hasher.update(id.to_be_bytes());
        Self(hasher.finalize().into())
    }

    /// Borrow the canonical peer-id bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Redacted hex prefix suitable for logs and proof artifacts.
    #[must_use]
    pub fn redacted(self) -> String {
        hex::encode(&self.0[..8])
    }
}

/// Invalid public key material for ATP peer identity derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerIdentityError {
    /// Public key material was empty.
    EmptyPublicKey,
    /// Public key material was all zero bytes.
    AllZeroPublicKey,
}

impl fmt::Display for PeerIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPublicKey => f.write_str("empty public key material"),
            Self::AllZeroPublicKey => f.write_str("all-zero public key material"),
        }
    }
}

impl std::error::Error for PeerIdentityError {}

/// Per-transfer nonce bound into the transcript and replay cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TransferNonce([u8; 32]);

impl TransferNonce {
    /// Construct a transfer nonce from caller-provided entropy.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Deterministically derive a nonce for tests and lab replay fixtures.
    #[must_use]
    pub fn from_seed(seed: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"ATP-TRANSFER-NONCE-V1\x00");
        hasher.update(seed.as_bytes());
        Self(hasher.finalize().into())
    }

    /// Borrow the nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether the nonce is all zero and therefore invalid on the wire.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

/// Deterministic ATP session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SessionId([u8; 32]);

impl SessionId {
    /// Borrow the session-id bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Redacted hex prefix suitable for human diagnostics.
    #[must_use]
    pub fn redacted(self) -> String {
        hex::encode(&self.0[..8])
    }
}

/// ATP trace id carried in logs and proof artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SessionTraceId(u64);

impl SessionTraceId {
    /// Construct a session trace id from a stable numeric value.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw trace id.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Where the negotiated ATP session will move data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SessionContextKind {
    /// Direct peer-to-peer path.
    Direct,
    /// Online ATP relay path.
    Relay,
    /// Store-and-forward encrypted mailbox path.
    Mailbox,
    /// Multi-source verified transfer.
    Swarm,
}

impl SessionContextKind {
    /// Feature that must be selected for this context, if any.
    #[must_use]
    pub const fn required_feature(self) -> Option<AtpFeature> {
        match self {
            Self::Direct => None,
            Self::Relay => Some(AtpFeature::Relay),
            Self::Mailbox => Some(AtpFeature::Mailbox),
            Self::Swarm => Some(AtpFeature::Swarm),
        }
    }

    /// Stable machine-readable context code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
            Self::Mailbox => "mailbox",
            Self::Swarm => "swarm",
        }
    }
}

/// ATP feature negotiated before object bytes move.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AtpFeature {
    /// RaptorQ or other repair-symbol coordination.
    Repair,
    /// QUIC DATAGRAM or datagram-like relay side channel.
    Datagrams,
    /// Compression plan negotiation.
    Compression,
    /// Explicit encryption policy negotiation.
    EncryptionPolicy,
    /// Multi-source verified transfer.
    Swarm,
    /// Store-and-forward encrypted mailbox delivery.
    Mailbox,
    /// ATP relay path.
    Relay,
    /// H3 adapter mode.
    H3Adapter,
    /// Browser/WebTransport adapter mode.
    WebTransportAdapter,
    /// MASQUE/CONNECT-UDP-style adapter mode.
    MasqueAdapter,
    /// Completion proof bundle exchange.
    ProofBundles,
    /// Crash-safe resume transcript/idempotency support.
    Resume,
}

impl AtpFeature {
    /// Every known ATP feature in canonical order.
    pub const ALL: [Self; 12] = [
        Self::Repair,
        Self::Datagrams,
        Self::Compression,
        Self::EncryptionPolicy,
        Self::Swarm,
        Self::Mailbox,
        Self::Relay,
        Self::H3Adapter,
        Self::WebTransportAdapter,
        Self::MasqueAdapter,
        Self::ProofBundles,
        Self::Resume,
    ];

    /// Stable machine-readable feature code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Repair => "repair",
            Self::Datagrams => "datagrams",
            Self::Compression => "compression",
            Self::EncryptionPolicy => "encryption_policy",
            Self::Swarm => "swarm",
            Self::Mailbox => "mailbox",
            Self::Relay => "relay",
            Self::H3Adapter => "h3_adapter",
            Self::WebTransportAdapter => "webtransport_adapter",
            Self::MasqueAdapter => "masque_adapter",
            Self::ProofBundles => "proof_bundles",
            Self::Resume => "resume",
        }
    }

    /// Stable reason code emitted when this optional feature is offered but not
    /// selected.
    #[must_use]
    pub const fn downgrade_reason_code(self) -> &'static str {
        match self {
            Self::H3Adapter => "h3_adapter_not_supported_by_peer",
            Self::WebTransportAdapter => "webtransport_adapter_not_supported_by_peer",
            Self::MasqueAdapter => "masque_adapter_not_supported_by_peer",
            Self::Datagrams => "datagrams_not_supported_by_selected_adapter",
            Self::Compression => "compression_not_supported_by_peer_policy",
            Self::Relay => "relay_not_supported_by_peer_policy",
            Self::Mailbox => "mailbox_not_supported_by_peer_policy",
            Self::Swarm => "swarm_not_supported_by_peer_policy",
            Self::Repair => "repair_not_supported_by_peer_policy",
            Self::ProofBundles => "proof_bundles_not_supported_by_peer_policy",
            Self::Resume => "resume_not_supported_by_peer_policy",
            Self::EncryptionPolicy => "encryption_policy_required",
        }
    }
}

/// ATP adapter families whose parity and downgrade behavior are tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AtpAdapterKind {
    /// Native ATP over Asupersync-owned QUIC.
    NativeQuic,
    /// ATP framed over HTTP/3 request/stream semantics.
    H3,
    /// Browser-facing WebTransport adapter.
    WebTransport,
    /// MASQUE CONNECT-UDP enterprise-egress adapter.
    MasqueConnectUdp,
    /// Hostile-network TCP/TLS 443 relay fallback.
    TcpTls443Fallback,
}

impl AtpAdapterKind {
    /// Stable adapter code for diagnostics, docs, and proof summaries.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NativeQuic => "native_quic",
            Self::H3 => "h3_adapter",
            Self::WebTransport => "webtransport_adapter",
            Self::MasqueConnectUdp => "masque_connect_udp",
            Self::TcpTls443Fallback => "tcp_tls_443_fallback",
        }
    }

    /// Feature bit that advertises this adapter during session negotiation.
    #[must_use]
    pub const fn negotiated_feature(self) -> Option<AtpFeature> {
        match self {
            Self::NativeQuic | Self::TcpTls443Fallback => None,
            Self::H3 => Some(AtpFeature::H3Adapter),
            Self::WebTransport => Some(AtpFeature::WebTransportAdapter),
            Self::MasqueConnectUdp => Some(AtpFeature::MasqueAdapter),
        }
    }
}

/// One checked row in the ATP adapter parity matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtpAdapterParity {
    /// Adapter family covered by the row.
    pub adapter: AtpAdapterKind,
    /// Features that may be selected for this adapter without downgrade.
    pub supported_features: &'static [AtpFeature],
    /// Features that must fail closed or downgrade explicitly for this adapter.
    pub unsupported_features: &'static [AtpFeature],
    /// Stable reason emitted when the adapter itself cannot satisfy a requested
    /// capability.
    pub adapter_downgrade_reason: &'static str,
    /// Stable proof summary label for CLI and audit artifacts.
    pub proof_summary_label: &'static str,
}

impl AtpAdapterParity {
    /// Whether this adapter row supports the feature directly.
    #[must_use]
    pub fn supports(self, feature: AtpFeature) -> bool {
        self.supported_features.contains(&feature)
    }

    /// Whether this adapter row explicitly rejects or downgrades the feature.
    #[must_use]
    pub fn downgrades(self, feature: AtpFeature) -> bool {
        self.unsupported_features.contains(&feature)
    }
}

/// Checked ATP adapter parity matrix used by docs, tests, and proof summaries.
pub const ATP_ADAPTER_PARITY_MATRIX: [AtpAdapterParity; 5] = [
    AtpAdapterParity {
        adapter: AtpAdapterKind::NativeQuic,
        supported_features: &[
            AtpFeature::EncryptionPolicy,
            AtpFeature::ProofBundles,
            AtpFeature::Resume,
            AtpFeature::Repair,
            AtpFeature::Datagrams,
            AtpFeature::Compression,
            AtpFeature::Swarm,
            AtpFeature::Mailbox,
            AtpFeature::Relay,
        ],
        unsupported_features: &[
            AtpFeature::H3Adapter,
            AtpFeature::WebTransportAdapter,
            AtpFeature::MasqueAdapter,
        ],
        adapter_downgrade_reason: "native_quic_requires_no_compat_adapter",
        proof_summary_label: "native_quic_full_atp",
    },
    AtpAdapterParity {
        adapter: AtpAdapterKind::H3,
        supported_features: &[
            AtpFeature::EncryptionPolicy,
            AtpFeature::ProofBundles,
            AtpFeature::Resume,
            AtpFeature::Repair,
            AtpFeature::Compression,
            AtpFeature::H3Adapter,
        ],
        unsupported_features: &[
            AtpFeature::Datagrams,
            AtpFeature::WebTransportAdapter,
            AtpFeature::MasqueAdapter,
            AtpFeature::Swarm,
            AtpFeature::Mailbox,
        ],
        adapter_downgrade_reason: "h3_adapter_lacks_native_datagram_and_swarm_parity",
        proof_summary_label: "h3_adapter_stream",
    },
    AtpAdapterParity {
        adapter: AtpAdapterKind::WebTransport,
        supported_features: &[
            AtpFeature::EncryptionPolicy,
            AtpFeature::ProofBundles,
            AtpFeature::Resume,
            AtpFeature::Repair,
            AtpFeature::Datagrams,
            AtpFeature::WebTransportAdapter,
        ],
        unsupported_features: &[
            AtpFeature::H3Adapter,
            AtpFeature::MasqueAdapter,
            AtpFeature::Mailbox,
            AtpFeature::Swarm,
        ],
        adapter_downgrade_reason: "webtransport_adapter_browser_policy_limited",
        proof_summary_label: "webtransport_adapter_browser",
    },
    AtpAdapterParity {
        adapter: AtpAdapterKind::MasqueConnectUdp,
        supported_features: &[
            AtpFeature::EncryptionPolicy,
            AtpFeature::ProofBundles,
            AtpFeature::Resume,
            AtpFeature::Repair,
            AtpFeature::Datagrams,
            AtpFeature::Relay,
            AtpFeature::MasqueAdapter,
        ],
        unsupported_features: &[
            AtpFeature::H3Adapter,
            AtpFeature::WebTransportAdapter,
            AtpFeature::Mailbox,
            AtpFeature::Swarm,
        ],
        adapter_downgrade_reason: "masque_connect_udp_requires_proxy_authority",
        proof_summary_label: "masque_connect_udp_proxy",
    },
    AtpAdapterParity {
        adapter: AtpAdapterKind::TcpTls443Fallback,
        supported_features: &[
            AtpFeature::EncryptionPolicy,
            AtpFeature::ProofBundles,
            AtpFeature::Resume,
            AtpFeature::Repair,
            AtpFeature::Compression,
            AtpFeature::Relay,
        ],
        unsupported_features: &[
            AtpFeature::Datagrams,
            AtpFeature::H3Adapter,
            AtpFeature::WebTransportAdapter,
            AtpFeature::MasqueAdapter,
            AtpFeature::Mailbox,
            AtpFeature::Swarm,
        ],
        adapter_downgrade_reason: "tcp_tls_443_fallback_lacks_datagrams",
        proof_summary_label: "tcp_tls_443_fallback_relay",
    },
];

/// Deterministic set of negotiated ATP features.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeatureSet {
    features: BTreeSet<AtpFeature>,
}

impl FeatureSet {
    /// Construct an empty feature set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a feature set from a slice.
    #[must_use]
    pub fn from_slice(features: &[AtpFeature]) -> Self {
        features.iter().copied().collect()
    }

    /// Add a feature.
    pub fn insert(&mut self, feature: AtpFeature) {
        self.features.insert(feature);
    }

    /// Whether a feature is present.
    #[must_use]
    pub fn contains(&self, feature: AtpFeature) -> bool {
        self.features.contains(&feature)
    }

    /// Iterate over features in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = AtpFeature> + '_ {
        self.features.iter().copied()
    }

    /// Select the deterministic intersection with another set.
    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        self.features
            .intersection(&other.features)
            .copied()
            .collect()
    }

    /// Whether this set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.features.is_empty()
    }
}

impl FromIterator<AtpFeature> for FeatureSet {
    fn from_iter<T: IntoIterator<Item = AtpFeature>>(iter: T) -> Self {
        Self {
            features: iter.into_iter().collect(),
        }
    }
}

/// Downgrade warning emitted when an optional offered feature is not selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DowngradeWarning {
    /// Feature that was offered but not selected.
    pub feature: AtpFeature,
    /// Stable reason code.
    pub reason_code: &'static str,
}

/// Capability action authorized by a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CapabilityAction {
    /// Read an object or object graph.
    Read,
    /// Write or upload object data.
    Write,
    /// Receive an incoming transfer.
    Receive,
    /// Share a capability or transfer offer.
    Share,
    /// Use a relay path.
    Relay,
    /// Seed data for peer-assisted transfer.
    Seed,
    /// Use encrypted mailbox storage.
    Mailbox,
    /// Delegate a narrower grant.
    Delegate,
    /// Invite another peer into a transfer/session.
    Invite,
}

impl CapabilityAction {
    /// Stable action code for logs and transcripts.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Receive => "receive",
            Self::Share => "share",
            Self::Relay => "relay",
            Self::Seed => "seed",
            Self::Mailbox => "mailbox",
            Self::Delegate => "delegate",
            Self::Invite => "invite",
        }
    }
}

/// Stable capability grant id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CapabilityGrantId([u8; 16]);

impl CapabilityGrantId {
    /// Construct from caller-provided bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Deterministically derive a grant id for tests/lab fixtures.
    #[must_use]
    pub fn from_label(label: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"ATP-CAPABILITY-GRANT-ID-V1\x00");
        hasher.update(label.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        Self(id)
    }

    /// Borrow the grant-id bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Path/object/context restrictions carried by a capability grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityScope {
    /// Whether every ATP path candidate id is allowed.
    pub allow_any_path: bool,
    /// Explicitly allowed path candidate ids.
    pub allowed_path_ids: BTreeSet<PathCandidateId>,
    /// Human/path prefixes for CLI/daemon policy surfaces.
    pub allowed_path_prefixes: BTreeSet<String>,
    /// Whether every trusted relay peer may satisfy a relay context.
    pub allow_any_relay_peer: bool,
    /// Explicit relay peers allowed by this grant.
    pub allowed_relay_peers: BTreeSet<PeerId>,
    /// Whether every manifest/object root is allowed.
    pub allow_any_manifest_root: bool,
    /// Explicitly allowed manifest roots.
    pub allowed_manifest_roots: BTreeSet<[u8; 32]>,
    /// Allowed ATP contexts.
    pub allowed_contexts: BTreeSet<SessionContextKind>,
}

impl CapabilityScope {
    /// Scope with no path/object/context restriction.
    #[must_use]
    pub fn unrestricted() -> Self {
        Self {
            allow_any_path: true,
            allowed_path_ids: BTreeSet::new(),
            allowed_path_prefixes: BTreeSet::new(),
            allow_any_relay_peer: true,
            allowed_relay_peers: BTreeSet::new(),
            allow_any_manifest_root: true,
            allowed_manifest_roots: BTreeSet::new(),
            allowed_contexts: SessionContextKind::ALL.into_iter().collect(),
        }
    }

    /// Scope for one context.
    #[must_use]
    pub fn for_context(context: SessionContextKind) -> Self {
        Self {
            allowed_contexts: std::iter::once(context).collect(),
            ..Self::unrestricted()
        }
    }

    /// Restrict to a single path candidate id.
    #[must_use]
    pub fn with_path_id(mut self, path_id: PathCandidateId) -> Self {
        self.allow_any_path = false;
        self.allowed_path_ids.insert(path_id);
        self
    }

    /// Restrict to a single trusted relay peer.
    #[must_use]
    pub fn with_relay_peer(mut self, relay_peer: PeerId) -> Self {
        self.allow_any_relay_peer = false;
        self.allowed_relay_peers.insert(relay_peer);
        self
    }

    /// Restrict to a manifest root.
    #[must_use]
    pub fn with_manifest_root(mut self, manifest_root: [u8; 32]) -> Self {
        self.allow_any_manifest_root = false;
        self.allowed_manifest_roots.insert(manifest_root);
        self
    }

    fn allows_request(&self, hello: &ClientHello) -> Result<(), SessionError> {
        if !self.allowed_contexts.contains(&hello.context) {
            return Err(SessionError::ContextDenied(hello.context));
        }

        if !self.allow_any_path {
            let path_id = hello
                .path_id
                .ok_or(SessionError::PathScopeDenied { path_id: None })?;
            if !self.allowed_path_ids.contains(&path_id) {
                return Err(SessionError::PathScopeDenied {
                    path_id: Some(path_id),
                });
            }
        }

        if matches!(hello.context, SessionContextKind::Relay) && !self.allow_any_relay_peer {
            let relay_peer = hello
                .relay_peer
                .ok_or(SessionError::RelayScopeDenied { relay_peer: None })?;
            if !self.allowed_relay_peers.contains(&relay_peer) {
                return Err(SessionError::RelayScopeDenied {
                    relay_peer: Some(relay_peer),
                });
            }
        }

        if !self.allow_any_manifest_root {
            let manifest_root = hello.manifest_root.ok_or(SessionError::ObjectScopeDenied {
                manifest_root: None,
            })?;
            if !self.allowed_manifest_roots.contains(&manifest_root) {
                return Err(SessionError::ObjectScopeDenied {
                    manifest_root: Some(manifest_root),
                });
            }
        }

        Ok(())
    }
}

impl SessionContextKind {
    /// Every session context in canonical order.
    pub const ALL: [Self; 4] = [Self::Direct, Self::Relay, Self::Mailbox, Self::Swarm];
}

/// Capability grant supplied during negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    /// Grant id.
    pub id: CapabilityGrantId,
    /// Peer that issued the grant.
    pub issuer: PeerId,
    /// Peer that may exercise the grant.
    pub subject: PeerId,
    /// Allowed actions.
    pub actions: BTreeSet<CapabilityAction>,
    /// Scope restrictions.
    pub scope: CapabilityScope,
    /// Earliest valid timestamp in microseconds.
    pub valid_from_micros: u64,
    /// Expiry timestamp in microseconds, if bounded.
    pub expires_at_micros: Option<u64>,
    /// Revoked grants fail closed.
    pub revoked: bool,
    /// Remaining delegation depth.
    pub delegation_depth: u8,
    /// Whether invite-style delegation is allowed.
    pub invite_scope: bool,
}

impl CapabilityGrant {
    /// Construct a grant.
    #[must_use]
    pub fn new(
        id: CapabilityGrantId,
        issuer: PeerId,
        subject: PeerId,
        actions: impl IntoIterator<Item = CapabilityAction>,
        scope: CapabilityScope,
    ) -> Self {
        Self {
            id,
            issuer,
            subject,
            actions: actions.into_iter().collect(),
            scope,
            valid_from_micros: 0,
            expires_at_micros: None,
            revoked: false,
            delegation_depth: 0,
            invite_scope: false,
        }
    }

    /// Set the validity window.
    #[must_use]
    pub const fn with_validity(mut self, valid_from_micros: u64, expires_at_micros: u64) -> Self {
        self.valid_from_micros = valid_from_micros;
        self.expires_at_micros = Some(expires_at_micros);
        self
    }

    /// Mark the grant revoked.
    #[must_use]
    pub const fn revoked(mut self) -> Self {
        self.revoked = true;
        self
    }

    /// Allow bounded delegation.
    #[must_use]
    pub const fn with_delegation(mut self, depth: u8, invite_scope: bool) -> Self {
        self.delegation_depth = depth;
        self.invite_scope = invite_scope;
        self
    }

    fn validate_for(
        &self,
        hello: &ClientHello,
        action: CapabilityAction,
        policy: &SessionPolicy,
    ) -> Result<(), SessionError> {
        if self.revoked {
            return Err(SessionError::GrantRevoked(self.id));
        }
        if self.valid_from_micros > policy.now_micros {
            return Err(SessionError::GrantNotYetValid(self.id));
        }
        if self
            .expires_at_micros
            .is_some_and(|expires_at| expires_at <= policy.now_micros)
        {
            return Err(SessionError::GrantExpired(self.id));
        }
        if self.subject != hello.initiator {
            return Err(SessionError::PeerConfusion);
        }
        if !policy.trusted_grant_issuers.contains(&self.issuer) {
            return Err(SessionError::UntrustedGrantIssuer(self.issuer));
        }
        if !self.actions.contains(&action) {
            return Err(SessionError::MissingGrantAction(action));
        }
        if matches!(action, CapabilityAction::Delegate) && self.delegation_depth == 0 {
            return Err(SessionError::DelegationDenied(self.id));
        }
        if matches!(action, CapabilityAction::Invite) && !self.invite_scope {
            return Err(SessionError::InviteDenied(self.id));
        }
        self.scope.allows_request(hello)
    }
}

/// Policy applied by the accepting peer before it sends `ServerHello`.
#[derive(Debug, Clone)]
pub struct SessionPolicy {
    /// Local accepting peer.
    pub local_peer: PeerId,
    /// Supported protocol versions.
    pub supported_versions: BTreeSet<ProtocolVersion>,
    /// Supported optional features.
    pub supported_features: FeatureSet,
    /// Required features that must be offered and selected.
    pub required_features: FeatureSet,
    /// Required capability actions for this acceptor.
    pub required_actions: BTreeSet<CapabilityAction>,
    /// Contexts this peer is willing to negotiate.
    pub accepted_contexts: BTreeSet<SessionContextKind>,
    /// Trusted grant issuers.
    pub trusted_grant_issuers: BTreeSet<PeerId>,
    /// Relay peers whose identity may be used for relay sessions.
    pub trusted_relays: BTreeSet<PeerId>,
    /// Replay cache for transfer nonces.
    pub seen_nonces: BTreeSet<TransferNonce>,
    /// Policy clock in microseconds.
    pub now_micros: u64,
    /// Whether the session must be bound to a known manifest root.
    pub require_manifest_binding: bool,
}

impl SessionPolicy {
    /// Construct a conservative policy for a local peer.
    #[must_use]
    pub fn new(local_peer: PeerId, now_micros: u64) -> Self {
        Self {
            local_peer,
            supported_versions: std::iter::once(ProtocolVersion::CURRENT).collect(),
            supported_features: FeatureSet::from_slice(&[
                AtpFeature::EncryptionPolicy,
                AtpFeature::ProofBundles,
                AtpFeature::Resume,
            ]),
            required_features: FeatureSet::from_slice(&[AtpFeature::EncryptionPolicy]),
            required_actions: BTreeSet::new(),
            accepted_contexts: SessionContextKind::ALL.into_iter().collect(),
            trusted_grant_issuers: std::iter::once(local_peer).collect(),
            trusted_relays: BTreeSet::new(),
            seen_nonces: BTreeSet::new(),
            now_micros,
            require_manifest_binding: false,
        }
    }

    /// Add supported features.
    #[must_use]
    pub fn with_supported_features(mut self, features: &[AtpFeature]) -> Self {
        self.supported_features = FeatureSet::from_slice(features);
        self
    }

    /// Add required feature policy.
    #[must_use]
    pub fn with_required_features(mut self, features: &[AtpFeature]) -> Self {
        self.required_features = FeatureSet::from_slice(features);
        self
    }

    /// Add required capability actions.
    #[must_use]
    pub fn with_required_actions(mut self, actions: &[CapabilityAction]) -> Self {
        self.required_actions = actions.iter().copied().collect();
        self
    }

    /// Restrict accepted contexts.
    #[must_use]
    pub fn with_accepted_contexts(mut self, contexts: &[SessionContextKind]) -> Self {
        self.accepted_contexts = contexts.iter().copied().collect();
        self
    }

    /// Trust relay peers for relay-context negotiation.
    #[must_use]
    pub fn with_trusted_relays(mut self, relays: &[PeerId]) -> Self {
        self.trusted_relays = relays.iter().copied().collect();
        self
    }

    /// Mark a nonce as already seen.
    #[must_use]
    pub fn with_seen_nonce(mut self, nonce: TransferNonce) -> Self {
        self.seen_nonces.insert(nonce);
        self
    }

    /// Require a manifest root binding.
    #[must_use]
    pub const fn require_manifest_binding(mut self) -> Self {
        self.require_manifest_binding = true;
        self
    }
}

/// Client hello fields bound into the transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// Initiating peer.
    pub initiator: PeerId,
    /// Expected accepting peer.
    pub responder: PeerId,
    /// Transfer nonce.
    pub nonce: TransferNonce,
    /// Requested protocol version.
    pub version: ProtocolVersion,
    /// Optional object/manifest root known at session setup time.
    pub manifest_root: Option<[u8; 32]>,
    /// Optional path candidate id.
    pub path_id: Option<PathCandidateId>,
    /// Relay peer identity required for relay contexts.
    pub relay_peer: Option<PeerId>,
    /// Negotiation context.
    pub context: SessionContextKind,
    /// Offered feature set.
    pub offered_features: FeatureSet,
    /// Capability grants presented by the initiator.
    pub grants: Vec<CapabilityGrant>,
    /// Actions requested by the initiator.
    pub requested_actions: BTreeSet<CapabilityAction>,
    /// Trace id for diagnostics.
    pub trace_id: SessionTraceId,
}

impl ClientHello {
    /// Construct a client hello.
    #[must_use]
    pub fn new(
        initiator: PeerId,
        responder: PeerId,
        nonce: TransferNonce,
        context: SessionContextKind,
        trace_id: SessionTraceId,
    ) -> Self {
        Self {
            initiator,
            responder,
            nonce,
            version: ProtocolVersion::CURRENT,
            manifest_root: None,
            path_id: None,
            relay_peer: None,
            context,
            offered_features: FeatureSet::from_slice(&[AtpFeature::EncryptionPolicy]),
            grants: Vec::new(),
            requested_actions: BTreeSet::new(),
            trace_id,
        }
    }

    /// Attach offered features.
    #[must_use]
    pub fn with_features(mut self, features: &[AtpFeature]) -> Self {
        self.offered_features = FeatureSet::from_slice(features);
        self
    }

    /// Attach a manifest root.
    #[must_use]
    pub const fn with_manifest_root(mut self, manifest_root: [u8; 32]) -> Self {
        self.manifest_root = Some(manifest_root);
        self
    }

    /// Attach a path candidate id.
    #[must_use]
    pub const fn with_path_id(mut self, path_id: PathCandidateId) -> Self {
        self.path_id = Some(path_id);
        self
    }

    /// Attach the relay peer identity for relay-context negotiation.
    #[must_use]
    pub const fn with_relay_peer(mut self, relay_peer: PeerId) -> Self {
        self.relay_peer = Some(relay_peer);
        self
    }

    /// Present grants to the acceptor.
    #[must_use]
    pub fn with_grants(mut self, grants: Vec<CapabilityGrant>) -> Self {
        self.grants = grants;
        self
    }

    /// Request capability actions.
    #[must_use]
    pub fn with_requested_actions(mut self, actions: &[CapabilityAction]) -> Self {
        self.requested_actions = actions.iter().copied().collect();
        self
    }

    /// Convert to a canonical ATP frame.
    pub fn to_frame(&self) -> Result<Frame, SessionError> {
        Frame::new(
            self.version,
            FrameType::Handshake,
            self.to_canonical_bytes(),
        )
        .map_err(SessionError::Frame)
    }

    fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        put_peer_id(&mut bytes, self.initiator);
        put_peer_id(&mut bytes, self.responder);
        bytes.extend_from_slice(self.nonce.as_bytes());
        bytes.extend_from_slice(&self.version.0.to_be_bytes());
        put_optional_hash(&mut bytes, self.manifest_root);
        put_optional_u64(&mut bytes, self.path_id.map(PathCandidateId::get));
        put_optional_peer_id(&mut bytes, self.relay_peer);
        bytes.push(context_code(self.context));
        put_features(&mut bytes, &self.offered_features);
        put_actions(&mut bytes, &self.requested_actions);
        bytes.extend_from_slice(&self.trace_id.get().to_be_bytes());
        put_grants(&mut bytes, &self.grants);
        bytes
    }
}

/// Server hello fields bound into the transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// Negotiated session id.
    pub session_id: SessionId,
    /// Accepting peer.
    pub acceptor: PeerId,
    /// Initiating peer.
    pub initiator: PeerId,
    /// Transfer nonce from the client hello.
    pub nonce: TransferNonce,
    /// Accepted protocol version.
    pub version: ProtocolVersion,
    /// Negotiation context.
    pub context: SessionContextKind,
    /// Selected features.
    pub selected_features: FeatureSet,
    /// Non-fatal downgrade warnings.
    pub downgrade_warnings: Vec<DowngradeWarning>,
    /// Grants that authorized the requested actions.
    pub accepted_grants: Vec<CapabilityGrantId>,
    /// Trace id carried from the client hello.
    pub trace_id: SessionTraceId,
}

impl ServerHello {
    /// Convert to a canonical ATP frame.
    pub fn to_frame(&self) -> Result<Frame, SessionError> {
        Frame::new(
            self.version,
            FrameType::HandshakeAck,
            self.to_canonical_bytes(),
        )
        .map_err(SessionError::Frame)
    }

    fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.session_id.as_bytes());
        put_peer_id(&mut bytes, self.acceptor);
        put_peer_id(&mut bytes, self.initiator);
        bytes.extend_from_slice(self.nonce.as_bytes());
        bytes.extend_from_slice(&self.version.0.to_be_bytes());
        bytes.push(context_code(self.context));
        put_features(&mut bytes, &self.selected_features);
        put_u32(&mut bytes, self.downgrade_warnings.len());
        for warning in &self.downgrade_warnings {
            bytes.push(feature_code(warning.feature));
            put_str(&mut bytes, warning.reason_code);
        }
        put_u32(&mut bytes, self.accepted_grants.len());
        for grant_id in &self.accepted_grants {
            bytes.extend_from_slice(grant_id.as_bytes());
        }
        bytes.extend_from_slice(&self.trace_id.get().to_be_bytes());
        bytes
    }
}

/// Terminal negotiated session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedSession {
    /// Session id.
    pub session_id: SessionId,
    /// Local peer for the state machine that produced this value.
    pub local_peer: PeerId,
    /// Remote peer.
    pub remote_peer: PeerId,
    /// Transfer nonce.
    pub nonce: TransferNonce,
    /// Protocol version.
    pub version: ProtocolVersion,
    /// Selected context.
    pub context: SessionContextKind,
    /// Selected features.
    pub selected_features: FeatureSet,
    /// Accepted grants.
    pub accepted_grants: Vec<CapabilityGrantId>,
    /// Transcript hash after hello and ack.
    pub transcript_hash: TranscriptHash,
    /// Trace id.
    pub trace_id: SessionTraceId,
}

/// User-facing proof/log artifact for session negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionProofArtifact {
    /// Local peer id, redacted.
    pub local_peer: String,
    /// Remote peer id, redacted.
    pub remote_peer: String,
    /// Session id, if negotiation reached that point.
    pub session_id: Option<String>,
    /// Transfer nonce.
    pub transfer_nonce: TransferNonce,
    /// Selected feature codes.
    pub selected_features: Vec<&'static str>,
    /// Rejected feature/grant/path/object reason, if any.
    pub rejected_reason: Option<String>,
    /// Redacted transcript hash.
    pub transcript_hash: String,
    /// Cx/session trace id.
    pub trace_id: SessionTraceId,
}

impl SessionProofArtifact {
    fn accepted(
        local_peer: PeerId,
        remote_peer: PeerId,
        session_id: SessionId,
        nonce: TransferNonce,
        selected_features: &FeatureSet,
        transcript_hash: TranscriptHash,
        trace_id: SessionTraceId,
    ) -> Self {
        Self {
            local_peer: local_peer.redacted(),
            remote_peer: remote_peer.redacted(),
            session_id: Some(session_id.redacted()),
            transfer_nonce: nonce,
            selected_features: selected_features.iter().map(AtpFeature::code).collect(),
            rejected_reason: None,
            transcript_hash: redact_transcript_hash(transcript_hash),
            trace_id,
        }
    }

    fn rejected(
        local_peer: PeerId,
        remote_peer: PeerId,
        nonce: TransferNonce,
        reason: &SessionError,
        transcript_hash: TranscriptHash,
        trace_id: SessionTraceId,
    ) -> Self {
        Self {
            local_peer: local_peer.redacted(),
            remote_peer: remote_peer.redacted(),
            session_id: None,
            transfer_nonce: nonce,
            selected_features: Vec::new(),
            rejected_reason: Some(reason.code().to_string()),
            transcript_hash: redact_transcript_hash(transcript_hash),
            trace_id,
        }
    }
}

/// Role of a session state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// Initiating peer.
    Client,
    /// Accepting peer.
    Server,
}

/// Deterministic session negotiation state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionNegotiationState {
    /// No frame has been processed.
    Idle,
    /// Client hello has been sent by the initiator.
    ClientHelloSent,
    /// Server hello has been sent by the acceptor.
    ServerHelloSent,
    /// Session is fully established.
    Established(SessionId),
    /// Session failed closed.
    Rejected(String),
    /// Session is closed.
    Closed,
}

/// ATP session negotiation state machine.
#[derive(Debug, Clone)]
pub struct SessionNegotiator {
    role: SessionRole,
    local_peer: PeerId,
    state: SessionNegotiationState,
    transcript: SessionTranscript,
}

impl SessionNegotiator {
    /// Construct a client-side session negotiator.
    #[must_use]
    pub fn client(local_peer: PeerId) -> Self {
        Self::new(SessionRole::Client, local_peer)
    }

    /// Construct a server-side session negotiator.
    #[must_use]
    pub fn server(local_peer: PeerId) -> Self {
        Self::new(SessionRole::Server, local_peer)
    }

    fn new(role: SessionRole, local_peer: PeerId) -> Self {
        Self {
            role,
            local_peer,
            state: SessionNegotiationState::Idle,
            transcript: SessionTranscript::new(),
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> &SessionNegotiationState {
        &self.state
    }

    /// Start client negotiation and produce the handshake frame.
    pub fn start_client_hello(&mut self, hello: &ClientHello) -> Result<Frame, SessionError> {
        self.expect_role(SessionRole::Client)?;
        self.expect_state(&SessionNegotiationState::Idle)?;
        if hello.initiator != self.local_peer {
            return self.reject(SessionError::PeerConfusion);
        }
        validate_nonce(hello.nonce)?;
        let frame = hello.to_frame()?;
        self.transcript.add_frame(&frame);
        self.state = SessionNegotiationState::ClientHelloSent;
        Ok(frame)
    }

    /// Accept a client hello, select features, and produce a server hello frame.
    pub fn accept_client_hello(
        &mut self,
        hello: &ClientHello,
        policy: &mut SessionPolicy,
    ) -> Result<(ServerHello, Frame, SessionProofArtifact), SessionError> {
        self.expect_role(SessionRole::Server)?;
        self.expect_state(&SessionNegotiationState::Idle)?;
        if policy.local_peer != self.local_peer {
            return self.reject(SessionError::PeerConfusion);
        }
        if hello.responder != self.local_peer {
            return self.reject(SessionError::PeerConfusion);
        }

        let client_frame = hello.to_frame()?;
        self.transcript.add_frame(&client_frame);

        match build_server_hello(hello, policy) {
            Ok(server_hello) => {
                let server_frame = server_hello.to_frame()?;
                self.transcript.add_frame(&server_frame);
                self.state = SessionNegotiationState::ServerHelloSent;
                let transcript_hash = self.transcript.current_hash();
                let proof = SessionProofArtifact::accepted(
                    self.local_peer,
                    hello.initiator,
                    server_hello.session_id,
                    hello.nonce,
                    &server_hello.selected_features,
                    transcript_hash,
                    hello.trace_id,
                );
                Ok((server_hello, server_frame, proof))
            }
            Err(error) => {
                let proof = SessionProofArtifact::rejected(
                    self.local_peer,
                    hello.initiator,
                    hello.nonce,
                    &error,
                    self.transcript.current_hash(),
                    hello.trace_id,
                );
                self.state = SessionNegotiationState::Rejected(error.code().to_string());
                Err(error.with_proof(proof))
            }
        }
    }

    /// Finish client negotiation after receiving a server hello.
    pub fn finish_client(
        &mut self,
        hello: &ClientHello,
        server_hello: &ServerHello,
        policy: &SessionPolicy,
    ) -> Result<(NegotiatedSession, SessionProofArtifact), SessionError> {
        self.expect_role(SessionRole::Client)?;
        self.expect_state(&SessionNegotiationState::ClientHelloSent)?;
        if hello.initiator != self.local_peer || server_hello.initiator != self.local_peer {
            return self.reject(SessionError::PeerConfusion);
        }
        validate_server_hello(hello, server_hello, policy)?;
        let server_frame = server_hello.to_frame()?;
        self.transcript.add_frame(&server_frame);
        self.state = SessionNegotiationState::Established(server_hello.session_id);
        let transcript_hash = self.transcript.current_hash();
        let session = NegotiatedSession {
            session_id: server_hello.session_id,
            local_peer: self.local_peer,
            remote_peer: server_hello.acceptor,
            nonce: hello.nonce,
            version: server_hello.version,
            context: server_hello.context,
            selected_features: server_hello.selected_features.clone(),
            accepted_grants: server_hello.accepted_grants.clone(),
            transcript_hash,
            trace_id: hello.trace_id,
        };
        let proof = SessionProofArtifact::accepted(
            self.local_peer,
            server_hello.acceptor,
            session.session_id,
            session.nonce,
            &session.selected_features,
            session.transcript_hash,
            session.trace_id,
        );
        Ok((session, proof))
    }

    fn expect_role(&self, expected: SessionRole) -> Result<(), SessionError> {
        if self.role == expected {
            Ok(())
        } else {
            Err(SessionError::InvalidRole {
                expected,
                actual: self.role,
            })
        }
    }

    fn expect_state(&self, expected: &SessionNegotiationState) -> Result<(), SessionError> {
        if &self.state == expected {
            Ok(())
        } else {
            Err(SessionError::InvalidTransition {
                from: format!("{:?}", self.state),
                expected: format!("{expected:?}"),
            })
        }
    }

    fn reject<T>(&mut self, error: SessionError) -> Result<T, SessionError> {
        self.state = SessionNegotiationState::Rejected(error.code().to_string());
        Err(error)
    }
}

/// Session negotiation errors.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Underlying frame error.
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),
    /// State transition was not legal.
    #[error("invalid transition from {from}; expected {expected}")]
    InvalidTransition {
        /// Actual state.
        from: String,
        /// Expected state.
        expected: String,
    },
    /// Method called on the wrong negotiator role.
    #[error("invalid role: expected {expected:?}, actual {actual:?}")]
    InvalidRole {
        /// Expected role.
        expected: SessionRole,
        /// Actual role.
        actual: SessionRole,
    },
    /// Peer ids do not match the expected initiator/responder/grant subject.
    #[error("peer confusion")]
    PeerConfusion,
    /// Nonce is all zero.
    #[error("zero transfer nonce")]
    ZeroNonce,
    /// Nonce already appeared in the replay cache.
    #[error("replayed transfer nonce")]
    ReplayedNonce,
    /// Protocol version is not supported.
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u32),
    /// Context is denied by policy or grant scope.
    #[error("context denied: {0:?}")]
    ContextDenied(SessionContextKind),
    /// Manifest root is required but absent.
    #[error("manifest root required")]
    ManifestRootRequired,
    /// Required feature was not offered or selected.
    #[error("missing required feature: {0:?}")]
    MissingRequiredFeature(AtpFeature),
    /// Feature selected by peer was not offered by the client.
    #[error("feature confusion: {0:?}")]
    FeatureConfusion(AtpFeature),
    /// No grant authorized a required action.
    #[error("missing grant action: {0:?}")]
    MissingGrantAction(CapabilityAction),
    /// Grant issuer was not trusted by the acceptor.
    #[error("untrusted grant issuer: {0:?}")]
    UntrustedGrantIssuer(PeerId),
    /// Grant is not yet valid.
    #[error("grant is not yet valid")]
    GrantNotYetValid(CapabilityGrantId),
    /// Grant expired.
    #[error("grant expired")]
    GrantExpired(CapabilityGrantId),
    /// Grant was revoked.
    #[error("grant revoked")]
    GrantRevoked(CapabilityGrantId),
    /// Grant cannot delegate.
    #[error("delegation denied")]
    DelegationDenied(CapabilityGrantId),
    /// Grant cannot invite.
    #[error("invite denied")]
    InviteDenied(CapabilityGrantId),
    /// Path restrictions rejected the request.
    #[error("path scope denied")]
    PathScopeDenied {
        /// Rejected path id.
        path_id: Option<PathCandidateId>,
    },
    /// Relay context did not name a relay peer.
    #[error("relay identity required")]
    MissingRelayIdentity,
    /// Non-relay context carried a relay peer.
    #[error("unexpected relay identity")]
    UnexpectedRelayIdentity,
    /// Relay peer is not trusted by policy.
    #[error("untrusted relay identity: {0:?}")]
    UntrustedRelayIdentity(PeerId),
    /// Relay restrictions rejected the request.
    #[error("relay scope denied")]
    RelayScopeDenied {
        /// Rejected relay peer.
        relay_peer: Option<PeerId>,
    },
    /// Object restrictions rejected the request.
    #[error("object scope denied")]
    ObjectScopeDenied {
        /// Rejected manifest root.
        manifest_root: Option<[u8; 32]>,
    },
    /// Server reply did not derive the expected session id.
    #[error("session id mismatch")]
    SessionIdMismatch,
    /// Error annotated with a proof artifact.
    #[error("{source}")]
    WithProof {
        /// Original error.
        source: Box<SessionError>,
        /// Rejection proof.
        proof: SessionProofArtifact,
    },
}

impl SessionError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Frame(_) => "frame_error",
            Self::InvalidTransition { .. } => "invalid_transition",
            Self::InvalidRole { .. } => "invalid_role",
            Self::PeerConfusion => "peer_confusion",
            Self::ZeroNonce => "zero_nonce",
            Self::ReplayedNonce => "replayed_nonce",
            Self::UnsupportedVersion(_) => "unsupported_version",
            Self::ContextDenied(_) => "context_denied",
            Self::ManifestRootRequired => "manifest_root_required",
            Self::MissingRequiredFeature(_) => "missing_required_feature",
            Self::FeatureConfusion(_) => "feature_confusion",
            Self::MissingGrantAction(_) => "missing_grant_action",
            Self::UntrustedGrantIssuer(_) => "untrusted_grant_issuer",
            Self::GrantNotYetValid(_) => "grant_not_yet_valid",
            Self::GrantExpired(_) => "grant_expired",
            Self::GrantRevoked(_) => "grant_revoked",
            Self::DelegationDenied(_) => "delegation_denied",
            Self::InviteDenied(_) => "invite_denied",
            Self::PathScopeDenied { .. } => "path_scope_denied",
            Self::MissingRelayIdentity => "missing_relay_identity",
            Self::UnexpectedRelayIdentity => "unexpected_relay_identity",
            Self::UntrustedRelayIdentity(_) => "untrusted_relay_identity",
            Self::RelayScopeDenied { .. } => "relay_scope_denied",
            Self::ObjectScopeDenied { .. } => "object_scope_denied",
            Self::SessionIdMismatch => "session_id_mismatch",
            Self::WithProof { source, .. } => source.code(),
        }
    }

    fn with_proof(self, proof: SessionProofArtifact) -> Self {
        Self::WithProof {
            source: Box::new(self),
            proof,
        }
    }

    /// Borrow the attached proof if this error carries one.
    #[must_use]
    pub const fn proof(&self) -> Option<&SessionProofArtifact> {
        match self {
            Self::WithProof { proof, .. } => Some(proof),
            _ => None,
        }
    }
}

fn build_server_hello(
    hello: &ClientHello,
    policy: &mut SessionPolicy,
) -> Result<ServerHello, SessionError> {
    validate_client_hello(hello, policy)?;
    let (selected_features, downgrade_warnings) = select_features(hello, policy)?;
    let accepted_grants = authorize_actions(hello, policy)?;
    reserve_client_nonce(hello, policy)?;
    let session_id = derive_session_id(hello, &selected_features);

    Ok(ServerHello {
        session_id,
        acceptor: policy.local_peer,
        initiator: hello.initiator,
        nonce: hello.nonce,
        version: hello.version,
        context: hello.context,
        selected_features,
        downgrade_warnings,
        accepted_grants,
        trace_id: hello.trace_id,
    })
}

fn validate_client_hello(hello: &ClientHello, policy: &SessionPolicy) -> Result<(), SessionError> {
    validate_nonce(hello.nonce)?;
    if !policy.supported_versions.contains(&hello.version) {
        return Err(SessionError::UnsupportedVersion(hello.version.0));
    }
    if policy.seen_nonces.contains(&hello.nonce) {
        return Err(SessionError::ReplayedNonce);
    }
    if !policy.accepted_contexts.contains(&hello.context) {
        return Err(SessionError::ContextDenied(hello.context));
    }
    validate_relay_identity(hello, policy)?;
    if policy.require_manifest_binding && hello.manifest_root.is_none() {
        return Err(SessionError::ManifestRootRequired);
    }
    Ok(())
}

fn validate_relay_identity(
    hello: &ClientHello,
    policy: &SessionPolicy,
) -> Result<(), SessionError> {
    match (hello.context, hello.relay_peer) {
        (SessionContextKind::Relay, Some(relay_peer)) => {
            if relay_peer == hello.initiator || relay_peer == hello.responder {
                return Err(SessionError::PeerConfusion);
            }
            if policy.trusted_relays.contains(&relay_peer) {
                Ok(())
            } else {
                Err(SessionError::UntrustedRelayIdentity(relay_peer))
            }
        }
        (SessionContextKind::Relay, None) => Err(SessionError::MissingRelayIdentity),
        (_, Some(_)) => Err(SessionError::UnexpectedRelayIdentity),
        (_, None) => Ok(()),
    }
}

fn reserve_client_nonce(
    hello: &ClientHello,
    policy: &mut SessionPolicy,
) -> Result<(), SessionError> {
    if policy.seen_nonces.insert(hello.nonce) {
        Ok(())
    } else {
        Err(SessionError::ReplayedNonce)
    }
}

fn validate_nonce(nonce: TransferNonce) -> Result<(), SessionError> {
    if nonce.is_zero() {
        Err(SessionError::ZeroNonce)
    } else {
        Ok(())
    }
}

fn select_features(
    hello: &ClientHello,
    policy: &SessionPolicy,
) -> Result<(FeatureSet, Vec<DowngradeWarning>), SessionError> {
    let selected = hello
        .offered_features
        .intersection(&policy.supported_features);
    for feature in policy.required_features.iter() {
        if !selected.contains(feature) {
            return Err(SessionError::MissingRequiredFeature(feature));
        }
    }
    if let Some(required) = hello.context.required_feature() {
        if !selected.contains(required) {
            return Err(SessionError::MissingRequiredFeature(required));
        }
    }

    let downgrade_warnings = hello
        .offered_features
        .iter()
        .filter(|feature| !selected.contains(*feature))
        .map(|feature| DowngradeWarning {
            feature,
            reason_code: feature.downgrade_reason_code(),
        })
        .collect();

    Ok((selected, downgrade_warnings))
}

fn authorize_actions(
    hello: &ClientHello,
    policy: &SessionPolicy,
) -> Result<Vec<CapabilityGrantId>, SessionError> {
    let mut required = policy.required_actions.clone();
    required.extend(hello.requested_actions.iter().copied());

    let mut accepted = BTreeSet::new();
    for action in required {
        let grant = hello
            .grants
            .iter()
            .find(|grant| grant.validate_for(hello, action, policy).is_ok())
            .ok_or(SessionError::MissingGrantAction(action))?;
        grant.validate_for(hello, action, policy)?;
        accepted.insert(grant.id);
    }
    Ok(accepted.into_iter().collect())
}

fn validate_server_hello(
    hello: &ClientHello,
    server_hello: &ServerHello,
    policy: &SessionPolicy,
) -> Result<(), SessionError> {
    if server_hello.acceptor != hello.responder {
        return Err(SessionError::PeerConfusion);
    }
    if server_hello.initiator != hello.initiator {
        return Err(SessionError::PeerConfusion);
    }
    if server_hello.nonce != hello.nonce {
        return Err(SessionError::PeerConfusion);
    }
    if server_hello.context != hello.context {
        return Err(SessionError::PeerConfusion);
    }
    validate_relay_identity(hello, policy)?;
    if !policy.supported_versions.contains(&server_hello.version) {
        return Err(SessionError::UnsupportedVersion(server_hello.version.0));
    }
    for feature in server_hello.selected_features.iter() {
        if !hello.offered_features.contains(feature) {
            return Err(SessionError::FeatureConfusion(feature));
        }
    }
    for feature in policy.required_features.iter() {
        if !server_hello.selected_features.contains(feature) {
            return Err(SessionError::MissingRequiredFeature(feature));
        }
    }
    if derive_session_id(hello, &server_hello.selected_features) != server_hello.session_id {
        return Err(SessionError::SessionIdMismatch);
    }
    Ok(())
}

fn derive_session_id(hello: &ClientHello, selected_features: &FeatureSet) -> SessionId {
    let mut hasher = Sha256::new();
    hasher.update(b"ATP-SESSION-ID-V1\x00");
    hasher.update(hello.initiator.as_bytes());
    hasher.update(hello.responder.as_bytes());
    hasher.update(hello.nonce.as_bytes());
    hasher.update(hello.version.0.to_be_bytes());
    hasher.update([context_code(hello.context)]);
    if let Some(manifest_root) = hello.manifest_root {
        hasher.update([1]);
        hasher.update(manifest_root);
    } else {
        hasher.update([0]);
    }
    if let Some(path_id) = hello.path_id {
        hasher.update([1]);
        hasher.update(path_id.get().to_be_bytes());
    } else {
        hasher.update([0]);
    }
    if let Some(relay_peer) = hello.relay_peer {
        hasher.update([1]);
        hasher.update(relay_peer.as_bytes());
    } else {
        hasher.update([0]);
    }
    for feature in selected_features.iter() {
        hasher.update([feature_code(feature)]);
    }
    SessionId(hasher.finalize().into())
}

fn redact_transcript_hash(hash: TranscriptHash) -> String {
    hex::encode(&hash.as_bytes()[..12])
}

fn put_peer_id(bytes: &mut Vec<u8>, peer_id: PeerId) {
    bytes.extend_from_slice(peer_id.as_bytes());
}

fn put_optional_hash(bytes: &mut Vec<u8>, hash: Option<[u8; 32]>) {
    match hash {
        Some(hash) => {
            bytes.push(1);
            bytes.extend_from_slice(&hash);
        }
        None => bytes.push(0),
    }
}

fn put_optional_u64(bytes: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        None => bytes.push(0),
    }
}

fn put_features(bytes: &mut Vec<u8>, features: &FeatureSet) {
    let features = features.iter().collect::<Vec<_>>();
    put_u32(bytes, features.len());
    for feature in features {
        bytes.push(feature_code(feature));
    }
}

fn put_actions(bytes: &mut Vec<u8>, actions: &BTreeSet<CapabilityAction>) {
    put_u32(bytes, actions.len());
    for action in actions {
        bytes.push(action_code(*action));
    }
}

fn put_grants(bytes: &mut Vec<u8>, grants: &[CapabilityGrant]) {
    put_u32(bytes, grants.len());
    for grant in grants {
        bytes.extend_from_slice(grant.id.as_bytes());
        put_peer_id(bytes, grant.issuer);
        put_peer_id(bytes, grant.subject);
        put_actions(bytes, &grant.actions);
        bytes.extend_from_slice(&grant.valid_from_micros.to_be_bytes());
        put_optional_u64(bytes, grant.expires_at_micros);
        bytes.push(u8::from(grant.revoked));
        bytes.push(grant.delegation_depth);
        bytes.push(u8::from(grant.invite_scope));
        put_scope(bytes, &grant.scope);
    }
}

fn put_scope(bytes: &mut Vec<u8>, scope: &CapabilityScope) {
    bytes.push(u8::from(scope.allow_any_path));
    put_u32(bytes, scope.allowed_path_ids.len());
    for path_id in &scope.allowed_path_ids {
        bytes.extend_from_slice(&path_id.get().to_be_bytes());
    }
    put_u32(bytes, scope.allowed_path_prefixes.len());
    for prefix in &scope.allowed_path_prefixes {
        put_str(bytes, prefix);
    }
    bytes.push(u8::from(scope.allow_any_relay_peer));
    put_u32(bytes, scope.allowed_relay_peers.len());
    for relay_peer in &scope.allowed_relay_peers {
        put_peer_id(bytes, *relay_peer);
    }
    bytes.push(u8::from(scope.allow_any_manifest_root));
    put_u32(bytes, scope.allowed_manifest_roots.len());
    for root in &scope.allowed_manifest_roots {
        bytes.extend_from_slice(root);
    }
    put_u32(bytes, scope.allowed_contexts.len());
    for context in &scope.allowed_contexts {
        bytes.push(context_code(*context));
    }
}

fn put_str(bytes: &mut Vec<u8>, value: &str) {
    put_u32(bytes, value.len());
    bytes.extend_from_slice(value.as_bytes());
}

fn put_optional_peer_id(bytes: &mut Vec<u8>, value: Option<PeerId>) {
    match value {
        Some(peer_id) => {
            bytes.push(1);
            put_peer_id(bytes, peer_id);
        }
        None => bytes.push(0),
    }
}

fn put_u32(bytes: &mut Vec<u8>, value: usize) {
    bytes.extend_from_slice(&(value as u32).to_be_bytes());
}

fn context_code(context: SessionContextKind) -> u8 {
    match context {
        SessionContextKind::Direct => 0,
        SessionContextKind::Relay => 1,
        SessionContextKind::Mailbox => 2,
        SessionContextKind::Swarm => 3,
    }
}

fn feature_code(feature: AtpFeature) -> u8 {
    match feature {
        AtpFeature::Repair => 0,
        AtpFeature::Datagrams => 1,
        AtpFeature::Compression => 2,
        AtpFeature::EncryptionPolicy => 3,
        AtpFeature::Swarm => 4,
        AtpFeature::Mailbox => 5,
        AtpFeature::Relay => 6,
        AtpFeature::H3Adapter => 7,
        AtpFeature::WebTransportAdapter => 8,
        AtpFeature::MasqueAdapter => 9,
        AtpFeature::ProofBundles => 10,
        AtpFeature::Resume => 11,
    }
}

fn action_code(action: CapabilityAction) -> u8 {
    match action {
        CapabilityAction::Read => 0,
        CapabilityAction::Write => 1,
        CapabilityAction::Receive => 2,
        CapabilityAction::Share => 3,
        CapabilityAction::Relay => 4,
        CapabilityAction::Seed => 5,
        CapabilityAction::Mailbox => 6,
        CapabilityAction::Delegate => 7,
        CapabilityAction::Invite => 8,
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "peer:{}", self.redacted())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peers() -> (PeerId, PeerId) {
        (PeerId::from_label("alice"), PeerId::from_label("bob"))
    }

    fn relay_peer() -> PeerId {
        PeerId::from_label("relay-a")
    }

    fn alternate_relay_peer() -> PeerId {
        PeerId::from_label("relay-b")
    }

    #[test]
    fn peer_id_from_public_key_is_canonical_and_rejects_bad_material() {
        let public_key = b"ed25519:alice-device-public-key";
        let first = PeerId::from_public_key(public_key).unwrap();
        let second = PeerId::from_public_key(public_key).unwrap();

        assert_eq!(first, second);
        assert_ne!(first, PeerId::from_label("ed25519:alice-device-public-key"));
        assert_eq!(
            PeerId::from_public_key(&[]),
            Err(PeerIdentityError::EmptyPublicKey)
        );
        assert_eq!(
            PeerId::from_public_key(&[0; 32]),
            Err(PeerIdentityError::AllZeroPublicKey)
        );
    }

    fn manifest_root(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn grant_for(
        issuer: PeerId,
        subject: PeerId,
        actions: &[CapabilityAction],
        context: SessionContextKind,
    ) -> CapabilityGrant {
        CapabilityGrant::new(
            CapabilityGrantId::from_label("grant"),
            issuer,
            subject,
            actions.iter().copied(),
            if matches!(context, SessionContextKind::Relay) {
                CapabilityScope::for_context(context).with_relay_peer(relay_peer())
            } else {
                CapabilityScope::for_context(context)
            },
        )
    }

    fn hello_for(context: SessionContextKind) -> ClientHello {
        let (alice, bob) = peers();
        let hello = ClientHello::new(
            alice,
            bob,
            TransferNonce::from_seed(context.code()),
            context,
            SessionTraceId::new(42),
        )
        .with_features(&[
            AtpFeature::EncryptionPolicy,
            AtpFeature::ProofBundles,
            AtpFeature::Resume,
            AtpFeature::Relay,
            AtpFeature::Mailbox,
            AtpFeature::Swarm,
            AtpFeature::Repair,
            AtpFeature::Datagrams,
        ])
        .with_requested_actions(&[CapabilityAction::Write])
        .with_grants(vec![grant_for(
            bob,
            alice,
            &[CapabilityAction::Write],
            context,
        )]);
        if matches!(context, SessionContextKind::Relay) {
            hello.with_relay_peer(relay_peer())
        } else {
            hello
        }
    }

    fn policy_for(context: SessionContextKind) -> SessionPolicy {
        let (_alice, bob) = peers();
        let policy = SessionPolicy::new(bob, 100)
            .with_supported_features(&[
                AtpFeature::EncryptionPolicy,
                AtpFeature::ProofBundles,
                AtpFeature::Resume,
                AtpFeature::Relay,
                AtpFeature::Mailbox,
                AtpFeature::Swarm,
                AtpFeature::Repair,
                AtpFeature::Datagrams,
            ])
            .with_required_features(&[AtpFeature::EncryptionPolicy])
            .with_required_actions(&[CapabilityAction::Write])
            .with_accepted_contexts(&[context]);
        if matches!(context, SessionContextKind::Relay) {
            policy.with_trusted_relays(&[relay_peer()])
        } else {
            policy
        }
    }

    fn negotiate(
        hello: &ClientHello,
        policy: &mut SessionPolicy,
    ) -> Result<
        (
            NegotiatedSession,
            SessionProofArtifact,
            SessionProofArtifact,
        ),
        SessionError,
    > {
        let mut client = SessionNegotiator::client(hello.initiator);
        let mut server = SessionNegotiator::server(policy.local_peer);
        let client_frame = client.start_client_hello(hello)?;
        assert_eq!(client_frame.frame_type(), FrameType::Handshake);

        let (server_hello, server_frame, server_proof) =
            server.accept_client_hello(hello, policy)?;
        assert_eq!(server_frame.frame_type(), FrameType::HandshakeAck);

        let (session, client_proof) = client.finish_client(hello, &server_hello, policy)?;
        Ok((session, client_proof, server_proof))
    }

    #[test]
    fn direct_first_contact_pairing_establishes_session() {
        let hello = hello_for(SessionContextKind::Direct);
        let mut policy = policy_for(SessionContextKind::Direct);

        let (session, client_proof, server_proof) = negotiate(&hello, &mut policy).unwrap();

        assert_eq!(session.context, SessionContextKind::Direct);
        assert!(
            session
                .selected_features
                .contains(AtpFeature::EncryptionPolicy)
        );
        assert_eq!(session.accepted_grants.len(), 1);
        assert_eq!(client_proof.session_id, server_proof.session_id);
        assert_eq!(client_proof.rejected_reason, None);
        assert!(!client_proof.transcript_hash.is_empty());
    }

    #[test]
    fn relay_mailbox_and_swarm_contexts_require_matching_features() {
        for (context, feature, action) in [
            (
                SessionContextKind::Relay,
                AtpFeature::Relay,
                CapabilityAction::Relay,
            ),
            (
                SessionContextKind::Mailbox,
                AtpFeature::Mailbox,
                CapabilityAction::Mailbox,
            ),
            (
                SessionContextKind::Swarm,
                AtpFeature::Swarm,
                CapabilityAction::Seed,
            ),
        ] {
            let (alice, bob) = peers();
            let hello = ClientHello::new(
                alice,
                bob,
                TransferNonce::from_seed(context.code()),
                context,
                SessionTraceId::new(77),
            )
            .with_features(&[AtpFeature::EncryptionPolicy, feature])
            .with_requested_actions(&[action])
            .with_grants(vec![grant_for(bob, alice, &[action], context)]);
            let hello = if matches!(context, SessionContextKind::Relay) {
                hello.with_relay_peer(relay_peer())
            } else {
                hello
            };
            let policy = SessionPolicy::new(bob, 100)
                .with_supported_features(&[AtpFeature::EncryptionPolicy, feature])
                .with_required_features(&[AtpFeature::EncryptionPolicy])
                .with_required_actions(&[action])
                .with_accepted_contexts(&[context]);
            let mut policy = if matches!(context, SessionContextKind::Relay) {
                policy.with_trusted_relays(&[relay_peer()])
            } else {
                policy
            };

            let (session, _client_proof, _server_proof) = negotiate(&hello, &mut policy).unwrap();
            assert_eq!(session.context, context);
            assert!(session.selected_features.contains(feature));
        }
    }

    #[test]
    fn relay_context_requires_trusted_relay_identity() {
        let (alice, bob) = peers();
        let relay_grant = grant_for(
            bob,
            alice,
            &[CapabilityAction::Relay],
            SessionContextKind::Relay,
        );
        let base = ClientHello::new(
            alice,
            bob,
            TransferNonce::from_seed("relay-auth"),
            SessionContextKind::Relay,
            SessionTraceId::new(88),
        )
        .with_features(&[AtpFeature::EncryptionPolicy, AtpFeature::Relay])
        .with_requested_actions(&[CapabilityAction::Relay])
        .with_grants(vec![relay_grant]);

        let mut missing_policy = SessionPolicy::new(bob, 100)
            .with_supported_features(&[AtpFeature::EncryptionPolicy, AtpFeature::Relay])
            .with_required_features(&[AtpFeature::EncryptionPolicy])
            .with_required_actions(&[CapabilityAction::Relay])
            .with_accepted_contexts(&[SessionContextKind::Relay])
            .with_trusted_relays(&[relay_peer()]);
        let mut server = SessionNegotiator::server(bob);
        let error = server
            .accept_client_hello(&base, &mut missing_policy)
            .unwrap_err();
        assert_eq!(error.code(), "missing_relay_identity");

        let mut untrusted_policy = SessionPolicy::new(bob, 100)
            .with_supported_features(&[AtpFeature::EncryptionPolicy, AtpFeature::Relay])
            .with_required_features(&[AtpFeature::EncryptionPolicy])
            .with_required_actions(&[CapabilityAction::Relay])
            .with_accepted_contexts(&[SessionContextKind::Relay])
            .with_trusted_relays(&[relay_peer()]);
        let mut server = SessionNegotiator::server(bob);
        let error = server
            .accept_client_hello(
                &base.clone().with_relay_peer(alternate_relay_peer()),
                &mut untrusted_policy,
            )
            .unwrap_err();
        assert_eq!(error.code(), "untrusted_relay_identity");
    }

    #[test]
    fn relay_grant_scope_and_session_id_bind_relay_identity() {
        let (alice, bob) = peers();
        let grant = grant_for(
            bob,
            alice,
            &[CapabilityAction::Relay],
            SessionContextKind::Relay,
        );
        let hello = ClientHello::new(
            alice,
            bob,
            TransferNonce::from_seed("relay-scope"),
            SessionContextKind::Relay,
            SessionTraceId::new(89),
        )
        .with_features(&[AtpFeature::EncryptionPolicy, AtpFeature::Relay])
        .with_requested_actions(&[CapabilityAction::Relay])
        .with_relay_peer(alternate_relay_peer())
        .with_grants(vec![grant.clone()]);
        let policy = SessionPolicy::new(bob, 100)
            .with_supported_features(&[AtpFeature::EncryptionPolicy, AtpFeature::Relay])
            .with_required_features(&[AtpFeature::EncryptionPolicy])
            .with_required_actions(&[CapabilityAction::Relay])
            .with_accepted_contexts(&[SessionContextKind::Relay])
            .with_trusted_relays(&[relay_peer(), alternate_relay_peer()]);

        match grant
            .validate_for(&hello, CapabilityAction::Relay, &policy)
            .expect_err("relay grant scope")
        {
            SessionError::RelayScopeDenied {
                relay_peer: Some(rejected),
            } => assert_eq!(rejected, alternate_relay_peer()),
            other => panic!("unexpected error: {other:?}"),
        }

        let selected = FeatureSet::from_slice(&[AtpFeature::EncryptionPolicy, AtpFeature::Relay]);
        let relay_a_session =
            derive_session_id(&hello.clone().with_relay_peer(relay_peer()), &selected);
        let relay_b_session = derive_session_id(&hello, &selected);
        assert_ne!(relay_a_session, relay_b_session);
    }

    #[test]
    fn unsupported_optional_features_emit_downgrade_warnings() {
        let hello = hello_for(SessionContextKind::Direct).with_features(&[
            AtpFeature::EncryptionPolicy,
            AtpFeature::Repair,
            AtpFeature::Compression,
            AtpFeature::H3Adapter,
            AtpFeature::WebTransportAdapter,
        ]);
        let mut policy = policy_for(SessionContextKind::Direct)
            .with_supported_features(&[AtpFeature::EncryptionPolicy, AtpFeature::Repair]);
        let mut server = SessionNegotiator::server(policy.local_peer);

        let (server_hello, _frame, proof) =
            server.accept_client_hello(&hello, &mut policy).unwrap();

        assert!(server_hello.selected_features.contains(AtpFeature::Repair));
        assert!(
            !server_hello
                .selected_features
                .contains(AtpFeature::Compression)
        );
        let warned = server_hello
            .downgrade_warnings
            .iter()
            .map(|warning| warning.feature)
            .collect::<BTreeSet<_>>();
        assert!(warned.contains(&AtpFeature::Compression));
        assert!(warned.contains(&AtpFeature::H3Adapter));
        assert!(warned.contains(&AtpFeature::WebTransportAdapter));
        assert_eq!(proof.selected_features, vec!["repair", "encryption_policy"]);
    }

    #[test]
    fn missing_required_feature_fails_closed() {
        let hello = hello_for(SessionContextKind::Direct).with_features(&[AtpFeature::Repair]);
        let mut policy = policy_for(SessionContextKind::Direct);
        let mut server = SessionNegotiator::server(policy.local_peer);

        let error = server.accept_client_hello(&hello, &mut policy).unwrap_err();

        assert_eq!(error.code(), "missing_required_feature");
        assert_eq!(
            error
                .proof()
                .and_then(|proof| proof.rejected_reason.as_deref()),
            Some("missing_required_feature")
        );
    }

    #[test]
    fn expired_and_revoked_grants_are_rejected() {
        let (alice, bob) = peers();
        let base = ClientHello::new(
            alice,
            bob,
            TransferNonce::from_seed("expired"),
            SessionContextKind::Direct,
            SessionTraceId::new(1),
        )
        .with_features(&[AtpFeature::EncryptionPolicy])
        .with_requested_actions(&[CapabilityAction::Write]);
        let mut policy = policy_for(SessionContextKind::Direct);

        let expired = grant_for(
            bob,
            alice,
            &[CapabilityAction::Write],
            SessionContextKind::Direct,
        )
        .with_validity(0, 50);
        let mut server = SessionNegotiator::server(policy.local_peer);
        let error = server
            .accept_client_hello(&base.clone().with_grants(vec![expired]), &mut policy)
            .unwrap_err();
        assert_eq!(error.code(), "missing_grant_action");

        let revoked = grant_for(
            bob,
            alice,
            &[CapabilityAction::Write],
            SessionContextKind::Direct,
        )
        .revoked();
        let mut server = SessionNegotiator::server(policy.local_peer);
        let error = server
            .accept_client_hello(&base.with_grants(vec![revoked]), &mut policy)
            .unwrap_err();
        assert_eq!(error.code(), "missing_grant_action");
    }

    #[test]
    fn replayed_nonce_is_rejected_before_authorization() {
        let hello = hello_for(SessionContextKind::Direct);
        let mut policy = policy_for(SessionContextKind::Direct).with_seen_nonce(hello.nonce);
        let mut server = SessionNegotiator::server(policy.local_peer);

        let error = server.accept_client_hello(&hello, &mut policy).unwrap_err();

        assert_eq!(error.code(), "replayed_nonce");
    }

    #[test]
    fn successful_accept_records_nonce_for_future_replay_rejection() {
        let hello = hello_for(SessionContextKind::Direct);
        let mut policy = policy_for(SessionContextKind::Direct);
        let mut server = SessionNegotiator::server(policy.local_peer);

        server.accept_client_hello(&hello, &mut policy).unwrap();

        assert!(policy.seen_nonces.contains(&hello.nonce));

        let mut replay_server = SessionNegotiator::server(policy.local_peer);
        let error = replay_server
            .accept_client_hello(&hello, &mut policy)
            .unwrap_err();

        assert_eq!(error.code(), "replayed_nonce");
    }

    #[test]
    fn path_and_object_scope_escalation_is_rejected() {
        let (alice, bob) = peers();
        let allowed_path = PathCandidateId::new(7);
        let denied_path = PathCandidateId::new(8);
        let allowed_root = manifest_root(1);
        let denied_root = manifest_root(2);
        let scope = CapabilityScope::for_context(SessionContextKind::Direct)
            .with_path_id(allowed_path)
            .with_manifest_root(allowed_root);
        let grant = CapabilityGrant::new(
            CapabilityGrantId::from_label("scoped"),
            bob,
            alice,
            [CapabilityAction::Write],
            scope,
        );
        let mut policy = policy_for(SessionContextKind::Direct).require_manifest_binding();

        let path_escalation = ClientHello::new(
            alice,
            bob,
            TransferNonce::from_seed("path-escalation"),
            SessionContextKind::Direct,
            SessionTraceId::new(2),
        )
        .with_features(&[AtpFeature::EncryptionPolicy])
        .with_requested_actions(&[CapabilityAction::Write])
        .with_manifest_root(allowed_root)
        .with_path_id(denied_path)
        .with_grants(vec![grant.clone()]);
        let mut server = SessionNegotiator::server(policy.local_peer);
        let error = server
            .accept_client_hello(&path_escalation, &mut policy)
            .unwrap_err();
        assert_eq!(error.code(), "missing_grant_action");

        let object_escalation = ClientHello::new(
            alice,
            bob,
            TransferNonce::from_seed("object-escalation"),
            SessionContextKind::Direct,
            SessionTraceId::new(3),
        )
        .with_features(&[AtpFeature::EncryptionPolicy])
        .with_requested_actions(&[CapabilityAction::Write])
        .with_manifest_root(denied_root)
        .with_path_id(allowed_path)
        .with_grants(vec![grant]);
        let mut server = SessionNegotiator::server(policy.local_peer);
        let error = server
            .accept_client_hello(&object_escalation, &mut policy)
            .unwrap_err();
        assert_eq!(error.code(), "missing_grant_action");
    }

    #[test]
    fn invalid_transitions_fail_closed() {
        let hello = hello_for(SessionContextKind::Direct);
        let mut client = SessionNegotiator::client(hello.initiator);

        client.start_client_hello(&hello).unwrap();
        let error = client.start_client_hello(&hello).unwrap_err();

        assert_eq!(error.code(), "invalid_transition");
    }

    #[test]
    fn server_feature_confusion_is_rejected_by_client() {
        let hello =
            hello_for(SessionContextKind::Direct).with_features(&[AtpFeature::EncryptionPolicy]);
        let policy = policy_for(SessionContextKind::Direct);
        let mut client = SessionNegotiator::client(hello.initiator);
        client.start_client_hello(&hello).unwrap();

        let server_hello = ServerHello {
            session_id: derive_session_id(
                &hello,
                &FeatureSet::from_slice(&[AtpFeature::EncryptionPolicy, AtpFeature::Compression]),
            ),
            acceptor: hello.responder,
            initiator: hello.initiator,
            nonce: hello.nonce,
            version: ProtocolVersion::CURRENT,
            context: SessionContextKind::Direct,
            selected_features: FeatureSet::from_slice(&[
                AtpFeature::EncryptionPolicy,
                AtpFeature::Compression,
            ]),
            downgrade_warnings: Vec::new(),
            accepted_grants: vec![CapabilityGrantId::from_label("grant")],
            trace_id: hello.trace_id,
        };

        let error = client
            .finish_client(&hello, &server_hello, &policy)
            .unwrap_err();

        assert_eq!(error.code(), "feature_confusion");
    }
}
