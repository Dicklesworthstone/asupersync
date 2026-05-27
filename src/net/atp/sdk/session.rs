//! ATP session management and lifecycle.

use super::{AtpSdk, SdkMode, SessionConfig};
use crate::cx::Cx;
use crate::net::atp::protocol::{
    AtpError, AtpFeature, AtpOutcome, CapabilityAction, CapabilityGrant, ClientHello,
    NegotiatedSession, PeerId, ProtocolError, SessionContextKind, SessionError, SessionId,
    SessionNegotiator, SessionPolicy, SessionProofArtifact, SessionTraceId, TransferNonce,
};
use std::sync::Arc;

/// High-level session handle for ATP transfers.
#[derive(Debug, Clone)]
pub struct AtpSession {
    /// Underlying negotiated session.
    session: Arc<NegotiatedSession>,
    /// Session configuration.
    config: SessionConfig,
    /// SDK mode for operation delegation.
    pub mode: SdkMode,
    /// Session proof artifact for audit.
    proof: SessionProofArtifact,
}

/// Session establishment options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOptions {
    /// Remote peer to connect to.
    pub remote_peer: PeerId,
    /// Session context (direct, relay, mailbox, swarm).
    pub context: SessionContextKind,
    /// Optional manifest root for binding.
    pub manifest_root: Option<[u8; 32]>,
    /// Optional path candidate ID.
    pub path_id: Option<u64>,
    /// Custom session timeout.
    pub timeout_ms: Option<u64>,
    /// Required capabilities for this session.
    pub required_capabilities: Vec<CapabilityAction>,
    /// Capability grants to present.
    pub grants: Vec<CapabilityGrant>,
    /// Custom trace ID for diagnostics.
    pub trace_id: Option<SessionTraceId>,
}

impl SessionOptions {
    /// Create session options for a direct peer-to-peer transfer.
    #[must_use]
    pub fn direct(remote_peer: PeerId) -> Self {
        Self {
            remote_peer,
            context: SessionContextKind::Direct,
            manifest_root: None,
            path_id: None,
            timeout_ms: None,
            required_capabilities: vec![CapabilityAction::Write, CapabilityAction::Read],
            grants: Vec::new(),
            trace_id: None,
        }
    }

    /// Create session options for a relay-mediated transfer.
    #[must_use]
    pub fn relay(remote_peer: PeerId) -> Self {
        Self {
            remote_peer,
            context: SessionContextKind::Relay,
            manifest_root: None,
            path_id: None,
            timeout_ms: None,
            required_capabilities: vec![CapabilityAction::Relay],
            grants: Vec::new(),
            trace_id: None,
        }
    }

    /// Create session options for mailbox delivery.
    #[must_use]
    pub fn mailbox(remote_peer: PeerId) -> Self {
        Self {
            remote_peer,
            context: SessionContextKind::Mailbox,
            manifest_root: None,
            path_id: None,
            timeout_ms: None,
            required_capabilities: vec![CapabilityAction::Mailbox],
            grants: Vec::new(),
            trace_id: None,
        }
    }

    /// Create session options for swarm transfer.
    #[must_use]
    pub fn swarm(remote_peer: PeerId) -> Self {
        Self {
            remote_peer,
            context: SessionContextKind::Swarm,
            manifest_root: None,
            path_id: None,
            timeout_ms: None,
            required_capabilities: vec![CapabilityAction::Seed],
            grants: Vec::new(),
            trace_id: None,
        }
    }

    /// Bind session to a specific manifest root.
    #[must_use]
    pub const fn with_manifest_root(mut self, manifest_root: [u8; 32]) -> Self {
        self.manifest_root = Some(manifest_root);
        self
    }

    /// Set a custom trace ID for diagnostics.
    #[must_use]
    pub const fn with_trace_id(mut self, trace_id: SessionTraceId) -> Self {
        self.trace_id = Some(trace_id);
        self
    }

    /// Add capability grants to present during negotiation.
    #[must_use]
    pub fn with_grants(mut self, grants: Vec<CapabilityGrant>) -> Self {
        self.grants = grants;
        self
    }

    /// Set custom session timeout.
    #[must_use]
    pub const fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = Some(timeout_ms);
        self
    }
}

impl AtpSdk {
    /// Open a new ATP session with the specified peer.
    pub async fn open_session(&self, cx: &Cx, options: SessionOptions) -> AtpOutcome<AtpSession> {
        match &self.mode {
            SdkMode::InProcess => self.open_session_in_process(cx, options).await,
            SdkMode::DaemonDelegated { .. } => {
                self.open_session_daemon_delegated(cx, options).await
            }
        }
    }

    async fn open_session_in_process(
        &self,
        cx: &Cx,
        options: SessionOptions,
    ) -> AtpOutcome<AtpSession> {
        if cx.checkpoint().is_err() {
            return AtpOutcome::Err(AtpError::Platform(
                crate::net::atp::protocol::PlatformError::OperatingSystemError,
            ));
        }

        let nonce = generate_transfer_nonce(cx);
        let trace_id = options.trace_id.unwrap_or_else(|| {
            SessionTraceId::new(0) // Default trace ID
        });

        // Create client hello with session options
        let hello = ClientHello::new(
            self.default_config.local_peer,
            options.remote_peer,
            nonce,
            options.context,
            trace_id,
        )
        .with_features(&self.get_supported_features())
        .with_requested_actions(&options.required_capabilities)
        .with_grants(options.grants);

        let hello = if let Some(manifest_root) = options.manifest_root {
            hello.with_manifest_root(manifest_root)
        } else {
            hello
        };

        let mut client = SessionNegotiator::client(self.default_config.local_peer);
        let _client_frame = match client.start_client_hello(&hello) {
            Ok(frame) => frame,
            Err(e) => return AtpOutcome::Err(AtpError::Protocol(session_error_to_protocol(&e))),
        };

        let mut server = SessionNegotiator::server(options.remote_peer);
        let mut policy = SessionPolicy::new(options.remote_peer, 0)
            .with_supported_features(&self.get_supported_features())
            .with_required_features(&[AtpFeature::EncryptionPolicy])
            .with_required_actions(&options.required_capabilities);
        let (server_hello, _server_frame, _server_proof) = match server
            .accept_client_hello(&hello, &mut policy)
        {
            Ok(result) => result,
            Err(e) => return AtpOutcome::Err(AtpError::Protocol(session_error_to_protocol(&e))),
        };

        let (negotiated, proof) = match client.finish_client(&hello, &server_hello, &policy) {
            Ok(result) => result,
            Err(e) => return AtpOutcome::Err(AtpError::Protocol(session_error_to_protocol(&e))),
        };

        AtpOutcome::Ok(AtpSession {
            session: Arc::new(negotiated),
            config: self.default_config.clone(),
            mode: self.mode.clone(),
            proof,
        })
    }

    async fn open_session_daemon_delegated(
        &self,
        cx: &Cx,
        options: SessionOptions,
    ) -> AtpOutcome<AtpSession> {
        if cx.checkpoint().is_err() {
            return AtpOutcome::Err(AtpError::Platform(
                crate::net::atp::protocol::PlatformError::OperatingSystemError,
            ));
        }

        if daemon_endpoint_is_reachable(&self.mode).is_err() {
            return AtpOutcome::Err(AtpError::Daemon(
                crate::net::atp::protocol::DaemonError::DaemonOffline,
            ));
        }

        let _ = options;
        AtpOutcome::Err(AtpError::Daemon(
            crate::net::atp::protocol::DaemonError::ServiceUnavailable,
        ))
    }

    fn get_supported_features(&self) -> Vec<AtpFeature> {
        let mut features = vec![AtpFeature::EncryptionPolicy, AtpFeature::ProofBundles];

        if self.default_config.enable_compression {
            features.push(AtpFeature::Compression);
        }

        if self.default_config.enable_repair {
            features.push(AtpFeature::Repair);
        }

        if self.default_config.enable_resume {
            features.push(AtpFeature::Resume);
        }

        features
    }
}

impl AtpSession {
    /// Get the session ID.
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.session.session_id
    }

    /// Get the transfer nonce bound into this session transcript.
    #[must_use]
    pub fn transfer_nonce(&self) -> TransferNonce {
        self.session.nonce
    }

    /// Get the final negotiated transcript hash.
    #[must_use]
    pub fn transcript_hash(&self) -> crate::net::atp::protocol::TranscriptHash {
        self.session.transcript_hash
    }

    /// Get the remote peer ID.
    #[must_use]
    pub fn remote_peer(&self) -> PeerId {
        self.session.remote_peer
    }

    /// Get the local peer ID.
    #[must_use]
    pub fn local_peer(&self) -> PeerId {
        self.session.local_peer
    }

    /// Get the session context.
    #[must_use]
    pub fn context(&self) -> SessionContextKind {
        self.session.context
    }

    /// Get the session configuration.
    #[must_use]
    pub const fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Get the session proof artifact.
    #[must_use]
    pub const fn proof(&self) -> &SessionProofArtifact {
        &self.proof
    }

    /// Check if a feature is selected for this session.
    #[must_use]
    pub fn has_feature(&self, feature: AtpFeature) -> bool {
        self.session.selected_features.contains(feature)
    }

    /// Close the session gracefully.
    pub async fn close(&self, cx: &Cx) -> AtpOutcome<()> {
        if cx.checkpoint().is_err() {
            return AtpOutcome::Err(AtpError::Platform(
                crate::net::atp::protocol::PlatformError::OperatingSystemError,
            ));
        }
        match &self.mode {
            SdkMode::InProcess => AtpOutcome::Err(AtpError::Protocol(
                crate::net::atp::protocol::ProtocolError::SessionStateMismatch,
            )),
            SdkMode::DaemonDelegated { .. } => AtpOutcome::Err(AtpError::Daemon(
                crate::net::atp::protocol::DaemonError::ServiceUnavailable,
            )),
        }
    }
}

fn daemon_endpoint_is_reachable(mode: &SdkMode) -> std::io::Result<()> {
    let SdkMode::DaemonDelegated {
        daemon_endpoint, ..
    } = mode
    else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "SDK mode is not daemon delegated",
        ));
    };
    let endpoint = daemon_endpoint
        .strip_prefix("tcp://")
        .unwrap_or(daemon_endpoint);
    let addr: std::net::SocketAddr = endpoint.parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "daemon endpoint must be tcp://host:port or host:port",
        )
    })?;

    std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(250)).map(|_| ())
}

/// Generate a transfer nonce from the context's CSPRNG-backed byte source.
fn generate_transfer_nonce(cx: &Cx) -> TransferNonce {
    loop {
        let mut nonce_bytes = [0u8; 32];
        cx.random_bytes(&mut nonce_bytes);

        let nonce = TransferNonce::new(nonce_bytes);
        if !nonce.is_zero() {
            return nonce;
        }
    }
}

fn session_error_to_protocol(error: &SessionError) -> ProtocolError {
    match error {
        SessionError::Frame(_) => ProtocolError::MalformedFrame,
        SessionError::UnsupportedVersion(_) | SessionError::MissingRequiredFeature(_) => {
            ProtocolError::ProtocolVersionMismatch
        }
        SessionError::InvalidTransition { .. }
        | SessionError::InvalidRole { .. }
        | SessionError::PeerConfusion
        | SessionError::FeatureConfusion(_)
        | SessionError::SessionIdMismatch => ProtocolError::SessionStateMismatch,
        SessionError::ZeroNonce
        | SessionError::ReplayedNonce
        | SessionError::ContextDenied(_)
        | SessionError::ManifestRootRequired
        | SessionError::MissingGrantAction(_)
        | SessionError::UntrustedGrantIssuer(_)
        | SessionError::GrantNotYetValid(_)
        | SessionError::GrantExpired(_)
        | SessionError::GrantRevoked(_)
        | SessionError::DelegationDenied(_)
        | SessionError::InviteDenied(_)
        | SessionError::PathScopeDenied { .. }
        | SessionError::MissingRelayIdentity
        | SessionError::UnexpectedRelayIdentity
        | SessionError::UntrustedRelayIdentity(_)
        | SessionError::RelayScopeDenied { .. }
        | SessionError::ObjectScopeDenied { .. } => ProtocolError::SessionStateMismatch,
        SessionError::WithProof { source, .. } => session_error_to_protocol(source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::net::atp::protocol::{CapabilityGrantId, CapabilityScope};
    use futures_lite::future::block_on;

    fn grant_for_direct_peer(issuer: PeerId, subject: PeerId, label: &str) -> CapabilityGrant {
        CapabilityGrant::new(
            CapabilityGrantId::from_label(label),
            issuer,
            subject,
            [CapabilityAction::Read, CapabilityAction::Write],
            CapabilityScope::for_context(SessionContextKind::Direct),
        )
    }

    fn granted_direct_options(
        local_peer: PeerId,
        remote_peer: PeerId,
        label: &str,
    ) -> SessionOptions {
        SessionOptions::direct(remote_peer).with_grants(vec![grant_for_direct_peer(
            remote_peer,
            local_peer,
            label,
        )])
    }

    #[test]
    fn session_options_construction() {
        let peer = PeerId::from_label("test_peer");

        let direct = SessionOptions::direct(peer);
        assert_eq!(direct.context, SessionContextKind::Direct);
        assert!(
            direct
                .required_capabilities
                .contains(&CapabilityAction::Write)
        );

        let relay = SessionOptions::relay(peer);
        assert_eq!(relay.context, SessionContextKind::Relay);
        assert!(
            relay
                .required_capabilities
                .contains(&CapabilityAction::Relay)
        );

        let mailbox = SessionOptions::mailbox(peer);
        assert_eq!(mailbox.context, SessionContextKind::Mailbox);
        assert!(
            mailbox
                .required_capabilities
                .contains(&CapabilityAction::Mailbox)
        );

        let swarm = SessionOptions::swarm(peer);
        assert_eq!(swarm.context, SessionContextKind::Swarm);
        assert!(
            swarm
                .required_capabilities
                .contains(&CapabilityAction::Seed)
        );
    }

    #[test]
    fn session_options_with_manifest() {
        let peer = PeerId::from_label("test_peer");
        let manifest_root = [42u8; 32];

        let options = SessionOptions::direct(peer).with_manifest_root(manifest_root);
        assert_eq!(options.manifest_root, Some(manifest_root));
    }

    #[test]
    fn transfer_nonce_uses_full_context_entropy() {
        let cx = Cx::for_testing();
        let nonce = generate_transfer_nonce(&cx);

        let mut weak_expansion = [0u8; 32];
        let weak_seed = cx.random_u64();
        for (i, byte) in weak_expansion.iter_mut().enumerate() {
            *byte = weak_seed.wrapping_add(i as u64) as u8;
        }

        assert!(!nonce.is_zero());
        assert_ne!(nonce.as_bytes(), &weak_expansion);
        assert_ne!(nonce, generate_transfer_nonce(&cx));
    }

    #[test]
    fn in_process_session_creation() {
        block_on(async {
            let config = SessionConfig::default();
            let local_peer = config.local_peer;
            let sdk = AtpSdk::new_in_process(config);

            let cx = Cx::for_testing();
            let peer = PeerId::from_label("remote_peer");
            let options = granted_direct_options(local_peer, peer, "sdk-session-grant");

            let session = sdk.open_session(&cx, options).await;
            assert!(session.is_ok());

            if let AtpOutcome::Ok(session) = session {
                assert_eq!(session.remote_peer(), peer);
                assert_eq!(session.context(), SessionContextKind::Direct);
                assert_eq!(session.session.accepted_grants.len(), 1);
                assert_ne!(session.session.transcript_hash.0, [0u8; 32]);
                assert_ne!(session.proof().transcript_hash, "0000000000000000");
            }
        });
    }

    #[test]
    fn in_process_session_rejects_empty_grants() {
        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let cx = Cx::for_testing();
            let peer = PeerId::from_label("remote_peer");
            let result = sdk.open_session(&cx, SessionOptions::direct(peer)).await;

            match result {
                AtpOutcome::Err(AtpError::Protocol(_)) => {}
                other => panic!("empty grants must not negotiate a session: {other:?}"),
            }
        });
    }

    #[test]
    fn daemon_session_creation_fails() {
        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_daemon_delegated(
                config,
                "localhost:8080".to_string(),
                Some("token".to_string()),
            );

            let cx = Cx::for_testing();
            let peer = PeerId::from_label("remote_peer");
            let options = SessionOptions::direct(peer);

            let session = sdk.open_session(&cx, options).await;
            assert!(session.is_err()); // No daemon service is listening for this test endpoint.
        });
    }
}
