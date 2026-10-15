//! Self-hosted ATP rendezvous and relay service configuration.
//!
//! This module is the typed contract behind `atp rendezvous serve` and
//! `atp relay serve`. It keeps operator policy explicit before runtime wiring:
//! identity, TLS posture, quotas, expiry windows, rate limits, access policy,
//! mailbox storage, logging, federation, and restart behavior are all modeled
//! as data instead of ambient daemon assumptions.

use super::relay::{RelayError, RelayServiceConfig};
use super::rendezvous::{Quotas as RendezvousQuotas, ServiceConfig as RendezvousServiceConfig};

const MIB: u64 = 1024 * 1024;

/// ATP service command represented by one self-hosted serve config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtpServeCommand {
    /// `atp rendezvous serve`.
    RendezvousServe,
    /// `atp relay serve`.
    RelayServe,
}

impl AtpServeCommand {
    /// Stable CLI words for logs, help text, and proof contracts.
    #[must_use]
    pub const fn words(self) -> &'static [&'static str] {
        match self {
            Self::RendezvousServe => &["atp", "rendezvous", "serve"],
            Self::RelayServe => &["atp", "relay", "serve"],
        }
    }
}

/// Supported self-hosted deployment profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtpDeploymentMode {
    /// Single operator, loopback or private-hosted service.
    Personal,
    /// Team service with authenticated peers and durable restart state.
    Team,
    /// CI service with small quotas and no restart-state retention.
    Ci,
    /// Public-facing gateway with TLS required and redacted logs by default.
    PublicGateway,
}

/// Service identity visible in operator logs and proof artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpServiceIdentity {
    service_id: String,
    operator_label: String,
}

impl AtpServiceIdentity {
    /// Construct a service identity.
    ///
    /// # Errors
    ///
    /// Returns an error when either identifier is blank.
    pub fn new(
        service_id: impl Into<String>,
        operator_label: impl Into<String>,
    ) -> Result<Self, AtpOpsConfigError> {
        let service_id = service_id.into();
        let operator_label = operator_label.into();
        if service_id.trim().is_empty() {
            return Err(AtpOpsConfigError::EmptyServiceId);
        }
        if operator_label.trim().is_empty() {
            return Err(AtpOpsConfigError::EmptyOperatorLabel);
        }
        Ok(Self {
            service_id,
            operator_label,
        })
    }

    /// Stable service id.
    #[must_use]
    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    /// Human/operator-facing deployment label.
    #[must_use]
    pub fn operator_label(&self) -> &str {
        &self.operator_label
    }
}

/// TLS posture for a self-hosted service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtpTlsPolicy {
    /// Plaintext is only acceptable for loopback or explicitly private labs.
    DisabledLoopbackOnly,
    /// TLS is required. Client auth can be required separately for team modes.
    Required {
        /// Whether peers must authenticate at the TLS/session boundary.
        client_auth_required: bool,
    },
}

impl AtpTlsPolicy {
    /// Return true when the service requires TLS on its listener.
    #[must_use]
    pub const fn requires_tls(self) -> bool {
        matches!(self, Self::Required { .. })
    }

    /// Return true when peer/client auth is required at the TLS boundary.
    #[must_use]
    pub const fn requires_client_auth(self) -> bool {
        matches!(
            self,
            Self::Required {
                client_auth_required: true,
            }
        )
    }
}

/// Per-service rate limits exposed to operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtpRateLimitPolicy {
    /// Accepted reservations per minute.
    pub max_reservations_per_minute: u32,
    /// Accepted relay packets per second.
    pub max_packets_per_second: u32,
    /// Accepted mailbox bytes per minute.
    pub max_mailbox_bytes_per_minute: u64,
}

impl AtpRateLimitPolicy {
    /// Validate that all rate limits are non-zero.
    pub const fn validate(self) -> Result<Self, AtpOpsConfigError> {
        if self.max_reservations_per_minute == 0
            || self.max_packets_per_second == 0
            || self.max_mailbox_bytes_per_minute == 0
        {
            return Err(AtpOpsConfigError::InvalidQuota);
        }
        Ok(self)
    }
}

/// Expiry windows for service-scoped state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtpExpiryPolicy {
    /// Maximum rendezvous candidate lifetime.
    pub candidate_ttl_micros: u64,
    /// Default relay reservation lifetime.
    pub relay_reservation_ttl_micros: u64,
    /// Default mailbox retention lifetime.
    pub mailbox_ttl_secs: u64,
}

impl AtpExpiryPolicy {
    /// Validate that all expiry windows are non-zero.
    pub const fn validate(self) -> Result<Self, AtpOpsConfigError> {
        if self.candidate_ttl_micros == 0
            || self.relay_reservation_ttl_micros == 0
            || self.mailbox_ttl_secs == 0
        {
            return Err(AtpOpsConfigError::InvalidExpiry);
        }
        Ok(self)
    }
}

/// Access policy for peers and groups allowed to use a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpAccessPolicy {
    allowed_peers: Vec<String>,
    allowed_groups: Vec<String>,
    public_registration: bool,
}

impl AtpAccessPolicy {
    /// Private access policy with no public registration.
    #[must_use]
    pub const fn private() -> Self {
        Self {
            allowed_peers: Vec::new(),
            allowed_groups: Vec::new(),
            public_registration: false,
        }
    }

    /// Public registration policy for an explicitly public gateway.
    #[must_use]
    pub const fn public_registration() -> Self {
        Self {
            allowed_peers: Vec::new(),
            allowed_groups: Vec::new(),
            public_registration: true,
        }
    }

    /// Add one allowed peer id.
    ///
    /// # Errors
    ///
    /// Returns an error when the peer id is blank.
    pub fn with_allowed_peer(
        mut self,
        peer_id: impl Into<String>,
    ) -> Result<Self, AtpOpsConfigError> {
        let peer_id = peer_id.into();
        if peer_id.trim().is_empty() {
            return Err(AtpOpsConfigError::EmptyAccessEntry);
        }
        self.allowed_peers.push(peer_id);
        Ok(self)
    }

    /// Add one allowed group id.
    ///
    /// # Errors
    ///
    /// Returns an error when the group id is blank.
    pub fn with_allowed_group(
        mut self,
        group_id: impl Into<String>,
    ) -> Result<Self, AtpOpsConfigError> {
        let group_id = group_id.into();
        if group_id.trim().is_empty() {
            return Err(AtpOpsConfigError::EmptyAccessEntry);
        }
        self.allowed_groups.push(group_id);
        Ok(self)
    }

    /// Allowed peer ids.
    #[must_use]
    pub fn allowed_peers(&self) -> &[String] {
        &self.allowed_peers
    }

    /// Allowed group ids.
    #[must_use]
    pub fn allowed_groups(&self) -> &[String] {
        &self.allowed_groups
    }

    /// Whether public registration is enabled.
    #[must_use]
    pub const fn public_registration_enabled(&self) -> bool {
        self.public_registration
    }
}

impl Default for AtpAccessPolicy {
    fn default() -> Self {
        Self::private()
    }
}

/// Mailbox storage policy for relay-backed offline delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpMailboxStoragePolicy {
    storage_label: String,
    max_bytes: u64,
    max_records: u64,
    encrypted_only: bool,
}

impl AtpMailboxStoragePolicy {
    /// Construct mailbox storage policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the label is blank or quotas are zero.
    pub fn new(
        storage_label: impl Into<String>,
        max_bytes: u64,
        max_records: u64,
        encrypted_only: bool,
    ) -> Result<Self, AtpOpsConfigError> {
        let storage_label = storage_label.into();
        if storage_label.trim().is_empty() {
            return Err(AtpOpsConfigError::EmptyMailboxStorageLabel);
        }
        if max_bytes == 0 || max_records == 0 {
            return Err(AtpOpsConfigError::InvalidQuota);
        }
        Ok(Self {
            storage_label,
            max_bytes,
            max_records,
            encrypted_only,
        })
    }

    /// Storage label for operator diagnostics.
    #[must_use]
    pub fn storage_label(&self) -> &str {
        &self.storage_label
    }

    /// Maximum mailbox storage bytes.
    #[must_use]
    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Maximum mailbox record count.
    #[must_use]
    pub const fn max_records(&self) -> u64 {
        self.max_records
    }

    /// Whether mailbox custody requires encrypted bytes.
    #[must_use]
    pub const fn encrypted_only(&self) -> bool {
        self.encrypted_only
    }
}

/// Operator log policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtpOperatorLogPolicy {
    /// Whether logs may include redacted peer id prefixes.
    pub log_peer_ids: bool,
    /// Whether service events must be emitted as structured records.
    pub structured_events: bool,
    /// Whether restart snapshots retain active state.
    pub retain_state_on_restart: bool,
}

/// Optional federation policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpFederationPolicy {
    trusted_services: Vec<String>,
    trust_assumptions: Vec<String>,
}

impl AtpFederationPolicy {
    /// Disable federation.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            trusted_services: Vec::new(),
            trust_assumptions: Vec::new(),
        }
    }

    /// Enable federation with explicit trusted services and trust assumptions.
    ///
    /// # Errors
    ///
    /// Returns an error unless both lists are non-empty and contain no blank
    /// entries.
    pub fn opt_in(
        trusted_services: Vec<String>,
        trust_assumptions: Vec<String>,
    ) -> Result<Self, AtpOpsConfigError> {
        if trusted_services.is_empty() {
            return Err(AtpOpsConfigError::FederationRequiresTrustedService);
        }
        if trust_assumptions.is_empty() {
            return Err(AtpOpsConfigError::FederationRequiresTrustAssumption);
        }
        if trusted_services
            .iter()
            .chain(trust_assumptions.iter())
            .any(|entry| entry.trim().is_empty())
        {
            return Err(AtpOpsConfigError::EmptyFederationEntry);
        }
        Ok(Self {
            trusted_services,
            trust_assumptions,
        })
    }

    /// Whether federation is enabled.
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.trusted_services.is_empty()
    }

    /// Trusted federated service ids.
    #[must_use]
    pub fn trusted_services(&self) -> &[String] {
        &self.trusted_services
    }

    /// Explicit operator trust assumptions.
    #[must_use]
    pub fn trust_assumptions(&self) -> &[String] {
        &self.trust_assumptions
    }
}

impl Default for AtpFederationPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

/// Relay plaintext visibility guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayContentVisibility {
    /// Relay sees routing metadata, timing, and ciphertext, never object bytes.
    OpaqueEncryptedOnly,
}

/// Self-hosted `atp rendezvous serve` configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpRendezvousServeConfig {
    command: AtpServeCommand,
    mode: AtpDeploymentMode,
    identity: AtpServiceIdentity,
    tls: AtpTlsPolicy,
    quotas: RendezvousQuotas,
    expiry: AtpExpiryPolicy,
    rate_limits: AtpRateLimitPolicy,
    access: AtpAccessPolicy,
    federation: AtpFederationPolicy,
    logs: AtpOperatorLogPolicy,
}

impl AtpRendezvousServeConfig {
    /// Build a mode-specific rendezvous serve config.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity or generated policy values.
    pub fn for_mode(
        mode: AtpDeploymentMode,
        service_id: impl Into<String>,
        operator_label: impl Into<String>,
    ) -> Result<Self, AtpOpsConfigError> {
        let config = Self {
            command: AtpServeCommand::RendezvousServe,
            mode,
            identity: AtpServiceIdentity::new(service_id, operator_label)?,
            tls: default_tls_policy(mode),
            quotas: rendezvous_quotas(mode),
            expiry: expiry_policy(mode).validate()?,
            rate_limits: rate_limits(mode).validate()?,
            access: default_access_policy(mode),
            federation: AtpFederationPolicy::disabled(),
            logs: log_policy(mode),
        };
        config.validate()?;
        Ok(config)
    }

    /// Command represented by this config.
    #[must_use]
    pub const fn command(&self) -> AtpServeCommand {
        self.command
    }

    /// Deployment mode.
    #[must_use]
    pub const fn mode(&self) -> AtpDeploymentMode {
        self.mode
    }

    /// Service identity.
    #[must_use]
    pub const fn identity(&self) -> &AtpServiceIdentity {
        &self.identity
    }

    /// TLS policy.
    #[must_use]
    pub const fn tls(&self) -> AtpTlsPolicy {
        self.tls
    }

    /// Rendezvous quotas.
    #[must_use]
    pub const fn quotas(&self) -> RendezvousQuotas {
        self.quotas
    }

    /// Expiry policy.
    #[must_use]
    pub const fn expiry(&self) -> AtpExpiryPolicy {
        self.expiry
    }

    /// Rate-limit policy.
    #[must_use]
    pub const fn rate_limits(&self) -> AtpRateLimitPolicy {
        self.rate_limits
    }

    /// Access policy.
    #[must_use]
    pub const fn access(&self) -> &AtpAccessPolicy {
        &self.access
    }

    /// Federation policy.
    #[must_use]
    pub const fn federation(&self) -> &AtpFederationPolicy {
        &self.federation
    }

    /// Operator log policy.
    #[must_use]
    pub const fn logs(&self) -> AtpOperatorLogPolicy {
        self.logs
    }

    /// Override TLS policy.
    ///
    /// # Errors
    ///
    /// Returns an error when a public gateway would become non-TLS.
    pub fn with_tls_policy(mut self, tls: AtpTlsPolicy) -> Result<Self, AtpOpsConfigError> {
        self.tls = tls;
        self.validate()?;
        Ok(self)
    }

    /// Override access policy.
    #[must_use]
    pub fn with_access_policy(mut self, access: AtpAccessPolicy) -> Self {
        self.access = access;
        self
    }

    /// Override federation policy.
    ///
    /// # Errors
    ///
    /// Returns an error when public gateway TLS requirements would be violated.
    pub fn with_federation_policy(
        mut self,
        federation: AtpFederationPolicy,
    ) -> Result<Self, AtpOpsConfigError> {
        self.federation = federation;
        self.validate()?;
        Ok(self)
    }

    /// Convert to the deterministic rendezvous state-machine config.
    pub fn rendezvous_service_config(
        &self,
    ) -> Result<RendezvousServiceConfig, super::rendezvous::Error> {
        RendezvousServiceConfig::new(self.identity.service_id.clone(), self.quotas).map(|config| {
            config
                .with_log_peer_ids(self.logs.log_peer_ids)
                .with_retain_state_on_restart(self.logs.retain_state_on_restart)
        })
    }

    fn validate(&self) -> Result<(), AtpOpsConfigError> {
        validate_public_tls(self.mode, self.tls)
    }
}

/// Self-hosted `atp relay serve` configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpRelayServeConfig {
    command: AtpServeCommand,
    mode: AtpDeploymentMode,
    identity: AtpServiceIdentity,
    tls: AtpTlsPolicy,
    max_active_reservations: usize,
    expiry: AtpExpiryPolicy,
    rate_limits: AtpRateLimitPolicy,
    access: AtpAccessPolicy,
    mailbox_storage: AtpMailboxStoragePolicy,
    federation: AtpFederationPolicy,
    logs: AtpOperatorLogPolicy,
}

impl AtpRelayServeConfig {
    /// Build a mode-specific relay serve config.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity or generated policy values.
    pub fn for_mode(
        mode: AtpDeploymentMode,
        relay_id: impl Into<String>,
        operator_label: impl Into<String>,
    ) -> Result<Self, AtpOpsConfigError> {
        let config = Self {
            command: AtpServeCommand::RelayServe,
            mode,
            identity: AtpServiceIdentity::new(relay_id, operator_label)?,
            tls: default_tls_policy(mode),
            max_active_reservations: relay_reservation_limit(mode),
            expiry: expiry_policy(mode).validate()?,
            rate_limits: rate_limits(mode).validate()?,
            access: default_access_policy(mode),
            mailbox_storage: mailbox_storage_policy(mode)?,
            federation: AtpFederationPolicy::disabled(),
            logs: log_policy(mode),
        };
        config.validate()?;
        Ok(config)
    }

    /// Command represented by this config.
    #[must_use]
    pub const fn command(&self) -> AtpServeCommand {
        self.command
    }

    /// Deployment mode.
    #[must_use]
    pub const fn mode(&self) -> AtpDeploymentMode {
        self.mode
    }

    /// Service identity.
    #[must_use]
    pub const fn identity(&self) -> &AtpServiceIdentity {
        &self.identity
    }

    /// TLS policy.
    #[must_use]
    pub const fn tls(&self) -> AtpTlsPolicy {
        self.tls
    }

    /// Maximum active relay reservations.
    #[must_use]
    pub const fn max_active_reservations(&self) -> usize {
        self.max_active_reservations
    }

    /// Expiry policy.
    #[must_use]
    pub const fn expiry(&self) -> AtpExpiryPolicy {
        self.expiry
    }

    /// Rate-limit policy.
    #[must_use]
    pub const fn rate_limits(&self) -> AtpRateLimitPolicy {
        self.rate_limits
    }

    /// Access policy.
    #[must_use]
    pub const fn access(&self) -> &AtpAccessPolicy {
        &self.access
    }

    /// Mailbox storage policy.
    #[must_use]
    pub const fn mailbox_storage(&self) -> &AtpMailboxStoragePolicy {
        &self.mailbox_storage
    }

    /// Federation policy.
    #[must_use]
    pub const fn federation(&self) -> &AtpFederationPolicy {
        &self.federation
    }

    /// Operator log policy.
    #[must_use]
    pub const fn logs(&self) -> AtpOperatorLogPolicy {
        self.logs
    }

    /// Relay content visibility guarantee.
    #[must_use]
    pub const fn content_visibility(&self) -> RelayContentVisibility {
        RelayContentVisibility::OpaqueEncryptedOnly
    }

    /// Override TLS policy.
    ///
    /// # Errors
    ///
    /// Returns an error when a public gateway would become non-TLS.
    pub fn with_tls_policy(mut self, tls: AtpTlsPolicy) -> Result<Self, AtpOpsConfigError> {
        self.tls = tls;
        self.validate()?;
        Ok(self)
    }

    /// Override access policy.
    #[must_use]
    pub fn with_access_policy(mut self, access: AtpAccessPolicy) -> Self {
        self.access = access;
        self
    }

    /// Override federation policy.
    ///
    /// # Errors
    ///
    /// Returns an error when public gateway TLS requirements would be violated.
    pub fn with_federation_policy(
        mut self,
        federation: AtpFederationPolicy,
    ) -> Result<Self, AtpOpsConfigError> {
        self.federation = federation;
        self.validate()?;
        Ok(self)
    }

    /// Convert to the deterministic relay state-machine config.
    pub fn relay_service_config(&self) -> Result<RelayServiceConfig, RelayError> {
        RelayServiceConfig::new(
            self.identity.service_id.clone(),
            self.max_active_reservations,
        )
        .map(|config| {
            config
                .with_log_peer_ids(self.logs.log_peer_ids)
                .with_retain_state_on_restart(self.logs.retain_state_on_restart)
        })
    }

    fn validate(&self) -> Result<(), AtpOpsConfigError> {
        validate_public_tls(self.mode, self.tls)?;
        if self.max_active_reservations == 0 {
            return Err(AtpOpsConfigError::InvalidQuota);
        }
        if !self.mailbox_storage.encrypted_only {
            return Err(AtpOpsConfigError::MailboxMustBeEncrypted);
        }
        Ok(())
    }
}

fn validate_public_tls(
    mode: AtpDeploymentMode,
    tls: AtpTlsPolicy,
) -> Result<(), AtpOpsConfigError> {
    if mode == AtpDeploymentMode::PublicGateway && !tls.requires_tls() {
        return Err(AtpOpsConfigError::PublicGatewayRequiresTls);
    }
    Ok(())
}

const fn default_tls_policy(mode: AtpDeploymentMode) -> AtpTlsPolicy {
    match mode {
        AtpDeploymentMode::Personal | AtpDeploymentMode::Ci => AtpTlsPolicy::DisabledLoopbackOnly,
        AtpDeploymentMode::Team => AtpTlsPolicy::Required {
            client_auth_required: true,
        },
        AtpDeploymentMode::PublicGateway => AtpTlsPolicy::Required {
            client_auth_required: false,
        },
    }
}

const fn rendezvous_quotas(mode: AtpDeploymentMode) -> RendezvousQuotas {
    match mode {
        AtpDeploymentMode::Personal => RendezvousQuotas {
            max_candidates_per_peer: 8,
            max_total_candidates: 32,
            max_observations_per_peer: 4,
            max_total_observations: 32,
            max_attempts_per_peer: 8,
        },
        AtpDeploymentMode::Team => RendezvousQuotas {
            max_candidates_per_peer: 16,
            max_total_candidates: 512,
            max_observations_per_peer: 8,
            max_total_observations: 1024,
            max_attempts_per_peer: 16,
        },
        AtpDeploymentMode::Ci => RendezvousQuotas {
            max_candidates_per_peer: 4,
            max_total_candidates: 16,
            max_observations_per_peer: 2,
            max_total_observations: 16,
            max_attempts_per_peer: 4,
        },
        AtpDeploymentMode::PublicGateway => RendezvousQuotas {
            max_candidates_per_peer: 8,
            max_total_candidates: 4096,
            max_observations_per_peer: 4,
            max_total_observations: 8192,
            max_attempts_per_peer: 8,
        },
    }
}

const fn relay_reservation_limit(mode: AtpDeploymentMode) -> usize {
    match mode {
        AtpDeploymentMode::Personal => 64,
        AtpDeploymentMode::Team => 2048,
        AtpDeploymentMode::Ci => 32,
        AtpDeploymentMode::PublicGateway => 8192,
    }
}

const fn expiry_policy(mode: AtpDeploymentMode) -> AtpExpiryPolicy {
    match mode {
        AtpDeploymentMode::Personal => AtpExpiryPolicy {
            candidate_ttl_micros: 60_000_000,
            relay_reservation_ttl_micros: 300_000_000,
            mailbox_ttl_secs: 86_400,
        },
        AtpDeploymentMode::Team => AtpExpiryPolicy {
            candidate_ttl_micros: 60_000_000,
            relay_reservation_ttl_micros: 600_000_000,
            mailbox_ttl_secs: 604_800,
        },
        AtpDeploymentMode::Ci => AtpExpiryPolicy {
            candidate_ttl_micros: 10_000_000,
            relay_reservation_ttl_micros: 60_000_000,
            mailbox_ttl_secs: 3_600,
        },
        AtpDeploymentMode::PublicGateway => AtpExpiryPolicy {
            candidate_ttl_micros: 30_000_000,
            relay_reservation_ttl_micros: 120_000_000,
            mailbox_ttl_secs: 86_400,
        },
    }
}

const fn rate_limits(mode: AtpDeploymentMode) -> AtpRateLimitPolicy {
    match mode {
        AtpDeploymentMode::Personal => AtpRateLimitPolicy {
            max_reservations_per_minute: 60,
            max_packets_per_second: 2_000,
            max_mailbox_bytes_per_minute: 64 * MIB,
        },
        AtpDeploymentMode::Team => AtpRateLimitPolicy {
            max_reservations_per_minute: 2_000,
            max_packets_per_second: 200_000,
            max_mailbox_bytes_per_minute: 4 * 1024 * MIB,
        },
        AtpDeploymentMode::Ci => AtpRateLimitPolicy {
            max_reservations_per_minute: 30,
            max_packets_per_second: 1_000,
            max_mailbox_bytes_per_minute: 32 * MIB,
        },
        AtpDeploymentMode::PublicGateway => AtpRateLimitPolicy {
            max_reservations_per_minute: 1_000,
            max_packets_per_second: 100_000,
            max_mailbox_bytes_per_minute: 1024 * MIB,
        },
    }
}

fn default_access_policy(mode: AtpDeploymentMode) -> AtpAccessPolicy {
    if mode == AtpDeploymentMode::PublicGateway {
        AtpAccessPolicy::public_registration()
    } else {
        AtpAccessPolicy::private()
    }
}

fn mailbox_storage_policy(
    mode: AtpDeploymentMode,
) -> Result<AtpMailboxStoragePolicy, AtpOpsConfigError> {
    match mode {
        AtpDeploymentMode::Personal => {
            AtpMailboxStoragePolicy::new("personal-mailbox", 512 * MIB, 16_384, true)
        }
        AtpDeploymentMode::Team => {
            AtpMailboxStoragePolicy::new("team-mailbox", 64 * 1024 * MIB, 1_000_000, true)
        }
        AtpDeploymentMode::Ci => AtpMailboxStoragePolicy::new("ci-mailbox", 128 * MIB, 4096, true),
        AtpDeploymentMode::PublicGateway => {
            AtpMailboxStoragePolicy::new("public-gateway-mailbox", 16 * 1024 * MIB, 250_000, true)
        }
    }
}

const fn log_policy(mode: AtpDeploymentMode) -> AtpOperatorLogPolicy {
    match mode {
        AtpDeploymentMode::Personal => AtpOperatorLogPolicy {
            log_peer_ids: false,
            structured_events: true,
            retain_state_on_restart: true,
        },
        AtpDeploymentMode::Team => AtpOperatorLogPolicy {
            log_peer_ids: false,
            structured_events: true,
            retain_state_on_restart: true,
        },
        AtpDeploymentMode::Ci => AtpOperatorLogPolicy {
            log_peer_ids: true,
            structured_events: true,
            retain_state_on_restart: false,
        },
        AtpDeploymentMode::PublicGateway => AtpOperatorLogPolicy {
            log_peer_ids: false,
            structured_events: true,
            retain_state_on_restart: true,
        },
    }
}

/// ATP ops configuration errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AtpOpsConfigError {
    /// Service id was blank.
    #[error("ATP service id is empty")]
    EmptyServiceId,
    /// Operator label was blank.
    #[error("ATP operator label is empty")]
    EmptyOperatorLabel,
    /// Peer or group access entry was blank.
    #[error("ATP access entry is empty")]
    EmptyAccessEntry,
    /// Mailbox storage label was blank.
    #[error("ATP mailbox storage label is empty")]
    EmptyMailboxStorageLabel,
    /// Quota or rate-limit value was zero.
    #[error("ATP service quota is invalid")]
    InvalidQuota,
    /// Expiry value was zero.
    #[error("ATP service expiry is invalid")]
    InvalidExpiry,
    /// Public gateways must require TLS.
    #[error("public ATP gateways require TLS")]
    PublicGatewayRequiresTls,
    /// Federation must name at least one trusted service.
    #[error("ATP federation requires at least one trusted service")]
    FederationRequiresTrustedService,
    /// Federation must document trust assumptions explicitly.
    #[error("ATP federation requires explicit trust assumptions")]
    FederationRequiresTrustAssumption,
    /// Federation trusted-service or assumption entry was blank.
    #[error("ATP federation entry is empty")]
    EmptyFederationEntry,
    /// Relay mailbox custody must require encrypted bytes.
    #[error("ATP relay mailbox storage must be encrypted-only")]
    MailboxMustBeEncrypted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serve_modes_map_to_cli_commands_and_state_machine_configs() {
        let rendezvous =
            AtpRendezvousServeConfig::for_mode(AtpDeploymentMode::Team, "rv-team", "team-ops")
                .expect("team rendezvous config");
        assert_eq!(
            rendezvous.command().words(),
            &["atp", "rendezvous", "serve"]
        );
        assert!(rendezvous.tls().requires_client_auth());
        assert_eq!(rendezvous.quotas().max_total_candidates, 512);

        let state_config = rendezvous
            .rendezvous_service_config()
            .expect("rendezvous service config");
        assert_eq!(state_config.service_id(), "rv-team");
        assert_eq!(state_config.default_quotas().max_total_candidates, 512);
        assert!(!state_config.log_peer_ids());
        assert!(state_config.retain_state_on_restart());

        let relay = AtpRelayServeConfig::for_mode(AtpDeploymentMode::Ci, "relay-ci", "ci-ops")
            .expect("ci relay config");
        assert_eq!(relay.command().words(), &["atp", "relay", "serve"]);
        assert_eq!(relay.max_active_reservations(), 32);
        assert!(!relay.logs().retain_state_on_restart);

        let relay_state = relay.relay_service_config().expect("relay state config");
        assert_eq!(relay_state.relay_id(), "relay-ci");
        assert_eq!(relay_state.max_active_reservations(), 32);
        assert!(relay_state.log_peer_ids());
        assert!(!relay_state.retain_state_on_restart());
    }

    #[test]
    fn config_covers_access_logs_mailbox_quotas_expiry_and_rate_limits() {
        let access = AtpAccessPolicy::private()
            .with_allowed_peer("peer:alice")
            .expect("allowed peer")
            .with_allowed_group("team:infra")
            .expect("allowed group");
        let relay =
            AtpRelayServeConfig::for_mode(AtpDeploymentMode::Team, "relay-team", "team-ops")
                .expect("relay config")
                .with_access_policy(access);

        assert_eq!(relay.access().allowed_peers(), &["peer:alice".to_owned()]);
        assert_eq!(relay.access().allowed_groups(), &["team:infra".to_owned()]);
        assert!(!relay.access().public_registration_enabled());
        assert_eq!(relay.mailbox_storage().storage_label(), "team-mailbox");
        assert!(relay.mailbox_storage().encrypted_only());
        assert!(relay.mailbox_storage().max_bytes() >= 64 * 1024 * MIB);
        assert_eq!(relay.expiry().mailbox_ttl_secs, 604_800);
        assert!(relay.rate_limits().max_packets_per_second >= 200_000);
        assert!(relay.logs().structured_events);
    }

    #[test]
    fn federation_is_disabled_by_default_and_opt_in_requires_trust() {
        let rendezvous =
            AtpRendezvousServeConfig::for_mode(AtpDeploymentMode::Personal, "rv-personal", "me")
                .expect("personal rendezvous");
        assert!(!rendezvous.federation().enabled());

        assert_eq!(
            AtpFederationPolicy::opt_in(Vec::new(), vec!["team roots are pinned".to_owned()])
                .expect_err("trusted service required"),
            AtpOpsConfigError::FederationRequiresTrustedService
        );
        assert_eq!(
            AtpFederationPolicy::opt_in(vec!["rv-team".to_owned()], Vec::new())
                .expect_err("trust assumption required"),
            AtpOpsConfigError::FederationRequiresTrustAssumption
        );

        let federated = rendezvous
            .with_federation_policy(
                AtpFederationPolicy::opt_in(
                    vec!["rv-team".to_owned()],
                    vec!["operators pin each service identity out of band".to_owned()],
                )
                .expect("federation policy"),
            )
            .expect("federated rendezvous config");
        assert!(federated.federation().enabled());
        assert_eq!(
            federated.federation().trusted_services(),
            &["rv-team".to_owned()]
        );
    }

    #[test]
    fn public_gateway_requires_tls_and_relay_visibility_stays_opaque() {
        let relay = AtpRelayServeConfig::for_mode(
            AtpDeploymentMode::PublicGateway,
            "relay-public",
            "public-ops",
        )
        .expect("public relay config");
        assert!(relay.tls().requires_tls());
        assert!(!relay.tls().requires_client_auth());
        assert!(relay.access().public_registration_enabled());
        assert_eq!(
            relay.content_visibility(),
            RelayContentVisibility::OpaqueEncryptedOnly
        );

        assert_eq!(
            relay
                .clone()
                .with_tls_policy(AtpTlsPolicy::DisabledLoopbackOnly)
                .expect_err("public gateway must require TLS"),
            AtpOpsConfigError::PublicGatewayRequiresTls
        );
    }
}
