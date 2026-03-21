//! Privacy-preserving export helpers for FABRIC metadata summaries.
//!
//! This module applies disclosure policy, subject blinding, and optional
//! differential-privacy-style noise to metadata that crosses a trust boundary.
//! Authoritative internal state always stays exact. Only exported summaries are
//! blinded or noised.

use super::ir::{MetadataDisclosure, PrivacyPolicy};
use crate::util::DetHasher;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::hash::{Hash, Hasher};
use thiserror::Error;

const KEY_MATERIAL_BYTES: usize = 32;
type HmacSha256 = Hmac<Sha256>;

/// Exact internal metadata summary before any privacy transform is applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoritativeMetadataSummary {
    /// Stable summary family or advisory name.
    pub summary_name: String,
    /// Internal tenant identifier.
    pub tenant: String,
    /// Internal subject or route key.
    pub subject: String,
    /// Exact message count before export noise.
    pub message_count: u64,
    /// Exact byte count before export noise.
    pub byte_count: u64,
    /// Exact error count before export noise.
    pub error_count: u64,
    /// Whether this export would cross a tenant boundary.
    pub cross_tenant: bool,
}

impl AuthoritativeMetadataSummary {
    fn validate(&self) -> Result<(), PrivacyExportError> {
        validate_text("summary_name", &self.summary_name)?;
        validate_text("tenant", &self.tenant)?;
        validate_text("subject", &self.subject)?;
        Ok(())
    }
}

/// Exported summary after policy-driven blinding and optional noise.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExportedMetadataSummary {
    /// Stable summary family or advisory name.
    pub summary_name: String,
    /// Policy name that governed the export.
    pub policy_name: String,
    /// Boundary disclosure mode used for the export.
    pub disclosure: MetadataDisclosure,
    /// Subject token shown to the observer after blinding.
    pub subject_token: String,
    /// Tenant token shown to the observer after blinding.
    pub tenant_token: String,
    /// Exported message count after optional noise.
    pub message_count: u64,
    /// Exported byte count after optional noise.
    pub byte_count: u64,
    /// Exported error count after optional noise.
    pub error_count: u64,
    /// Applied message-count noise delta.
    pub message_noise: i64,
    /// Applied byte-count noise delta.
    pub byte_noise: i64,
    /// Applied error-count noise delta.
    pub error_noise: i64,
    /// Budget spent by this export, when noise is enabled.
    pub privacy_budget_spent: Option<f64>,
    /// Whether the export crossed a tenant boundary.
    pub cross_tenant: bool,
}

/// Running budget for boundary-crossing privacy disclosures.
#[derive(Debug, Clone, PartialEq)]
pub struct PrivacyBudgetLedger {
    total_budget: f64,
    spent_budget: f64,
    disclosures: u64,
}

impl PrivacyBudgetLedger {
    /// Create a new finite privacy budget ledger.
    pub fn new(total_budget: f64) -> Result<Self, PrivacyExportError> {
        if !total_budget.is_finite() || total_budget <= 0.0 {
            return Err(PrivacyExportError::InvalidBudget {
                field: "total_budget",
                value: total_budget,
            });
        }
        Ok(Self {
            total_budget,
            spent_budget: 0.0,
            disclosures: 0,
        })
    }

    /// Remaining export budget.
    #[must_use]
    pub fn remaining_budget(&self) -> f64 {
        (self.total_budget - self.spent_budget).max(0.0)
    }

    /// Total budget already spent.
    #[must_use]
    pub fn spent_budget(&self) -> f64 {
        self.spent_budget
    }

    /// Number of accepted disclosures.
    #[must_use]
    pub const fn disclosures(&self) -> u64 {
        self.disclosures
    }

    fn spend(&mut self, epsilon: f64) -> Result<(), PrivacyExportError> {
        if !epsilon.is_finite() || epsilon <= 0.0 {
            return Err(PrivacyExportError::InvalidBudget {
                field: "epsilon",
                value: epsilon,
            });
        }

        let remaining = self.remaining_budget();
        if epsilon > remaining {
            return Err(PrivacyExportError::BudgetExhausted {
                requested: epsilon,
                remaining,
            });
        }

        self.spent_budget += epsilon;
        self.disclosures += 1;
        Ok(())
    }
}

/// Derived key material for FABRIC brokerless privacy primitives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedKeyMaterial([u8; KEY_MATERIAL_BYTES]);

impl DerivedKeyMaterial {
    /// Build deterministic key material from a stable text label.
    pub fn from_label(label: &str) -> Result<Self, KeyHierarchyError> {
        validate_key_text("label", label)?;
        let digest = Sha256::digest(label.as_bytes());
        let mut bytes = [0_u8; KEY_MATERIAL_BYTES];
        bytes.copy_from_slice(&digest);
        Ok(Self(bytes))
    }

    fn as_bytes(&self) -> &[u8; KEY_MATERIAL_BYTES] {
        &self.0
    }

    /// Render the key material as a stable hex fingerprint for audits/tests.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut fingerprint = String::with_capacity(self.0.len() * 2);
        for byte in self.0 {
            fingerprint.push(hex_nibble(byte >> 4));
            fingerprint.push(hex_nibble(byte & 0x0f));
        }
        fingerprint
    }
}

/// Root secret for a stewardship pool epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolEpochKeyMaterial {
    /// Placement pool that owns the root secret.
    pub placement_pool_id: String,
    /// Steward-pool epoch.
    pub pool_epoch: u64,
    root_secret: DerivedKeyMaterial,
}

impl PoolEpochKeyMaterial {
    /// Construct pool-epoch root material from deterministic label text.
    pub fn from_label(
        placement_pool_id: impl Into<String>,
        pool_epoch: u64,
        label: &str,
    ) -> Result<Self, KeyHierarchyError> {
        let placement_pool_id = placement_pool_id.into();
        validate_key_text("placement_pool_id", &placement_pool_id)?;
        validate_key_text("label", label)?;

        let mut hasher = Sha256::new();
        hasher.update(placement_pool_id.as_bytes());
        hasher.update([0]);
        hasher.update(pool_epoch.to_be_bytes());
        hasher.update([0]);
        hasher.update(label.as_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0_u8; KEY_MATERIAL_BYTES];
        bytes.copy_from_slice(&digest);

        Ok(Self {
            placement_pool_id,
            pool_epoch,
            root_secret: DerivedKeyMaterial(bytes),
        })
    }
}

/// Placement subgroup context derived from a stewardship pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubgroupKeyContext {
    /// Subgroup epoch inside the placement pool.
    pub subgroup_epoch: u64,
    /// Stable hash or fingerprint of the subgroup roster.
    pub subgroup_roster_hash: String,
}

impl SubgroupKeyContext {
    fn validate(&self) -> Result<(), KeyHierarchyError> {
        validate_key_text("subgroup_roster_hash", &self.subgroup_roster_hash)
    }
}

/// Cell-local derivation context under a placement subgroup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellKeyContext {
    /// Canonical subject-cell identity.
    pub cell_id: String,
    /// Current authoritative cell epoch.
    pub cell_epoch: u64,
    /// Stable hash or fingerprint of the current steward roster.
    pub roster_hash: String,
    /// Stable hash of the controlling config epoch.
    pub config_epoch_hash: String,
    /// Rekey generation for the current cell epoch.
    pub cell_rekey_generation: u64,
}

impl CellKeyContext {
    fn validate(&self) -> Result<(), KeyHierarchyError> {
        validate_key_text("cell_id", &self.cell_id)?;
        validate_key_text("roster_hash", &self.roster_hash)?;
        validate_key_text("config_epoch_hash", &self.config_epoch_hash)?;
        Ok(())
    }
}

/// Full derivation context for brokerless cell secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellKeyHierarchySpec {
    /// Placement subgroup that hosts the cell.
    pub subgroup: SubgroupKeyContext,
    /// Cell-local binding data.
    pub cell: CellKeyContext,
}

impl CellKeyHierarchySpec {
    pub(crate) fn validate(&self) -> Result<(), KeyHierarchyError> {
        self.subgroup.validate()?;
        self.cell.validate()?;
        Ok(())
    }

    /// Rebind the derivation context before restoring into a real environment.
    pub fn scrub_for_restore(
        &self,
        request: &RestoreScrubRequest,
    ) -> Result<Self, KeyHierarchyError> {
        request.validate()?;

        if self.cell.cell_id == request.cell.cell_id {
            return Err(KeyHierarchyError::RestoreCellIdMustChange);
        }

        if self.cell.cell_epoch == request.cell.cell_epoch {
            return Err(KeyHierarchyError::RestoreCellEpochMustChange);
        }

        Ok(Self {
            subgroup: request.subgroup.clone(),
            cell: request.cell.clone(),
        })
    }
}

/// Restore-time rebinding request for brokerless cell key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreScrubRequest {
    /// Fresh subgroup binding for the restored cell.
    pub subgroup: SubgroupKeyContext,
    /// Fresh cell binding for the restored cell.
    pub cell: CellKeyContext,
}

impl RestoreScrubRequest {
    fn validate(&self) -> Result<(), KeyHierarchyError> {
        self.subgroup.validate()?;
        self.cell.validate()?;
        Ok(())
    }
}

/// Fully derived key hierarchy for one brokerless subject cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellKeyHierarchy {
    /// Placement pool for the hierarchy.
    pub placement_pool_id: String,
    /// Steward-pool epoch.
    pub pool_epoch: u64,
    /// Placement subgroup epoch.
    pub subgroup_epoch: u64,
    /// Canonical cell identity.
    pub cell_id: String,
    /// Cell epoch.
    pub cell_epoch: u64,
    /// HKDF-style subgroup epoch key derived from the pool root.
    pub subgroup_epoch_key: DerivedKeyMaterial,
    /// Cell root key derived from the subgroup epoch key.
    pub cell_root_key: DerivedKeyMaterial,
    /// Capability-separated segment key.
    pub segment_key: DerivedKeyMaterial,
    /// Capability-separated symbol-wrap key.
    pub symbol_wrap_key: DerivedKeyMaterial,
    /// Capability-separated symbol-auth key.
    pub symbol_auth_key: DerivedKeyMaterial,
    /// Capability-separated reply-space key.
    pub reply_space_key: DerivedKeyMaterial,
    /// Capability-separated metadata-blinding key.
    pub metadata_blind_key: DerivedKeyMaterial,
    /// Capability-separated witness-wrap key.
    pub witness_wrap_key: DerivedKeyMaterial,
}

impl CellKeyHierarchy {
    /// Derive the full brokerless cell key hierarchy from a pool root.
    pub fn derive(
        pool_epoch: &PoolEpochKeyMaterial,
        spec: &CellKeyHierarchySpec,
    ) -> Result<Self, KeyHierarchyError> {
        validate_key_text("placement_pool_id", &pool_epoch.placement_pool_id)?;
        spec.validate()?;

        let subgroup_epoch_bytes = spec.subgroup.subgroup_epoch.to_be_bytes();
        let subgroup_epoch_key = derive_key_material(
            pool_epoch.root_secret.as_bytes(),
            "subgroup-epoch",
            &[
                pool_epoch.placement_pool_id.as_bytes(),
                &subgroup_epoch_bytes,
                spec.subgroup.subgroup_roster_hash.as_bytes(),
            ],
        )?;

        let cell_epoch_bytes = spec.cell.cell_epoch.to_be_bytes();
        let cell_rekey_generation_bytes = spec.cell.cell_rekey_generation.to_be_bytes();
        let cell_root_key = derive_key_material(
            subgroup_epoch_key.as_bytes(),
            "cell-root",
            &[
                spec.cell.cell_id.as_bytes(),
                &cell_epoch_bytes,
                spec.cell.roster_hash.as_bytes(),
                spec.cell.config_epoch_hash.as_bytes(),
                &cell_rekey_generation_bytes,
            ],
        )?;

        let segment_key = derive_key_material(cell_root_key.as_bytes(), "segment", &[])?;
        let symbol_wrap_key = derive_key_material(cell_root_key.as_bytes(), "symbol-wrap", &[])?;
        let symbol_auth_key = derive_key_material(cell_root_key.as_bytes(), "symbol-auth", &[])?;
        let reply_space_key = derive_key_material(cell_root_key.as_bytes(), "reply-space", &[])?;
        let metadata_blind_key =
            derive_key_material(cell_root_key.as_bytes(), "metadata-blind", &[])?;
        let witness_wrap_key = derive_key_material(cell_root_key.as_bytes(), "witness-wrap", &[])?;

        Ok(Self {
            placement_pool_id: pool_epoch.placement_pool_id.clone(),
            pool_epoch: pool_epoch.pool_epoch,
            subgroup_epoch: spec.subgroup.subgroup_epoch,
            cell_id: spec.cell.cell_id.clone(),
            cell_epoch: spec.cell.cell_epoch,
            subgroup_epoch_key,
            cell_root_key,
            segment_key,
            symbol_wrap_key,
            symbol_auth_key,
            reply_space_key,
            metadata_blind_key,
            witness_wrap_key,
        })
    }

    /// Issue narrow witness material without exposing the cell root.
    pub fn issue_witness_material(
        &self,
        witness_name: &str,
        retention_generation: u64,
    ) -> Result<WitnessScopeMaterial, KeyHierarchyError> {
        validate_key_text("witness_name", witness_name)?;
        let retention_generation_bytes = retention_generation.to_be_bytes();

        let wrapped_fragment_key = derive_key_material(
            self.witness_wrap_key.as_bytes(),
            "witness-fragment",
            &[witness_name.as_bytes(), &retention_generation_bytes],
        )?;
        let symbol_auth_key = derive_key_material(
            self.symbol_auth_key.as_bytes(),
            "witness-auth",
            &[witness_name.as_bytes(), &retention_generation_bytes],
        )?;

        Ok(WitnessScopeMaterial {
            witness_name: witness_name.to_owned(),
            cell_id: self.cell_id.clone(),
            cell_epoch: self.cell_epoch,
            retention_generation,
            wrapped_fragment_key,
            symbol_auth_key,
        })
    }

    /// Issue a bounded read-delegation ticket that never exposes the cell root.
    pub fn issue_read_delegation_ticket(
        &self,
        spec: &ReadDelegationSpec,
    ) -> Result<ReadDelegationTicket, KeyHierarchyError> {
        spec.validate()?;

        let issued_generation_bytes = spec.issued_generation.to_be_bytes();
        let cacheable_until_generation_bytes = spec.cacheable_until_generation.to_be_bytes();
        let revocation_generation_bytes = spec.revocation_generation.to_be_bytes();

        let ticket_key = derive_key_material(
            self.reply_space_key.as_bytes(),
            "read-delegation-ticket",
            &[
                spec.delegate.as_bytes(),
                &issued_generation_bytes,
                &cacheable_until_generation_bytes,
                &revocation_generation_bytes,
            ],
        )?;
        let reply_space_key = derive_key_material(
            self.reply_space_key.as_bytes(),
            "delegated-reply-space",
            &[
                spec.delegate.as_bytes(),
                &issued_generation_bytes,
                &cacheable_until_generation_bytes,
                &revocation_generation_bytes,
            ],
        )?;
        let metadata_blind_key = derive_key_material(
            self.metadata_blind_key.as_bytes(),
            "delegated-metadata-blind",
            &[
                spec.delegate.as_bytes(),
                &issued_generation_bytes,
                &cacheable_until_generation_bytes,
                &revocation_generation_bytes,
            ],
        )?;

        Ok(ReadDelegationTicket {
            delegate: spec.delegate.clone(),
            cell_id: self.cell_id.clone(),
            cell_epoch: self.cell_epoch,
            issued_generation: spec.issued_generation,
            cacheable_until_generation: spec.cacheable_until_generation,
            revocation_generation: spec.revocation_generation,
            ticket_key,
            reply_space_key,
            metadata_blind_key,
        })
    }
}

/// Witness-scoped key material for repair fragments or audits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessScopeMaterial {
    /// Witness identity or role label.
    pub witness_name: String,
    /// Cell the witness material belongs to.
    pub cell_id: String,
    /// Cell epoch the witness material belongs to.
    pub cell_epoch: u64,
    /// Retention generation bound into the witness derivation.
    pub retention_generation: u64,
    /// Wrapped fragment key for witness storage.
    pub wrapped_fragment_key: DerivedKeyMaterial,
    /// Narrow authentication key for witness-served fragments.
    pub symbol_auth_key: DerivedKeyMaterial,
}

/// Specification for a bounded read-delegation ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadDelegationSpec {
    /// Delegate identity receiving bounded read service.
    pub delegate: String,
    /// First generation the ticket may serve from cache.
    pub issued_generation: u64,
    /// Last generation the ticket may serve from cache.
    pub cacheable_until_generation: u64,
    /// Current revocation generation at ticket issue time.
    pub revocation_generation: u64,
}

impl ReadDelegationSpec {
    fn validate(&self) -> Result<(), KeyHierarchyError> {
        validate_key_text("delegate", &self.delegate)?;
        if self.cacheable_until_generation < self.issued_generation {
            return Err(KeyHierarchyError::InvalidGenerationWindow {
                field: "cacheable_until_generation",
                start: self.issued_generation,
                end: self.cacheable_until_generation,
            });
        }
        Ok(())
    }
}

/// Read-delegation material that narrows cacheability and revocation scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadDelegationTicket {
    /// Delegate identity receiving the ticket.
    pub delegate: String,
    /// Cell this ticket belongs to.
    pub cell_id: String,
    /// Cell epoch this ticket belongs to.
    pub cell_epoch: u64,
    /// First cache generation covered by the ticket.
    pub issued_generation: u64,
    /// Last cache generation covered by the ticket.
    pub cacheable_until_generation: u64,
    /// Revocation generation this ticket is bound to.
    pub revocation_generation: u64,
    /// Ticket-specific authentication material.
    pub ticket_key: DerivedKeyMaterial,
    /// Narrow reply-space material for delegated read paths.
    pub reply_space_key: DerivedKeyMaterial,
    /// Narrow metadata blinding material for delegated read paths.
    pub metadata_blind_key: DerivedKeyMaterial,
}

impl ReadDelegationTicket {
    /// Return true when the ticket is still valid for the requested generation.
    #[must_use]
    pub fn is_usable_for(
        &self,
        cell_epoch: u64,
        cache_generation: u64,
        current_revocation_generation: u64,
    ) -> bool {
        cell_epoch == self.cell_epoch
            && cache_generation >= self.issued_generation
            && cache_generation <= self.cacheable_until_generation
            && current_revocation_generation == self.revocation_generation
    }
}

/// Key-hierarchy derivation failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KeyHierarchyError {
    /// Required text fields must be non-empty.
    #[error("key hierarchy field `{field}` must not be empty")]
    EmptyField {
        /// Field that failed validation.
        field: &'static str,
    },
    /// Cacheability or generation windows must remain monotone.
    #[error("key hierarchy generation window `{field}` is invalid: start {start}, end {end}")]
    InvalidGenerationWindow {
        /// Field being validated.
        field: &'static str,
        /// Start of the requested window.
        start: u64,
        /// End of the requested window.
        end: u64,
    },
    /// Restore scrubbing must allocate a fresh external cell identity.
    #[error("restore scrub request must allocate a fresh cell id")]
    RestoreCellIdMustChange,
    /// Restore scrubbing must allocate a fresh epoch binding.
    #[error("restore scrub request must allocate a fresh cell epoch")]
    RestoreCellEpochMustChange,
    /// Internal derivation failure while constructing keyed material.
    #[error("failed to derive key material")]
    DerivationFailed,
}

/// Export-time privacy failures.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum PrivacyExportError {
    /// Required summary fields must be non-empty.
    #[error("privacy summary field `{field}` must not be empty")]
    EmptyField {
        /// Field that failed validation.
        field: &'static str,
    },
    /// Privacy budgets must be positive finite values.
    #[error("privacy budget `{field}` must be finite and greater than zero, got {value}")]
    InvalidBudget {
        /// Budget field being validated.
        field: &'static str,
        /// Invalid value that was supplied.
        value: f64,
    },
    /// Cross-tenant disclosure requires explicit policy opt-in.
    #[error("privacy policy `{policy_name}` does not permit cross-tenant metadata export")]
    CrossTenantFlowDisallowed {
        /// Policy that rejected the export.
        policy_name: String,
    },
    /// Privacy export budget was exhausted.
    #[error("privacy budget exhausted: requested {requested}, remaining {remaining}")]
    BudgetExhausted {
        /// Requested epsilon spend.
        requested: f64,
        /// Remaining epsilon before the failed spend.
        remaining: f64,
    },
}

/// Export one metadata summary across a trust boundary.
///
/// `disclosure_nonce` intentionally makes repeated exports deterministic for
/// tests and replay while still producing field-specific independent noise.
pub fn export_metadata_summary(
    policy: &PrivacyPolicy,
    ledger: &mut PrivacyBudgetLedger,
    summary: &AuthoritativeMetadataSummary,
    disclosure_nonce: u64,
) -> Result<ExportedMetadataSummary, PrivacyExportError> {
    // Differential privacy composition: we release 3 independent noised
    // quantities (message_count, byte_count, error_count). By basic
    // composition, the total privacy cost is 3×per-field-epsilon. We
    // charge the full epsilon from the budget and divide by 3 for each
    // field so the aggregate cost stays within the charged budget.
    const NOISED_FIELD_COUNT: f64 = 3.0;

    summary.validate()?;
    validate_text("policy_name", &policy.name)?;

    if summary.cross_tenant && !policy.allow_cross_tenant_flow {
        return Err(PrivacyExportError::CrossTenantFlowDisallowed {
            policy_name: policy.name.clone(),
        });
    }

    let (per_field_epsilon, privacy_budget_spent) = if let Some(epsilon) = policy.noise_budget {
        ledger.spend(epsilon)?;
        (Some(epsilon / NOISED_FIELD_COUNT), Some(epsilon))
    } else {
        (None, None)
    };

    let subject_token = blind_subject(
        policy.metadata_disclosure,
        &summary.subject,
        policy.redact_subject_literals,
    );
    let tenant_token = blind_identifier(policy.metadata_disclosure, &summary.tenant);

    let message_noise = laplace_noise(
        noise_seed(policy, summary, "message_count", disclosure_nonce),
        per_field_epsilon,
    );
    let byte_noise = laplace_noise(
        noise_seed(policy, summary, "byte_count", disclosure_nonce),
        per_field_epsilon,
    );
    let error_noise = laplace_noise(
        noise_seed(policy, summary, "error_count", disclosure_nonce),
        per_field_epsilon,
    );

    Ok(ExportedMetadataSummary {
        summary_name: summary.summary_name.clone(),
        policy_name: policy.name.clone(),
        disclosure: policy.metadata_disclosure,
        subject_token,
        tenant_token,
        message_count: apply_noise(summary.message_count, message_noise),
        byte_count: apply_noise(summary.byte_count, byte_noise),
        error_count: apply_noise(summary.error_count, error_noise),
        message_noise,
        byte_noise,
        error_noise,
        privacy_budget_spent,
        cross_tenant: summary.cross_tenant,
    })
}

fn validate_key_text(field: &'static str, value: &str) -> Result<(), KeyHierarchyError> {
    if value.trim().is_empty() {
        return Err(KeyHierarchyError::EmptyField { field });
    }
    Ok(())
}

fn derive_key_material(
    parent: &[u8; KEY_MATERIAL_BYTES],
    label: &str,
    components: &[&[u8]],
) -> Result<DerivedKeyMaterial, KeyHierarchyError> {
    let mut mac =
        HmacSha256::new_from_slice(parent).map_err(|_| KeyHierarchyError::DerivationFailed)?;
    mac.update(label.as_bytes());
    for component in components {
        mac.update(&[0xff]);
        mac.update(component);
    }
    let bytes = mac.finalize().into_bytes();
    let mut material = [0_u8; KEY_MATERIAL_BYTES];
    material.copy_from_slice(&bytes);
    Ok(DerivedKeyMaterial(material))
}

fn validate_text(field: &'static str, value: &str) -> Result<(), PrivacyExportError> {
    if value.trim().is_empty() {
        return Err(PrivacyExportError::EmptyField { field });
    }
    Ok(())
}

fn blind_subject(disclosure: MetadataDisclosure, subject: &str, redact_literals: bool) -> String {
    match disclosure {
        MetadataDisclosure::Full if redact_literals => subject
            .split('.')
            .map(|_| "*")
            .collect::<Vec<_>>()
            .join("."),
        MetadataDisclosure::Full => subject.to_owned(),
        MetadataDisclosure::Hashed => hash_token(subject),
        MetadataDisclosure::Redacted => "<redacted>".to_owned(),
    }
}

fn blind_identifier(disclosure: MetadataDisclosure, value: &str) -> String {
    match disclosure {
        MetadataDisclosure::Full => value.to_owned(),
        MetadataDisclosure::Hashed => hash_token(value),
        MetadataDisclosure::Redacted => "<redacted>".to_owned(),
    }
}

fn hash_token(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut token = String::with_capacity("sha256:".len() + digest.len() * 2);
    token.push_str("sha256:");
    for byte in digest {
        token.push(hex_nibble(byte >> 4));
        token.push(hex_nibble(byte & 0x0f));
    }
    token
}

fn hex_nibble(nibble: u8) -> char {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    char::from(HEX_DIGITS[usize::from(nibble & 0x0f)])
}

fn noise_seed(
    policy: &PrivacyPolicy,
    summary: &AuthoritativeMetadataSummary,
    field: &str,
    disclosure_nonce: u64,
) -> u64 {
    let mut hasher = DetHasher::default();
    policy.name.hash(&mut hasher);
    summary.summary_name.hash(&mut hasher);
    summary.subject.hash(&mut hasher);
    summary.tenant.hash(&mut hasher);
    summary.cross_tenant.hash(&mut hasher);
    field.hash(&mut hasher);
    disclosure_nonce.hash(&mut hasher);
    hasher.finish()
}

fn laplace_noise(seed: u64, epsilon: Option<f64>) -> i64 {
    let Some(epsilon) = epsilon else {
        return 0;
    };

    let centered = unit_interval(seed) - 0.5;
    let scale = 1.0 / epsilon;
    let noise = -scale * centered.signum() * 2.0f64.mul_add(-centered.abs(), 1.0).ln();
    noise.round() as i64
}

#[allow(clippy::cast_precision_loss)]
fn unit_interval(seed: u64) -> f64 {
    const TWO_POW_52_F64: f64 = 4_503_599_627_370_496.0;
    // Generate 52 bits of randomness (range 0 to 2^52 - 1).
    let bits = splitmix64(seed) >> 12;
    // By using 52 bits, `bits + 0.5` strictly fits within the 53-bit mantissa of f64.
    // This avoids the even-rounding that produces exactly 1.0.
    // The result is exactly uniformly distributed in the open interval (0, 1).
    (bits as f64 + 0.5) / TWO_POW_52_F64
}

fn splitmix64(mut state: u64) -> u64 {
    state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn apply_noise(value: u64, delta: i64) -> u64 {
    if delta >= 0 {
        value.saturating_add(delta.unsigned_abs())
    } else {
        value.saturating_sub(delta.unsigned_abs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary() -> AuthoritativeMetadataSummary {
        AuthoritativeMetadataSummary {
            summary_name: "fabric.advisory".to_owned(),
            tenant: "tenant-a".to_owned(),
            subject: "orders.eu.created".to_owned(),
            message_count: 41,
            byte_count: 4096,
            error_count: 2,
            cross_tenant: false,
        }
    }

    fn ledger() -> PrivacyBudgetLedger {
        PrivacyBudgetLedger::new(5.0).expect("valid privacy budget")
    }

    fn default_policy() -> PrivacyPolicy {
        PrivacyPolicy::default()
    }

    fn full_policy() -> PrivacyPolicy {
        let mut policy = default_policy();
        policy.metadata_disclosure = MetadataDisclosure::Full;
        policy
    }

    fn pool_epoch() -> PoolEpochKeyMaterial {
        PoolEpochKeyMaterial::from_label("pool-a", 7, "pool-seed")
            .expect("pool epoch key material should derive")
    }

    fn hierarchy_spec() -> CellKeyHierarchySpec {
        CellKeyHierarchySpec {
            subgroup: SubgroupKeyContext {
                subgroup_epoch: 3,
                subgroup_roster_hash: "subgroup-roster-hash".to_owned(),
            },
            cell: CellKeyContext {
                cell_id: "cell.orders.eu".to_owned(),
                cell_epoch: 11,
                roster_hash: "cell-roster-hash".to_owned(),
                config_epoch_hash: "config-epoch-hash".to_owned(),
                cell_rekey_generation: 2,
            },
        }
    }

    #[test]
    fn full_export_without_noise_preserves_authoritative_values() {
        let mut ledger = ledger();
        let exported = export_metadata_summary(&full_policy(), &mut ledger, &summary(), 7)
            .expect("full export should succeed");

        assert_eq!(exported.summary_name, "fabric.advisory");
        assert_eq!(exported.subject_token, "orders.eu.created");
        assert_eq!(exported.tenant_token, "tenant-a");
        assert_eq!(exported.message_count, 41);
        assert_eq!(exported.byte_count, 4096);
        assert_eq!(exported.error_count, 2);
        assert_eq!(exported.message_noise, 0);
        assert_eq!(exported.byte_noise, 0);
        assert_eq!(exported.error_noise, 0);
        assert_eq!(exported.privacy_budget_spent, None);
        assert_eq!(ledger.spent_budget(), 0.0);
    }

    #[test]
    fn hashed_export_blinds_subject_and_tenant() {
        let mut ledger = ledger();
        let policy = default_policy();

        let exported = export_metadata_summary(&policy, &mut ledger, &summary(), 17)
            .expect("hashed export should succeed");

        assert_eq!(exported.disclosure, MetadataDisclosure::Hashed);
        assert!(exported.subject_token.starts_with("sha256:"));
        assert!(exported.tenant_token.starts_with("sha256:"));
        assert_ne!(exported.subject_token, "orders.eu.created");
        assert_ne!(exported.tenant_token, "tenant-a");
    }

    #[test]
    fn default_privacy_policy_uses_hashed_disclosure() {
        assert_eq!(
            default_policy().metadata_disclosure,
            MetadataDisclosure::Hashed
        );
    }

    #[test]
    fn full_export_can_redact_subject_literals() {
        let mut ledger = ledger();
        let mut policy = full_policy();
        policy.redact_subject_literals = true;

        let exported = export_metadata_summary(&policy, &mut ledger, &summary(), 3)
            .expect("redacted full export should succeed");

        assert_eq!(exported.subject_token, "*.*.*");
        assert_eq!(exported.tenant_token, "tenant-a");
    }

    #[test]
    fn cross_tenant_export_requires_policy_opt_in() {
        let mut ledger = ledger();
        let mut summary = summary();
        summary.cross_tenant = true;

        let err = export_metadata_summary(&default_policy(), &mut ledger, &summary, 5)
            .expect_err("cross-tenant export should be rejected");

        assert!(matches!(
            err,
            PrivacyExportError::CrossTenantFlowDisallowed { .. }
        ));
    }

    #[test]
    fn privacy_budget_ledger_rejects_overspend() {
        let mut ledger = PrivacyBudgetLedger::new(0.75).expect("valid small budget");
        ledger.spend(0.5).expect("first spend fits");
        let err = ledger
            .spend(0.5)
            .expect_err("second spend should exceed budget");

        assert!(matches!(err, PrivacyExportError::BudgetExhausted { .. }));
        assert_eq!(ledger.disclosures(), 1);
    }

    #[test]
    fn noised_export_is_deterministic_and_preserves_authoritative_state() {
        let original = summary();
        let mut left_ledger = ledger();
        let mut right_ledger = ledger();
        let mut policy = default_policy();
        policy.noise_budget = Some(0.5);

        let left = export_metadata_summary(&policy, &mut left_ledger, &original, 99)
            .expect("left export should succeed");
        let right = export_metadata_summary(&policy, &mut right_ledger, &original, 99)
            .expect("right export should succeed");

        assert_eq!(left, right);
        assert_eq!(left.privacy_budget_spent, Some(0.5));
        assert_eq!(left_ledger.spent_budget(), 0.5);
        assert_eq!(left_ledger.disclosures(), 1);
        assert_eq!(original.message_count, 41);
        assert_eq!(original.byte_count, 4096);
        assert_eq!(original.error_count, 2);
    }

    #[test]
    fn invalid_summary_fields_fail_closed() {
        let mut ledger = ledger();
        let mut invalid = summary();
        invalid.subject = "   ".to_owned();

        let err = export_metadata_summary(&default_policy(), &mut ledger, &invalid, 11)
            .expect_err("invalid subject should fail");

        assert_eq!(err, PrivacyExportError::EmptyField { field: "subject" });
    }

    #[test]
    fn unit_interval_stays_inside_open_bounds_for_extreme_seeds() {
        for seed in [
            0,
            1,
            2,
            0x5555_5555_5555_5555,
            0xaaaa_aaaa_aaaa_aaaa,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let sample = unit_interval(seed);
            assert!(sample > 0.0, "seed {seed} should stay above zero");
            assert!(sample < 1.0, "seed {seed} should stay below one");
        }
    }

    #[test]
    fn cell_key_hierarchy_derivation_is_deterministic_and_capability_separated() {
        let left = CellKeyHierarchy::derive(&pool_epoch(), &hierarchy_spec())
            .expect("left hierarchy should derive");
        let right = CellKeyHierarchy::derive(&pool_epoch(), &hierarchy_spec())
            .expect("right hierarchy should derive");

        assert_eq!(left, right);
        assert_ne!(left.subgroup_epoch_key, left.cell_root_key);
        assert_ne!(left.cell_root_key, left.segment_key);
        assert_ne!(left.segment_key, left.symbol_wrap_key);
        assert_ne!(left.reply_space_key, left.metadata_blind_key);
        assert_ne!(left.metadata_blind_key, left.witness_wrap_key);
    }

    #[test]
    fn rotating_pool_subgroup_or_cell_changes_derived_keys() {
        let baseline = CellKeyHierarchy::derive(&pool_epoch(), &hierarchy_spec())
            .expect("baseline hierarchy should derive");

        let rotated_pool = CellKeyHierarchy::derive(
            &PoolEpochKeyMaterial::from_label("pool-a", 8, "pool-seed")
                .expect("rotated pool should derive"),
            &hierarchy_spec(),
        )
        .expect("rotated pool hierarchy should derive");
        assert_ne!(baseline.subgroup_epoch_key, rotated_pool.subgroup_epoch_key);

        let mut subgroup_rotated = hierarchy_spec();
        subgroup_rotated.subgroup.subgroup_epoch += 1;
        let subgroup_rotated = CellKeyHierarchy::derive(&pool_epoch(), &subgroup_rotated)
            .expect("rotated subgroup hierarchy should derive");
        assert_ne!(
            baseline.subgroup_epoch_key,
            subgroup_rotated.subgroup_epoch_key
        );
        assert_ne!(baseline.cell_root_key, subgroup_rotated.cell_root_key);

        let mut cell_rotated = hierarchy_spec();
        cell_rotated.cell.cell_epoch += 1;
        cell_rotated.cell.cell_rekey_generation += 1;
        let cell_rotated = CellKeyHierarchy::derive(&pool_epoch(), &cell_rotated)
            .expect("rotated cell hierarchy should derive");
        assert_ne!(baseline.cell_root_key, cell_rotated.cell_root_key);
        assert_ne!(baseline.reply_space_key, cell_rotated.reply_space_key);
    }

    #[test]
    fn witness_material_stays_narrow_and_generation_bound() {
        let hierarchy = CellKeyHierarchy::derive(&pool_epoch(), &hierarchy_spec())
            .expect("hierarchy should derive");

        let generation_one = hierarchy
            .issue_witness_material("witness-a", 1)
            .expect("generation one witness material should derive");
        let generation_two = hierarchy
            .issue_witness_material("witness-a", 2)
            .expect("generation two witness material should derive");

        assert_eq!(generation_one.cell_id, hierarchy.cell_id);
        assert_eq!(generation_one.cell_epoch, hierarchy.cell_epoch);
        assert_ne!(generation_one.wrapped_fragment_key, hierarchy.cell_root_key);
        assert_ne!(generation_one.symbol_auth_key, hierarchy.symbol_auth_key);
        assert_ne!(
            generation_one.wrapped_fragment_key,
            generation_two.wrapped_fragment_key
        );
        assert_ne!(
            generation_one.symbol_auth_key,
            generation_two.symbol_auth_key
        );
    }

    #[test]
    fn read_delegation_ticket_enforces_epoch_cacheability_and_revocation() {
        let hierarchy = CellKeyHierarchy::derive(&pool_epoch(), &hierarchy_spec())
            .expect("hierarchy should derive");
        let ticket = hierarchy
            .issue_read_delegation_ticket(&ReadDelegationSpec {
                delegate: "reader-a".to_owned(),
                issued_generation: 3,
                cacheable_until_generation: 5,
                revocation_generation: 9,
            })
            .expect("ticket should derive");

        assert_ne!(ticket.ticket_key, hierarchy.cell_root_key);
        assert_ne!(ticket.reply_space_key, hierarchy.reply_space_key);
        assert_ne!(ticket.metadata_blind_key, hierarchy.metadata_blind_key);
        assert!(ticket.is_usable_for(hierarchy.cell_epoch, 3, 9));
        assert!(!ticket.is_usable_for(hierarchy.cell_epoch + 1, 4, 8));
        assert!(!ticket.is_usable_for(hierarchy.cell_epoch, 4, 8));
        assert!(!ticket.is_usable_for(hierarchy.cell_epoch, 6, 8));
        assert!(!ticket.is_usable_for(hierarchy.cell_epoch, 4, 10));
    }

    #[test]
    fn narrowed_read_delegation_ticket_rotates_scoped_subkeys() {
        let hierarchy = CellKeyHierarchy::derive(&pool_epoch(), &hierarchy_spec())
            .expect("hierarchy should derive");
        let broad = hierarchy
            .issue_read_delegation_ticket(&ReadDelegationSpec {
                delegate: "reader-a".to_owned(),
                issued_generation: 3,
                cacheable_until_generation: 9,
                revocation_generation: 12,
            })
            .expect("broad ticket should derive");
        let narrow = hierarchy
            .issue_read_delegation_ticket(&ReadDelegationSpec {
                delegate: "reader-a".to_owned(),
                issued_generation: 3,
                cacheable_until_generation: 5,
                revocation_generation: 12,
            })
            .expect("narrow ticket should derive");

        assert_ne!(broad.ticket_key, narrow.ticket_key);
        assert_ne!(broad.reply_space_key, narrow.reply_space_key);
        assert_ne!(broad.metadata_blind_key, narrow.metadata_blind_key);
    }

    #[test]
    fn restore_scrub_rebinds_context_and_changes_replay_sensitive_keys() {
        let original_spec = hierarchy_spec();
        let scrubbed_spec = original_spec
            .scrub_for_restore(&RestoreScrubRequest {
                subgroup: SubgroupKeyContext {
                    subgroup_epoch: 4,
                    subgroup_roster_hash: "subgroup-roster-hash-restored".to_owned(),
                },
                cell: CellKeyContext {
                    cell_id: "cell.orders.eu.restored".to_owned(),
                    cell_epoch: 12,
                    roster_hash: "cell-roster-hash-restored".to_owned(),
                    config_epoch_hash: "config-epoch-hash-restored".to_owned(),
                    cell_rekey_generation: 4,
                },
            })
            .expect("restore scrub should rebind context");

        let original = CellKeyHierarchy::derive(&pool_epoch(), &original_spec)
            .expect("original hierarchy should derive");
        let scrubbed = CellKeyHierarchy::derive(&pool_epoch(), &scrubbed_spec)
            .expect("scrubbed hierarchy should derive");

        assert_ne!(original.cell_id, scrubbed.cell_id);
        assert_ne!(original.cell_epoch, scrubbed.cell_epoch);
        assert_ne!(original.cell_root_key, scrubbed.cell_root_key);
        assert_ne!(original.reply_space_key, scrubbed.reply_space_key);
        assert_ne!(original.witness_wrap_key, scrubbed.witness_wrap_key);
    }

    #[test]
    fn invalid_read_delegation_cache_window_fails_closed() {
        let hierarchy = CellKeyHierarchy::derive(&pool_epoch(), &hierarchy_spec())
            .expect("hierarchy should derive");
        let err = hierarchy
            .issue_read_delegation_ticket(&ReadDelegationSpec {
                delegate: "reader-a".to_owned(),
                issued_generation: 5,
                cacheable_until_generation: 4,
                revocation_generation: 7,
            })
            .expect_err("cacheability window must be monotone");

        assert_eq!(
            err,
            KeyHierarchyError::InvalidGenerationWindow {
                field: "cacheable_until_generation",
                start: 5,
                end: 4,
            }
        );
    }

    #[test]
    fn restore_scrub_requires_fresh_binding() {
        let spec = hierarchy_spec();
        let err = spec
            .scrub_for_restore(&RestoreScrubRequest {
                subgroup: spec.subgroup.clone(),
                cell: spec.cell.clone(),
            })
            .expect_err("restore scrub should reject unchanged cell identity");

        assert_eq!(err, KeyHierarchyError::RestoreCellIdMustChange);
    }

    #[test]
    fn restore_scrub_requires_fresh_epoch_binding() {
        let spec = hierarchy_spec();
        let err = spec
            .scrub_for_restore(&RestoreScrubRequest {
                subgroup: SubgroupKeyContext {
                    subgroup_epoch: spec.subgroup.subgroup_epoch + 1,
                    subgroup_roster_hash: "subgroup-roster-hash-restored".to_owned(),
                },
                cell: CellKeyContext {
                    cell_id: "cell.orders.eu.restored".to_owned(),
                    cell_epoch: spec.cell.cell_epoch,
                    roster_hash: "cell-roster-hash-restored".to_owned(),
                    config_epoch_hash: "config-epoch-hash-restored".to_owned(),
                    cell_rekey_generation: spec.cell.cell_rekey_generation + 1,
                },
            })
            .expect_err("restore scrub should reject unchanged cell epoch");

        assert_eq!(err, KeyHierarchyError::RestoreCellEpochMustChange);
    }
}
