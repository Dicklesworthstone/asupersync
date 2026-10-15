//! Channel-bonding invariants for ATP RaptorQ transfers.
//!
//! Channel bonding lets multiple donors seed the same byte-identical transfer:
//! each donor emits a disjoint residue class of RaptorQ ESIs, and the receiver
//! treats every authenticated symbol as fungible. Phase A is deliberately pure
//! data and math. Transport wiring consumes these types later; this module does
//! not open sockets, read files, or mutate transfer state.
//!
//! The security model is layered:
//!
//! - Descriptor identity is content-addressed: donors recompute per-entry
//!   SHA-256, content ids, the flat object-graph merkle root, and the RQ
//!   transfer id before donating. A mismatch refuses donation.
//! - Symbol auth uses the existing symbol HMAC key shared by all approved
//!   donors. The key reference here is an out-of-band handle; raw key bytes must
//!   travel only through the encrypted control plane, not argv or logs.
//! - An authenticated but malicious donor can waste bandwidth by sending symbols
//!   that fail auth or duplicate already-seen ESIs. It cannot make the receiver
//!   commit corrupt output because the receiver still verifies per-entry SHA-256
//!   and merkle root before commit.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::atp::object::{ContentId, ObjectId as AtpObjectId};
use crate::net::atp::transport_common::{EntryDigest, flat_merkle_root_from_digests, hex_encode};
use crate::types::symbol::ObjectId as RaptorqObjectId;

/// Current channel-bonding protocol version.
pub const BONDING_PROTOCOL_VERSION: u16 = 1;

/// Maximum donor count accepted by the Phase A static-residue scheme.
pub const MAX_STATIC_RESIDUE_DONORS: u32 = 1024;

/// Transfer descriptor shared by receiver and donors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondTransferDescriptor {
    /// RQ transfer id derived from the merkle root, total bytes, and file count.
    pub transfer_id: String,
    /// Display/root name from the original transfer manifest.
    pub root_name: String,
    /// Whether the transfer represents a directory tree.
    pub is_directory: bool,
    /// Total bytes across all entries.
    pub total_bytes: u64,
    /// Canonical flat object-graph merkle root.
    pub merkle_root_hex: String,
    /// Per-entry byte identity.
    pub entries: Vec<BondDescriptorEntry>,
    /// RaptorQ symbol size donors must use.
    pub symbol_size: u16,
    /// Maximum RaptorQ source block size donors must use.
    pub max_block_size: usize,
    /// Out-of-band key handle for shared symbol authentication.
    pub auth_key_ref: Option<String>,
}

impl BondTransferDescriptor {
    /// Build a descriptor from a donor-local byte proof.
    pub fn from_donor_proof(
        root_name: impl Into<String>,
        is_directory: bool,
        symbol_size: u16,
        max_block_size: usize,
        auth_key_ref: Option<String>,
        proof_entries: Vec<BondDonorProofEntry>,
    ) -> Result<Self, ChannelBondingError> {
        validate_proof_entries(&proof_entries)?;
        let total_bytes = total_bytes_for_proof(&proof_entries)?;
        let merkle_root_hex = merkle_root_for_proof(&proof_entries)?;
        let transfer_id = transfer_id_hex(&merkle_root_hex, total_bytes, proof_entries.len());
        let entries = proof_entries
            .iter()
            .map(BondDescriptorEntry::from)
            .collect();

        let descriptor = Self {
            transfer_id,
            root_name: root_name.into(),
            is_directory,
            total_bytes,
            merkle_root_hex,
            entries,
            symbol_size,
            max_block_size,
            auth_key_ref,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Validate descriptor self-consistency.
    pub fn validate(&self) -> Result<(), ChannelBondingError> {
        validate_hex_32("merkle_root_hex", None, &self.merkle_root_hex)?;
        if self.transfer_id
            != transfer_id_hex(&self.merkle_root_hex, self.total_bytes, self.entries.len())
        {
            return Err(ChannelBondingError::TransferIdMismatch {
                expected: transfer_id_hex(
                    &self.merkle_root_hex,
                    self.total_bytes,
                    self.entries.len(),
                ),
                actual: self.transfer_id.clone(),
            });
        }
        validate_descriptor_entries(&self.entries)?;
        let computed_total = total_bytes_for_descriptor(&self.entries)?;
        if computed_total != self.total_bytes {
            return Err(ChannelBondingError::TotalBytesMismatch {
                expected: self.total_bytes,
                actual: computed_total,
            });
        }
        Ok(())
    }

    /// Verify that a donor holds bytes identical to this descriptor.
    ///
    /// Donors build [`BondDonorByteProof`] from their local content stream. The
    /// verifier checks descriptor fields first, then recomputes the canonical
    /// flat merkle root from the donor's content ids and SHA-256 digests. Any
    /// mismatch is fail-closed.
    pub fn verify_donor_byte_match(
        &self,
        proof: &BondDonorByteProof,
    ) -> Result<(), ChannelBondingError> {
        self.validate()?;
        proof.validate()?;

        if proof.transfer_id != self.transfer_id {
            return Err(ChannelBondingError::TransferIdMismatch {
                expected: self.transfer_id.clone(),
                actual: proof.transfer_id.clone(),
            });
        }
        if proof.total_bytes != self.total_bytes {
            return Err(ChannelBondingError::TotalBytesMismatch {
                expected: self.total_bytes,
                actual: proof.total_bytes,
            });
        }
        if proof.merkle_root_hex != self.merkle_root_hex {
            return Err(ChannelBondingError::MerkleRootMismatch {
                expected: self.merkle_root_hex.clone(),
                actual: proof.merkle_root_hex.clone(),
            });
        }

        let expected = descriptor_entries_by_index(&self.entries)?;
        let actual = proof_entries_by_index(&proof.entries)?;
        if expected.len() != actual.len() {
            return Err(ChannelBondingError::EntryCountMismatch {
                expected: expected.len(),
                actual: actual.len(),
            });
        }

        for (index, descriptor_entry) in expected {
            let proof_entry = actual
                .get(&index)
                .ok_or(ChannelBondingError::MissingProofEntry { index })?;
            compare_entry_identity(descriptor_entry, proof_entry)?;
        }

        let computed_merkle = merkle_root_for_proof(&proof.entries)?;
        if computed_merkle != self.merkle_root_hex {
            return Err(ChannelBondingError::MerkleRootMismatch {
                expected: self.merkle_root_hex.clone(),
                actual: computed_merkle,
            });
        }

        Ok(())
    }

    /// Derive the RaptorQ object id for an entry in this transfer.
    #[must_use]
    pub fn entry_object_id(&self, entry_index: u32) -> RaptorqObjectId {
        entry_object_id(&self.transfer_id, entry_index)
    }
}

/// Descriptor row for one transfer entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondDescriptorEntry {
    /// Stable entry index from the transfer manifest.
    pub index: u32,
    /// Transfer-relative path.
    pub rel_path: String,
    /// Entry size in bytes.
    pub size: u64,
    /// Plain content SHA-256, lowercase hex in canonical producers.
    pub sha256_hex: String,
}

impl From<&BondDonorProofEntry> for BondDescriptorEntry {
    fn from(entry: &BondDonorProofEntry) -> Self {
        Self {
            index: entry.index,
            rel_path: entry.rel_path.clone(),
            size: entry.size,
            sha256_hex: entry.sha256_hex.clone(),
        }
    }
}

/// Donor-local proof that its bytes match a descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondDonorByteProof {
    /// Transfer id recomputed from the donor's local entries.
    pub transfer_id: String,
    /// Total bytes recomputed from the donor's local entries.
    pub total_bytes: u64,
    /// Merkle root recomputed from donor-local content ids and SHA-256 digests.
    pub merkle_root_hex: String,
    /// Per-entry donor-local byte proof.
    pub entries: Vec<BondDonorProofEntry>,
}

impl BondDonorByteProof {
    /// Build a donor proof from precomputed streaming entry digests.
    pub fn from_entries(entries: Vec<BondDonorProofEntry>) -> Result<Self, ChannelBondingError> {
        validate_proof_entries(&entries)?;
        let total_bytes = total_bytes_for_proof(&entries)?;
        let merkle_root_hex = merkle_root_for_proof(&entries)?;
        let transfer_id = transfer_id_hex(&merkle_root_hex, total_bytes, entries.len());
        Ok(Self {
            transfer_id,
            total_bytes,
            merkle_root_hex,
            entries,
        })
    }

    /// Validate proof self-consistency.
    pub fn validate(&self) -> Result<(), ChannelBondingError> {
        validate_hex_32("merkle_root_hex", None, &self.merkle_root_hex)?;
        validate_proof_entries(&self.entries)?;
        let computed_total = total_bytes_for_proof(&self.entries)?;
        if computed_total != self.total_bytes {
            return Err(ChannelBondingError::TotalBytesMismatch {
                expected: self.total_bytes,
                actual: computed_total,
            });
        }
        let computed_merkle = merkle_root_for_proof(&self.entries)?;
        if computed_merkle != self.merkle_root_hex {
            return Err(ChannelBondingError::MerkleRootMismatch {
                expected: self.merkle_root_hex.clone(),
                actual: computed_merkle,
            });
        }
        let computed_transfer_id =
            transfer_id_hex(&self.merkle_root_hex, self.total_bytes, self.entries.len());
        if computed_transfer_id != self.transfer_id {
            return Err(ChannelBondingError::TransferIdMismatch {
                expected: computed_transfer_id,
                actual: self.transfer_id.clone(),
            });
        }
        Ok(())
    }
}

/// Proof row for one donor-local entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondDonorProofEntry {
    /// Stable entry index from the transfer manifest.
    pub index: u32,
    /// Transfer-relative path.
    pub rel_path: String,
    /// Entry size in bytes.
    pub size: u64,
    /// Domain-separated content id (`ContentId::from_bytes`) as hex.
    pub content_id_hex: String,
    /// Plain content SHA-256 as hex.
    pub sha256_hex: String,
}

impl BondDonorProofEntry {
    /// Build an entry proof from bytes already held by a caller.
    ///
    /// Streaming transport code should prefer `ContentIdHasher` plus
    /// `Sha256` over this convenience constructor; tests and small fixtures can
    /// use it directly.
    #[must_use]
    pub fn from_bytes(index: u32, rel_path: impl Into<String>, bytes: &[u8]) -> Self {
        let content_id = ContentId::from_bytes(bytes);
        let sha256 = Sha256::digest(bytes);
        Self {
            index,
            rel_path: rel_path.into(),
            size: bytes.len() as u64,
            content_id_hex: content_id.to_hex(),
            sha256_hex: hex_encode(&sha256),
        }
    }
}

/// Per-donor ESI assignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DonorAssignment {
    /// Zero-based donor index.
    pub donor_index: u32,
    /// Total donors participating in this transfer.
    pub donor_count: u32,
    /// Optional explicit ESI windows reserved for Phase E dynamic allocation.
    pub esi_windows: Option<Vec<EsiWindow>>,
    /// Receiver UDP endpoints reachable by this donor.
    pub receiver_udp_endpoints: Vec<SocketAddr>,
    /// Out-of-band key handle for the shared symbol auth key.
    pub auth_key_ref: Option<String>,
}

impl DonorAssignment {
    /// Validate index bounds and optional ESI windows.
    pub fn validate(&self) -> Result<(), ChannelBondingError> {
        validate_donor_index(self.donor_index, self.donor_count)?;
        if self.donor_count > MAX_STATIC_RESIDUE_DONORS {
            return Err(ChannelBondingError::TooManyDonors {
                donor_count: self.donor_count,
                max: MAX_STATIC_RESIDUE_DONORS,
            });
        }
        if let Some(windows) = &self.esi_windows {
            for window in windows {
                window.validate()?;
            }
        }
        Ok(())
    }

    /// Whether this assignment owns an ESI.
    #[must_use]
    pub fn owns_esi(&self, esi: u32) -> bool {
        if !owns_esi(self.donor_index, self.donor_count, esi) {
            return false;
        }
        self.esi_windows
            .as_ref()
            .is_none_or(|windows| windows.iter().any(|window| window.contains(esi)))
    }
}

/// Encrypted control plane used to distribute the shared donor auth key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BondAuthControlPlane {
    /// SSH control connection.
    Ssh,
    /// Tailscale/WireGuard control connection.
    Tailscale,
}

/// Donor-local location for shared symbol-auth key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BondAuthKeyLocation {
    /// Environment variable containing key material.
    EnvVar(String),
    /// File containing key material.
    KeyFile(String),
    /// Explicitly rejected: argv is visible through process listings on shared hosts.
    Argv(String),
}

/// Reference to the shared symbol-auth key for a bonded transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondAuthKeyRef {
    /// Stable key identifier; never raw key material.
    pub key_id: String,
    /// Encrypted control plane that delivered the key material.
    pub control_plane: BondAuthControlPlane,
    /// Donor-local key material location.
    pub location: BondAuthKeyLocation,
}

impl BondAuthKeyRef {
    /// Validate the key reference and fail closed on unsafe delivery.
    pub fn validate(&self) -> Result<(), ChannelBondingError> {
        if self.key_id.trim().is_empty() {
            return Err(ChannelBondingError::MissingAuthKeyId);
        }
        match &self.location {
            BondAuthKeyLocation::EnvVar(name) => {
                if name.trim().is_empty() {
                    return Err(ChannelBondingError::MissingAuthKeyLocation);
                }
            }
            BondAuthKeyLocation::KeyFile(path) => {
                if path.trim().is_empty() {
                    return Err(ChannelBondingError::MissingAuthKeyLocation);
                }
            }
            BondAuthKeyLocation::Argv(_) => {
                return Err(ChannelBondingError::InsecureAuthKeyDelivery);
            }
        }
        Ok(())
    }
}

/// Fail-closed security model for bonded donor symbols.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondingSecurityModel {
    /// Shared symbol-auth key reference.
    pub auth_key: BondAuthKeyRef,
    /// Receiver verifies each symbol tag before decode.
    pub auth_before_decode: bool,
    /// Receiver commits only after final SHA-256 and Merkle verification.
    pub fail_closed_on_merkle_mismatch: bool,
}

impl BondingSecurityModel {
    /// Validate that both auth and final content integrity remain enabled.
    pub fn validate(&self) -> Result<(), ChannelBondingError> {
        self.auth_key.validate()?;
        if !self.auth_before_decode {
            return Err(ChannelBondingError::AuthBeforeDecodeDisabled);
        }
        if !self.fail_closed_on_merkle_mismatch {
            return Err(ChannelBondingError::MerkleFailClosedDisabled);
        }
        Ok(())
    }
}

/// Half-open ESI window `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsiWindow {
    /// First included ESI.
    pub start_inclusive: u32,
    /// First excluded ESI.
    pub end_exclusive: u32,
}

impl EsiWindow {
    /// Construct a half-open ESI window.
    #[must_use]
    pub const fn new(start_inclusive: u32, end_exclusive: u32) -> Self {
        Self {
            start_inclusive,
            end_exclusive,
        }
    }

    /// Check that the window is non-empty.
    pub fn validate(&self) -> Result<(), ChannelBondingError> {
        if self.start_inclusive >= self.end_exclusive {
            return Err(ChannelBondingError::InvalidEsiWindow {
                start_inclusive: self.start_inclusive,
                end_exclusive: self.end_exclusive,
            });
        }
        Ok(())
    }

    /// Whether the half-open window contains `esi`.
    #[must_use]
    pub const fn contains(&self, esi: u32) -> bool {
        self.start_inclusive <= esi && esi < self.end_exclusive
    }
}

/// Transport family advertised during bonding negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BondTransport {
    /// Direct IP path.
    DirectIp,
    /// SSH control/data path.
    Ssh,
    /// Tailscale/WireGuard path.
    Tailscale,
}

/// Negotiation offer from a receiver or donor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondingHandshake {
    /// Lowest compatible bonding protocol version.
    pub min_protocol_version: u16,
    /// Highest compatible bonding protocol version.
    pub max_protocol_version: u16,
    /// Supported path transports.
    pub supported_transports: BTreeSet<BondTransport>,
    /// Whether explicit dynamic ESI windows are supported.
    pub supports_dynamic_windows: bool,
    /// Whether resume metadata is supported.
    pub supports_resume: bool,
    /// Whether symbol auth is required by this endpoint.
    pub auth_required: bool,
    /// Maximum donor count accepted by this endpoint.
    pub max_donor_count: u32,
    /// Forward-compatible extension tokens. Unknown tokens are ignored.
    pub extension_capabilities: BTreeSet<String>,
}

impl BondingHandshake {
    /// Build a version-1 static-residue offer.
    #[must_use]
    pub fn v1_static(
        transports: impl IntoIterator<Item = BondTransport>,
        max_donor_count: u32,
        auth_required: bool,
    ) -> Self {
        Self {
            min_protocol_version: BONDING_PROTOCOL_VERSION,
            max_protocol_version: BONDING_PROTOCOL_VERSION,
            supported_transports: transports.into_iter().collect(),
            supports_dynamic_windows: false,
            supports_resume: false,
            auth_required,
            max_donor_count,
            extension_capabilities: BTreeSet::new(),
        }
    }

    /// Set an inclusive bonding protocol version range.
    #[must_use]
    pub const fn with_protocol_range(
        mut self,
        min_protocol_version: u16,
        max_protocol_version: u16,
    ) -> Self {
        self.min_protocol_version = min_protocol_version;
        self.max_protocol_version = max_protocol_version;
        self
    }

    /// Advertise receiver-allocated dynamic ESI windows.
    #[must_use]
    pub const fn with_dynamic_windows(mut self, supported: bool) -> Self {
        self.supports_dynamic_windows = supported;
        self
    }

    /// Advertise partial-transfer resume metadata.
    #[must_use]
    pub const fn with_resume(mut self, supported: bool) -> Self {
        self.supports_resume = supported;
        self
    }

    /// Advertise a forward-compatible extension token.
    #[must_use]
    pub fn with_extension_capability(mut self, capability: impl Into<String>) -> Self {
        self.extension_capabilities.insert(capability.into());
        self
    }

    /// Negotiate a compatible agreement with a peer.
    pub fn negotiate(&self, peer: &Self) -> Result<BondingAgreement, ChannelBondingError> {
        validate_handshake_offer(self)?;
        validate_handshake_offer(peer)?;
        if self.supported_transports.is_empty() || peer.supported_transports.is_empty() {
            return Err(ChannelBondingError::NoCommonTransport);
        }

        let selected_version = self.max_protocol_version.min(peer.max_protocol_version);
        let required_min = self.min_protocol_version.max(peer.min_protocol_version);
        if selected_version < required_min {
            return Err(ChannelBondingError::IncompatibleProtocolVersion {
                local_min: self.min_protocol_version,
                local_max: self.max_protocol_version,
                peer_min: peer.min_protocol_version,
                peer_max: peer.max_protocol_version,
            });
        }

        let supported_transports = self
            .supported_transports
            .intersection(&peer.supported_transports)
            .copied()
            .collect::<BTreeSet<_>>();
        if supported_transports.is_empty() {
            return Err(ChannelBondingError::NoCommonTransport);
        }

        let max_donor_count = self.max_donor_count.min(peer.max_donor_count);
        if max_donor_count == 0 {
            return Err(ChannelBondingError::InvalidDonorCount { donor_count: 0 });
        }

        Ok(BondingAgreement {
            protocol_version: selected_version,
            supported_transports,
            assignment_mode: if self.supports_dynamic_windows && peer.supports_dynamic_windows {
                BondingAssignmentMode::DynamicWindows
            } else {
                BondingAssignmentMode::StaticResidue
            },
            resume_supported: self.supports_resume && peer.supports_resume,
            auth_required: self.auth_required || peer.auth_required,
            max_donor_count,
        })
    }
}

/// Result of a compatible bonding handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondingAgreement {
    /// Selected bonding protocol version.
    pub protocol_version: u16,
    /// Common supported transports.
    pub supported_transports: BTreeSet<BondTransport>,
    /// Assignment mode for this donor/receiver pair.
    pub assignment_mode: BondingAssignmentMode,
    /// Whether resume may be used.
    pub resume_supported: bool,
    /// Whether symbols must carry auth tags.
    pub auth_required: bool,
    /// Negotiated donor-count ceiling.
    pub max_donor_count: u32,
}

impl BondingAgreement {
    /// Whether this agreement permits a transport family.
    #[must_use]
    pub fn supports_transport(&self, transport: BondTransport) -> bool {
        self.supported_transports.contains(&transport)
    }
}

/// ESI allocation mode selected by negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BondingAssignmentMode {
    /// Static donor residue classes: donor `i` owns `esi % N == i`.
    StaticResidue,
    /// Receiver-allocated explicit ESI windows.
    DynamicWindows,
}

/// Iterator over the ESI residue class for one donor.
#[derive(Debug, Clone)]
pub struct DonorEsiStream {
    donor_index: u32,
    donor_count: u32,
    next_seq: Option<u32>,
}

impl DonorEsiStream {
    /// Create an ESI stream for `donor_index` of `donor_count`.
    pub fn new(donor_index: u32, donor_count: u32) -> Result<Self, ChannelBondingError> {
        validate_donor_index(donor_index, donor_count)?;
        Ok(Self {
            donor_index,
            donor_count,
            next_seq: Some(0),
        })
    }
}

impl Iterator for DonorEsiStream {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        let seq = self.next_seq?;
        match esi_for_donor(self.donor_index, self.donor_count, seq) {
            Ok(esi) => {
                self.next_seq = seq.checked_add(1);
                Some(esi)
            }
            Err(_) => {
                self.next_seq = None;
                None
            }
        }
    }
}

/// Return the `seq`th ESI owned by donor `i` of `N`.
pub fn esi_for_donor(
    donor_index: u32,
    donor_count: u32,
    seq: u32,
) -> Result<u32, ChannelBondingError> {
    validate_donor_index(donor_index, donor_count)?;
    seq.checked_mul(donor_count)
        .and_then(|base| base.checked_add(donor_index))
        .ok_or(ChannelBondingError::EsiOverflow)
}

/// Whether donor `i` of `N` owns `esi` in the static-residue scheme.
#[must_use]
pub const fn owns_esi(donor_index: u32, donor_count: u32, esi: u32) -> bool {
    donor_count != 0 && donor_index < donor_count && esi % donor_count == donor_index
}

/// Derive the per-entry RaptorQ object id from a transfer id and entry index.
#[must_use]
pub fn entry_object_id(transfer_id: &str, index: u32) -> RaptorqObjectId {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.entry-object-id.v1\0");
    hasher.update(transfer_id.as_bytes());
    hasher.update(index.to_be_bytes());
    let digest = hasher.finalize();
    let high = u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    let low = u64::from_be_bytes([
        digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14],
        digest[15],
    ]);
    RaptorqObjectId::new(high, low)
}

/// Derive the RQ transfer id for a bonded descriptor.
#[must_use]
pub fn transfer_id_hex(merkle_root_hex: &str, total_bytes: u64, file_count: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.transfer-id.v1\0");
    hasher.update(merkle_root_hex.as_bytes());
    hasher.update(total_bytes.to_be_bytes());
    hasher.update(u64::try_from(file_count).unwrap_or(u64::MAX).to_be_bytes());
    hex_encode(&hasher.finalize()[..16])
}

/// Channel-bonding Phase A validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelBondingError {
    /// Donor count was zero.
    InvalidDonorCount {
        /// Invalid donor count.
        donor_count: u32,
    },
    /// Donor index is outside `0..donor_count`.
    InvalidDonorIndex {
        /// Donor index supplied.
        donor_index: u32,
        /// Donor count supplied.
        donor_count: u32,
    },
    /// Donor count exceeds the static-residue cap.
    TooManyDonors {
        /// Donor count supplied.
        donor_count: u32,
        /// Maximum accepted donor count.
        max: u32,
    },
    /// ESI arithmetic overflowed `u32`.
    EsiOverflow,
    /// ESI window is empty or inverted.
    InvalidEsiWindow {
        /// First included ESI.
        start_inclusive: u32,
        /// First excluded ESI.
        end_exclusive: u32,
    },
    /// Protocol range was internally invalid.
    InvalidProtocolRange {
        /// Minimum accepted version.
        min: u16,
        /// Maximum accepted version.
        max: u16,
    },
    /// Local and peer protocol ranges do not overlap.
    IncompatibleProtocolVersion {
        /// Local minimum accepted version.
        local_min: u16,
        /// Local maximum accepted version.
        local_max: u16,
        /// Peer minimum accepted version.
        peer_min: u16,
        /// Peer maximum accepted version.
        peer_max: u16,
    },
    /// No transport family is common to both peers.
    NoCommonTransport,
    /// Hex field is not a 32-byte digest.
    InvalidHexDigest {
        /// Field name.
        field: &'static str,
        /// Optional entry index.
        index: Option<u32>,
        /// Invalid value.
        value: String,
    },
    /// Duplicate descriptor or proof entry index.
    DuplicateEntryIndex {
        /// Duplicate index.
        index: u32,
    },
    /// Duplicate descriptor or proof relative path.
    DuplicateEntryPath {
        /// Duplicate path.
        rel_path: String,
    },
    /// Entry count differs between descriptor and proof.
    EntryCountMismatch {
        /// Expected count.
        expected: usize,
        /// Actual count.
        actual: usize,
    },
    /// Proof omitted a descriptor entry.
    MissingProofEntry {
        /// Missing entry index.
        index: u32,
    },
    /// Entry field differs between descriptor and proof.
    EntryMismatch {
        /// Entry index.
        index: u32,
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: String,
        /// Actual value.
        actual: String,
    },
    /// Total bytes differs from the entries.
    TotalBytesMismatch {
        /// Expected total.
        expected: u64,
        /// Actual total.
        actual: u64,
    },
    /// Entry sizes overflowed `u64`.
    TotalBytesOverflow,
    /// Transfer id differs from the canonical RQ descriptor id.
    TransferIdMismatch {
        /// Expected transfer id.
        expected: String,
        /// Actual transfer id.
        actual: String,
    },
    /// Merkle root differs from the canonical donor proof root.
    MerkleRootMismatch {
        /// Expected merkle root.
        expected: String,
        /// Actual merkle root.
        actual: String,
    },
    /// Shared symbol-auth key id is empty.
    MissingAuthKeyId,
    /// Shared symbol-auth key location is empty.
    MissingAuthKeyLocation,
    /// Shared symbol-auth key was configured for argv delivery.
    InsecureAuthKeyDelivery,
    /// Receiver auth-before-decode was disabled.
    AuthBeforeDecodeDisabled,
    /// Final Merkle/SHA fail-closed verification was disabled.
    MerkleFailClosedDisabled,
}

impl fmt::Display for ChannelBondingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDonorCount { donor_count } => {
                write!(f, "invalid donor_count {donor_count}; must be nonzero")
            }
            Self::InvalidDonorIndex {
                donor_index,
                donor_count,
            } => write!(
                f,
                "invalid donor_index {donor_index}; donor_count is {donor_count}"
            ),
            Self::TooManyDonors { donor_count, max } => {
                write!(f, "donor_count {donor_count} exceeds max {max}")
            }
            Self::EsiOverflow => f.write_str("ESI arithmetic overflow"),
            Self::InvalidEsiWindow {
                start_inclusive,
                end_exclusive,
            } => write!(f, "invalid ESI window [{start_inclusive}, {end_exclusive})"),
            Self::InvalidProtocolRange { min, max } => {
                write!(f, "invalid bonding protocol range {min}..={max}")
            }
            Self::IncompatibleProtocolVersion {
                local_min,
                local_max,
                peer_min,
                peer_max,
            } => write!(
                f,
                "incompatible bonding protocol versions: local {local_min}..={local_max}, peer {peer_min}..={peer_max}"
            ),
            Self::NoCommonTransport => f.write_str("no common bonding transport"),
            Self::InvalidHexDigest {
                field,
                index,
                value,
            } => write!(f, "invalid {field} digest for entry {index:?}: {value:?}"),
            Self::DuplicateEntryIndex { index } => {
                write!(f, "duplicate bonded entry index {index}")
            }
            Self::DuplicateEntryPath { rel_path } => {
                write!(f, "duplicate bonded entry path {rel_path:?}")
            }
            Self::EntryCountMismatch { expected, actual } => {
                write!(
                    f,
                    "entry count mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::MissingProofEntry { index } => {
                write!(f, "donor proof missing entry index {index}")
            }
            Self::EntryMismatch {
                index,
                field,
                expected,
                actual,
            } => write!(
                f,
                "entry {index} {field} mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::TotalBytesMismatch { expected, actual } => {
                write!(
                    f,
                    "total bytes mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::TotalBytesOverflow => f.write_str("total bytes overflow"),
            Self::TransferIdMismatch { expected, actual } => write!(
                f,
                "transfer id mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::MerkleRootMismatch { expected, actual } => write!(
                f,
                "merkle root mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::MissingAuthKeyId => f.write_str("bonding auth key id must not be empty"),
            Self::MissingAuthKeyLocation => {
                f.write_str("bonding auth key location must not be empty")
            }
            Self::InsecureAuthKeyDelivery => {
                f.write_str("bonding auth key must not be delivered through argv")
            }
            Self::AuthBeforeDecodeDisabled => {
                f.write_str("channel bonding requires auth-before-decode")
            }
            Self::MerkleFailClosedDisabled => {
                f.write_str("channel bonding requires fail-closed Merkle/SHA verification")
            }
        }
    }
}

impl std::error::Error for ChannelBondingError {}

fn validate_donor_index(donor_index: u32, donor_count: u32) -> Result<(), ChannelBondingError> {
    validate_donor_count(donor_count)?;
    if donor_index >= donor_count {
        return Err(ChannelBondingError::InvalidDonorIndex {
            donor_index,
            donor_count,
        });
    }
    Ok(())
}

fn validate_donor_count(donor_count: u32) -> Result<(), ChannelBondingError> {
    if donor_count == 0 {
        return Err(ChannelBondingError::InvalidDonorCount { donor_count });
    }
    Ok(())
}

fn validate_protocol_range(min: u16, max: u16) -> Result<(), ChannelBondingError> {
    if min == 0 || min > max {
        return Err(ChannelBondingError::InvalidProtocolRange { min, max });
    }
    Ok(())
}

fn validate_handshake_offer(offer: &BondingHandshake) -> Result<(), ChannelBondingError> {
    validate_protocol_range(offer.min_protocol_version, offer.max_protocol_version)?;
    validate_donor_count(offer.max_donor_count)?;
    if offer.max_donor_count > MAX_STATIC_RESIDUE_DONORS {
        return Err(ChannelBondingError::TooManyDonors {
            donor_count: offer.max_donor_count,
            max: MAX_STATIC_RESIDUE_DONORS,
        });
    }
    Ok(())
}

fn validate_descriptor_entries(entries: &[BondDescriptorEntry]) -> Result<(), ChannelBondingError> {
    let mut indices = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for entry in entries {
        if !indices.insert(entry.index) {
            return Err(ChannelBondingError::DuplicateEntryIndex { index: entry.index });
        }
        if !paths.insert(entry.rel_path.clone()) {
            return Err(ChannelBondingError::DuplicateEntryPath {
                rel_path: entry.rel_path.clone(),
            });
        }
        validate_hex_32("sha256_hex", Some(entry.index), &entry.sha256_hex)?;
    }
    Ok(())
}

fn validate_proof_entries(entries: &[BondDonorProofEntry]) -> Result<(), ChannelBondingError> {
    let mut indices = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for entry in entries {
        if !indices.insert(entry.index) {
            return Err(ChannelBondingError::DuplicateEntryIndex { index: entry.index });
        }
        if !paths.insert(entry.rel_path.clone()) {
            return Err(ChannelBondingError::DuplicateEntryPath {
                rel_path: entry.rel_path.clone(),
            });
        }
        validate_hex_32("content_id_hex", Some(entry.index), &entry.content_id_hex)?;
        validate_hex_32("sha256_hex", Some(entry.index), &entry.sha256_hex)?;
    }
    Ok(())
}

fn validate_hex_32(
    field: &'static str,
    index: Option<u32>,
    value: &str,
) -> Result<(), ChannelBondingError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ChannelBondingError::InvalidHexDigest {
            field,
            index,
            value: value.to_string(),
        });
    }
    Ok(())
}

fn descriptor_entries_by_index(
    entries: &[BondDescriptorEntry],
) -> Result<BTreeMap<u32, &BondDescriptorEntry>, ChannelBondingError> {
    let mut by_index = BTreeMap::new();
    for entry in entries {
        if by_index.insert(entry.index, entry).is_some() {
            return Err(ChannelBondingError::DuplicateEntryIndex { index: entry.index });
        }
    }
    Ok(by_index)
}

fn proof_entries_by_index(
    entries: &[BondDonorProofEntry],
) -> Result<BTreeMap<u32, &BondDonorProofEntry>, ChannelBondingError> {
    let mut by_index = BTreeMap::new();
    for entry in entries {
        if by_index.insert(entry.index, entry).is_some() {
            return Err(ChannelBondingError::DuplicateEntryIndex { index: entry.index });
        }
    }
    Ok(by_index)
}

fn compare_entry_identity(
    descriptor: &BondDescriptorEntry,
    proof: &BondDonorProofEntry,
) -> Result<(), ChannelBondingError> {
    if descriptor.rel_path != proof.rel_path {
        return Err(ChannelBondingError::EntryMismatch {
            index: descriptor.index,
            field: "rel_path",
            expected: descriptor.rel_path.clone(),
            actual: proof.rel_path.clone(),
        });
    }
    if descriptor.size != proof.size {
        return Err(ChannelBondingError::EntryMismatch {
            index: descriptor.index,
            field: "size",
            expected: descriptor.size.to_string(),
            actual: proof.size.to_string(),
        });
    }
    if descriptor.sha256_hex != proof.sha256_hex {
        return Err(ChannelBondingError::EntryMismatch {
            index: descriptor.index,
            field: "sha256_hex",
            expected: descriptor.sha256_hex.clone(),
            actual: proof.sha256_hex.clone(),
        });
    }
    Ok(())
}

fn total_bytes_for_descriptor(entries: &[BondDescriptorEntry]) -> Result<u64, ChannelBondingError> {
    entries.iter().try_fold(0u64, |acc, entry| {
        acc.checked_add(entry.size)
            .ok_or(ChannelBondingError::TotalBytesOverflow)
    })
}

fn total_bytes_for_proof(entries: &[BondDonorProofEntry]) -> Result<u64, ChannelBondingError> {
    entries.iter().try_fold(0u64, |acc, entry| {
        acc.checked_add(entry.size)
            .ok_or(ChannelBondingError::TotalBytesOverflow)
    })
}

fn merkle_root_for_proof(entries: &[BondDonorProofEntry]) -> Result<String, ChannelBondingError> {
    let digests = entries
        .iter()
        .map(|entry| {
            let content_id = ContentId::new(parse_hex_32(
                "content_id_hex",
                Some(entry.index),
                &entry.content_id_hex,
            )?);
            Ok(EntryDigest {
                rel_path: entry.rel_path.clone(),
                size: entry.size,
                content_id: AtpObjectId::content(content_id),
                content_sha256: parse_hex_32("sha256_hex", Some(entry.index), &entry.sha256_hex)?,
            })
        })
        .collect::<Result<Vec<_>, ChannelBondingError>>()?;
    Ok(flat_merkle_root_from_digests(&digests))
}

fn parse_hex_32(
    field: &'static str,
    index: Option<u32>,
    value: &str,
) -> Result<[u8; 32], ChannelBondingError> {
    validate_hex_32(field, index, value)?;
    let mut out = [0u8; 32];
    hex::decode_to_slice(value, &mut out).map_err(|_| ChannelBondingError::InvalidHexDigest {
        field,
        index,
        value: value.to_string(),
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{AuthenticatedSymbol, SecurityContext};
    use crate::types::{Symbol, SymbolId, SymbolKind};

    fn sample_proof() -> BondDonorByteProof {
        BondDonorByteProof::from_entries(vec![
            BondDonorProofEntry::from_bytes(0, "alpha.txt", b"alpha"),
            BondDonorProofEntry::from_bytes(1, "dir/beta.txt", b"beta"),
        ])
        .expect("valid proof")
    }

    #[test]
    fn donor_esi_partition_covers_without_overlap() {
        for donor_count in [1, 2, 3, 5, 8] {
            let limit = 257u32;
            let mut owners = vec![0u32; limit as usize];
            for donor_index in 0..donor_count {
                for esi in 0..limit {
                    if owns_esi(donor_index, donor_count, esi) {
                        owners[esi as usize] += 1;
                    }
                }
                let stream = DonorEsiStream::new(donor_index, donor_count).expect("valid stream");
                for (seq, esi) in stream.take(32).enumerate() {
                    assert_eq!(
                        esi,
                        esi_for_donor(donor_index, donor_count, seq as u32).expect("esi")
                    );
                    assert!(owns_esi(donor_index, donor_count, esi));
                }
            }
            assert!(owners.iter().all(|owner_count| *owner_count == 1));
        }
    }

    #[test]
    fn n_one_owns_every_esi() {
        for esi in 0..512 {
            assert!(owns_esi(0, 1, esi));
            assert_eq!(esi_for_donor(0, 1, esi).expect("esi"), esi);
        }
    }

    #[test]
    fn donor_esi_partition_rejects_invalid_or_overflowing_inputs() {
        assert_eq!(
            DonorEsiStream::new(0, 0).unwrap_err(),
            ChannelBondingError::InvalidDonorCount { donor_count: 0 }
        );
        assert_eq!(
            esi_for_donor(2, 2, 0).unwrap_err(),
            ChannelBondingError::InvalidDonorIndex {
                donor_index: 2,
                donor_count: 2,
            }
        );
        assert_eq!(
            esi_for_donor(u32::MAX - 1, u32::MAX, 1).unwrap_err(),
            ChannelBondingError::EsiOverflow
        );
    }

    #[test]
    fn donor_esi_stream_yields_final_u32_esi_once() {
        let mut stream = DonorEsiStream::new(0, 1).expect("single donor stream");
        stream.next_seq = Some(u32::MAX);

        assert_eq!(stream.next(), Some(u32::MAX));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.next(), None);
    }

    #[test]
    fn descriptor_accepts_matching_donor_proof() {
        let proof = sample_proof();
        let descriptor = BondTransferDescriptor::from_donor_proof(
            "sample",
            true,
            1200,
            256 * 1024,
            Some("env:ATP_BOND_AUTH_KEY".to_string()),
            proof.entries.clone(),
        )
        .expect("descriptor");

        descriptor
            .verify_donor_byte_match(&proof)
            .expect("matching donor proof accepted");
    }

    #[test]
    fn descriptor_rejects_content_mismatch_fail_closed() {
        let proof = sample_proof();
        let descriptor = BondTransferDescriptor::from_donor_proof(
            "sample",
            true,
            1200,
            256 * 1024,
            None,
            proof.entries.clone(),
        )
        .expect("descriptor");
        let tampered = BondDonorByteProof::from_entries(vec![
            BondDonorProofEntry::from_bytes(0, "alpha.txt", b"alpha"),
            BondDonorProofEntry::from_bytes(1, "dir/beta.txt", b"tampered"),
        ])
        .expect("tampered proof is internally consistent");

        let err = descriptor
            .verify_donor_byte_match(&tampered)
            .expect_err("mismatch rejected");
        assert!(matches!(
            err,
            ChannelBondingError::TransferIdMismatch { .. }
                | ChannelBondingError::MerkleRootMismatch { .. }
                | ChannelBondingError::EntryMismatch { .. }
        ));
    }

    #[test]
    fn descriptor_rejects_same_sha_with_wrong_content_id_merkle() {
        let proof = sample_proof();
        let descriptor = BondTransferDescriptor::from_donor_proof(
            "sample",
            true,
            1200,
            256 * 1024,
            None,
            proof.entries.clone(),
        )
        .expect("descriptor");
        let mut forged_entries = proof.entries.clone();
        forged_entries[0].content_id_hex = "11".repeat(32);
        let forged = BondDonorByteProof {
            transfer_id: proof.transfer_id,
            total_bytes: proof.total_bytes,
            merkle_root_hex: proof.merkle_root_hex,
            entries: forged_entries,
        };

        let err = descriptor
            .verify_donor_byte_match(&forged)
            .expect_err("wrong content id rejected");
        assert!(matches!(
            err,
            ChannelBondingError::MerkleRootMismatch { .. }
        ));
    }

    #[test]
    fn entry_object_id_is_deterministic_and_entry_specific() {
        let transfer = "0123456789abcdef0123456789abcdef";
        let first = entry_object_id(transfer, 0);
        assert_eq!(first, entry_object_id(transfer, 0));
        assert_ne!(first, entry_object_id(transfer, 1));
        assert_ne!(first, entry_object_id("different", 0));
    }

    #[test]
    fn assignment_windows_restrict_static_residue() {
        let assignment = DonorAssignment {
            donor_index: 1,
            donor_count: 3,
            esi_windows: Some(vec![EsiWindow::new(0, 10)]),
            receiver_udp_endpoints: Vec::new(),
            auth_key_ref: Some("keyfile:/run/asupersync/bond.key".to_string()),
        };
        assignment.validate().expect("valid assignment");
        assert!(assignment.owns_esi(1));
        assert!(assignment.owns_esi(4));
        assert!(!assignment.owns_esi(10));
        assert!(!assignment.owns_esi(2));
    }

    #[test]
    fn assignment_windows_are_exact_static_residue_intersections() {
        let windows = vec![EsiWindow::new(2, 11), EsiWindow::new(15, 22)];
        for donor_count in [2, 3, 5, 8] {
            for donor_index in 0..donor_count {
                let assignment = DonorAssignment {
                    donor_index,
                    donor_count,
                    esi_windows: Some(windows.clone()),
                    receiver_udp_endpoints: Vec::new(),
                    auth_key_ref: None,
                };
                assignment.validate().expect("valid assignment");

                for esi in 0..25 {
                    let expected = owns_esi(donor_index, donor_count, esi)
                        && windows.iter().any(|window| window.contains(esi));
                    assert_eq!(
                        assignment.owns_esi(esi),
                        expected,
                        "donor {donor_index}/{donor_count} ownership mismatch for esi {esi}"
                    );
                }
            }
        }
    }

    #[test]
    fn assignment_validation_rejects_invalid_window_and_donor_ceiling() {
        let invalid_window = DonorAssignment {
            donor_index: 0,
            donor_count: 1,
            esi_windows: Some(vec![EsiWindow::new(5, 5)]),
            receiver_udp_endpoints: Vec::new(),
            auth_key_ref: None,
        };
        assert_eq!(
            invalid_window.validate().unwrap_err(),
            ChannelBondingError::InvalidEsiWindow {
                start_inclusive: 5,
                end_exclusive: 5,
            }
        );

        let too_many_donors = DonorAssignment {
            donor_index: 0,
            donor_count: MAX_STATIC_RESIDUE_DONORS + 1,
            esi_windows: None,
            receiver_udp_endpoints: Vec::new(),
            auth_key_ref: None,
        };
        assert_eq!(
            too_many_donors.validate().unwrap_err(),
            ChannelBondingError::TooManyDonors {
                donor_count: MAX_STATIC_RESIDUE_DONORS + 1,
                max: MAX_STATIC_RESIDUE_DONORS,
            }
        );
    }

    #[test]
    fn handshake_degrades_to_static_residue_when_dynamic_missing() {
        let receiver = BondingHandshake::v1_static(
            [BondTransport::DirectIp, BondTransport::Tailscale],
            16,
            true,
        )
        .with_dynamic_windows(true)
        .with_resume(true)
        .with_extension_capability("phase-e.dynamic-window-v1");
        let donor = BondingHandshake::v1_static([BondTransport::Tailscale], 8, false);

        let agreement = receiver.negotiate(&donor).expect("compatible");
        assert_eq!(agreement.protocol_version, BONDING_PROTOCOL_VERSION);
        assert_eq!(
            agreement.assignment_mode,
            BondingAssignmentMode::StaticResidue
        );
        assert!(!agreement.resume_supported);
        assert!(agreement.auth_required);
        assert_eq!(agreement.max_donor_count, 8);
        assert_eq!(
            agreement.supported_transports,
            BTreeSet::from([BondTransport::Tailscale])
        );
        assert!(agreement.supports_transport(BondTransport::Tailscale));
        assert!(!agreement.supports_transport(BondTransport::DirectIp));
    }

    #[test]
    fn handshake_selects_dynamic_windows_when_both_peers_support_them() {
        let receiver = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true)
            .with_dynamic_windows(true)
            .with_resume(true)
            .with_extension_capability("receiver-private-future");
        let donor = BondingHandshake::v1_static([BondTransport::DirectIp], 12, true)
            .with_dynamic_windows(true)
            .with_resume(true)
            .with_extension_capability("donor-private-future");

        let agreement = receiver.negotiate(&donor).expect("compatible");

        assert_eq!(
            agreement.assignment_mode,
            BondingAssignmentMode::DynamicWindows
        );
        assert!(agreement.resume_supported);
        assert_eq!(agreement.max_donor_count, 12);
        assert!(agreement.supports_transport(BondTransport::DirectIp));
    }

    #[test]
    fn handshake_ignores_unknown_extensions_but_refuses_no_common_transport() {
        let receiver = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true)
            .with_extension_capability("unknown.receiver.future");
        let donor = BondingHandshake::v1_static([BondTransport::Tailscale], 16, true)
            .with_extension_capability("unknown.donor.future");

        let err = receiver.negotiate(&donor).expect_err("no common transport");
        assert_eq!(err, ChannelBondingError::NoCommonTransport);
    }

    #[test]
    fn handshake_refuses_incompatible_versions() {
        let receiver = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true)
            .with_protocol_range(2, 2);
        let donor = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true);

        let err = receiver.negotiate(&donor).expect_err("version mismatch");
        assert!(matches!(
            err,
            ChannelBondingError::IncompatibleProtocolVersion { .. }
        ));
    }

    #[test]
    fn handshake_refuses_invalid_version_zero_and_donor_ceiling() {
        let donor = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true);
        let version_zero = BondingHandshake::v1_static([BondTransport::DirectIp], 16, true)
            .with_protocol_range(0, BONDING_PROTOCOL_VERSION);
        let err = version_zero.negotiate(&donor).expect_err("version zero");
        assert_eq!(
            err,
            ChannelBondingError::InvalidProtocolRange {
                min: 0,
                max: BONDING_PROTOCOL_VERSION,
            }
        );

        let zero_donors = BondingHandshake::v1_static([BondTransport::DirectIp], 0, true);
        let err = zero_donors.negotiate(&donor).expect_err("zero donors");
        assert_eq!(
            err,
            ChannelBondingError::InvalidDonorCount { donor_count: 0 }
        );

        let too_many_donors = BondingHandshake::v1_static(
            [BondTransport::DirectIp],
            MAX_STATIC_RESIDUE_DONORS + 1,
            true,
        );
        let err = too_many_donors
            .negotiate(&donor)
            .expect_err("donor ceiling exceeds phase-a cap");
        assert_eq!(
            err,
            ChannelBondingError::TooManyDonors {
                donor_count: MAX_STATIC_RESIDUE_DONORS + 1,
                max: MAX_STATIC_RESIDUE_DONORS,
            }
        );
    }

    #[test]
    fn security_model_rejects_argv_and_disabled_fail_closed_layers() {
        let mut model = BondingSecurityModel {
            auth_key: BondAuthKeyRef {
                key_id: "bond-key-1".to_string(),
                control_plane: BondAuthControlPlane::Ssh,
                location: BondAuthKeyLocation::EnvVar("ATP_BOND_AUTH_KEY".to_string()),
            },
            auth_before_decode: true,
            fail_closed_on_merkle_mismatch: true,
        };
        model.validate().expect("valid security model");

        model.auth_key.location = BondAuthKeyLocation::Argv("--bond-key=secret".to_string());
        assert_eq!(
            model.validate().unwrap_err(),
            ChannelBondingError::InsecureAuthKeyDelivery
        );

        model.auth_key.location = BondAuthKeyLocation::EnvVar("ATP_BOND_AUTH_KEY".to_string());
        model.auth_before_decode = false;
        assert_eq!(
            model.validate().unwrap_err(),
            ChannelBondingError::AuthBeforeDecodeDisabled
        );

        model.auth_before_decode = true;
        model.fail_closed_on_merkle_mismatch = false;
        assert_eq!(
            model.validate().unwrap_err(),
            ChannelBondingError::MerkleFailClosedDisabled
        );
    }

    #[test]
    fn wrong_donor_auth_key_rejects_symbol_before_decode() {
        let signer = SecurityContext::for_testing(0xA11CE);
        let verifier = SecurityContext::for_testing(0xB0B);
        let symbol = Symbol::new(
            SymbolId::new_for_test(7, 0, 3),
            b"bonded repair".to_vec(),
            SymbolKind::Repair,
        );
        let signed = signer.sign_symbol(&symbol);
        let tag = *signed.tag();
        let mut received = AuthenticatedSymbol::from_parts(signed.into_symbol(), tag);

        let err = verifier
            .verify_authenticated_symbol(&mut received)
            .expect_err("wrong shared donor key must reject symbol");
        assert!(err.is_invalid_tag());
        assert!(!received.is_verified());
    }
}
