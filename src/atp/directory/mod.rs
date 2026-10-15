//! Local-first ATP peer directory.
//!
//! The directory maps durable peer identities to human names, device names,
//! groups, grants, trust scopes, and path hints. It deliberately treats names
//! as convenience labels: ambiguous labels never resolve implicitly, and every
//! mutating operation records an audit entry.

use crate::net::atp::protocol::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Stable schema marker for exported peer directories.
pub const PEER_DIRECTORY_SCHEMA_V1: &str = "asupersync.atp.peer_directory.v1";

/// Local-first peer directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerDirectory {
    /// Export/import schema version.
    pub schema_version: String,
    /// Peers indexed by cryptographic id.
    #[serde(with = "peer_map_hex")]
    pub peers: BTreeMap<PeerId, PeerRecord>,
    /// Teams and local groups.
    pub groups: BTreeMap<String, GroupRecord>,
    /// Auditable change log.
    pub audit_log: Vec<DirectoryAuditRecord>,
    next_sequence: u64,
}

impl Default for PeerDirectory {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerDirectory {
    /// Create an empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema_version: PEER_DIRECTORY_SCHEMA_V1.to_string(),
            peers: BTreeMap::new(),
            groups: BTreeMap::new(),
            audit_log: Vec::new(),
            next_sequence: 1,
        }
    }

    /// Load a directory JSON document.
    pub fn load_json(path: impl AsRef<Path>) -> Result<Self, DirectoryIoError> {
        let bytes = fs::read(path.as_ref()).map_err(DirectoryIoError::Read)?;
        let mut directory: Self =
            serde_json::from_slice(&bytes).map_err(DirectoryIoError::Decode)?;
        directory.repair_sequence();
        Ok(directory)
    }

    /// Save a directory JSON document.
    pub fn save_json(&self, path: impl AsRef<Path>) -> Result<(), DirectoryIoError> {
        let bytes = serde_json::to_vec_pretty(self).map_err(DirectoryIoError::Encode)?;
        fs::write(path.as_ref(), bytes).map_err(DirectoryIoError::Write)
    }

    /// Insert or replace a peer record.
    pub fn upsert_peer(&mut self, peer: PeerRecord, actor: Option<PeerId>) {
        let target = DirectorySubject::Peer(peer.peer_id);
        let operation = if self.peers.contains_key(&peer.peer_id) {
            DirectoryOperation::PeerUpdated
        } else {
            DirectoryOperation::PeerAdded
        };
        let summary = format!("peer {}", peer.display_name);
        self.peers.insert(peer.peer_id, peer);
        self.audit(actor, operation, target, summary);
    }

    /// Rename a peer display name and keep the old name as an alias.
    pub fn rename_peer(
        &mut self,
        subject: DirectorySubject,
        display_name: impl Into<String>,
        actor: Option<PeerId>,
    ) -> Result<(), DirectoryError> {
        let peer_id = self.subject_peer_id(&subject)?;
        let display_name = normalize_name(display_name.into())?;
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(DirectoryError::PeerNotFound(peer_id))?;
        if peer.display_name != display_name {
            peer.aliases.insert(peer.display_name.clone());
            peer.display_name.clone_from(&display_name);
        }
        self.audit(
            actor,
            DirectoryOperation::PeerRenamed,
            DirectorySubject::Peer(peer_id),
            format!("peer renamed to {display_name}"),
        );
        Ok(())
    }

    /// Add or replace a device under a peer.
    pub fn upsert_device(
        &mut self,
        peer_id: PeerId,
        device: DeviceRecord,
        actor: Option<PeerId>,
    ) -> Result<(), DirectoryError> {
        if device.peer_id != peer_id {
            return Err(DirectoryError::DevicePeerMismatch {
                expected: peer_id,
                actual: device.peer_id,
            });
        }
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(DirectoryError::PeerNotFound(peer_id))?;
        let device_id = device.device_id.clone();
        peer.devices.insert(device_id.clone(), device);
        peer.last_seen_micros = now_micros();
        self.audit(
            actor,
            DirectoryOperation::DeviceUpdated,
            DirectorySubject::Device { peer_id, device_id },
            "device updated".to_string(),
        );
        Ok(())
    }

    /// Rename a device under a peer.
    pub fn rename_device(
        &mut self,
        peer_id: PeerId,
        device_id: &str,
        device_name: impl Into<String>,
        actor: Option<PeerId>,
    ) -> Result<(), DirectoryError> {
        let device_name = normalize_name(device_name.into())?;
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(DirectoryError::PeerNotFound(peer_id))?;
        let device =
            peer.devices
                .get_mut(device_id)
                .ok_or_else(|| DirectoryError::DeviceNotFound {
                    peer_id,
                    device_id: device_id.to_string(),
                })?;
        if device.device_name != device_name {
            device.aliases.insert(device.device_name.clone());
            device.device_name.clone_from(&device_name);
        }
        self.audit(
            actor,
            DirectoryOperation::DeviceRenamed,
            DirectorySubject::Device {
                peer_id,
                device_id: device_id.to_string(),
            },
            format!("device renamed to {device_name}"),
        );
        Ok(())
    }

    /// Revoke a peer and all of its devices for future name resolution.
    pub fn revoke_peer(
        &mut self,
        subject: DirectorySubject,
        reason: impl Into<String>,
        actor: Option<PeerId>,
    ) -> Result<(), DirectoryError> {
        let peer_id = self.subject_peer_id(&subject)?;
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(DirectoryError::PeerNotFound(peer_id))?;
        peer.revoked = true;
        let reason = reason.into();
        peer.trust_notes.push(reason.clone());
        for device in peer.devices.values_mut() {
            device.revoked = true;
        }
        self.audit(
            actor,
            DirectoryOperation::PeerRevoked,
            DirectorySubject::Peer(peer_id),
            reason,
        );
        Ok(())
    }

    /// Insert or replace a group.
    pub fn upsert_group(&mut self, group: GroupRecord, actor: Option<PeerId>) {
        let group_name = group.name.clone();
        let operation = if self.groups.contains_key(&group_name) {
            DirectoryOperation::GroupUpdated
        } else {
            DirectoryOperation::GroupAdded
        };
        self.groups.insert(group_name.clone(), group);
        self.audit(
            actor,
            operation,
            DirectorySubject::Group(group_name.clone()),
            format!("group {group_name}"),
        );
    }

    /// Add one peer/device/group subject to a group.
    pub fn add_group_member(
        &mut self,
        group_name: &str,
        member: DirectorySubject,
        actor: Option<PeerId>,
    ) -> Result<(), DirectoryError> {
        self.validate_subject_exists(&member)?;
        let group = self
            .groups
            .get_mut(group_name)
            .ok_or_else(|| DirectoryError::GroupNotFound(group_name.to_string()))?;
        group.members.insert(member.clone());
        self.audit(
            actor,
            DirectoryOperation::GroupMemberAdded,
            DirectorySubject::Group(group_name.to_string()),
            format!("member {}", member.display_label()),
        );
        Ok(())
    }

    /// Attach a grant to a peer, device, or group without dropping constraints.
    pub fn attach_grant(
        &mut self,
        subject: DirectorySubject,
        grant: DirectoryGrant,
        actor: Option<PeerId>,
    ) -> Result<(), DirectoryError> {
        self.validate_subject_exists(&subject)?;
        match &subject {
            DirectorySubject::Peer(peer_id) => {
                self.peers
                    .get_mut(peer_id)
                    .ok_or(DirectoryError::PeerNotFound(*peer_id))?
                    .grants
                    .push(grant.clone());
            }
            DirectorySubject::Device { peer_id, device_id } => {
                self.peers
                    .get_mut(peer_id)
                    .ok_or(DirectoryError::PeerNotFound(*peer_id))?
                    .devices
                    .get_mut(device_id)
                    .ok_or_else(|| DirectoryError::DeviceNotFound {
                        peer_id: *peer_id,
                        device_id: device_id.clone(),
                    })?
                    .grants
                    .push(grant.clone());
            }
            DirectorySubject::Group(group) => {
                self.groups
                    .get_mut(group)
                    .ok_or_else(|| DirectoryError::GroupNotFound(group.clone()))?
                    .grants
                    .push(grant.clone());
            }
            DirectorySubject::Relay(relay) => {
                return Err(DirectoryError::UnsupportedSubject(relay.clone()));
            }
        }
        self.audit(
            actor,
            DirectoryOperation::GrantAttached,
            subject,
            grant.grant_id,
        );
        Ok(())
    }

    /// Resolve grants applying to a group and its members.
    pub fn resolve_group_grants(
        &self,
        group_name: &str,
    ) -> Result<Vec<ResolvedDirectoryGrant>, DirectoryError> {
        let group = self
            .groups
            .get(group_name)
            .ok_or_else(|| DirectoryError::GroupNotFound(group_name.to_string()))?;
        if group.revoked {
            return Err(DirectoryError::RevokedSubject(DirectorySubject::Group(
                group_name.to_string(),
            )));
        }

        let mut resolved = Vec::new();
        for grant in &group.grants {
            resolved.push(ResolvedDirectoryGrant {
                source: DirectorySubject::Group(group.name.clone()),
                subject: DirectorySubject::Group(group.name.clone()),
                grant: grant.clone(),
            });
        }
        for member in &group.members {
            self.collect_member_grants(member, &mut resolved)?;
        }
        Ok(resolved)
    }

    /// Resolve a human label to exactly one active subject.
    pub fn resolve_name(&self, query: &str) -> Result<DirectorySubject, DirectoryError> {
        let query = normalize_lookup(query);
        let matches = self.matching_subjects(&query);
        match matches.as_slice() {
            [] => Err(DirectoryError::NameNotFound(query)),
            [subject] => Ok(subject.clone()),
            _ => Err(DirectoryError::AmbiguousName {
                query,
                matches: matches
                    .into_iter()
                    .map(|subject| subject.display_label())
                    .collect(),
            }),
        }
    }

    /// Inspect one explicit or name-resolved subject.
    pub fn inspect(
        &self,
        subject: &DirectorySubject,
    ) -> Result<DirectoryEntryView, DirectoryError> {
        match subject {
            DirectorySubject::Peer(peer_id) => {
                let peer = self
                    .peers
                    .get(peer_id)
                    .ok_or(DirectoryError::PeerNotFound(*peer_id))?;
                Ok(DirectoryEntryView::Peer(peer.clone()))
            }
            DirectorySubject::Device { peer_id, device_id } => {
                let device = self
                    .peers
                    .get(peer_id)
                    .ok_or(DirectoryError::PeerNotFound(*peer_id))?
                    .devices
                    .get(device_id)
                    .ok_or_else(|| DirectoryError::DeviceNotFound {
                        peer_id: *peer_id,
                        device_id: device_id.clone(),
                    })?;
                Ok(DirectoryEntryView::Device(device.clone()))
            }
            DirectorySubject::Group(name) => {
                let group = self
                    .groups
                    .get(name)
                    .ok_or_else(|| DirectoryError::GroupNotFound(name.clone()))?;
                Ok(DirectoryEntryView::Group(group.clone()))
            }
            DirectorySubject::Relay(relay) => {
                Err(DirectoryError::UnsupportedSubject(relay.clone()))
            }
        }
    }

    /// List active peers and groups for CLI output.
    #[must_use]
    pub fn list_entries(&self) -> DirectoryList {
        let peers = self
            .peers
            .values()
            .filter(|peer| !peer.revoked)
            .map(|peer| DirectoryPeerSummary {
                peer_id: peer.peer_id,
                display_name: peer.display_name.clone(),
                groups: peer.groups.iter().cloned().collect(),
                device_count: peer
                    .devices
                    .values()
                    .filter(|device| !device.revoked)
                    .count(),
                grant_count: peer.grants.len(),
                last_seen_micros: peer.last_seen_micros,
            })
            .collect();
        let groups = self
            .groups
            .values()
            .filter(|group| !group.revoked)
            .map(|group| DirectoryGroupSummary {
                name: group.name.clone(),
                display_name: group.display_name.clone(),
                member_count: group.members.len(),
                grant_count: group.grants.len(),
            })
            .collect();
        DirectoryList { peers, groups }
    }

    /// Return stale path hints for operational diagnostics.
    #[must_use]
    pub fn stale_path_hints(&self, now_micros: u64) -> Vec<StalePathHint> {
        let mut stale = Vec::new();
        for peer in self.peers.values() {
            if peer.revoked {
                continue;
            }
            for hint in &peer.path_hints {
                if hint.is_stale(now_micros) {
                    stale.push(StalePathHint {
                        subject: DirectorySubject::Peer(peer.peer_id),
                        hint: hint.clone(),
                    });
                }
            }
            for device in peer.devices.values() {
                if device.revoked {
                    continue;
                }
                for hint in &device.path_hints {
                    if hint.is_stale(now_micros) {
                        stale.push(StalePathHint {
                            subject: DirectorySubject::Device {
                                peer_id: peer.peer_id,
                                device_id: device.device_id.clone(),
                            },
                            hint: hint.clone(),
                        });
                    }
                }
            }
        }
        stale
    }

    fn subject_peer_id(&self, subject: &DirectorySubject) -> Result<PeerId, DirectoryError> {
        match subject {
            DirectorySubject::Peer(peer_id) => Ok(*peer_id),
            DirectorySubject::Device { peer_id, .. } => Ok(*peer_id),
            DirectorySubject::Group(group) => {
                Err(DirectoryError::UnsupportedSubject(group.clone()))
            }
            DirectorySubject::Relay(relay) => {
                Err(DirectoryError::UnsupportedSubject(relay.clone()))
            }
        }
    }

    fn validate_subject_exists(&self, subject: &DirectorySubject) -> Result<(), DirectoryError> {
        match subject {
            DirectorySubject::Peer(peer_id) => {
                let peer = self
                    .peers
                    .get(peer_id)
                    .ok_or(DirectoryError::PeerNotFound(*peer_id))?;
                if peer.revoked {
                    Err(DirectoryError::RevokedSubject(subject.clone()))
                } else {
                    Ok(())
                }
            }
            DirectorySubject::Device { peer_id, device_id } => {
                let peer = self
                    .peers
                    .get(peer_id)
                    .ok_or(DirectoryError::PeerNotFound(*peer_id))?;
                let device =
                    peer.devices
                        .get(device_id)
                        .ok_or_else(|| DirectoryError::DeviceNotFound {
                            peer_id: *peer_id,
                            device_id: device_id.clone(),
                        })?;
                if peer.revoked || device.revoked {
                    Err(DirectoryError::RevokedSubject(subject.clone()))
                } else {
                    Ok(())
                }
            }
            DirectorySubject::Group(group) => {
                let group = self
                    .groups
                    .get(group)
                    .ok_or_else(|| DirectoryError::GroupNotFound(group.clone()))?;
                if group.revoked {
                    Err(DirectoryError::RevokedSubject(subject.clone()))
                } else {
                    Ok(())
                }
            }
            DirectorySubject::Relay(_) => Ok(()),
        }
    }

    fn collect_member_grants(
        &self,
        subject: &DirectorySubject,
        resolved: &mut Vec<ResolvedDirectoryGrant>,
    ) -> Result<(), DirectoryError> {
        match subject {
            DirectorySubject::Peer(peer_id) => {
                let peer = self
                    .peers
                    .get(peer_id)
                    .ok_or(DirectoryError::PeerNotFound(*peer_id))?;
                if peer.revoked {
                    return Ok(());
                }
                for grant in &peer.grants {
                    resolved.push(ResolvedDirectoryGrant {
                        source: DirectorySubject::Peer(*peer_id),
                        subject: DirectorySubject::Peer(*peer_id),
                        grant: grant.clone(),
                    });
                }
            }
            DirectorySubject::Device { peer_id, device_id } => {
                let peer = self
                    .peers
                    .get(peer_id)
                    .ok_or(DirectoryError::PeerNotFound(*peer_id))?;
                if peer.revoked {
                    return Ok(());
                }
                if let Some(device) = peer.devices.get(device_id) {
                    if !device.revoked {
                        for grant in &device.grants {
                            resolved.push(ResolvedDirectoryGrant {
                                source: DirectorySubject::Device {
                                    peer_id: *peer_id,
                                    device_id: device_id.clone(),
                                },
                                subject: DirectorySubject::Device {
                                    peer_id: *peer_id,
                                    device_id: device_id.clone(),
                                },
                                grant: grant.clone(),
                            });
                        }
                    }
                }
            }
            DirectorySubject::Group(group_name) => {
                for grant in self.resolve_group_grants(group_name)? {
                    resolved.push(grant);
                }
            }
            DirectorySubject::Relay(_) => {}
        }
        Ok(())
    }

    fn matching_subjects(&self, query: &str) -> Vec<DirectorySubject> {
        let mut matches = Vec::new();
        for peer in self.peers.values() {
            if peer.revoked {
                continue;
            }
            if peer.matches_name(query) {
                matches.push(DirectorySubject::Peer(peer.peer_id));
            }
            for device in peer.devices.values() {
                if !device.revoked && device.matches_name(query) {
                    matches.push(DirectorySubject::Device {
                        peer_id: peer.peer_id,
                        device_id: device.device_id.clone(),
                    });
                }
            }
        }
        for group in self.groups.values() {
            if !group.revoked && group.matches_name(query) {
                matches.push(DirectorySubject::Group(group.name.clone()));
            }
        }
        matches.sort();
        matches.dedup();
        matches
    }

    fn audit(
        &mut self,
        actor: Option<PeerId>,
        operation: DirectoryOperation,
        target: DirectorySubject,
        summary: String,
    ) {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.audit_log.push(DirectoryAuditRecord {
            sequence,
            actor,
            operation,
            target,
            timestamp_micros: now_micros(),
            summary,
        });
    }

    fn repair_sequence(&mut self) {
        self.next_sequence = self
            .audit_log
            .iter()
            .map(|record| record.sequence)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
    }
}

/// One person, relay, or durable peer identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRecord {
    /// Durable cryptographic peer id.
    pub peer_id: PeerId,
    /// Human display name.
    pub display_name: String,
    /// Optional aliases.
    pub aliases: BTreeSet<String>,
    /// Groups this peer belongs to.
    pub groups: BTreeSet<String>,
    /// Devices owned by this peer.
    pub devices: BTreeMap<String, DeviceRecord>,
    /// Direct grants attached to this peer.
    pub grants: Vec<DirectoryGrant>,
    /// Path hints for this peer.
    pub path_hints: Vec<PathHint>,
    /// Last observed activity timestamp.
    pub last_seen_micros: u64,
    /// Operator trust notes.
    pub trust_notes: Vec<String>,
    /// Revoked peers do not resolve by name.
    pub revoked: bool,
}

impl PeerRecord {
    /// Construct a peer record.
    pub fn new(peer_id: PeerId, display_name: impl Into<String>) -> Result<Self, DirectoryError> {
        Ok(Self {
            peer_id,
            display_name: normalize_name(display_name.into())?,
            aliases: BTreeSet::new(),
            groups: BTreeSet::new(),
            devices: BTreeMap::new(),
            grants: Vec::new(),
            path_hints: Vec::new(),
            last_seen_micros: now_micros(),
            trust_notes: Vec::new(),
            revoked: false,
        })
    }

    fn matches_name(&self, query: &str) -> bool {
        normalize_lookup(&self.display_name) == query
            || self
                .aliases
                .iter()
                .any(|alias| normalize_lookup(alias) == query)
    }
}

/// One named device under a peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// Stable local device id.
    pub device_id: String,
    /// Owning peer.
    pub peer_id: PeerId,
    /// Human device name.
    pub device_name: String,
    /// Optional aliases.
    pub aliases: BTreeSet<String>,
    /// Direct grants attached to this device.
    pub grants: Vec<DirectoryGrant>,
    /// Device-specific path hints.
    pub path_hints: Vec<PathHint>,
    /// Last seen timestamp.
    pub last_seen_micros: u64,
    /// Trust scopes accepted for this device.
    pub trust_scopes: BTreeSet<TrustScope>,
    /// Revoked devices do not resolve by name.
    pub revoked: bool,
}

impl DeviceRecord {
    /// Construct a device record.
    pub fn new(
        peer_id: PeerId,
        device_id: impl Into<String>,
        device_name: impl Into<String>,
    ) -> Result<Self, DirectoryError> {
        Ok(Self {
            device_id: normalize_name(device_id.into())?,
            peer_id,
            device_name: normalize_name(device_name.into())?,
            aliases: BTreeSet::new(),
            grants: Vec::new(),
            path_hints: Vec::new(),
            last_seen_micros: now_micros(),
            trust_scopes: BTreeSet::new(),
            revoked: false,
        })
    }

    fn matches_name(&self, query: &str) -> bool {
        normalize_lookup(&self.device_name) == query
            || normalize_lookup(&self.device_id) == query
            || self
                .aliases
                .iter()
                .any(|alias| normalize_lookup(alias) == query)
    }
}

/// Team or group of peers/devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupRecord {
    /// Stable group name.
    pub name: String,
    /// Human display name.
    pub display_name: String,
    /// Members can be peers, devices, or nested groups.
    pub members: BTreeSet<DirectorySubject>,
    /// Grants attached to the group.
    pub grants: Vec<DirectoryGrant>,
    /// Operator notes.
    pub trust_notes: Vec<String>,
    /// Revoked groups do not resolve by name.
    pub revoked: bool,
}

impl GroupRecord {
    /// Construct a group record.
    pub fn new(
        name: impl Into<String>,
        display_name: impl Into<String>,
    ) -> Result<Self, DirectoryError> {
        Ok(Self {
            name: normalize_name(name.into())?,
            display_name: normalize_name(display_name.into())?,
            members: BTreeSet::new(),
            grants: Vec::new(),
            trust_notes: Vec::new(),
            revoked: false,
        })
    }

    fn matches_name(&self, query: &str) -> bool {
        normalize_lookup(&self.name) == query || normalize_lookup(&self.display_name) == query
    }
}

/// Directory subject address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DirectorySubject {
    /// Peer by durable id.
    Peer(PeerId),
    /// Device by owning peer and stable device id.
    Device {
        /// Owning peer.
        peer_id: PeerId,
        /// Stable device id.
        device_id: String,
    },
    /// Group or team name.
    Group(String),
    /// Relay name.
    Relay(String),
}

impl DirectorySubject {
    /// Human-safe label for diagnostics.
    #[must_use]
    pub fn display_label(&self) -> String {
        match self {
            Self::Peer(peer_id) => format!("peer:{}", peer_id.redacted()),
            Self::Device { peer_id, device_id } => {
                format!("device:{}:{device_id}", peer_id.redacted())
            }
            Self::Group(group) => format!("group:{group}"),
            Self::Relay(relay) => format!("relay:{relay}"),
        }
    }
}

/// Trust scope carried by a peer, device, or grant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TrustScope {
    /// Personal peer-to-peer transfer scope.
    Personal,
    /// Team/group scope.
    Team(String),
    /// Device-specific scope.
    Device(String),
    /// Relay or rendezvous scope.
    Relay(String),
    /// Custom local scope.
    Custom(String),
}

/// Directory grant with explicit constraints preserved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryGrant {
    /// Stable grant id.
    pub grant_id: String,
    /// Scope this grant applies to.
    pub trust_scope: TrustScope,
    /// Allowed action labels.
    pub actions: BTreeSet<String>,
    /// Capability constraints serialized as local-first key/value metadata.
    pub constraints: BTreeMap<String, String>,
    /// Revoked grants are retained for auditability.
    pub revoked: bool,
}

impl DirectoryGrant {
    /// Construct a grant.
    pub fn new<I, S>(
        grant_id: impl Into<String>,
        trust_scope: TrustScope,
        actions: I,
    ) -> Result<Self, DirectoryError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let grant_id = normalize_name(grant_id.into())?;
        Ok(Self {
            grant_id,
            trust_scope,
            actions: actions.into_iter().map(Into::into).collect(),
            constraints: BTreeMap::new(),
            revoked: false,
        })
    }
}

/// Resolved grant plus its source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedDirectoryGrant {
    /// Subject the grant came from.
    pub source: DirectorySubject,
    /// Subject the grant applies to.
    pub subject: DirectorySubject,
    /// Grant data with constraints preserved.
    pub grant: DirectoryGrant,
}

/// Directory path hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathHint {
    /// Route kind, for example `lan`, `relay`, or `tailscale`.
    pub kind: String,
    /// Endpoint or rendezvous hint.
    pub endpoint: String,
    /// When this hint was last seen.
    pub last_seen_micros: u64,
    /// Hint expiry time.
    pub expires_at_micros: u64,
    /// Optional trust scope expected by this route.
    pub trust_scope: Option<TrustScope>,
}

impl PathHint {
    /// Return true if this hint is stale at `now_micros`.
    #[inline]
    #[must_use]
    pub const fn is_stale(&self, now_micros: u64) -> bool {
        now_micros >= self.expires_at_micros
    }
}

/// Stale path hint diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StalePathHint {
    /// Subject owning the stale hint.
    pub subject: DirectorySubject,
    /// Stale hint.
    pub hint: PathHint,
}

/// Directory audit operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectoryOperation {
    /// Peer added.
    PeerAdded,
    /// Peer updated.
    PeerUpdated,
    /// Peer renamed.
    PeerRenamed,
    /// Peer revoked.
    PeerRevoked,
    /// Device updated.
    DeviceUpdated,
    /// Device renamed.
    DeviceRenamed,
    /// Group added.
    GroupAdded,
    /// Group updated.
    GroupUpdated,
    /// Group member added.
    GroupMemberAdded,
    /// Grant attached.
    GrantAttached,
}

/// One auditable directory mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryAuditRecord {
    /// Monotonic local sequence.
    pub sequence: u64,
    /// Actor peer if known.
    pub actor: Option<PeerId>,
    /// Operation performed.
    pub operation: DirectoryOperation,
    /// Target subject.
    pub target: DirectorySubject,
    /// Wall-clock timestamp in microseconds since epoch.
    pub timestamp_micros: u64,
    /// Human-readable summary without secret material.
    pub summary: String,
}

/// CLI list payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryList {
    /// Active peers.
    pub peers: Vec<DirectoryPeerSummary>,
    /// Active groups.
    pub groups: Vec<DirectoryGroupSummary>,
}

/// Peer list row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryPeerSummary {
    /// Peer id.
    pub peer_id: PeerId,
    /// Display name.
    pub display_name: String,
    /// Groups.
    pub groups: Vec<String>,
    /// Active device count.
    pub device_count: usize,
    /// Direct grant count.
    pub grant_count: usize,
    /// Last seen timestamp.
    pub last_seen_micros: u64,
}

/// Group list row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryGroupSummary {
    /// Group name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Member count.
    pub member_count: usize,
    /// Grant count.
    pub grant_count: usize,
}

/// Inspect payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "entry")]
pub enum DirectoryEntryView {
    /// Peer view.
    Peer(PeerRecord),
    /// Device view.
    Device(DeviceRecord),
    /// Group view.
    Group(GroupRecord),
}

/// Directory model errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DirectoryError {
    /// Name was blank.
    #[error("directory name is empty")]
    EmptyName,
    /// Peer not found.
    #[error("peer not found: {0:?}")]
    PeerNotFound(PeerId),
    /// Device not found.
    #[error("device not found: {peer_id:?}/{device_id}")]
    DeviceNotFound {
        /// Owning peer.
        peer_id: PeerId,
        /// Device id.
        device_id: String,
    },
    /// Group not found.
    #[error("group not found: {0}")]
    GroupNotFound(String),
    /// Device owned by a different peer.
    #[error("device peer mismatch: expected {expected:?}, actual {actual:?}")]
    DevicePeerMismatch {
        /// Expected peer.
        expected: PeerId,
        /// Actual peer.
        actual: PeerId,
    },
    /// Human name matched no active subject.
    #[error("name not found: {0}")]
    NameNotFound(String),
    /// Human name matched multiple active subjects.
    #[error("ambiguous name {query}: {matches:?}")]
    AmbiguousName {
        /// Queried name.
        query: String,
        /// Matching subjects.
        matches: Vec<String>,
    },
    /// Subject is revoked.
    #[error("subject is revoked: {0:?}")]
    RevokedSubject(DirectorySubject),
    /// Subject type is not supported for this operation.
    #[error("unsupported directory subject: {0}")]
    UnsupportedSubject(String),
    /// Peer id hex is invalid.
    #[error("invalid peer id hex")]
    InvalidPeerIdHex,
}

/// Directory persistence errors.
#[derive(Debug, thiserror::Error)]
pub enum DirectoryIoError {
    /// Read failed.
    #[error("failed to read directory: {0}")]
    Read(io::Error),
    /// Decode failed.
    #[error("failed to decode directory: {0}")]
    Decode(serde_json::Error),
    /// Encode failed.
    #[error("failed to encode directory: {0}")]
    Encode(serde_json::Error),
    /// Write failed.
    #[error("failed to write directory: {0}")]
    Write(io::Error),
}

/// Parse a full 32-byte peer id hex string.
pub fn peer_id_from_hex(hex_text: &str) -> Result<PeerId, DirectoryError> {
    let bytes = hex::decode(hex_text).map_err(|_| DirectoryError::InvalidPeerIdHex)?; // ubs:ignore - hex decoding, not JWT decoding
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DirectoryError::InvalidPeerIdHex)?;
    Ok(PeerId::new(bytes))
}

/// Return lowercase peer id hex.
#[must_use]
pub fn peer_id_to_hex(peer_id: PeerId) -> String {
    hex::encode(peer_id.as_bytes())
}

fn normalize_name(name: String) -> Result<String, DirectoryError> {
    let name = name.trim().to_string();
    if name.is_empty() {
        Err(DirectoryError::EmptyName)
    } else {
        Ok(name)
    }
}

fn normalize_lookup(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

fn now_micros() -> u64 {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();
    u64::try_from(micros).unwrap_or(u64::MAX)
}

mod peer_map_hex {
    use super::{PeerId, PeerRecord, peer_id_from_hex, peer_id_to_hex};
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
    use std::collections::BTreeMap;

    pub fn serialize<S>(
        peers: &BTreeMap<PeerId, PeerRecord>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let peers_by_hex: BTreeMap<String, &PeerRecord> = peers
            .iter()
            .map(|(peer_id, record)| (peer_id_to_hex(*peer_id), record))
            .collect();
        peers_by_hex.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<PeerId, PeerRecord>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let peers_by_hex = BTreeMap::<String, PeerRecord>::deserialize(deserializer)?;
        let mut peers = BTreeMap::new();
        for (peer_id_hex, record) in peers_by_hex {
            let peer_id = peer_id_from_hex(&peer_id_hex).map_err(D::Error::custom)?;
            if record.peer_id != peer_id {
                return Err(D::Error::custom(format!(
                    "peer map key does not match peer record id: {peer_id_hex}"
                )));
            }
            peers.insert(peer_id, record);
        }
        Ok(peers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn peer(label: &str) -> PeerId {
        PeerId::from_label(label)
    }

    fn directory_with_alice() -> PeerDirectory {
        let mut directory = PeerDirectory::new();
        let alice_id = peer("alice");
        let mut alice = PeerRecord::new(alice_id, "Alice").expect("peer");
        alice.aliases.insert("alice@example".to_string());
        alice.path_hints.push(PathHint {
            kind: "lan".to_string(),
            endpoint: "192.168.1.10:4433".to_string(),
            last_seen_micros: 10,
            expires_at_micros: 20,
            trust_scope: Some(TrustScope::Personal),
        });
        directory.upsert_peer(alice, None);
        directory
            .upsert_device(
                alice_id,
                DeviceRecord::new(alice_id, "laptop", "gpu-box").expect("device"),
                None,
            )
            .expect("device");
        directory
    }

    #[test]
    fn resolves_unique_peer_and_requires_disambiguation_for_ambiguous_names() {
        let mut directory = directory_with_alice();
        let bob_id = peer("bob");
        let bob = PeerRecord::new(bob_id, "gpu-box").expect("peer");
        directory.upsert_peer(bob, None);

        assert_eq!(
            directory.resolve_name("alice").expect("alice"),
            DirectorySubject::Peer(peer("alice"))
        );
        let err = directory.resolve_name("gpu-box").expect_err("ambiguous");
        assert!(matches!(err, DirectoryError::AmbiguousName { .. }));
    }

    #[test]
    fn renamed_device_keeps_old_name_as_alias() {
        let mut directory = directory_with_alice();
        let alice_id = peer("alice");
        directory
            .rename_device(alice_id, "laptop", "workstation", None)
            .expect("rename");

        let subject = directory.resolve_name("gpu-box").expect("old alias");
        assert_eq!(
            subject,
            DirectorySubject::Device {
                peer_id: alice_id,
                device_id: "laptop".to_string()
            }
        );
        let view = directory.inspect(&subject).expect("inspect"); // ubs:ignore - test oracle
        let DirectoryEntryView::Device(device) = view else {
            panic!("expected device"); // ubs:ignore - test oracle
        };
        assert_eq!(device.device_name, "workstation");
    }

    #[test]
    fn group_grants_preserve_constraints_for_members() {
        let mut directory = directory_with_alice();
        let alice_id = peer("alice");
        let mut grant = DirectoryGrant::new(
            "grant-team-read",
            TrustScope::Team("eng".to_string()),
            ["read"],
        )
        .expect("grant");
        grant
            .constraints
            .insert("max_bytes".to_string(), "1048576".to_string());
        directory.upsert_group(GroupRecord::new("eng", "Engineering").expect("group"), None);
        directory
            .add_group_member("eng", DirectorySubject::Peer(alice_id), None)
            .expect("member");
        directory
            .attach_grant(
                DirectorySubject::Group("eng".to_string()),
                grant.clone(),
                None,
            )
            .expect("grant");

        let resolved = directory.resolve_group_grants("eng").expect("resolve");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].grant.constraints, grant.constraints);
        assert_eq!(
            resolved[0].grant.trust_scope,
            TrustScope::Team("eng".to_string())
        );
    }

    #[test]
    fn revoked_peer_no_longer_resolves_and_is_audited() {
        let mut directory = directory_with_alice();
        directory
            .revoke_peer(DirectorySubject::Peer(peer("alice")), "lost key", None)
            .expect("revoke");

        assert!(matches!(
            directory.resolve_name("alice"),
            Err(DirectoryError::NameNotFound(_))
        ));
        assert!(
            directory
                .audit_log
                .iter()
                .any(|record| record.operation == DirectoryOperation::PeerRevoked)
        );
    }

    #[test]
    fn stale_path_hints_are_reported() {
        let directory = directory_with_alice();
        let stale = directory.stale_path_hints(21);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].hint.endpoint, "192.168.1.10:4433");
    }

    #[test]
    fn directory_round_trips_as_json_with_audit_log() {
        let directory = directory_with_alice();
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("peers.json");
        directory.save_json(&path).expect("save");
        let loaded = PeerDirectory::load_json(&path).expect("load");

        assert_eq!(loaded.schema_version, PEER_DIRECTORY_SCHEMA_V1);
        assert_eq!(loaded.peers.len(), 1);
        assert!(!loaded.audit_log.is_empty());
    }
}
