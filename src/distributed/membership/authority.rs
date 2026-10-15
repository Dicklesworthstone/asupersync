//! Explicitly authorized membership incarnations and generation-fenced leases.
//!
//! This opt-in path does not trust raw SWIM/UDP observations. One provisioned
//! authority signs monotonically sequenced decisions within an explicit epoch
//! and a fixed member allow-list. Its key is separate from transport credentials.
//! A newer incarnation retires all leases of the old one; terminal incarnations
//! never resume. Existing `MembershipView` and `MembershipLeaseManager` semantics
//! are unchanged. No route, certificate, runtime obligation or task is created.
//!
//! Revocation records are retained until the owner acknowledges actual obligation
//! cleanup. This controller updates the existing `Lease` state machine; the owner
//! still aborts/commits runtime obligations and runs compensation. Supply clock
//! values from that owner and call `expire` when its next deadline becomes due.
//! Persist/reestablish trusted epoch and sequence floors before restarting: an
//! authentic old statement is not evidence of current authority or liveness.

use super::{MembershipEvent, MembershipKind};
use crate::remote::{Lease, LeaseError, NodeId};
use crate::security::{AuthKey, AuthenticationTag};
use crate::types::{ObligationId, Time};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

const MAGIC: &[u8; 8] = b"ASUPMBR\0";
const DOMAIN: &[u8] = b"asupersync.membership-authority.v1";
/// Maximum complete signed statement; both identities are at most 255 bytes.
pub const MAX_MEMBERSHIP_UPDATE_BYTES: usize = 581;

/// Independent bounds on provisioned members and lifetime accepted lease IDs.
#[derive(Debug, Clone, Copy)]
pub struct MembershipControllerLimits {
    /// Maximum member allow-list length, including repeated input entries.
    pub max_members: usize,
    /// Maximum distinct obligation IDs ever admitted by this controller.
    /// Retired IDs remain remembered, preventing reuse after rejoin or release.
    pub max_lease_ids: usize,
}

/// Independently trusted admission floors for one provisioned member.
#[derive(Debug, Clone)]
pub struct MembershipFloor {
    /// Authorized logical member; this grants no address or certificate authority.
    pub node: NodeId,
    /// Older incarnations are refused even before the first accepted statement.
    pub incarnation: u64,
    /// Statements must advance this sequence; zero permits a first sequence of 1.
    /// Sequence numbers increase across incarnations within the authority epoch.
    pub sequence: u64,
}

/// An authority's decision; signing it is an explicit policy action, not detection.
#[derive(Debug, Clone)]
pub struct MembershipUpdate {
    /// Observed state and subject incarnation. Raw events are never auto-signed.
    pub event: MembershipEvent,
    /// Strictly advancing per-member sequence within the configured authority epoch.
    pub sequence: u64,
}

/// Last accepted membership statement for a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipStamp {
    /// Current subject incarnation.
    pub incarnation: u64,
    /// Last accepted per-member authority sequence.
    pub sequence: u64,
    /// Current state; a terminal incarnation cannot become Alive/Suspect again.
    pub kind: MembershipKind,
}

/// Result of applying an authenticated statement, not an obligation-drain receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipApplied {
    /// A new statement was applied; this many leases entered the revocation outbox.
    Applied { revoked: usize },
    /// Exact duplicate of the most recently accepted statement; no work repeated.
    Duplicate,
}

/// Payload-free refusal from authority admission or local lease operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MembershipControlError {
    /// Malformed encoding, identity, or provisioned allow-list.
    #[error("invalid authenticated membership configuration or statement")]
    Format,
    /// MAC validation failed under the separately provisioned authority key.
    #[error("membership statement authentication failed")]
    Authentication,
    /// The signer identity or authority epoch does not match local policy.
    #[error("membership statement has the wrong authority or epoch")]
    Authority,
    /// Subject is not in the provisioned member set.
    #[error("membership subject is not authorized")]
    UnknownMember,
    /// Sequence or incarnation fell behind its trusted/observed floor.
    #[error("stale membership sequence or incarnation")]
    Stale,
    /// Different contents reused the latest accepted sequence.
    #[error("conflicting membership statement sequence")]
    Conflict,
    /// A terminal incarnation requires a strictly newer incarnation to rejoin.
    #[error("terminal membership incarnation cannot resume")]
    Terminal,
    /// Count admission refused; no existing lease or member was evicted.
    #[error("membership controller capacity exhausted")]
    Capacity,
    /// Reservation of bounded revocation storage failed before mutation.
    #[error("membership revocation allocation failed")]
    Allocation,
    /// New grants require an accepted Alive statement for the exact incarnation.
    #[error("membership does not permit this lease grant")]
    GrantDenied,
    /// An obligation identity cannot be reused, even after cleanup or release.
    #[error("membership lease obligation identity was already used")]
    ReusedLease,
    /// The token no longer names an active lease of the current incarnation.
    #[error("membership lease is absent or belongs to an old incarnation")]
    UnknownLease,
    /// The caller's clock regressed relative to a previous local lease operation.
    #[error("membership lease clock moved backwards")]
    Clock,
    /// Existing lease lifecycle validation failed.
    #[error(transparent)]
    Lease(#[from] LeaseError),
}

/// Returned on a refused grant so the caller retains the obligation owner.
#[derive(Debug)]
pub struct RejectedMembershipLease {
    /// Reason admission was denied.
    pub error: MembershipControlError,
    /// Unconsumed lease; the caller must resolve its underlying obligation.
    pub lease: Lease,
}

/// Token binding an accepted lease to one exact logical-member incarnation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipLeaseId {
    node: NodeId,
    incarnation: u64,
    obligation_id: ObligationId,
}
impl MembershipLeaseId {
    /// Logical member, not a transport destination.
    pub fn node(&self) -> &NodeId { &self.node }
    /// Incarnation under which the obligation was admitted.
    pub const fn incarnation(&self) -> u64 { self.incarnation }
    /// Runtime obligation the owner must eventually resolve.
    pub const fn obligation_id(&self) -> ObligationId { self.obligation_id }
}

/// Why an admitted lease must be aborted by its runtime owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipRevocationReason {
    /// Authority declared the incarnation Dead or Left.
    Terminal,
    /// Authority installed a strictly newer subject incarnation.
    Superseded,
    /// The owner's clock reached the lease deadline.
    Expired,
}

/// Retained cleanup instruction. Reading it does not acknowledge obligation abort.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipRevocation {
    /// Exact member/incarnation/obligation being retired.
    pub lease: MembershipLeaseId,
    /// Reason for abort, not evidence of remote quiescence.
    pub reason: MembershipRevocationReason,
}

struct Member {
    floor: MembershipFloor,
    stamp: Option<MembershipStamp>,
    leases: BTreeMap<ObligationId, Lease>,
}

/// Bounded authority admission plus the existing time-bounded lease state machine.
///
/// Unknown members are denied, not discovered. All accepted obligation IDs remain
/// remembered for this controller lifetime. Capacity never causes eviction or
/// reuse; start a new controller only at an externally managed drained boundary.
/// The revocation outbox is also count-bounded by `max_lease_ids`. Caller-owned
/// input and output copies are separate from these logical bounds.
pub struct MembershipLeaseController {
    authority: NodeId,
    epoch: u64,
    key: AuthKey,
    members: BTreeMap<NodeId, Member>,
    seen_leases: BTreeSet<ObligationId>,
    revocations: Vec<MembershipRevocation>,
    limits: MembershipControllerLimits,
    now: Time,
}
impl fmt::Debug for MembershipLeaseController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MembershipLeaseController")
            .field("members", &self.members.len())
            .field("lease_ids", &self.seen_leases.len())
            .field("pending_revocations", &self.revocations.len())
            .finish_non_exhaustive()
    }
}

fn valid_label(label: &str) -> bool { !label.is_empty() && label.len() <= 255 }
fn terminal(kind: MembershipKind) -> bool { matches!(kind, MembershipKind::Dead | MembershipKind::Left) }
fn kind_byte(kind: MembershipKind) -> u8 {
    match kind { MembershipKind::Alive => 0, MembershipKind::Suspect => 1,
        MembershipKind::Dead => 2, MembershipKind::Left => 3 }
}

impl MembershipUpdate {
    /// Encode and authenticate one explicitly authorized decision using existing
    /// domain-framed HMAC. No detection, key generation, transport, or I/O occurs.
    pub fn authenticated_bytes(
        &self, authority: &NodeId, epoch: u64, key: &AuthKey,
    ) -> Result<Vec<u8>, MembershipControlError> {
        if !valid_label(authority.as_str()) || !valid_label(self.event.node.as_str()) {
            return Err(MembershipControlError::Format);
        }
        let mut bytes = Vec::with_capacity(71 + authority.as_str().len() + self.event.node.as_str().len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.push(authority.as_str().len() as u8);
        bytes.extend_from_slice(authority.as_str().as_bytes());
        bytes.extend_from_slice(&epoch.to_le_bytes());
        bytes.push(self.event.node.as_str().len() as u8);
        bytes.extend_from_slice(self.event.node.as_str().as_bytes());
        bytes.extend_from_slice(&self.event.incarnation.to_le_bytes());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes.push(kind_byte(self.event.kind));
        let tag = AuthenticationTag::compute_for_domain_payload(key, DOMAIN, &bytes);
        bytes.extend_from_slice(tag.as_bytes());
        Ok(bytes)
    }
}

struct Cursor<'a> { bytes: &'a [u8], at: usize }
impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], MembershipControlError> {
        let end = self.at.checked_add(count).ok_or(MembershipControlError::Format)?;
        let bytes = self.bytes.get(self.at..end).ok_or(MembershipControlError::Format)?;
        self.at = end;
        Ok(bytes)
    }
    fn u64(&mut self) -> Result<u64, MembershipControlError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("eight bytes")))
    }
    fn label(&mut self) -> Result<&'a str, MembershipControlError> {
        let count = usize::from(self.take(1)?[0]);
        if count == 0 { return Err(MembershipControlError::Format); }
        std::str::from_utf8(self.take(count)?).map_err(|_| MembershipControlError::Format)
    }
}

impl MembershipLeaseController {
    /// Provision an authority epoch and fixed member set; no grants are permitted
    /// until a fresh authenticated Alive statement has advanced the supplied floor.
    pub fn new(
        authority: NodeId, epoch: u64, key: AuthKey, floors: Vec<MembershipFloor>,
        limits: MembershipControllerLimits,
    ) -> Result<Self, MembershipControlError> {
        if !valid_label(authority.as_str()) { return Err(MembershipControlError::Format); }
        if floors.len() > limits.max_members { return Err(MembershipControlError::Capacity); }
        let mut members = BTreeMap::new();
        for floor in floors {
            if !valid_label(floor.node.as_str()) || members.contains_key(&floor.node) {
                return Err(MembershipControlError::Format);
            }
            members.insert(floor.node.clone(), Member { floor, stamp: None, leases: BTreeMap::new() });
        }
        Ok(Self { authority, epoch, key, members, seen_leases: BTreeSet::new(),
            revocations: Vec::new(), limits, now: Time::ZERO })
    }

    /// Configured authority identity; never taken from an incoming statement.
    pub fn authority(&self) -> &NodeId { &self.authority }
    /// Last accepted state (None also covers provisioned but uninitialized members).
    pub fn stamp(&self, node: &NodeId) -> Option<MembershipStamp> {
        self.members.get(node).and_then(|member| member.stamp)
    }
    /// Number of retained active lease objects for a member; call expire for due ones.
    pub fn active_leases(&self, node: &NodeId) -> usize {
        self.members.get(node).map_or(0, |member| member.leases.len())
    }
    /// Earliest retained lease deadline for the owner's timer driver.
    pub fn next_expiry(&self) -> Option<Time> {
        self.members.values().flat_map(|member| member.leases.values()).map(Lease::expires_at).min()
    }
    /// Pending cleanup instructions, retained across repeated reads and rejoin.
    pub fn revocations(&self) -> &[MembershipRevocation] { &self.revocations }
    /// Acknowledge AFTER the owning runtime has aborted this exact obligation.
    /// This does not itself touch RuntimeState or establish remote quiescence.
    pub fn acknowledge_revocation(&mut self, lease: &MembershipLeaseId) -> bool {
        let Some(index) = self.revocations.iter().position(|entry| &entry.lease == lease) else { return false; };
        self.revocations.remove(index);
        true
    }

    /// Verify the bounded encoding before parsing identities or mutating state.
    /// Exact latest duplicates are idempotent; stale or conflicting statements
    /// never change grant policy. A higher incarnation retires old leases even
    /// when its first reported state is Suspect/Dead/Left rather than Alive.
    pub fn apply_authenticated(&mut self, bytes: &[u8]) -> Result<MembershipApplied, MembershipControlError> {
        if !(73..=MAX_MEMBERSHIP_UPDATE_BYTES).contains(&bytes.len()) { return Err(MembershipControlError::Format); }
        let end = bytes.len() - 32;
        let tag = AuthenticationTag::from_bytes(bytes[end..].try_into().expect("tag bytes"));
        if !tag.verify_domain_payload(&self.key, DOMAIN, &bytes[..end]) { return Err(MembershipControlError::Authentication); }
        let mut cursor = Cursor { bytes: &bytes[..end], at: 0 };
        if cursor.take(8)? != MAGIC || cursor.take(4)? != 1_u32.to_le_bytes() { return Err(MembershipControlError::Format); }
        if cursor.label()? != self.authority.as_str() || cursor.u64()? != self.epoch { return Err(MembershipControlError::Authority); }
        let subject = cursor.label()?;
        let incarnation = cursor.u64()?;
        let sequence = cursor.u64()?;
        let kind = match cursor.take(1)?[0] {
            0 => MembershipKind::Alive, 1 => MembershipKind::Suspect,
            2 => MembershipKind::Dead, 3 => MembershipKind::Left,
            _ => return Err(MembershipControlError::Format),
        };
        if cursor.at != end { return Err(MembershipControlError::Format); }
        // Only one bounded label is allocated, after authenticating the full input.
        let node = NodeId::new(subject);
        let member = self.members.get_mut(&node).ok_or(MembershipControlError::UnknownMember)?;
        let previous = member.stamp;
        let old_incarnation = previous.map_or(member.floor.incarnation, |stamp| stamp.incarnation);
        let old_sequence = previous.map_or(member.floor.sequence, |stamp| stamp.sequence);
        let stamp = MembershipStamp { incarnation, sequence, kind };
        if sequence == old_sequence {
            return if previous == Some(stamp) { Ok(MembershipApplied::Duplicate) }
                else if previous.is_some() { Err(MembershipControlError::Conflict) }
                else { Err(MembershipControlError::Stale) };
        }
        if sequence < old_sequence || incarnation < old_incarnation { return Err(MembershipControlError::Stale); }
        if incarnation == old_incarnation && previous.is_some_and(|old| terminal(old.kind)) && !terminal(kind) {
            return Err(MembershipControlError::Terminal);
        }
        let reason = if incarnation > old_incarnation { Some(MembershipRevocationReason::Superseded) }
            else if terminal(kind) { Some(MembershipRevocationReason::Terminal) } else { None };
        let revoked = if reason.is_some() { member.leases.len() } else { 0 };
        self.revocations.try_reserve(revoked).map_err(|_| MembershipControlError::Allocation)?;
        if let Some(reason) = reason {
            for (obligation_id, mut lease) in std::mem::take(&mut member.leases) {
                let _ = lease.mark_expired();
                self.revocations.push(MembershipRevocation { lease: MembershipLeaseId {
                    node: node.clone(), incarnation: old_incarnation, obligation_id,
                }, reason });
            }
        }
        member.stamp = Some(stamp);
        Ok(MembershipApplied::Applied { revoked })
    }

    /// Admit an existing runtime-owned lease only for an accepted Alive incarnation.
    /// A denied grant always returns the unconsumed lease for caller cleanup.
    pub fn try_grant(
        &mut self, node: &NodeId, incarnation: u64, lease: Lease, now: Time,
    ) -> Result<MembershipLeaseId, RejectedMembershipLease> {
        let error = if now < self.now { Some(MembershipControlError::Clock) }
            else if !lease.is_active(now)
                || self.stamp(node).is_none_or(|stamp| stamp.incarnation != incarnation || stamp.kind != MembershipKind::Alive) {
                Some(MembershipControlError::GrantDenied)
            } else if self.seen_leases.contains(&lease.obligation_id()) { Some(MembershipControlError::ReusedLease) }
            else if self.seen_leases.len() >= self.limits.max_lease_ids { Some(MembershipControlError::Capacity) }
            else { None };
        if let Some(error) = error { return Err(RejectedMembershipLease { error, lease }); }
        let token = MembershipLeaseId { node: node.clone(), incarnation, obligation_id: lease.obligation_id() };
        self.seen_leases.insert(token.obligation_id);
        self.members.get_mut(node).expect("admitted member").leases.insert(token.obligation_id, lease);
        self.now = now;
        Ok(token)
    }

    /// Expire due leases into the retained cleanup outbox. No runtime obligations
    /// are discharged here, and a backward clock is refused without mutation.
    pub fn expire(&mut self, now: Time) -> Result<usize, MembershipControlError> {
        if now < self.now { return Err(MembershipControlError::Clock); }
        let count = self.members.values().flat_map(|member| member.leases.values())
            .filter(|lease| lease.is_expired(now)).count();
        self.revocations.try_reserve(count).map_err(|_| MembershipControlError::Allocation)?;
        let outbox = &mut self.revocations;
        for (node, member) in &mut self.members {
            let incarnation = member.stamp.map_or(member.floor.incarnation, |stamp| stamp.incarnation);
            member.leases.retain(|&obligation_id, lease| {
                if !lease.is_expired(now) { return true; }
                let _ = lease.mark_expired();
                outbox.push(MembershipRevocation { lease: MembershipLeaseId {
                    node: node.clone(), incarnation, obligation_id,
                }, reason: MembershipRevocationReason::Expired });
                false
            });
        }
        self.now = now;
        Ok(count)
    }

    /// Renew an existing exact-incarnation lease. Suspicion pauses new grants but
    /// does not revoke/forbid renewal of unexpired existing leases. Due leases are
    /// retired first; an old-incarnation token cannot address a new incarnation.
    pub fn renew(&mut self, token: &MembershipLeaseId, duration: Duration, now: Time) -> Result<(), MembershipControlError> {
        self.expire(now)?;
        if duration.is_zero() || now + duration <= now { return Err(MembershipControlError::GrantDenied); }
        let member = self.members.get_mut(&token.node).ok_or(MembershipControlError::UnknownLease)?;
        if member.stamp.is_none_or(|stamp| stamp.incarnation != token.incarnation) { return Err(MembershipControlError::UnknownLease); }
        let lease = member.leases.get_mut(&token.obligation_id).ok_or(MembershipControlError::UnknownLease)?;
        if lease.renewal_count() == u32::MAX { return Err(MembershipControlError::Capacity); }
        lease.renew(duration, now)?;
        Ok(())
    }

    /// Release and return the terminal lease so its owner can commit the actual
    /// runtime obligation. Its ID remains unavailable for all future grants.
    pub fn release(&mut self, token: &MembershipLeaseId, now: Time) -> Result<Lease, MembershipControlError> {
        self.expire(now)?;
        let member = self.members.get_mut(&token.node).ok_or(MembershipControlError::UnknownLease)?;
        if member.stamp.is_none_or(|stamp| stamp.incarnation != token.incarnation) { return Err(MembershipControlError::UnknownLease); }
        let lease = member.leases.get_mut(&token.obligation_id).ok_or(MembershipControlError::UnknownLease)?;
        lease.release(now)?;
        Ok(member.leases.remove(&token.obligation_id).expect("released lease"))
    }
}

#[cfg(test)]
mod tests;
