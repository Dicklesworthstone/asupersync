//! SPORK: OTP-grade supervision, registry, and actor layer for Asupersync.
//!
//! This module provides a unified entry point for all Spork functionality.
//! The module layout mirrors the OTP mental model:
//!
//! | OTP Concept     | Spork Module           | Key Types                              |
//! |-----------------|------------------------|----------------------------------------|
//! | Application     | [`app`]                | `AppSpec`, `AppHandle`, `CompiledApp`  |
//! | Supervisor      | [`supervisor`]         | `SupervisorBuilder`, `ChildSpec`       |
//! | GenServer       | [`gen_server`]         | `GenServer`, `GenServerHandle`, `Reply`, `SystemMsg` |
//! | Registry        | [`registry`]           | `NameRegistry`, `RegistryHandle`, `NameLease` |
//! | Process Groups  | [`process_group`]      | `GroupName`, `GroupMemberId`, `GroupMembership`, `GroupSnapshot`, `GroupEventSubscriber`, `GroupEventBatch`, `GroupMonitorDelivery`, `GroupBroadcastPlan`, `GroupBroadcastReport`, `GroupBroadcastSummary` |
//! | Monitor         | [`monitor`]            | `MonitorRef`, `DownReason`             |
//! | Link            | [`link`]               | `LinkRef`, `ExitPolicy`, `ExitSignal`  |
//!
//! # Quick Start
//!
//! ```ignore
//! use asupersync::spork::prelude::*;
//!
//! // Build an application with a supervisor and children
//! let app = AppSpec::new("my_app")
//!     .child(
//!         ChildSpec::new("worker", MyWorkerStart)
//!             .restart_policy(SupervisionStrategy::Restart(
//!                 RestartConfig::default()
//!             ))
//!     )
//!     .start(&mut cx)
//!     .await?;
//!
//! app.stop(&mut cx).await?;
//! ```
//!
//! # Invariant Checklist
//!
//! When adding or reviewing Spork behavior, validate these contracts explicitly:
//!
//! - Region close implies quiescence and no orphan children.
//! - Cancellation follows request -> drain -> finalize with bounded cleanup.
//! - Reply/name/permit obligations are always committed or aborted.
//! - Ordering-sensitive behavior follows deterministic tie-break rules.
//!
//! Canonical references:
//!
//! - [`docs/spork_glossary_invariants.md`](../docs/spork_glossary_invariants.md)
//! - [`docs/spork_deterministic_ordering.md`](../docs/spork_deterministic_ordering.md)
//! - [`docs/replay-debugging.md`](../docs/replay-debugging.md)
//!
//! # Primitive Semantics Matrix
//!
//! | Primitive | Cancellation Semantics | Determinism / Ordering Contract | Obligation Linearity |
//! |-----------|------------------------|---------------------------------|----------------------|
//! | `spork::app` | Region close implies quiescence | Child start/stop ordering follows supervisor contracts | N/A |
//! | `spork::supervisor` | Failed children are drained before restart/escalation | `SUP-START` / `SUP-STOP` ordering in deterministic docs | Child lifecycle transitions remain monotone |
//! | `spork::gen_server` | Request -> drain -> `on_stop` under terminate budget | Mailbox FIFO + `SYS-ORDER` for shutdown messages | Calls create reply obligations that must resolve |
//! | `spork::registry` | Name ownership ends on task/region close | `REG-FIRST` and deterministic collision tie-breaks | Name leases are obligations |
//! | `spork::process_group` | Membership will be lease-backed by the runtime join surface | Snapshots sort by `(join_sequence, node, task)` | Join handles will own name/permit obligations |
//! | `spork::monitor` | Monitor scope ends with owner region | `DOWN-ORDER`: `(vt, tid)` for batched down notifications | N/A |
//! | `spork::link` | Exit propagation participates in cancel protocol | `SYS-LINK-MONITOR` for `Down`/`Exit` ordering | N/A |
//! | `spork::crash` | Crash artifacts emitted on terminal failure paths | Replay certificates detect ordering divergence | Artifact manifest must remain internally consistent |
//!
//! # Deterministic Failure Triage
//!
//! Standard incident workflow for humans and coding agents:
//!
//! 1. Read `repro_manifest.json` and capture `test_id` + `seed`.
//! 2. Re-run with the same seed and artifact directory.
//! 3. Inspect and verify the trace file.
//! 4. If needed, diff against a known-good trace.
//!
//! ```bash
//! ASUPERSYNC_SEED=<seed> ASUPERSYNC_TEST_ARTIFACTS_DIR=target/test-artifacts \
//!   cargo test <test_id> -- --nocapture
//!
//! cargo run --features cli --bin asupersync -- trace info target/test-artifacts/trace.async
//! cargo run --features cli --bin asupersync -- trace verify --strict \
//!   target/test-artifacts/trace.async
//! cargo run --features cli --bin asupersync -- trace diff <trace_a> <trace_b>
//! ```
//!
//! # Minimal Compile-Time Example
//!
//! ```
//! use asupersync::spork::error::{SporkError, SporkSeverity};
//! use asupersync::spork::prelude::{CastError, RestartConfig, RestartPolicy, SupervisionStrategy};
//!
//! let strategy = SupervisionStrategy::Restart(RestartConfig::default());
//! let policy = RestartPolicy::OneForOne;
//! assert!(matches!(strategy, SupervisionStrategy::Restart(_)));
//! assert!(matches!(policy, RestartPolicy::OneForOne));
//!
//! let err = SporkError::from(CastError::Full);
//! assert_eq!(err.severity(), SporkSeverity::Transient);
//! ```
//!
//! # Prelude
//!
//! The [`prelude`] re-exports the most commonly needed types so that a
//! single `use asupersync::spork::prelude::*` is sufficient for typical
//! supervised application development.
//!
//! # Bead
//!
//! bd-2td4e | Parent: bd-1f3nn

/// Application lifecycle: build, compile, start, stop.
///
/// Re-exports from [`crate::app`].
/// Cancellation semantics: app stop triggers region cancellation and requires
/// quiescence before completion.
pub mod app {
    pub use crate::app::{
        AppCompileError, AppHandle, AppSpawnError, AppSpec, AppStartError, AppStopError,
        CompiledApp, StoppedApp,
    };
}

/// Supervision trees: strategies, child specs, builders.
///
/// Re-exports from [`crate::supervision`].
/// Determinism contract: child start/stop follows compiled ordering and
/// restart policy tie-break rules.
pub mod supervisor {
    pub use crate::supervision::{
        BackoffStrategy, ChildName, ChildSpec, ChildStart, CompiledSupervisor, EscalationPolicy,
        RestartConfig, RestartPolicy, StartTieBreak, StartedChild, SupervisionStrategy,
        SupervisorBuilder, SupervisorCompileError, SupervisorHandle, SupervisorSpawnError,
    };
}

/// Typed request-response actors (GenServer pattern).
///
/// Re-exports from [`crate::gen_server`].
/// Invariant notes:
/// - Cancellation uses request -> drain -> finalize.
/// - Ordering follows mailbox FIFO and shutdown `SYS-ORDER`.
/// - `call` replies are linear obligations (reply or abort).
pub mod gen_server {
    pub use crate::gen_server::{
        CallError, CastError, CastOverflowPolicy, DownMsg, ExitMsg, GenServer, GenServerHandle,
        GenServerRef, InfoError, NamedGenServerStart, Reply, ReplyOutcome, SystemMsg, TimeoutMsg,
        named_gen_server_start,
    };
}

/// Capability-scoped name registry and lease obligations.
///
/// Re-exports from [`crate::cx::registry`].
/// Determinism contract: first-commit collision resolution with stable
/// tie-break behavior in lab mode.
pub mod registry {
    pub use crate::cx::registry::{
        GrantedLease, NameCollisionOutcome, NameCollisionPolicy, NameLease, NameLeaseError,
        NameOwnershipKind, NameOwnershipNotification, NamePermit, NameRegistry, NameWatchRef,
        RegistryCap, RegistryEvent, RegistryHandle,
    };
}

/// Node-local process-group model.
///
/// This module is the stable value layer for Spork process groups. The runtime
/// join/broadcast surface is built on top of these identifiers, deterministic
/// snapshots, and membership events.
pub mod process_group {
    use crate::channel::mpsc;
    use crate::cx::Cx;
    use crate::monitor::DownReason;
    use crate::remote::NodeId;
    use crate::types::cancel::{CancelKind, CancelReason};
    use crate::types::outcome::Outcome;
    use crate::types::{TaskId, Time};
    use std::collections::BTreeMap;
    use std::fmt;

    /// Validation failure for process-group names.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum GroupNameError {
        /// Group names must contain at least one non-whitespace byte.
        Empty,
        /// Group names are registry keys and cannot contain interior NUL bytes.
        ContainsNul,
    }

    impl fmt::Display for GroupNameError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Empty => write!(f, "process group name is empty"),
                Self::ContainsNul => write!(f, "process group name contains NUL"),
            }
        }
    }

    impl std::error::Error for GroupNameError {}

    /// A validated Spork process-group name.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct GroupName(String);

    impl GroupName {
        /// Validates and stores a process-group name.
        ///
        /// Names are intentionally opaque. The only constraints here are the
        /// cross-surface invariants required by registry-backed memberships.
        ///
        /// # Errors
        ///
        /// Returns [`GroupNameError::Empty`] when the name contains only
        /// whitespace, and [`GroupNameError::ContainsNul`] when it contains an
        /// interior NUL byte.
        pub fn new(name: impl Into<String>) -> Result<Self, GroupNameError> {
            let name = name.into();
            if name.trim().is_empty() {
                return Err(GroupNameError::Empty);
            }
            if name.contains('\0') {
                return Err(GroupNameError::ContainsNul);
            }
            Ok(Self(name))
        }

        /// Returns the name as a string slice.
        #[must_use]
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    impl fmt::Display for GroupName {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl TryFrom<String> for GroupName {
        type Error = GroupNameError;

        fn try_from(value: String) -> Result<Self, Self::Error> {
            Self::new(value)
        }
    }

    impl TryFrom<&str> for GroupName {
        type Error = GroupNameError;

        fn try_from(value: &str) -> Result<Self, Self::Error> {
            Self::new(value)
        }
    }

    /// Process-group member identity.
    ///
    /// The node component is present even for this node-local first slice so
    /// later cluster-wide process groups do not need a different member ID.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct GroupMemberId {
        node: NodeId,
        task: TaskId,
    }

    impl GroupMemberId {
        /// Creates a member identity from its node and task components.
        #[must_use]
        pub fn new(node: NodeId, task: TaskId) -> Self {
            Self { node, task }
        }

        /// Returns the node component.
        #[must_use]
        pub fn node(&self) -> &NodeId {
            &self.node
        }

        /// Returns the task component.
        #[must_use]
        pub fn task(&self) -> TaskId {
            self.task
        }
    }

    impl fmt::Display for GroupMemberId {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}", self.node, self.task)
        }
    }

    /// Process-group state transition failure.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ProcessGroupError {
        /// A join attempted to add an already-active member.
        DuplicateMember(GroupMemberId),
        /// A leave/down transition targeted a member not present in the group.
        MemberNotFound(GroupMemberId),
        /// The deterministic join sequence counter has no remaining values.
        JoinSequenceExhausted,
        /// The deterministic event sequence counter has no remaining values.
        EventSequenceExhausted,
        /// A broadcast report did not account for a planned recipient.
        BroadcastRecipientMissing(GroupMemberId),
        /// A broadcast report mentioned a recipient outside the broadcast plan.
        BroadcastRecipientUnknown(GroupMemberId),
        /// A broadcast report accounted for the same recipient more than once.
        BroadcastRecipientDuplicate(GroupMemberId),
        /// A membership handle was used with a different process group.
        GroupMismatch {
            /// The group recorded in the membership handle.
            handle: GroupName,
            /// The group owned by the target state.
            state: GroupName,
        },
    }

    impl fmt::Display for ProcessGroupError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::DuplicateMember(member) => {
                    write!(f, "process group member already joined: {member}")
                }
                Self::MemberNotFound(member) => {
                    write!(f, "process group member not found: {member}")
                }
                Self::JoinSequenceExhausted => {
                    write!(f, "process group join sequence exhausted")
                }
                Self::EventSequenceExhausted => {
                    write!(f, "process group event sequence exhausted")
                }
                Self::BroadcastRecipientMissing(member) => {
                    write!(f, "process group broadcast recipient missing: {member}")
                }
                Self::BroadcastRecipientUnknown(member) => {
                    write!(f, "process group broadcast recipient unknown: {member}")
                }
                Self::BroadcastRecipientDuplicate(member) => {
                    write!(f, "process group broadcast recipient duplicated: {member}")
                }
                Self::GroupMismatch { handle, state } => {
                    write!(
                        f,
                        "process group membership for {handle} used with state for {state}"
                    )
                }
            }
        }
    }

    impl std::error::Error for ProcessGroupError {}

    /// A single active process-group member.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GroupMember {
        id: GroupMemberId,
        joined_at: Time,
        join_sequence: u64,
    }

    impl GroupMember {
        /// Creates a member record.
        ///
        /// `join_sequence` is the deterministic registration-order key minted
        /// by the runtime join surface.
        #[must_use]
        pub fn new(id: GroupMemberId, joined_at: Time, join_sequence: u64) -> Self {
            Self {
                id,
                joined_at,
                join_sequence,
            }
        }

        /// Returns this member's identity.
        #[must_use]
        pub fn id(&self) -> &GroupMemberId {
            &self.id
        }

        /// Returns the virtual or wall-clock time when this member joined.
        #[must_use]
        pub fn joined_at(&self) -> Time {
            self.joined_at
        }

        /// Returns the deterministic join-order sequence.
        #[must_use]
        pub fn join_sequence(&self) -> u64 {
            self.join_sequence
        }
    }

    /// One active local process-group membership.
    ///
    /// This is the value-layer shape that the async `join` surface can wrap
    /// around a registry lease. It is intentionally not `Clone`: a membership
    /// handle represents one owner, and leave/down transitions are one-shot.
    #[derive(Debug, PartialEq, Eq)]
    pub struct GroupMembership {
        group: GroupName,
        member: GroupMemberId,
        joined_event: GroupEvent,
        active: bool,
    }

    impl GroupMembership {
        #[must_use]
        fn new(group: GroupName, member: GroupMemberId, joined_event: GroupEvent) -> Self {
            Self {
                group,
                member,
                joined_event,
                active: true,
            }
        }

        /// Returns the process group that owns this membership.
        #[must_use]
        pub fn group(&self) -> &GroupName {
            &self.group
        }

        /// Returns this membership's member identity.
        #[must_use]
        pub fn member(&self) -> &GroupMemberId {
            &self.member
        }

        /// Returns the join event that minted this membership.
        #[must_use]
        pub fn joined_event(&self) -> &GroupEvent {
            &self.joined_event
        }

        /// Returns whether the membership has not yet left or gone down.
        #[must_use]
        pub fn is_active(&self) -> bool {
            self.active
        }

        /// Leaves the group once through the explicit release path.
        ///
        /// Returns `Ok(None)` when the handle has already resolved, making
        /// cleanup idempotent after retry or drop-supervision paths.
        ///
        /// # Errors
        ///
        /// Returns [`ProcessGroupError::GroupMismatch`] if this handle is used
        /// with a different group state, or forwards the state transition
        /// failure from [`ProcessGroupState::leave`].
        pub fn leave(
            &mut self,
            state: &mut ProcessGroupState,
            at: Time,
        ) -> Result<Option<GroupEvent>, ProcessGroupError> {
            if !self.active {
                return Ok(None);
            }
            self.ensure_group(state)?;
            let event = state.leave(&self.member, at)?;
            self.active = false;
            Ok(Some(event))
        }

        /// Marks the member down once through monitor/region cleanup.
        ///
        /// Returns `Ok(None)` when the handle has already resolved.
        ///
        /// # Errors
        ///
        /// Returns [`ProcessGroupError::GroupMismatch`] if this handle is used
        /// with a different group state, or forwards the state transition
        /// failure from [`ProcessGroupState::mark_down`].
        pub fn mark_down(
            &mut self,
            state: &mut ProcessGroupState,
            reason: DownReason,
            at: Time,
        ) -> Result<Option<GroupEvent>, ProcessGroupError> {
            if !self.active {
                return Ok(None);
            }
            self.ensure_group(state)?;
            let event = state.mark_down(&self.member, reason, at)?;
            self.active = false;
            Ok(Some(event))
        }

        fn ensure_group(&self, state: &ProcessGroupState) -> Result<(), ProcessGroupError> {
            if &self.group == state.group() {
                Ok(())
            } else {
                Err(ProcessGroupError::GroupMismatch {
                    handle: self.group.clone(),
                    state: state.group().clone(),
                })
            }
        }
    }

    /// Deterministically ordered snapshot of a process group.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GroupSnapshot {
        group: GroupName,
        members: Vec<GroupMember>,
    }

    impl GroupSnapshot {
        /// Creates a snapshot and normalizes member ordering.
        ///
        /// Members are sorted by `(join_sequence, node, task)`, which preserves
        /// registration order and gives deterministic tie-breaking for lab
        /// schedules that observe equal sequence values.
        #[must_use]
        pub fn new(group: GroupName, mut members: Vec<GroupMember>) -> Self {
            members.sort_by(|left, right| {
                left.join_sequence()
                    .cmp(&right.join_sequence())
                    .then_with(|| left.id().cmp(right.id()))
            });
            Self { group, members }
        }

        /// Returns the process-group name.
        #[must_use]
        pub fn group(&self) -> &GroupName {
            &self.group
        }

        /// Returns the ordered member records.
        #[must_use]
        pub fn members(&self) -> &[GroupMember] {
            &self.members
        }

        /// Returns the ordered member identities.
        pub fn member_ids(&self) -> impl Iterator<Item = &GroupMemberId> {
            self.members.iter().map(GroupMember::id)
        }

        /// Returns the number of members.
        #[must_use]
        pub fn len(&self) -> usize {
            self.members.len()
        }

        /// Returns whether the snapshot contains no members.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.members.is_empty()
        }
    }

    /// Deterministic in-memory membership state for one process group.
    ///
    /// This is the synchronous core that future async `join`, `leave`,
    /// `monitor_group`, and broadcast surfaces use. It does not spawn tasks or
    /// touch global registries; callers provide the already-authorized member
    /// IDs and timestamps.
    #[derive(Debug, Clone)]
    pub struct ProcessGroupState {
        group: GroupName,
        members: BTreeMap<GroupMemberId, GroupMember>,
        events: Vec<GroupEvent>,
        next_join_sequence: u64,
        next_event_sequence: u64,
    }

    impl ProcessGroupState {
        /// Creates an empty process-group state.
        #[must_use]
        pub fn new(group: GroupName) -> Self {
            Self {
                group,
                members: BTreeMap::new(),
                events: Vec::new(),
                next_join_sequence: 0,
                next_event_sequence: 0,
            }
        }

        /// Returns the process-group name.
        #[must_use]
        pub fn group(&self) -> &GroupName {
            &self.group
        }

        /// Returns the number of active members.
        #[must_use]
        pub fn len(&self) -> usize {
            self.members.len()
        }

        /// Returns whether there are no active members.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.members.is_empty()
        }

        /// Returns whether the member is active.
        #[must_use]
        pub fn contains_member(&self, member: &GroupMemberId) -> bool {
            self.members.contains_key(member)
        }

        /// Returns the deterministic sequence that will be assigned next.
        #[must_use]
        pub fn next_join_sequence(&self) -> u64 {
            self.next_join_sequence
        }

        /// Returns the deterministic event sequence that will be assigned next.
        #[must_use]
        pub fn next_event_sequence(&self) -> u64 {
            self.next_event_sequence
        }

        /// Returns an active member record.
        #[must_use]
        pub fn member(&self, member: &GroupMemberId) -> Option<&GroupMember> {
            self.members.get(member)
        }

        /// Returns all recorded membership events in emission order.
        #[must_use]
        pub fn event_log(&self) -> &[GroupEvent] {
            &self.events
        }

        /// Replays events at or after `cursor` and advances it past the replay.
        ///
        /// This is the deterministic core for monitor-style streams: callers
        /// keep a cursor per subscriber, and each call returns only events not
        /// previously observed by that cursor.
        pub fn events_since(&self, cursor: &mut GroupEventCursor) -> &[GroupEvent] {
            let start = self
                .events
                .partition_point(|event| event.sequence() < cursor.next_sequence());
            let next_sequence = self.events.last().map_or(cursor.next_sequence(), |event| {
                event
                    .sequence()
                    .saturating_add(1)
                    .max(cursor.next_sequence())
            });
            cursor.set_next_sequence(next_sequence);
            &self.events[start..]
        }

        /// Returns an owned event batch without mutating the caller's cursor.
        ///
        /// This is the handoff shape for future monitor streams: event
        /// delivery can reserve queue capacity first, then commit an owned
        /// batch and advance the subscriber cursor only after the commit.
        #[must_use]
        pub fn event_batch(&self, cursor: GroupEventCursor) -> GroupEventBatch {
            let mut next_cursor = cursor;
            let events = self.events_since(&mut next_cursor).to_vec();
            GroupEventBatch::new(events, next_cursor)
        }

        /// Adds a member and returns the corresponding joined event.
        ///
        /// # Errors
        ///
        /// Returns [`ProcessGroupError::DuplicateMember`] if `member` is
        /// already active, or [`ProcessGroupError::JoinSequenceExhausted`] if
        /// no deterministic join sequence values remain.
        pub fn join(
            &mut self,
            member: GroupMemberId,
            at: Time,
        ) -> Result<GroupEvent, ProcessGroupError> {
            if self.members.contains_key(&member) {
                return Err(ProcessGroupError::DuplicateMember(member));
            }

            let join_sequence = self.next_join_sequence;
            let next_join_sequence = self
                .next_join_sequence
                .checked_add(1)
                .ok_or(ProcessGroupError::JoinSequenceExhausted)?;
            let event_sequence = self.next_event_sequence;
            let next_event_sequence = self
                .next_event_sequence
                .checked_add(1)
                .ok_or(ProcessGroupError::EventSequenceExhausted)?;

            let record = GroupMember::new(member.clone(), at, join_sequence);
            self.members.insert(member.clone(), record);
            self.next_join_sequence = next_join_sequence;
            self.next_event_sequence = next_event_sequence;
            let event = GroupEvent::with_sequence(
                self.group.clone(),
                member,
                GroupEventKind::Joined,
                at,
                event_sequence,
            );
            self.events.push(event.clone());
            Ok(event)
        }

        /// Adds a member and returns its one-shot membership handle.
        ///
        /// The returned handle is the synchronous value-layer stand-in for the
        /// future runtime join handle that will also own the registry lease.
        ///
        /// # Errors
        ///
        /// Forwards the state transition failure from [`Self::join`].
        pub fn join_membership(
            &mut self,
            member: GroupMemberId,
            at: Time,
        ) -> Result<GroupMembership, ProcessGroupError> {
            let joined_event = self.join(member.clone(), at)?;
            Ok(GroupMembership::new(
                self.group.clone(),
                member,
                joined_event,
            ))
        }

        /// Removes a member through the explicit leave path.
        ///
        /// # Errors
        ///
        /// Returns [`ProcessGroupError::MemberNotFound`] if `member` is not
        /// active.
        pub fn leave(
            &mut self,
            member: &GroupMemberId,
            at: Time,
        ) -> Result<GroupEvent, ProcessGroupError> {
            if !self.members.contains_key(member) {
                return Err(ProcessGroupError::MemberNotFound(member.clone()));
            }
            let event_sequence = self.next_event_sequence;
            self.next_event_sequence = self
                .next_event_sequence
                .checked_add(1)
                .ok_or(ProcessGroupError::EventSequenceExhausted)?;
            let _ = self.members.remove(member);
            let event = GroupEvent::with_sequence(
                self.group.clone(),
                member.clone(),
                GroupEventKind::Left,
                at,
                event_sequence,
            );
            self.events.push(event.clone());
            Ok(event)
        }

        /// Removes a member through monitor/region cleanup.
        ///
        /// # Errors
        ///
        /// Returns [`ProcessGroupError::MemberNotFound`] if `member` is not
        /// active.
        pub fn mark_down(
            &mut self,
            member: &GroupMemberId,
            reason: DownReason,
            at: Time,
        ) -> Result<GroupEvent, ProcessGroupError> {
            if !self.members.contains_key(member) {
                return Err(ProcessGroupError::MemberNotFound(member.clone()));
            }
            let event_sequence = self.next_event_sequence;
            self.next_event_sequence = self
                .next_event_sequence
                .checked_add(1)
                .ok_or(ProcessGroupError::EventSequenceExhausted)?;
            let _ = self.members.remove(member);
            let event = GroupEvent::with_sequence(
                self.group.clone(),
                member.clone(),
                GroupEventKind::Down(reason),
                at,
                event_sequence,
            );
            self.events.push(event.clone());
            Ok(event)
        }

        /// Returns a deterministic snapshot of active members.
        #[must_use]
        pub fn snapshot(&self) -> GroupSnapshot {
            GroupSnapshot::new(self.group.clone(), self.members.values().cloned().collect())
        }

        /// Returns the deterministic recipient plan for a group broadcast.
        ///
        /// This does not deliver messages. It freezes the recipient order and
        /// backpressure policy that the async broadcast surface must honor.
        #[must_use]
        pub fn broadcast_plan(&self, policy: BroadcastBackpressurePolicy) -> GroupBroadcastPlan {
            GroupBroadcastPlan::from_snapshot(&self.snapshot(), policy)
        }
    }

    /// Cursor into a process-group membership event log.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct GroupEventCursor {
        next_sequence: u64,
    }

    impl GroupEventCursor {
        /// Creates a cursor positioned before the first event.
        #[must_use]
        pub fn new() -> Self {
            Self { next_sequence: 0 }
        }

        /// Creates a cursor positioned at an explicit next event sequence.
        #[must_use]
        pub fn from_next_sequence(next_sequence: u64) -> Self {
            Self { next_sequence }
        }

        /// Returns the next event sequence this cursor will observe.
        #[must_use]
        pub fn next_sequence(&self) -> u64 {
            self.next_sequence
        }

        fn set_next_sequence(&mut self, next_sequence: u64) {
            self.next_sequence = next_sequence;
        }
    }

    impl Default for GroupEventCursor {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Subscriber-side cursor for monitor-style process-group event streams.
    ///
    /// The subscriber observes owned [`GroupEventBatch`] values and commits
    /// their cursor only after delivery succeeds. Committing a stale batch is a
    /// no-op so out-of-order retry cleanup cannot move the stream backwards.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct GroupEventSubscriber {
        cursor: GroupEventCursor,
    }

    impl GroupEventSubscriber {
        /// Creates a subscriber positioned before the first event.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Creates a subscriber from a previously committed cursor.
        #[must_use]
        pub fn from_cursor(cursor: GroupEventCursor) -> Self {
            Self { cursor }
        }

        /// Returns the currently committed cursor.
        #[must_use]
        pub fn cursor(&self) -> GroupEventCursor {
            self.cursor
        }

        /// Returns the next batch without advancing this subscriber.
        #[must_use]
        pub fn pending_batch(&self, state: &ProcessGroupState) -> GroupEventBatch {
            state.event_batch(self.cursor)
        }

        /// Delivers pending events into a broadcast monitor stream.
        ///
        /// The subscriber cursor advances only after the batch has reserved a
        /// broadcast send permit and committed to at least one live receiver.
        /// This is the synchronous two-phase core for the future async
        /// `monitor_group` surface.
        ///
        /// # Errors
        ///
        /// Returns [`GroupMonitorDeliveryError::Closed`] if no monitor
        /// receiver can accept the batch, and
        /// [`GroupMonitorDeliveryError::Cancelled`] if `cx` is cancelled
        /// before the broadcast permit is granted.
        pub fn deliver_pending_to(
            &mut self,
            cx: &crate::Cx,
            state: &ProcessGroupState,
            sender: &crate::channel::broadcast::Sender<GroupEventBatch>,
        ) -> Result<GroupMonitorDelivery, GroupMonitorDeliveryError> {
            let batch = self.pending_batch(state);
            if batch.is_empty() {
                return Ok(GroupMonitorDelivery::new(batch, 0, false));
            }

            let permit = match sender.reserve(cx) {
                Ok(permit) => permit,
                Err(crate::channel::broadcast::SendError::Closed(())) => {
                    return Err(GroupMonitorDeliveryError::Closed(batch));
                }
                Err(crate::channel::broadcast::SendError::Cancelled(())) => {
                    return Err(GroupMonitorDeliveryError::Cancelled(batch));
                }
            };

            let delivered_receiver_count = permit.send(batch.clone());
            if delivered_receiver_count == 0 {
                return Err(GroupMonitorDeliveryError::Closed(batch));
            }

            let cursor_advanced = self.commit(&batch);
            Ok(GroupMonitorDelivery::new(
                batch,
                delivered_receiver_count,
                cursor_advanced,
            ))
        }

        /// Commits a delivered batch cursor.
        ///
        /// Returns `true` if the subscriber advanced. Stale batches are ignored
        /// to preserve exactly-once cursor monotonicity across retry cleanup.
        pub fn commit(&mut self, batch: &GroupEventBatch) -> bool {
            let next_cursor = batch.next_cursor();
            if next_cursor <= self.cursor {
                return false;
            }
            self.cursor = next_cursor;
            true
        }
    }

    /// Result of delivering a process-group monitor batch.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GroupMonitorDelivery {
        batch: GroupEventBatch,
        delivered_receiver_count: usize,
        cursor_advanced: bool,
    }

    impl GroupMonitorDelivery {
        #[must_use]
        fn new(
            batch: GroupEventBatch,
            delivered_receiver_count: usize,
            cursor_advanced: bool,
        ) -> Self {
            Self {
                batch,
                delivered_receiver_count,
                cursor_advanced,
            }
        }

        /// Returns the delivered batch.
        #[must_use]
        pub fn batch(&self) -> &GroupEventBatch {
            &self.batch
        }

        /// Consumes this result and returns the delivered batch.
        #[must_use]
        pub fn into_batch(self) -> GroupEventBatch {
            self.batch
        }

        /// Returns the number of live receivers that accepted the batch.
        #[must_use]
        pub fn delivered_receiver_count(&self) -> usize {
            self.delivered_receiver_count
        }

        /// Returns true when delivery advanced the subscriber cursor.
        #[must_use]
        pub fn cursor_advanced(&self) -> bool {
            self.cursor_advanced
        }
    }

    /// Failure to deliver a monitor batch.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum GroupMonitorDeliveryError {
        /// No monitor receiver was live when the batch was reserved or
        /// committed.
        Closed(GroupEventBatch),
        /// The sender context was cancelled before reservation.
        Cancelled(GroupEventBatch),
    }

    impl GroupMonitorDeliveryError {
        /// Returns the batch that was not delivered.
        #[must_use]
        pub fn batch(&self) -> &GroupEventBatch {
            match self {
                Self::Closed(batch) | Self::Cancelled(batch) => batch,
            }
        }

        /// Consumes this error and returns the undelivered batch.
        #[must_use]
        pub fn into_batch(self) -> GroupEventBatch {
            match self {
                Self::Closed(batch) | Self::Cancelled(batch) => batch,
            }
        }
    }

    impl fmt::Display for GroupMonitorDeliveryError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Closed(batch) => {
                    write!(
                        f,
                        "process group monitor stream closed before delivering {} event(s)",
                        batch.len()
                    )
                }
                Self::Cancelled(batch) => {
                    write!(
                        f,
                        "process group monitor delivery cancelled before delivering {} event(s)",
                        batch.len()
                    )
                }
            }
        }
    }

    impl std::error::Error for GroupMonitorDeliveryError {}

    /// Owned membership-event batch for monitor-style consumers.
    ///
    /// A batch carries both the events to deliver and the cursor that should be
    /// committed after delivery succeeds. Keeping these together avoids the
    /// classic monitor-stream bug where a subscriber cursor advances before the
    /// event payload is actually enqueued.
    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct GroupEventBatch {
        events: Vec<GroupEvent>,
        next_cursor: GroupEventCursor,
    }

    impl GroupEventBatch {
        /// Creates an owned event batch.
        #[must_use]
        pub fn new(events: Vec<GroupEvent>, next_cursor: GroupEventCursor) -> Self {
            Self {
                events,
                next_cursor,
            }
        }

        /// Returns the events in deterministic emission order.
        #[must_use]
        pub fn events(&self) -> &[GroupEvent] {
            &self.events
        }

        /// Returns the cursor to commit after delivery succeeds.
        #[must_use]
        pub fn next_cursor(&self) -> GroupEventCursor {
            self.next_cursor
        }

        /// Returns the number of events in this batch.
        #[must_use]
        pub fn len(&self) -> usize {
            self.events.len()
        }

        /// Returns whether this batch contains no events.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.events.is_empty()
        }

        /// Consumes the batch and returns its owned event payload.
        #[must_use]
        pub fn into_events(self) -> Vec<GroupEvent> {
            self.events
        }
    }

    /// Membership-change event kind.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum GroupEventKind {
        /// A member joined the group.
        Joined,
        /// A member left the group through an explicit leave/release path.
        Left,
        /// A member went down and was removed by monitor/region cleanup.
        Down(DownReason),
    }

    /// A deterministic membership-change event.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GroupEvent {
        group: GroupName,
        member: GroupMemberId,
        kind: GroupEventKind,
        at: Time,
        sequence: u64,
    }

    impl GroupEvent {
        /// Creates a standalone membership-change event.
        #[must_use]
        pub fn new(
            group: GroupName,
            member: GroupMemberId,
            kind: GroupEventKind,
            at: Time,
        ) -> Self {
            Self::with_sequence(group, member, kind, at, 0)
        }

        /// Creates a membership-change event with a deterministic sequence.
        #[must_use]
        pub fn with_sequence(
            group: GroupName,
            member: GroupMemberId,
            kind: GroupEventKind,
            at: Time,
            sequence: u64,
        ) -> Self {
            Self {
                group,
                member,
                kind,
                at,
                sequence,
            }
        }

        /// Returns the group name.
        #[must_use]
        pub fn group(&self) -> &GroupName {
            &self.group
        }

        /// Returns the affected member.
        #[must_use]
        pub fn member(&self) -> &GroupMemberId {
            &self.member
        }

        /// Returns the event kind.
        #[must_use]
        pub fn kind(&self) -> &GroupEventKind {
            &self.kind
        }

        /// Returns the event timestamp.
        #[must_use]
        pub fn at(&self) -> Time {
            self.at
        }

        /// Returns the deterministic event sequence.
        #[must_use]
        pub fn sequence(&self) -> u64 {
            self.sequence
        }
    }

    /// Broadcast behavior when one member cannot accept a message immediately.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub enum BroadcastBackpressurePolicy {
        /// Wait for the slow member within the caller's budget.
        #[default]
        Wait,
        /// Skip the slow member and report the skip count.
        Skip,
        /// Fail the broadcast immediately.
        Error,
    }

    /// Deterministic broadcast recipient plan for one process group.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GroupBroadcastPlan {
        group: GroupName,
        policy: BroadcastBackpressurePolicy,
        recipients: Vec<GroupMemberId>,
    }

    impl GroupBroadcastPlan {
        /// Creates a broadcast plan from a deterministic snapshot.
        #[must_use]
        pub fn from_snapshot(
            snapshot: &GroupSnapshot,
            policy: BroadcastBackpressurePolicy,
        ) -> Self {
            Self {
                group: snapshot.group().clone(),
                policy,
                recipients: snapshot.member_ids().cloned().collect(),
            }
        }

        /// Returns the target group.
        #[must_use]
        pub fn group(&self) -> &GroupName {
            &self.group
        }

        /// Returns the policy to apply when a recipient cannot accept a
        /// message immediately.
        #[must_use]
        pub fn policy(&self) -> BroadcastBackpressurePolicy {
            self.policy
        }

        /// Returns the deterministic recipient order.
        #[must_use]
        pub fn recipients(&self) -> &[GroupMemberId] {
            &self.recipients
        }

        /// Returns the number of planned recipients.
        #[must_use]
        pub fn len(&self) -> usize {
            self.recipients.len()
        }

        /// Returns whether this plan has no recipients.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.recipients.is_empty()
        }

        /// Builds deterministic accounting from immediate delivery attempts.
        ///
        /// The closure returns `true` when the member accepted the message at
        /// the current policy boundary. A `false` result is classified from
        /// the plan policy: [`BroadcastBackpressurePolicy::Skip`] records a
        /// skipped recipient, while `Wait` and `Error` record backpressure
        /// that the future async executor must surface to the caller.
        #[must_use]
        pub fn immediate_delivery_report<F>(&self, mut deliver: F) -> GroupBroadcastReport
        where
            F: FnMut(&GroupMemberId) -> bool,
        {
            let blocked_status = self.blocked_recipient_status();
            let recipients = self
                .recipients()
                .iter()
                .cloned()
                .map(|member| {
                    let status = if deliver(&member) {
                        GroupBroadcastRecipientStatus::Delivered
                    } else {
                        blocked_status
                    };
                    GroupBroadcastRecipientReport::new(member, status)
                })
                .collect();

            GroupBroadcastReport {
                group: self.group.clone(),
                policy: self.policy,
                recipients,
            }
        }

        fn blocked_recipient_status(&self) -> GroupBroadcastRecipientStatus {
            match self.policy {
                BroadcastBackpressurePolicy::Skip => GroupBroadcastRecipientStatus::Skipped,
                BroadcastBackpressurePolicy::Wait | BroadcastBackpressurePolicy::Error => {
                    GroupBroadcastRecipientStatus::Backpressured
                }
            }
        }
    }

    /// Per-recipient outcome recorded by a broadcast executor.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum GroupBroadcastRecipientStatus {
        /// The recipient accepted the message.
        Delivered,
        /// The recipient was skipped according to
        /// [`BroadcastBackpressurePolicy::Skip`].
        Skipped,
        /// The recipient could not accept the message before the caller's
        /// budget or policy boundary.
        Backpressured,
    }

    /// Accounting row for one broadcast recipient.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GroupBroadcastRecipientReport {
        member: GroupMemberId,
        status: GroupBroadcastRecipientStatus,
    }

    impl GroupBroadcastRecipientReport {
        /// Creates a per-recipient broadcast accounting row.
        #[must_use]
        pub fn new(member: GroupMemberId, status: GroupBroadcastRecipientStatus) -> Self {
            Self { member, status }
        }

        /// Returns the accounted recipient.
        #[must_use]
        pub fn member(&self) -> &GroupMemberId {
            &self.member
        }

        /// Returns the recorded delivery status.
        #[must_use]
        pub fn status(&self) -> GroupBroadcastRecipientStatus {
            self.status
        }
    }

    /// Aggregate broadcast accounting for one process group.
    ///
    /// The summary keeps skip and backpressure counts distinct so the async
    /// delivery surface can report policy effects without collapsing them into
    /// a generic partial-failure bucket.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct GroupBroadcastSummary {
        delivered: usize,
        skipped: usize,
        backpressured: usize,
    }

    impl GroupBroadcastSummary {
        /// Creates a summary from explicit status counts.
        #[must_use]
        pub fn new(delivered: usize, skipped: usize, backpressured: usize) -> Self {
            Self {
                delivered,
                skipped,
                backpressured,
            }
        }

        /// Returns the number of delivered recipients.
        #[must_use]
        pub fn delivered(&self) -> usize {
            self.delivered
        }

        /// Returns the number of skipped recipients.
        #[must_use]
        pub fn skipped(&self) -> usize {
            self.skipped
        }

        /// Returns the number of backpressured recipients.
        #[must_use]
        pub fn backpressured(&self) -> usize {
            self.backpressured
        }

        /// Returns the total number of accounted recipients.
        #[must_use]
        pub fn total(&self) -> usize {
            self.delivered + self.skipped + self.backpressured
        }

        /// Returns true when every accounted recipient accepted the message.
        #[must_use]
        pub fn is_all_delivered(&self) -> bool {
            self.skipped == 0 && self.backpressured == 0
        }

        /// Returns true when at least one recipient was skipped by policy.
        #[must_use]
        pub fn has_skipped_recipients(&self) -> bool {
            self.skipped > 0
        }

        /// Returns true when at least one recipient hit backpressure.
        #[must_use]
        pub fn has_backpressured_recipients(&self) -> bool {
            self.backpressured > 0
        }
    }

    /// Complete accounting report for one process-group broadcast.
    ///
    /// Construction validates that every planned recipient appears exactly
    /// once. The async delivery surface will use this as its no-silent-drop
    /// boundary: a broadcast may deliver, skip, or backpressure a recipient,
    /// but it must account for each planned recipient deterministically.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GroupBroadcastReport {
        group: GroupName,
        policy: BroadcastBackpressurePolicy,
        recipients: Vec<GroupBroadcastRecipientReport>,
    }

    impl GroupBroadcastReport {
        /// Builds a report from an immutable recipient plan and outcome rows.
        ///
        /// # Errors
        ///
        /// Returns [`ProcessGroupError::BroadcastRecipientUnknown`] for
        /// recipients outside `plan`,
        /// [`ProcessGroupError::BroadcastRecipientDuplicate`] for duplicate
        /// rows, and [`ProcessGroupError::BroadcastRecipientMissing`] if a
        /// planned recipient has no outcome.
        pub fn from_plan<I>(
            plan: &GroupBroadcastPlan,
            outcomes: I,
        ) -> Result<Self, ProcessGroupError>
        where
            I: IntoIterator<Item = (GroupMemberId, GroupBroadcastRecipientStatus)>,
        {
            let mut statuses = BTreeMap::new();
            for (member, status) in outcomes {
                if !plan.recipients().contains(&member) {
                    return Err(ProcessGroupError::BroadcastRecipientUnknown(member));
                }
                if statuses.insert(member.clone(), status).is_some() {
                    return Err(ProcessGroupError::BroadcastRecipientDuplicate(member));
                }
            }

            let mut recipients = Vec::with_capacity(plan.len());
            for member in plan.recipients() {
                let status = statuses
                    .remove(member)
                    .ok_or_else(|| ProcessGroupError::BroadcastRecipientMissing(member.clone()))?;
                recipients.push(GroupBroadcastRecipientReport::new(member.clone(), status));
            }

            Ok(Self {
                group: plan.group().clone(),
                policy: plan.policy(),
                recipients,
            })
        }

        /// Builds an all-delivered report for the common successful path.
        #[must_use]
        pub fn all_delivered(plan: &GroupBroadcastPlan) -> Self {
            Self::uniform(plan, GroupBroadcastRecipientStatus::Delivered)
        }

        /// Builds an all-skipped report for skip-policy backpressure.
        #[must_use]
        pub fn all_skipped(plan: &GroupBroadcastPlan) -> Self {
            Self::uniform(plan, GroupBroadcastRecipientStatus::Skipped)
        }

        /// Builds an all-backpressured report for fail/wait policy boundaries.
        #[must_use]
        pub fn all_backpressured(plan: &GroupBroadcastPlan) -> Self {
            Self::uniform(plan, GroupBroadcastRecipientStatus::Backpressured)
        }

        fn uniform(plan: &GroupBroadcastPlan, status: GroupBroadcastRecipientStatus) -> Self {
            let recipients = plan
                .recipients()
                .iter()
                .cloned()
                .map(|member| GroupBroadcastRecipientReport::new(member, status))
                .collect();

            Self {
                group: plan.group().clone(),
                policy: plan.policy(),
                recipients,
            }
        }

        /// Returns the target group.
        #[must_use]
        pub fn group(&self) -> &GroupName {
            &self.group
        }

        /// Returns the broadcast backpressure policy.
        #[must_use]
        pub fn policy(&self) -> BroadcastBackpressurePolicy {
            self.policy
        }

        /// Returns per-recipient accounting rows in the plan's recipient order.
        #[must_use]
        pub fn recipients(&self) -> &[GroupBroadcastRecipientReport] {
            &self.recipients
        }

        /// Returns the number of accounted recipients.
        #[must_use]
        pub fn len(&self) -> usize {
            self.recipients.len()
        }

        /// Returns whether this report contains no recipients.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.recipients.is_empty()
        }

        /// Counts recipients with a particular delivery status.
        #[must_use]
        pub fn count_status(&self, status: GroupBroadcastRecipientStatus) -> usize {
            self.recipients
                .iter()
                .filter(|recipient| recipient.status() == status)
                .count()
        }

        /// Returns aggregate delivery accounting for this report.
        #[must_use]
        pub fn summary(&self) -> GroupBroadcastSummary {
            GroupBroadcastSummary::new(
                self.delivered_count(),
                self.skipped_count(),
                self.backpressured_count(),
            )
        }

        /// Returns the number of delivered recipients.
        #[must_use]
        pub fn delivered_count(&self) -> usize {
            self.count_status(GroupBroadcastRecipientStatus::Delivered)
        }

        /// Returns the number of skipped recipients.
        #[must_use]
        pub fn skipped_count(&self) -> usize {
            self.count_status(GroupBroadcastRecipientStatus::Skipped)
        }

        /// Returns the number of backpressured recipients.
        #[must_use]
        pub fn backpressured_count(&self) -> usize {
            self.count_status(GroupBroadcastRecipientStatus::Backpressured)
        }

        /// Returns true when every planned recipient accepted the message.
        #[must_use]
        pub fn is_all_delivered(&self) -> bool {
            self.summary().is_all_delivered()
        }
    }

    /// Executes a deterministic [`GroupBroadcastPlan`] against live member
    /// mailboxes, applying the plan's [`BroadcastBackpressurePolicy`] through
    /// the channel's two-phase `reserve`/`send` discipline.
    ///
    /// `mailboxes` maps each member to the sending half of its mailbox.
    /// Delivery follows the plan's deterministic recipient order. For each
    /// recipient the executor reserves a slot *before* committing the cloned
    /// message, so a cancelled or budget-exhausted broadcast can never leave a
    /// message half-delivered: the unused reservation is released on drop and
    /// the original message value is retained by the caller.
    ///
    /// Backpressure handling per policy:
    /// - [`BroadcastBackpressurePolicy::Wait`] awaits the reservation within
    ///   the caller's `cx` budget. If `cx` is cancelled or its budget is
    ///   exhausted while waiting, the whole broadcast resolves to
    ///   [`Outcome::Cancelled`] with the message preserved (no silent drop).
    /// - [`BroadcastBackpressurePolicy::Skip`] probes once with `try_reserve`
    ///   and records [`GroupBroadcastRecipientStatus::Skipped`] for a member
    ///   that cannot accept immediately.
    /// - [`BroadcastBackpressurePolicy::Error`] probes once and records
    ///   [`GroupBroadcastRecipientStatus::Backpressured`] for such a member, so
    ///   the caller observes `is_all_delivered() == false`.
    ///
    /// A recipient with no live mailbox (absent sender or dropped receiver) is
    /// accounted exactly like a member that cannot accept the message — never
    /// silently omitted. The returned [`GroupBroadcastReport`] therefore always
    /// accounts for every planned recipient exactly once, in plan order: the
    /// no-silent-drop boundary.
    pub async fn execute_broadcast<M>(
        cx: &Cx,
        plan: &GroupBroadcastPlan,
        message: &M,
        mailboxes: &BTreeMap<GroupMemberId, mpsc::Sender<M>>,
    ) -> Outcome<GroupBroadcastReport, ProcessGroupError>
    where
        M: Clone + Send + Sync,
    {
        let blocked = plan.blocked_recipient_status();
        let mut recipients = Vec::with_capacity(plan.len());

        for member in plan.recipients() {
            let status = match mailboxes.get(member) {
                None => blocked,
                Some(sender) => match plan.policy() {
                    BroadcastBackpressurePolicy::Wait => match sender.reserve(cx).await {
                        Ok(permit) => match permit.send(message.clone()) {
                            Outcome::Ok(()) => GroupBroadcastRecipientStatus::Delivered,
                            _ => blocked,
                        },
                        Err(mpsc::SendError::Cancelled(())) => {
                            return Outcome::Cancelled(
                                cx.cancel_reason()
                                    .unwrap_or_else(|| CancelReason::new(CancelKind::Deadline)),
                            );
                        }
                        Err(_) => blocked,
                    },
                    BroadcastBackpressurePolicy::Skip | BroadcastBackpressurePolicy::Error => {
                        match sender.try_reserve() {
                            Ok(permit) => match permit.send(message.clone()) {
                                Outcome::Ok(()) => GroupBroadcastRecipientStatus::Delivered,
                                _ => blocked,
                            },
                            Err(_) => blocked,
                        }
                    }
                },
            };
            recipients.push(GroupBroadcastRecipientReport::new(member.clone(), status));
        }

        Outcome::Ok(GroupBroadcastReport {
            group: plan.group().clone(),
            policy: plan.policy(),
            recipients,
        })
    }
}

/// Unidirectional down notifications.
///
/// Re-exports from [`crate::monitor`].
/// Ordering contract: batched down notifications are delivered by `(vt, tid)`.
pub mod monitor {
    pub use crate::monitor::{DownNotification, DownReason, MonitorRef};
}

/// Bidirectional exit signal propagation.
///
/// Re-exports from [`crate::link`].
/// Shutdown ordering contract: link exits follow `Down` and precede timeouts
/// for equal virtual timestamps.
pub mod link {
    pub use crate::link::{ExitPolicy, ExitSignal, LinkRef};
}

/// Crash pack format and artifact writing.
///
/// Re-exports from [`crate::trace::crashpack`].
/// Replay contract: crash artifacts preserve deterministic repro commands and
/// schedule certificate correlation.
pub mod crash {
    pub use crate::trace::crashpack::{
        ArtifactId, CrashPack, CrashPackConfig, CrashPackManifest, CrashPackWriteError,
        CrashPackWriter, FailureInfo, FailureOutcome, FileCrashPackWriter, MemoryCrashPackWriter,
        ReplayCommand,
    };
}

/// The SPORK prelude: import this for typical supervised application development.
///
/// ```ignore
/// use asupersync::spork::prelude::*;
/// ```
///
/// This exports the minimal set of types needed to build, run, and debug
/// a supervised application. Advanced types (evidence ledgers, obligation
/// tokens, etc.) are available through the sub-modules.
///
/// # What's Included
///
/// - **App lifecycle**: `AppSpec`, `AppHandle`, `StoppedApp`
/// - **Supervision**: `SupervisorBuilder`, `ChildSpec`, `ChildStart`,
///   `SupervisionStrategy`, `RestartConfig`, `RestartPolicy`
/// - **GenServer**: `GenServer`, `GenServerHandle`, `Reply`,
///   `SystemMsg`, `DownMsg`, `ExitMsg`, `TimeoutMsg`
/// - **Registry**: `NameRegistry`, `RegistryHandle`, `NameLease`
/// - **Process groups**: `GroupName`, `GroupMemberId`, `GroupMembership`,
///   `GroupSnapshot`, `GroupEventSubscriber`, `GroupEventBatch`,
///   `GroupMonitorDelivery`, `GroupBroadcastPlan`, `GroupBroadcastReport`,
///   `GroupBroadcastSummary`
/// - **Monitoring**: `MonitorRef`, `DownReason`, `DownNotification`
/// - **Linking**: `ExitPolicy`, `ExitSignal`, `LinkRef`
/// - **Errors**: `AppStartError`, `CallError`, `CastError`
pub mod prelude {
    // -- Application lifecycle --
    pub use crate::app::{AppHandle, AppSpec, StoppedApp};

    // -- Supervision --
    pub use crate::supervision::{
        BackoffStrategy, ChildName, ChildSpec, ChildStart, RestartConfig, RestartPolicy,
        SupervisionStrategy, SupervisorBuilder,
    };

    // -- GenServer --
    pub use crate::gen_server::{
        CallError, CastError, DownMsg, ExitMsg, GenServer, GenServerHandle, NamedGenServerStart,
        Reply, SystemMsg, TimeoutMsg, named_gen_server_start,
    };

    // -- Registry --
    pub use crate::cx::{NameLease, NameRegistry, RegistryHandle};

    // -- Process groups --
    pub use super::process_group::{
        BroadcastBackpressurePolicy, GroupBroadcastPlan, GroupBroadcastRecipientReport,
        GroupBroadcastRecipientStatus, GroupBroadcastReport, GroupBroadcastSummary, GroupEvent,
        GroupEventBatch, GroupEventCursor, GroupEventKind, GroupEventSubscriber, GroupMember,
        GroupMemberId, GroupMembership, GroupMonitorDelivery, GroupMonitorDeliveryError, GroupName,
        GroupNameError, GroupSnapshot, ProcessGroupError, ProcessGroupState, execute_broadcast,
    };

    // -- Monitor --
    pub use crate::monitor::{DownNotification, DownReason, MonitorRef};

    // -- Link --
    pub use crate::link::{ExitPolicy, ExitSignal, LinkRef};

    // -- Errors --
    pub use crate::app::{AppCompileError, AppStartError};
    pub use crate::supervision::SupervisorCompileError;

    // -- Unified error --
    pub use super::error::SporkError;
}

// =============================================================================
// Unified Error Taxonomy (bd-2x5xc)
// =============================================================================

/// Unified SPORK error taxonomy.
///
/// Rather than requiring callers to memorize domain-specific error enums
/// (`AppStartError`, `CallError`, `SupervisorCompileError`, ...),
/// `SporkError` provides a single error type that covers all SPORK operations.
///
/// # Domains
///
/// | Domain         | Covers                                      |
/// |----------------|---------------------------------------------|
/// | `Lifecycle`    | `AppStartError`, `AppStopError`             |
/// | `Compile`      | `AppCompileError`, `SupervisorCompileError` |
/// | `Spawn`        | `AppSpawnError`, `SupervisorSpawnError`      |
/// | `Call`         | `GenServerHandle::call()` failures          |
/// | `Cast`         | `GenServerHandle::cast()` failures          |
/// | `Info`         | `GenServerHandle::info()` failures          |
///
/// # Severity
///
/// All variants carry a [`SporkSeverity`] classification that is monotone:
/// a failure that was classified as `Permanent` by its origin domain will
/// never be downgraded by wrapping it in `SporkError`.
///
/// # Example
///
/// ```ignore
/// use asupersync::spork::prelude::*;
///
/// let result: Result<(), SporkError> = app.start(&mut cx).await.map_err(SporkError::from);
/// match result {
///     Err(e) if e.is_permanent() => eprintln!("fatal: {e}"),
///     Err(e) => eprintln!("transient: {e}"),
///     Ok(()) => {},
/// }
/// ```
pub mod error {
    use crate::app::{AppCompileError, AppSpawnError, AppStartError, AppStopError};
    use crate::gen_server::{CallError, CastError, InfoError};
    use crate::runtime::{RegionCreateError, SpawnError};
    use crate::supervision::{SupervisorCompileError, SupervisorSpawnError};

    /// Severity classification for SPORK errors.
    ///
    /// Monotone: wrapping an error in `SporkError` never downgrades severity.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum SporkSeverity {
        /// The operation may succeed if retried (e.g., mailbox full).
        Transient,
        /// The operation failed and should not be retried in the same way
        /// (e.g., cycle in topology, server stopped).
        Permanent,
    }

    /// Unified error type for all SPORK operations.
    #[derive(Debug)]
    pub enum SporkError {
        /// Application start failed (compile or spawn phase).
        Start(AppStartError),
        /// Application stop failed.
        Stop(AppStopError),
        /// Supervisor topology compilation failed.
        Compile(AppCompileError),
        /// Supervisor spawn failed.
        Spawn(AppSpawnError),
        /// GenServer `call()` failed.
        Call(CallError),
        /// GenServer `cast()` failed.
        Cast(CastError),
        /// GenServer `info()` send failed.
        Info(InfoError),
    }

    impl SporkError {
        fn region_create_severity(error: &RegionCreateError) -> SporkSeverity {
            match error {
                RegionCreateError::ParentAtCapacity { .. } => SporkSeverity::Transient,
                RegionCreateError::ParentNotFound(_) | RegionCreateError::ParentClosed { .. } => {
                    SporkSeverity::Permanent
                }
                RegionCreateError::ResourcePressure { .. } => SporkSeverity::Transient,
                RegionCreateError::CapabilityBudgetRefused { .. } => SporkSeverity::Permanent,
            }
        }

        fn runtime_spawn_severity(error: &SpawnError) -> SporkSeverity {
            match error {
                SpawnError::RegionAtCapacity { .. } => SporkSeverity::Transient,
                SpawnError::RuntimeUnavailable
                | SpawnError::RegionNotFound(_)
                | SpawnError::RegionClosed(_)
                | SpawnError::LocalSchedulerUnavailable
                | SpawnError::NameRegistrationFailed { .. }
                | SpawnError::AuthorizationDenied { .. } => SporkSeverity::Permanent,
            }
        }

        fn supervisor_spawn_severity(error: &SupervisorSpawnError) -> SporkSeverity {
            match error {
                SupervisorSpawnError::RegionCreate(error) => Self::region_create_severity(error),
                SupervisorSpawnError::ChildStartFailed { err, .. } => {
                    Self::runtime_spawn_severity(err)
                }
                SupervisorSpawnError::DependencyUnavailable {
                    dependency_error, ..
                } => dependency_error
                    .as_ref()
                    .map_or(SporkSeverity::Permanent, Self::runtime_spawn_severity),
            }
        }

        fn app_spawn_severity(error: &AppSpawnError) -> SporkSeverity {
            match error {
                AppSpawnError::RegionCreate(error) => Self::region_create_severity(error),
                AppSpawnError::SpawnFailed(error) => Self::supervisor_spawn_severity(error),
            }
        }

        /// Classify the severity of this error.
        ///
        /// Severity is monotone: permanent errors remain permanent.
        #[must_use]
        pub fn severity(&self) -> SporkSeverity {
            match self {
                Self::Start(AppStartError::CompileFailed(_)) | Self::Stop(_) | Self::Compile(_) => {
                    SporkSeverity::Permanent
                }
                Self::Start(AppStartError::SpawnFailed(error)) | Self::Spawn(error) => {
                    Self::app_spawn_severity(error)
                }
                // Communication errors depend on the variant
                Self::Call(e) => match e {
                    CallError::ServerStopped | CallError::NoReply | CallError::Cancelled(_) => {
                        SporkSeverity::Permanent
                    }
                },
                Self::Cast(e) => match e {
                    CastError::Full => SporkSeverity::Transient,
                    CastError::ServerStopped | CastError::Cancelled(_) => SporkSeverity::Permanent,
                },
                Self::Info(e) => match e {
                    InfoError::Full => SporkSeverity::Transient,
                    InfoError::ServerStopped | InfoError::Cancelled(_) => SporkSeverity::Permanent,
                },
            }
        }

        /// Returns `true` if this error is permanent (should not retry).
        #[must_use]
        pub fn is_permanent(&self) -> bool {
            self.severity() == SporkSeverity::Permanent
        }

        /// Returns `true` if this error is transient (may succeed on retry).
        #[must_use]
        pub fn is_transient(&self) -> bool {
            self.severity() == SporkSeverity::Transient
        }

        /// Returns a short domain tag for this error (e.g., `"start"`, `"call"`).
        #[must_use]
        pub fn domain(&self) -> &'static str {
            match self {
                Self::Start(_) => "start",
                Self::Stop(_) => "stop",
                Self::Compile(_) => "compile",
                Self::Spawn(_) => "spawn",
                Self::Call(_) => "call",
                Self::Cast(_) => "cast",
                Self::Info(_) => "info",
            }
        }
    }

    impl std::fmt::Display for SporkError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Start(e) => write!(f, "spork start: {e}"),
                Self::Stop(e) => write!(f, "spork stop: {e}"),
                Self::Compile(e) => write!(f, "spork compile: {e}"),
                Self::Spawn(e) => write!(f, "spork spawn: {e}"),
                Self::Call(e) => write!(f, "spork call: {e}"),
                Self::Cast(e) => write!(f, "spork cast: {e}"),
                Self::Info(e) => write!(f, "spork info: {e}"),
            }
        }
    }

    impl std::error::Error for SporkError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Start(e) => Some(e),
                Self::Stop(e) => Some(e),
                Self::Compile(e) => Some(e),
                Self::Spawn(e) => Some(e),
                Self::Call(e) => Some(e),
                Self::Cast(e) => Some(e),
                Self::Info(e) => Some(e),
            }
        }
    }

    // -- From conversions (zero-cost wrapping) --

    impl From<AppStartError> for SporkError {
        fn from(e: AppStartError) -> Self {
            Self::Start(e)
        }
    }

    impl From<AppStopError> for SporkError {
        fn from(e: AppStopError) -> Self {
            Self::Stop(e)
        }
    }

    impl From<AppCompileError> for SporkError {
        fn from(e: AppCompileError) -> Self {
            Self::Compile(e)
        }
    }

    impl From<AppSpawnError> for SporkError {
        fn from(e: AppSpawnError) -> Self {
            Self::Spawn(e)
        }
    }

    impl From<SupervisorCompileError> for SporkError {
        fn from(e: SupervisorCompileError) -> Self {
            Self::Compile(AppCompileError::SupervisorCompile(e))
        }
    }

    impl From<SupervisorSpawnError> for SporkError {
        fn from(e: SupervisorSpawnError) -> Self {
            Self::Spawn(AppSpawnError::SpawnFailed(e))
        }
    }

    impl From<CallError> for SporkError {
        fn from(e: CallError) -> Self {
            Self::Call(e)
        }
    }

    impl From<CastError> for SporkError {
        fn from(e: CastError) -> Self {
            Self::Cast(e)
        }
    }

    impl From<InfoError> for SporkError {
        fn from(e: InfoError) -> Self {
            Self::Info(e)
        }
    }
}

#[cfg(test)]
#[allow(clippy::no_effect_underscore_binding)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn prelude_imports_compile() {
        init_test("prelude_imports_compile");

        // Verify all prelude types are accessible
        let _ = std::any::type_name::<prelude::AppSpec>();
        let _ = std::any::type_name::<prelude::AppHandle>();
        let _ = std::any::type_name::<prelude::StoppedApp>();
        let _ = std::any::type_name::<prelude::SupervisorBuilder>();
        let _ = std::any::type_name::<prelude::ChildSpec>();
        let _ = std::any::type_name::<prelude::RestartConfig>();
        let _ = std::any::type_name::<prelude::SupervisionStrategy>();
        let _ = std::any::type_name::<prelude::RestartPolicy>();
        let _ = std::any::type_name::<prelude::BackoffStrategy>();
        let _ = std::any::type_name::<prelude::NameRegistry>();
        let _ = std::any::type_name::<prelude::RegistryHandle>();
        let _ = std::any::type_name::<prelude::NameLease>();
        let _ = std::any::type_name::<prelude::GroupName>();
        let _ = std::any::type_name::<prelude::GroupMemberId>();
        let _ = std::any::type_name::<prelude::GroupMembership>();
        let _ = std::any::type_name::<prelude::GroupSnapshot>();
        let _ = std::any::type_name::<prelude::GroupEvent>();
        let _ = std::any::type_name::<prelude::GroupEventBatch>();
        let _ = std::any::type_name::<prelude::GroupEventSubscriber>();
        let _ = std::any::type_name::<prelude::ProcessGroupState>();
        let _ = std::any::type_name::<prelude::ProcessGroupError>();
        let _ = std::any::type_name::<prelude::GroupEventCursor>();
        let _ = std::any::type_name::<prelude::GroupBroadcastPlan>();
        let _ = std::any::type_name::<prelude::GroupBroadcastReport>();
        let _ = std::any::type_name::<prelude::GroupBroadcastSummary>();
        let _ = std::any::type_name::<prelude::GroupBroadcastRecipientReport>();
        let _ = std::any::type_name::<prelude::GroupBroadcastRecipientStatus>();
        let _ = std::any::type_name::<prelude::BroadcastBackpressurePolicy>();
        let _ = std::any::type_name::<prelude::GroupMonitorDelivery>();
        let _ = std::any::type_name::<prelude::GroupMonitorDeliveryError>();
        let _ = std::any::type_name::<prelude::MonitorRef>();
        let _ = std::any::type_name::<prelude::DownReason>();
        let _ = std::any::type_name::<prelude::DownNotification>();
        let _ = std::any::type_name::<prelude::DownMsg>();
        let _ = std::any::type_name::<prelude::ExitMsg>();
        let _ = std::any::type_name::<prelude::TimeoutMsg>();
        let _ = std::any::type_name::<prelude::ExitPolicy>();
        let _ = std::any::type_name::<prelude::LinkRef>();
        let _ = std::any::type_name::<prelude::CallError>();
        let _ = std::any::type_name::<prelude::CastError>();
        let _ = std::any::type_name::<prelude::AppStartError>();
        let _ = std::any::type_name::<prelude::AppCompileError>();
        let _ = std::any::type_name::<prelude::SupervisorCompileError>();

        crate::test_complete!("prelude_imports_compile");
    }

    #[test]
    fn submodule_types_accessible() {
        init_test("submodule_types_accessible");

        // App sub-module
        let _ = std::any::type_name::<app::CompiledApp>();
        let _ = std::any::type_name::<app::AppSpawnError>();
        let _ = std::any::type_name::<app::AppStopError>();

        // Supervisor sub-module
        let _ = std::any::type_name::<supervisor::CompiledSupervisor>();
        let _ = std::any::type_name::<supervisor::EscalationPolicy>();
        let _ = std::any::type_name::<supervisor::StartTieBreak>();
        let _ = std::any::type_name::<supervisor::SupervisorHandle>();
        let _ = std::any::type_name::<supervisor::StartedChild>();
        let _ = std::any::type_name::<supervisor::SupervisorSpawnError>();

        // GenServer sub-module
        let _ = std::any::type_name::<gen_server::CastOverflowPolicy>();
        let _ = std::any::type_name::<gen_server::InfoError>();
        let _ = std::any::type_name::<gen_server::ReplyOutcome>();
        let _ = std::any::type_name::<gen_server::DownMsg>();
        let _ = std::any::type_name::<gen_server::ExitMsg>();
        let _ = std::any::type_name::<gen_server::TimeoutMsg>();

        // Registry sub-module
        let _ = std::any::type_name::<registry::NameRegistry>();
        let _ = std::any::type_name::<registry::RegistryHandle>();
        let _ = std::any::type_name::<registry::NameLease>();
        let _ = std::any::type_name::<registry::NameCollisionPolicy>();

        // Process group sub-module
        let _ = std::any::type_name::<process_group::GroupName>();
        let _ = std::any::type_name::<process_group::GroupMemberId>();
        let _ = std::any::type_name::<process_group::GroupMembership>();
        let _ = std::any::type_name::<process_group::GroupMember>();
        let _ = std::any::type_name::<process_group::GroupSnapshot>();
        let _ = std::any::type_name::<process_group::GroupEvent>();
        let _ = std::any::type_name::<process_group::GroupEventBatch>();
        let _ = std::any::type_name::<process_group::GroupEventSubscriber>();
        let _ = std::any::type_name::<process_group::GroupEventCursor>();
        let _ = std::any::type_name::<process_group::GroupBroadcastPlan>();
        let _ = std::any::type_name::<process_group::GroupBroadcastReport>();
        let _ = std::any::type_name::<process_group::GroupBroadcastSummary>();
        let _ = std::any::type_name::<process_group::GroupBroadcastRecipientReport>();
        let _ = std::any::type_name::<process_group::GroupBroadcastRecipientStatus>();
        let _ = std::any::type_name::<process_group::GroupEventKind>();
        let _ = std::any::type_name::<process_group::GroupMonitorDelivery>();
        let _ = std::any::type_name::<process_group::GroupMonitorDeliveryError>();
        let _ = std::any::type_name::<process_group::ProcessGroupState>();
        let _ = std::any::type_name::<process_group::ProcessGroupError>();
        let _ = std::any::type_name::<process_group::BroadcastBackpressurePolicy>();

        // Monitor sub-module
        let _ = std::any::type_name::<monitor::MonitorRef>();

        // Link sub-module
        let _ = std::any::type_name::<link::ExitPolicy>();

        // Crash sub-module
        let _ = std::any::type_name::<crash::CrashPack>();
        let _ = std::any::type_name::<crash::CrashPackConfig>();
        let _ = std::any::type_name::<crash::ReplayCommand>();

        crate::test_complete!("submodule_types_accessible");
    }

    #[test]
    fn supervision_strategy_constructible() {
        init_test("supervision_strategy_constructible");

        // Verify the prelude types can actually be used to construct values
        let _stop = prelude::SupervisionStrategy::Stop;
        let _restart = prelude::SupervisionStrategy::Restart(prelude::RestartConfig::default());
        let _escalate = prelude::SupervisionStrategy::Escalate;

        let _one_for_one = prelude::RestartPolicy::OneForOne;
        let _one_for_all = prelude::RestartPolicy::OneForAll;
        let _rest_for_one = prelude::RestartPolicy::RestForOne;

        let _none = prelude::BackoffStrategy::None;

        crate::test_complete!("supervision_strategy_constructible");
    }

    #[test]
    fn down_reason_constructible() {
        init_test("down_reason_constructible");

        let _normal = prelude::DownReason::Normal;
        let _error = prelude::DownReason::Error("oops".to_string());

        crate::test_complete!("down_reason_constructible");
    }

    #[test]
    fn exit_policy_constructible() {
        init_test("exit_policy_constructible");

        let _prop = prelude::ExitPolicy::Propagate;
        let _trap = prelude::ExitPolicy::Trap;
        let _ignore = prelude::ExitPolicy::Ignore;

        crate::test_complete!("exit_policy_constructible");
    }

    fn test_task_id(index: u32) -> crate::types::TaskId {
        crate::types::TaskId::from_arena(crate::util::ArenaIndex::new(index, 0))
    }

    fn test_member(node: &str, task_index: u32, sequence: u64) -> process_group::GroupMember {
        process_group::GroupMember::new(
            process_group::GroupMemberId::new(
                crate::remote::NodeId::new(node),
                test_task_id(task_index),
            ),
            crate::types::Time::from_nanos(sequence),
            sequence,
        )
    }

    #[test]
    fn process_group_name_validation_rejects_empty_and_nul() {
        init_test("process_group_name_validation_rejects_empty_and_nul");

        assert_eq!(
            process_group::GroupName::new("   ").unwrap_err(),
            process_group::GroupNameError::Empty
        );
        assert_eq!(
            process_group::GroupName::new("workers\0blue").unwrap_err(),
            process_group::GroupNameError::ContainsNul
        );
        assert_eq!(
            process_group::GroupName::new("workers").unwrap().as_str(),
            "workers"
        );

        crate::test_complete!("process_group_name_validation_rejects_empty_and_nul");
    }

    #[test]
    fn process_group_snapshot_orders_by_join_sequence_then_member_id() {
        init_test("process_group_snapshot_orders_by_join_sequence_then_member_id");

        let group = process_group::GroupName::new("workers").unwrap();
        let snapshot = process_group::GroupSnapshot::new(
            group,
            vec![
                test_member("node-b", 2, 20),
                test_member("node-c", 3, 10),
                test_member("node-a", 1, 10),
            ],
        );

        let ordered: Vec<String> = snapshot
            .member_ids()
            .map(std::string::ToString::to_string)
            .collect();
        assert_eq!(
            ordered,
            vec!["Node(node-a):T1", "Node(node-c):T3", "Node(node-b):T2"]
        );
        assert_eq!(snapshot.len(), 3);
        assert!(!snapshot.is_empty());

        crate::test_complete!("process_group_snapshot_orders_by_join_sequence_then_member_id");
    }

    #[test]
    fn process_group_event_preserves_down_reason() {
        init_test("process_group_event_preserves_down_reason");

        let group = process_group::GroupName::new("workers").unwrap();
        let member = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(7),
        );
        let event = process_group::GroupEvent::new(
            group,
            member,
            process_group::GroupEventKind::Down(monitor::DownReason::Error("boom".into())),
            crate::types::Time::from_millis(5),
        );

        assert_eq!(event.group().as_str(), "workers");
        assert_eq!(event.at(), crate::types::Time::from_millis(5));
        assert_eq!(event.sequence(), 0);
        assert!(matches!(
            event.kind(),
            process_group::GroupEventKind::Down(monitor::DownReason::Error(message))
                if message == "boom"
        ));

        crate::test_complete!("process_group_event_preserves_down_reason");
    }

    #[test]
    fn process_group_backpressure_default_waits() {
        init_test("process_group_backpressure_default_waits");

        assert_eq!(
            process_group::BroadcastBackpressurePolicy::default(),
            process_group::BroadcastBackpressurePolicy::Wait
        );

        crate::test_complete!("process_group_backpressure_default_waits");
    }

    #[test]
    fn process_group_broadcast_plan_preserves_join_order_and_policy() {
        init_test("process_group_broadcast_plan_preserves_join_order_and_policy");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        state
            .join(first, crate::types::Time::from_nanos(20))
            .unwrap();
        state
            .join(second, crate::types::Time::from_nanos(10))
            .unwrap();

        let plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Skip);
        let recipients: Vec<String> = plan
            .recipients()
            .iter()
            .map(std::string::ToString::to_string)
            .collect();

        assert_eq!(plan.group().as_str(), "workers");
        assert_eq!(
            plan.policy(),
            process_group::BroadcastBackpressurePolicy::Skip
        );
        assert_eq!(plan.len(), 2);
        assert_eq!(recipients, vec!["Node(node-b):T2", "Node(node-a):T1"]);

        crate::test_complete!("process_group_broadcast_plan_preserves_join_order_and_policy");
    }

    #[test]
    fn process_group_broadcast_plan_allows_empty_groups() {
        init_test("process_group_broadcast_plan_allows_empty_groups");

        let state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Error);

        assert!(plan.is_empty());
        assert_eq!(plan.len(), 0);
        assert_eq!(
            plan.policy(),
            process_group::BroadcastBackpressurePolicy::Error
        );

        crate::test_complete!("process_group_broadcast_plan_allows_empty_groups");
    }

    #[test]
    fn process_group_broadcast_report_preserves_plan_order_and_counts() {
        init_test("process_group_broadcast_report_preserves_plan_order_and_counts");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let third = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-c"),
            test_task_id(3),
        );
        state
            .join(first.clone(), crate::types::Time::from_nanos(20))
            .unwrap();
        state
            .join(second.clone(), crate::types::Time::from_nanos(10))
            .unwrap();
        state
            .join(third.clone(), crate::types::Time::from_nanos(30))
            .unwrap();

        let plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Skip);
        let report = process_group::GroupBroadcastReport::from_plan(
            &plan,
            vec![
                (
                    third,
                    process_group::GroupBroadcastRecipientStatus::Backpressured,
                ),
                (
                    first,
                    process_group::GroupBroadcastRecipientStatus::Delivered,
                ),
                (
                    second,
                    process_group::GroupBroadcastRecipientStatus::Skipped,
                ),
            ],
        )
        .unwrap();
        let recipients: Vec<(String, process_group::GroupBroadcastRecipientStatus)> = report
            .recipients()
            .iter()
            .map(|recipient| (recipient.member().to_string(), recipient.status()))
            .collect();

        assert_eq!(report.group().as_str(), "workers");
        assert_eq!(
            report.policy(),
            process_group::BroadcastBackpressurePolicy::Skip
        );
        assert_eq!(report.len(), 3);
        assert_eq!(
            recipients,
            vec![
                (
                    "Node(node-b):T2".to_string(),
                    process_group::GroupBroadcastRecipientStatus::Delivered,
                ),
                (
                    "Node(node-a):T1".to_string(),
                    process_group::GroupBroadcastRecipientStatus::Skipped,
                ),
                (
                    "Node(node-c):T3".to_string(),
                    process_group::GroupBroadcastRecipientStatus::Backpressured,
                ),
            ]
        );
        assert_eq!(
            report.count_status(process_group::GroupBroadcastRecipientStatus::Delivered),
            1
        );
        assert_eq!(
            report.count_status(process_group::GroupBroadcastRecipientStatus::Skipped),
            1
        );
        assert_eq!(
            report.count_status(process_group::GroupBroadcastRecipientStatus::Backpressured),
            1
        );

        crate::test_complete!("process_group_broadcast_report_preserves_plan_order_and_counts");
    }

    #[test]
    fn process_group_broadcast_summary_separates_policy_outcomes() {
        init_test("process_group_broadcast_summary_separates_policy_outcomes");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        let third = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-c"),
            test_task_id(3),
        );
        state
            .join(first.clone(), crate::types::Time::from_nanos(10))
            .unwrap();
        state
            .join(second.clone(), crate::types::Time::from_nanos(20))
            .unwrap();
        state
            .join(third.clone(), crate::types::Time::from_nanos(30))
            .unwrap();

        let plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Skip);
        let report = process_group::GroupBroadcastReport::from_plan(
            &plan,
            vec![
                (
                    first.clone(),
                    process_group::GroupBroadcastRecipientStatus::Delivered,
                ),
                (
                    second,
                    process_group::GroupBroadcastRecipientStatus::Skipped,
                ),
                (
                    third,
                    process_group::GroupBroadcastRecipientStatus::Backpressured,
                ),
            ],
        )
        .unwrap();
        let summary = report.summary();

        assert_eq!(summary, process_group::GroupBroadcastSummary::new(1, 1, 1));
        assert_eq!(summary.delivered(), 1);
        assert_eq!(summary.skipped(), 1);
        assert_eq!(summary.backpressured(), 1);
        assert_eq!(summary.total(), 3);
        assert_eq!(report.delivered_count(), 1);
        assert_eq!(report.skipped_count(), 1);
        assert_eq!(report.backpressured_count(), 1);
        assert!(!report.is_all_delivered());
        assert!(!summary.is_all_delivered());
        assert!(summary.has_skipped_recipients());
        assert!(summary.has_backpressured_recipients());

        let all_delivered = process_group::GroupBroadcastReport::all_delivered(&plan);
        assert_eq!(
            all_delivered.summary(),
            process_group::GroupBroadcastSummary::new(3, 0, 0)
        );
        assert!(all_delivered.is_all_delivered());

        crate::test_complete!("process_group_broadcast_summary_separates_policy_outcomes");
    }

    #[test]
    fn process_group_broadcast_policy_reports_account_every_recipient() {
        init_test("process_group_broadcast_policy_reports_account_every_recipient");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        state
            .join(first, crate::types::Time::from_nanos(10))
            .unwrap();
        state
            .join(second, crate::types::Time::from_nanos(20))
            .unwrap();

        let skip_plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Skip);
        let skipped = process_group::GroupBroadcastReport::all_skipped(&skip_plan);
        assert_eq!(
            skipped.policy(),
            process_group::BroadcastBackpressurePolicy::Skip
        );
        assert_eq!(skipped.len(), 2);
        assert_eq!(skipped.skipped_count(), 2);
        assert_eq!(
            skipped.summary(),
            process_group::GroupBroadcastSummary::new(0, 2, 0)
        );
        assert_eq!(
            skipped
                .recipients()
                .iter()
                .map(|recipient| (recipient.member().to_string(), recipient.status()))
                .collect::<Vec<_>>(),
            vec![
                (
                    "Node(node-a):T1".to_string(),
                    process_group::GroupBroadcastRecipientStatus::Skipped,
                ),
                (
                    "Node(node-b):T2".to_string(),
                    process_group::GroupBroadcastRecipientStatus::Skipped,
                ),
            ]
        );

        let error_plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Error);
        let backpressured = process_group::GroupBroadcastReport::all_backpressured(&error_plan);
        assert_eq!(
            backpressured.policy(),
            process_group::BroadcastBackpressurePolicy::Error
        );
        assert_eq!(backpressured.backpressured_count(), 2);
        assert_eq!(
            backpressured.summary(),
            process_group::GroupBroadcastSummary::new(0, 0, 2)
        );
        assert!(!backpressured.is_all_delivered());

        crate::test_complete!("process_group_broadcast_policy_reports_account_every_recipient");
    }

    #[test]
    fn process_group_broadcast_plan_reports_immediate_delivery_in_order() {
        init_test("process_group_broadcast_plan_reports_immediate_delivery_in_order");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        let third = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-c"),
            test_task_id(3),
        );
        state
            .join(first.clone(), crate::types::Time::from_nanos(10))
            .unwrap();
        state
            .join(second.clone(), crate::types::Time::from_nanos(20))
            .unwrap();
        state
            .join(third.clone(), crate::types::Time::from_nanos(30))
            .unwrap();

        let plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Skip);
        let mut visited = Vec::new();
        let report = plan.immediate_delivery_report(|member| {
            visited.push(member.to_string());
            member != &second
        });

        assert_eq!(
            visited,
            vec![
                "Node(node-a):T1".to_string(),
                "Node(node-b):T2".to_string(),
                "Node(node-c):T3".to_string(),
            ]
        );
        assert_eq!(
            report
                .recipients()
                .iter()
                .map(|recipient| (recipient.member().to_string(), recipient.status()))
                .collect::<Vec<_>>(),
            vec![
                (
                    first.to_string(),
                    process_group::GroupBroadcastRecipientStatus::Delivered,
                ),
                (
                    second.to_string(),
                    process_group::GroupBroadcastRecipientStatus::Skipped,
                ),
                (
                    third.to_string(),
                    process_group::GroupBroadcastRecipientStatus::Delivered,
                ),
            ]
        );
        assert_eq!(
            report.summary(),
            process_group::GroupBroadcastSummary::new(2, 1, 0)
        );

        crate::test_complete!("process_group_broadcast_plan_reports_immediate_delivery_in_order");
    }

    #[test]
    fn process_group_broadcast_plan_classifies_wait_and_error_backpressure() {
        init_test("process_group_broadcast_plan_classifies_wait_and_error_backpressure");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        state
            .join(first, crate::types::Time::from_nanos(10))
            .unwrap();
        state
            .join(second, crate::types::Time::from_nanos(20))
            .unwrap();

        let wait_plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Wait);
        let wait_report = wait_plan.immediate_delivery_report(|_| false);
        assert_eq!(
            wait_report.summary(),
            process_group::GroupBroadcastSummary::new(0, 0, 2)
        );
        assert!(wait_report.summary().has_backpressured_recipients());

        let error_plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Error);
        let error_report =
            error_plan.immediate_delivery_report(|member| member.to_string().ends_with(":T2"));
        assert_eq!(
            error_report.summary(),
            process_group::GroupBroadcastSummary::new(1, 0, 1)
        );
        assert_eq!(
            error_report
                .recipients()
                .iter()
                .map(process_group::GroupBroadcastRecipientReport::status)
                .collect::<Vec<_>>(),
            vec![
                process_group::GroupBroadcastRecipientStatus::Backpressured,
                process_group::GroupBroadcastRecipientStatus::Delivered,
            ]
        );

        crate::test_complete!(
            "process_group_broadcast_plan_classifies_wait_and_error_backpressure"
        );
    }

    #[test]
    fn process_group_broadcast_report_rejects_silent_accounting_gaps() {
        init_test("process_group_broadcast_report_rejects_silent_accounting_gaps");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        let unknown = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-c"),
            test_task_id(3),
        );
        state
            .join(first.clone(), crate::types::Time::from_nanos(10))
            .unwrap();
        state
            .join(second.clone(), crate::types::Time::from_nanos(20))
            .unwrap();
        let plan = state.broadcast_plan(process_group::BroadcastBackpressurePolicy::Error);

        assert_eq!(
            process_group::GroupBroadcastReport::from_plan(
                &plan,
                vec![(
                    first.clone(),
                    process_group::GroupBroadcastRecipientStatus::Delivered,
                )],
            )
            .unwrap_err(),
            process_group::ProcessGroupError::BroadcastRecipientMissing(second.clone())
        );
        assert_eq!(
            process_group::GroupBroadcastReport::from_plan(
                &plan,
                vec![
                    (
                        first.clone(),
                        process_group::GroupBroadcastRecipientStatus::Delivered,
                    ),
                    (
                        unknown.clone(),
                        process_group::GroupBroadcastRecipientStatus::Skipped,
                    ),
                ],
            )
            .unwrap_err(),
            process_group::ProcessGroupError::BroadcastRecipientUnknown(unknown)
        );
        assert_eq!(
            process_group::GroupBroadcastReport::from_plan(
                &plan,
                vec![
                    (
                        first.clone(),
                        process_group::GroupBroadcastRecipientStatus::Delivered,
                    ),
                    (
                        first.clone(),
                        process_group::GroupBroadcastRecipientStatus::Skipped,
                    ),
                    (
                        second,
                        process_group::GroupBroadcastRecipientStatus::Delivered,
                    ),
                ],
            )
            .unwrap_err(),
            process_group::ProcessGroupError::BroadcastRecipientDuplicate(first)
        );

        crate::test_complete!("process_group_broadcast_report_rejects_silent_accounting_gaps");
    }

    #[test]
    fn process_group_membership_handle_leaves_once() {
        init_test("process_group_membership_handle_leaves_once");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let member = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );

        let mut membership = state
            .join_membership(member.clone(), crate::types::Time::from_nanos(10))
            .unwrap();
        assert!(membership.is_active());
        assert_eq!(membership.group(), state.group());
        assert_eq!(membership.member(), &member);
        assert!(matches!(
            membership.joined_event().kind(),
            process_group::GroupEventKind::Joined
        ));
        assert!(state.contains_member(&member));

        let left = membership
            .leave(&mut state, crate::types::Time::from_nanos(20))
            .unwrap()
            .expect("first leave should emit an event");
        assert!(matches!(left.kind(), process_group::GroupEventKind::Left));
        assert_eq!(left.member(), &member);
        assert_eq!(left.sequence(), 1);
        assert!(!membership.is_active());
        assert!(!state.contains_member(&member));
        assert_eq!(state.event_log().len(), 2);

        assert_eq!(
            membership
                .leave(&mut state, crate::types::Time::from_nanos(30))
                .unwrap(),
            None
        );
        assert_eq!(state.event_log().len(), 2);

        crate::test_complete!("process_group_membership_handle_leaves_once");
    }

    #[test]
    fn process_group_membership_handle_marks_down_once() {
        init_test("process_group_membership_handle_marks_down_once");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let member = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let mut membership = state
            .join_membership(member.clone(), crate::types::Time::from_nanos(10))
            .unwrap();

        let down = membership
            .mark_down(
                &mut state,
                monitor::DownReason::Error("crashed".into()),
                crate::types::Time::from_nanos(20),
            )
            .unwrap()
            .expect("first down transition should emit an event");
        assert!(matches!(
            down.kind(),
            process_group::GroupEventKind::Down(monitor::DownReason::Error(message))
                if message == "crashed"
        ));
        assert_eq!(down.member(), &member);
        assert!(!membership.is_active());
        assert!(!state.contains_member(&member));

        assert_eq!(
            membership
                .mark_down(
                    &mut state,
                    monitor::DownReason::Normal,
                    crate::types::Time::from_nanos(30),
                )
                .unwrap(),
            None
        );
        assert_eq!(state.event_log().len(), 2);

        crate::test_complete!("process_group_membership_handle_marks_down_once");
    }

    #[test]
    fn process_group_membership_handle_rejects_wrong_group_state() {
        init_test("process_group_membership_handle_rejects_wrong_group_state");

        let mut workers = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let mut auditors = process_group::ProcessGroupState::new(
            process_group::GroupName::new("auditors").unwrap(),
        );
        let member = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let mut membership = workers
            .join_membership(member.clone(), crate::types::Time::from_nanos(10))
            .unwrap();

        assert_eq!(
            membership
                .leave(&mut auditors, crate::types::Time::from_nanos(20))
                .unwrap_err(),
            process_group::ProcessGroupError::GroupMismatch {
                handle: process_group::GroupName::new("workers").unwrap(),
                state: process_group::GroupName::new("auditors").unwrap(),
            }
        );
        assert!(membership.is_active());
        assert!(workers.contains_member(&member));
        assert!(!auditors.contains_member(&member));

        let left = membership
            .leave(&mut workers, crate::types::Time::from_nanos(30))
            .unwrap()
            .expect("membership should still be releasable from its owner group");
        assert!(matches!(left.kind(), process_group::GroupEventKind::Left));
        assert!(!membership.is_active());
        assert!(!workers.contains_member(&member));

        crate::test_complete!("process_group_membership_handle_rejects_wrong_group_state");
    }

    #[test]
    fn process_group_state_join_leave_and_down_events_are_exact() {
        init_test("process_group_state_join_leave_and_down_events_are_exact");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );

        let joined_first = state
            .join(first.clone(), crate::types::Time::from_nanos(10))
            .unwrap();
        let joined_second = state
            .join(second.clone(), crate::types::Time::from_nanos(5))
            .unwrap();
        assert!(matches!(
            joined_first.kind(),
            process_group::GroupEventKind::Joined
        ));
        assert!(matches!(
            joined_second.kind(),
            process_group::GroupEventKind::Joined
        ));
        assert_eq!(state.next_join_sequence(), 2);
        assert_eq!(state.next_event_sequence(), 2);
        assert_eq!(joined_first.sequence(), 0);
        assert_eq!(joined_second.sequence(), 1);

        let ordered: Vec<String> = state
            .snapshot()
            .member_ids()
            .map(std::string::ToString::to_string)
            .collect();
        assert_eq!(ordered, vec!["Node(node-a):T1", "Node(node-b):T2"]);

        let left = state
            .leave(&first, crate::types::Time::from_nanos(30))
            .unwrap();
        assert!(matches!(left.kind(), process_group::GroupEventKind::Left));
        assert_eq!(left.sequence(), 2);
        assert!(!state.contains_member(&first));

        let down = state
            .mark_down(
                &second,
                monitor::DownReason::Error("crashed".into()),
                crate::types::Time::from_nanos(40),
            )
            .unwrap();
        assert!(matches!(
            down.kind(),
            process_group::GroupEventKind::Down(monitor::DownReason::Error(message))
                if message == "crashed"
        ));
        assert_eq!(down.sequence(), 3);
        assert!(state.is_empty());
        assert_eq!(state.event_log().len(), 4);

        crate::test_complete!("process_group_state_join_leave_and_down_events_are_exact");
    }

    #[test]
    fn process_group_event_cursor_replays_each_transition_once() {
        init_test("process_group_event_cursor_replays_each_transition_once");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        let mut cursor = process_group::GroupEventCursor::new();

        assert!(state.events_since(&mut cursor).is_empty());
        assert_eq!(cursor.next_sequence(), 0);

        state
            .join(first.clone(), crate::types::Time::from_nanos(10))
            .unwrap();
        state
            .join(second.clone(), crate::types::Time::from_nanos(20))
            .unwrap();
        let initial_replay: Vec<(u64, String)> = state
            .events_since(&mut cursor)
            .iter()
            .map(|event| (event.sequence(), event.member().to_string()))
            .collect();
        assert_eq!(
            initial_replay,
            vec![
                (0, "Node(node-a):T1".to_string()),
                (1, "Node(node-b):T2".to_string()),
            ]
        );
        assert_eq!(cursor.next_sequence(), 2);
        assert!(state.events_since(&mut cursor).is_empty());
        assert_eq!(cursor.next_sequence(), 2);

        state
            .leave(&first, crate::types::Time::from_nanos(30))
            .unwrap();
        state
            .mark_down(
                &second,
                monitor::DownReason::Error("crashed".into()),
                crate::types::Time::from_nanos(40),
            )
            .unwrap();
        let second_replay: Vec<u64> = state
            .events_since(&mut cursor)
            .iter()
            .map(process_group::GroupEvent::sequence)
            .collect();
        assert_eq!(second_replay, vec![2, 3]);
        assert_eq!(cursor.next_sequence(), 4);

        let mut late_cursor = process_group::GroupEventCursor::from_next_sequence(3);
        let late_replay: Vec<u64> = state
            .events_since(&mut late_cursor)
            .iter()
            .map(process_group::GroupEvent::sequence)
            .collect();
        assert_eq!(late_replay, vec![3]);
        assert_eq!(late_cursor.next_sequence(), 4);

        crate::test_complete!("process_group_event_cursor_replays_each_transition_once");
    }

    #[test]
    fn process_group_event_batch_is_owned_and_cursor_safe() {
        init_test("process_group_event_batch_is_owned_and_cursor_safe");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        let cursor = process_group::GroupEventCursor::new();

        let empty = state.event_batch(cursor);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.next_cursor().next_sequence(), 0);
        assert_eq!(cursor.next_sequence(), 0);

        state
            .join(first.clone(), crate::types::Time::from_nanos(10))
            .unwrap();
        state
            .join(second.clone(), crate::types::Time::from_nanos(20))
            .unwrap();

        let batch = state.event_batch(cursor);
        assert_eq!(cursor.next_sequence(), 0);
        assert_eq!(batch.next_cursor().next_sequence(), 2);
        assert_eq!(batch.len(), 2);
        assert_eq!(
            batch
                .events()
                .iter()
                .map(process_group::GroupEvent::sequence)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );

        let next_cursor = batch.next_cursor();
        let owned_events = batch.into_events();
        drop(state);

        assert_eq!(
            owned_events
                .iter()
                .map(|event| event.member().to_string())
                .collect::<Vec<_>>(),
            vec!["Node(node-a):T1".to_string(), "Node(node-b):T2".to_string()]
        );
        assert_eq!(next_cursor.next_sequence(), 2);

        crate::test_complete!("process_group_event_batch_is_owned_and_cursor_safe");
    }

    #[test]
    fn process_group_event_subscriber_commits_batches_monotonically() {
        init_test("process_group_event_subscriber_commits_batches_monotonically");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        let mut subscriber = process_group::GroupEventSubscriber::new();

        state
            .join(first, crate::types::Time::from_nanos(10))
            .unwrap();
        let first_batch = subscriber.pending_batch(&state);
        assert_eq!(subscriber.cursor().next_sequence(), 0);
        assert_eq!(first_batch.len(), 1);
        assert_eq!(first_batch.next_cursor().next_sequence(), 1);

        assert!(subscriber.commit(&first_batch));
        assert_eq!(subscriber.cursor().next_sequence(), 1);
        assert!(!subscriber.commit(&first_batch));
        assert_eq!(subscriber.cursor().next_sequence(), 1);

        state
            .join(second.clone(), crate::types::Time::from_nanos(20))
            .unwrap();
        let second_batch = subscriber.pending_batch(&state);
        assert_eq!(second_batch.len(), 1);
        assert_eq!(second_batch.events()[0].member(), &second);
        assert_eq!(second_batch.next_cursor().next_sequence(), 2);
        assert!(subscriber.commit(&second_batch));
        assert_eq!(subscriber.cursor().next_sequence(), 2);

        let restored = process_group::GroupEventSubscriber::from_cursor(
            process_group::GroupEventCursor::new(),
        );
        let replay = restored.pending_batch(&state);
        assert_eq!(replay.len(), 2);
        assert_eq!(restored.cursor().next_sequence(), 0);

        crate::test_complete!("process_group_event_subscriber_commits_batches_monotonically");
    }

    #[test]
    fn process_group_event_subscriber_delivers_after_broadcast_commit() {
        init_test("process_group_event_subscriber_delivers_after_broadcast_commit");

        let cx = crate::Cx::for_testing();
        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let first = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let second = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-b"),
            test_task_id(2),
        );
        let (tx, mut rx) = crate::channel::broadcast::channel(4);
        let mut subscriber = process_group::GroupEventSubscriber::new();

        state
            .join(first.clone(), crate::types::Time::from_nanos(10))
            .unwrap();
        state
            .join(second.clone(), crate::types::Time::from_nanos(20))
            .unwrap();

        let delivery = subscriber.deliver_pending_to(&cx, &state, &tx).unwrap();
        assert_eq!(delivery.delivered_receiver_count(), 1);
        assert!(delivery.cursor_advanced());
        assert_eq!(delivery.batch().len(), 2);
        assert_eq!(subscriber.cursor().next_sequence(), 2);

        let received = rx.try_recv().unwrap();
        assert_eq!(
            received
                .events()
                .iter()
                .map(|event| (event.sequence(), event.member().to_string()))
                .collect::<Vec<_>>(),
            vec![
                (0, "Node(node-a):T1".to_string()),
                (1, "Node(node-b):T2".to_string()),
            ]
        );

        let empty_delivery = subscriber.deliver_pending_to(&cx, &state, &tx).unwrap();
        assert!(empty_delivery.batch().is_empty());
        assert_eq!(empty_delivery.delivered_receiver_count(), 0);
        assert!(!empty_delivery.cursor_advanced());
        assert!(matches!(
            rx.try_recv(),
            Err(crate::channel::broadcast::TryRecvError::Empty)
        ));

        crate::test_complete!("process_group_event_subscriber_delivers_after_broadcast_commit");
    }

    #[test]
    fn process_group_event_subscriber_keeps_cursor_when_monitor_closed() {
        init_test("process_group_event_subscriber_keeps_cursor_when_monitor_closed");

        let cx = crate::Cx::for_testing();
        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let member = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let (tx, rx) = crate::channel::broadcast::channel(4);
        drop(rx);
        let mut subscriber = process_group::GroupEventSubscriber::new();

        state
            .join(member, crate::types::Time::from_nanos(10))
            .unwrap();

        let err = subscriber
            .deliver_pending_to(&cx, &state, &tx)
            .expect_err("closed monitor should not advance cursor");
        assert!(matches!(
            &err,
            process_group::GroupMonitorDeliveryError::Closed(_)
        ));
        assert_eq!(err.batch().len(), 1);
        assert_eq!(subscriber.cursor().next_sequence(), 0);

        crate::test_complete!("process_group_event_subscriber_keeps_cursor_when_monitor_closed");
    }

    #[test]
    fn process_group_event_subscriber_keeps_cursor_when_send_cancelled() {
        init_test("process_group_event_subscriber_keeps_cursor_when_send_cancelled");

        let cx = crate::Cx::for_testing();
        cx.cancel_with(
            crate::types::CancelKind::User,
            Some("process group monitor delivery test"),
        );
        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let member = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        let (tx, mut rx) = crate::channel::broadcast::channel(4);
        let mut subscriber = process_group::GroupEventSubscriber::new();

        state
            .join(member, crate::types::Time::from_nanos(10))
            .unwrap();

        let err = subscriber
            .deliver_pending_to(&cx, &state, &tx)
            .expect_err("cancelled monitor send should not advance cursor");
        assert!(matches!(
            &err,
            process_group::GroupMonitorDeliveryError::Cancelled(_)
        ));
        assert_eq!(err.batch().len(), 1);
        assert_eq!(subscriber.cursor().next_sequence(), 0);
        assert!(matches!(
            rx.try_recv(),
            Err(crate::channel::broadcast::TryRecvError::Empty)
        ));

        crate::test_complete!("process_group_event_subscriber_keeps_cursor_when_send_cancelled");
    }

    #[test]
    fn process_group_state_rejects_duplicate_and_missing_members() {
        init_test("process_group_state_rejects_duplicate_and_missing_members");

        let mut state = process_group::ProcessGroupState::new(
            process_group::GroupName::new("workers").unwrap(),
        );
        let member = process_group::GroupMemberId::new(
            crate::remote::NodeId::new("node-a"),
            test_task_id(1),
        );
        state
            .join(member.clone(), crate::types::Time::from_nanos(1))
            .unwrap();

        assert_eq!(
            state
                .join(member.clone(), crate::types::Time::from_nanos(2))
                .unwrap_err(),
            process_group::ProcessGroupError::DuplicateMember(member.clone())
        );
        state
            .leave(&member, crate::types::Time::from_nanos(3))
            .unwrap();
        assert_eq!(
            state
                .mark_down(
                    &member,
                    monitor::DownReason::Normal,
                    crate::types::Time::from_nanos(4)
                )
                .unwrap_err(),
            process_group::ProcessGroupError::MemberNotFound(member)
        );

        crate::test_complete!("process_group_state_rejects_duplicate_and_missing_members");
    }

    // =====================================================================
    // Unified Error Taxonomy tests (bd-2x5xc)
    // =====================================================================

    mod error_taxonomy {
        use crate::app::{AppCompileError, AppSpawnError, AppStartError, AppStopError};
        use crate::gen_server::{CallError, CastError, InfoError};
        use crate::runtime::{RegionCreateError, SpawnError};
        use crate::spork::error::{SporkError, SporkSeverity};
        use crate::supervision::{SupervisorCompileError, SupervisorSpawnError};
        use crate::types::RegionId;
        use crate::util::arena::ArenaIndex;

        fn test_region_id() -> RegionId {
            RegionId::from_arena(ArenaIndex::new(0, 1))
        }

        fn parent_capacity_error(region: RegionId) -> RegionCreateError {
            RegionCreateError::ParentAtCapacity {
                region,
                limit: 1,
                live: 1,
            }
        }

        fn region_task_capacity_error(region: RegionId) -> SpawnError {
            SpawnError::RegionAtCapacity {
                region,
                limit: 1,
                live: 1,
            }
        }

        fn init_test(name: &str) {
            crate::test_utils::init_test_logging();
            crate::test_phase!(name);
        }

        // -- From conversions --

        #[test]
        fn from_call_error() {
            init_test("from_call_error");
            let e: SporkError = CallError::ServerStopped.into();
            assert!(matches!(e, SporkError::Call(CallError::ServerStopped)));
            crate::test_complete!("from_call_error");
        }

        #[test]
        fn from_cast_error() {
            init_test("from_cast_error");
            let e: SporkError = CastError::Full.into();
            assert!(matches!(e, SporkError::Cast(CastError::Full)));
            crate::test_complete!("from_cast_error");
        }

        #[test]
        fn from_info_error() {
            init_test("from_info_error");
            let e: SporkError = InfoError::ServerStopped.into();
            assert!(matches!(e, SporkError::Info(InfoError::ServerStopped)));
            crate::test_complete!("from_info_error");
        }

        #[test]
        fn from_app_compile_error() {
            init_test("from_app_compile_error");
            let inner = AppCompileError::SupervisorCompile(
                SupervisorCompileError::DuplicateChildName("dup".into()),
            );
            let e: SporkError = inner.into();
            assert!(matches!(e, SporkError::Compile(_)));
            crate::test_complete!("from_app_compile_error");
        }

        #[test]
        fn from_supervisor_compile_error() {
            init_test("from_supervisor_compile_error");
            let inner = SupervisorCompileError::DuplicateChildName("x".into());
            let e: SporkError = inner.into();
            // Should wrap via AppCompileError::SupervisorCompile
            assert!(matches!(
                e,
                SporkError::Compile(AppCompileError::SupervisorCompile(_))
            ));
            crate::test_complete!("from_supervisor_compile_error");
        }

        #[test]
        fn from_app_start_error() {
            init_test("from_app_start_error");
            let inner = AppStartError::CompileFailed(AppCompileError::SupervisorCompile(
                SupervisorCompileError::DuplicateChildName("a".into()),
            ));
            let e: SporkError = inner.into();
            assert!(matches!(e, SporkError::Start(_)));
            crate::test_complete!("from_app_start_error");
        }

        #[test]
        fn from_app_stop_error() {
            init_test("from_app_stop_error");
            let inner = AppStopError::RegionNotFound(test_region_id());
            let e: SporkError = inner.into();
            assert!(matches!(e, SporkError::Stop(_)));
            crate::test_complete!("from_app_stop_error");
        }

        // -- Severity classification --

        #[test]
        fn severity_permanent_lifecycle() {
            init_test("severity_permanent_lifecycle");
            let e = SporkError::Start(AppStartError::CompileFailed(
                AppCompileError::SupervisorCompile(SupervisorCompileError::DuplicateChildName(
                    "a".into(),
                )),
            ));
            assert_eq!(e.severity(), SporkSeverity::Permanent);
            assert!(e.is_permanent());
            assert!(!e.is_transient());
            crate::test_complete!("severity_permanent_lifecycle");
        }

        #[test]
        fn severity_permanent_call() {
            init_test("severity_permanent_call");
            let e = SporkError::Call(CallError::ServerStopped);
            assert_eq!(e.severity(), SporkSeverity::Permanent);
            assert!(e.is_permanent());
            crate::test_complete!("severity_permanent_call");
        }

        #[test]
        fn severity_transient_cast_full() {
            init_test("severity_transient_cast_full");
            let e = SporkError::Cast(CastError::Full);
            assert_eq!(e.severity(), SporkSeverity::Transient);
            assert!(e.is_transient());
            assert!(!e.is_permanent());
            crate::test_complete!("severity_transient_cast_full");
        }

        #[test]
        fn severity_transient_info_full() {
            init_test("severity_transient_info_full");
            let e = SporkError::Info(InfoError::Full);
            assert_eq!(e.severity(), SporkSeverity::Transient);
            assert!(e.is_transient());
            crate::test_complete!("severity_transient_info_full");
        }

        #[test]
        fn severity_permanent_cast_stopped() {
            init_test("severity_permanent_cast_stopped");
            let e = SporkError::Cast(CastError::ServerStopped);
            assert_eq!(e.severity(), SporkSeverity::Permanent);
            crate::test_complete!("severity_permanent_cast_stopped");
        }

        #[test]
        fn severity_transient_spawn_parent_capacity() {
            init_test("severity_transient_spawn_parent_capacity");
            let region = test_region_id();
            let e = SporkError::Spawn(AppSpawnError::RegionCreate(parent_capacity_error(region)));
            assert_eq!(e.severity(), SporkSeverity::Transient);
            assert!(e.is_transient());
            crate::test_complete!("severity_transient_spawn_parent_capacity");
        }

        #[test]
        fn severity_transient_start_parent_capacity() {
            init_test("severity_transient_start_parent_capacity");
            let region = test_region_id();
            let e = SporkError::Start(AppStartError::SpawnFailed(AppSpawnError::RegionCreate(
                parent_capacity_error(region),
            )));
            assert_eq!(e.severity(), SporkSeverity::Transient);
            assert!(e.is_transient());
            crate::test_complete!("severity_transient_start_parent_capacity");
        }

        #[test]
        fn severity_transient_spawn_child_start_region_capacity() {
            init_test("severity_transient_spawn_child_start_region_capacity");
            let region = test_region_id();
            let e = SporkError::Spawn(AppSpawnError::SpawnFailed(
                SupervisorSpawnError::ChildStartFailed {
                    child: "worker".into(),
                    err: region_task_capacity_error(region),
                    region,
                },
            ));
            assert_eq!(e.severity(), SporkSeverity::Transient);
            assert!(e.is_transient());
            crate::test_complete!("severity_transient_spawn_child_start_region_capacity");
        }

        #[test]
        fn severity_transient_spawn_dependency_unavailable_preserves_root_cause() {
            init_test("severity_transient_spawn_dependency_unavailable_preserves_root_cause");
            let region = test_region_id();
            let e = SporkError::Spawn(AppSpawnError::SpawnFailed(
                SupervisorSpawnError::DependencyUnavailable {
                    child: "api".into(),
                    dependency: "db".into(),
                    dependency_error: Some(region_task_capacity_error(region)),
                    region,
                },
            ));
            assert_eq!(e.severity(), SporkSeverity::Transient);
            assert!(e.is_transient());
            crate::test_complete!(
                "severity_transient_spawn_dependency_unavailable_preserves_root_cause"
            );
        }

        // -- Domain tags --

        #[test]
        fn domain_tags() {
            init_test("domain_tags");
            assert_eq!(
                SporkError::Start(AppStartError::CompileFailed(
                    AppCompileError::SupervisorCompile(SupervisorCompileError::DuplicateChildName(
                        "a".into()
                    ))
                ))
                .domain(),
                "start"
            );
            assert_eq!(
                SporkError::Stop(AppStopError::RegionNotFound(test_region_id())).domain(),
                "stop"
            );
            assert_eq!(
                SporkError::Compile(AppCompileError::SupervisorCompile(
                    SupervisorCompileError::DuplicateChildName("a".into())
                ))
                .domain(),
                "compile"
            );
            assert_eq!(SporkError::Call(CallError::ServerStopped).domain(), "call");
            assert_eq!(SporkError::Cast(CastError::Full).domain(), "cast");
            assert_eq!(SporkError::Info(InfoError::ServerStopped).domain(), "info");
            crate::test_complete!("domain_tags");
        }

        // -- Display --

        #[test]
        fn display_format() {
            init_test("display_format");
            let e = SporkError::Call(CallError::ServerStopped);
            let s = format!("{e}");
            assert!(s.starts_with("spork call:"), "got: {s}");

            let e2 = SporkError::Cast(CastError::Full);
            let s2 = format!("{e2}");
            assert!(s2.starts_with("spork cast:"), "got: {s2}");
            crate::test_complete!("display_format");
        }

        // -- Error source chain --

        #[test]
        fn error_source_chain() {
            init_test("error_source_chain");
            let e = SporkError::Call(CallError::NoReply);
            let source = std::error::Error::source(&e);
            assert!(source.is_some(), "SporkError should have a source");
            crate::test_complete!("error_source_chain");
        }

        // -- SporkSeverity ordering --

        #[test]
        fn severity_ordering() {
            init_test("severity_ordering");
            assert!(SporkSeverity::Transient < SporkSeverity::Permanent);
            crate::test_complete!("severity_ordering");
        }
    }
}
