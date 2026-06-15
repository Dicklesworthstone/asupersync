//! Membership-handle lifecycle proofs for `spork::process_group`
//! (bead asupersync-dist-otp-completeness-8y37kz.1).
//!
//! AC1 of the bead is the join/leave/death matrix: a member that leaves or goes
//! down has its membership revoked, the matching down/left event delivered, and
//! its lease obligation resolved exactly once. The async runtime that owns the
//! real registry lease is not yet wired, but the synchronous value layer ships
//! the obligation-shaped stand-in for it: [`GroupMembership`], minted by
//! [`ProcessGroupState::join_membership`].
//!
//! `GroupMembership` is the value-layer model of the lease obligation. It is a
//! non-`Clone` one-shot handle: resolving it through `leave` or `mark_down`
//! discharges it exactly once (later attempts are `Ok(None)` no-ops), revokes
//! membership from the state, and emits the terminal `Left`/`Down` event. A
//! handle is also fail-closed against the wrong group: applying it to a foreign
//! state yields [`ProcessGroupError::GroupMismatch`] WITHOUT consuming the
//! handle, so the obligation it carries is never silently lost.
//!
//! These three handle surfaces — `join_membership`, `GroupMembership`
//! (leave/mark_down/is_active/joined_event), and `GroupMismatch` — had no
//! integration coverage in the existing process-group test files. This is an
//! oracle-free integration test on the public prelude surface; it does not touch
//! `src/spork.rs`. The remaining runtime-wiring ACs (lease-backed async join,
//! real broadcast/backpressure execution, the oracle-checked death matrix over
//! the live runtime) remain open.

use asupersync::remote::NodeId;
use asupersync::spork::prelude::{
    DownReason, GroupEvent, GroupEventKind, GroupMemberId, GroupMembership, GroupName,
    ProcessGroupError, ProcessGroupState,
};
use asupersync::types::{TaskId, Time};

/// Deterministic member id from a node label and task index.
fn member(node: &str, task_index: u32) -> GroupMemberId {
    GroupMemberId::new(NodeId::new(node), TaskId::new_for_test(task_index, 0))
}

fn group(name: &str) -> ProcessGroupState {
    ProcessGroupState::new(GroupName::new(name).expect("valid group name"))
}

/// How a membership handle is resolved in the join/leave/death matrix.
#[derive(Clone)]
enum Resolution {
    /// Explicit cooperative leave.
    Leave,
    /// Monitor/region-driven down (models a panicking/exiting member task).
    Down(DownReason),
}

impl Resolution {
    fn resolve(
        &self,
        handle: &mut GroupMembership,
        state: &mut ProcessGroupState,
        at: Time,
    ) -> Result<Option<GroupEvent>, ProcessGroupError> {
        match self {
            Resolution::Leave => handle.leave(state, at),
            Resolution::Down(reason) => handle.mark_down(state, reason.clone(), at),
        }
    }

    /// Whether the terminal event for this resolution matches `kind`.
    fn matches_terminal(&self, kind: &GroupEventKind) -> bool {
        match self {
            Resolution::Leave => matches!(kind, GroupEventKind::Left),
            Resolution::Down(_) => matches!(kind, GroupEventKind::Down(_)),
        }
    }
}

// -- minting: join_membership ------------------------------------------------

#[test]
fn join_membership_mints_active_handle_linked_to_joined_event() {
    let mut state = group("workers");
    let m = member("node-a", 1);

    let handle = state
        .join_membership(m.clone(), Time::from_nanos(10))
        .expect("join_membership");

    // The handle is live and identifies its own group + member.
    assert!(handle.is_active(), "fresh handle must be active");
    assert_eq!(handle.group(), state.group());
    assert_eq!(handle.member(), &m);

    // The handle carries the exact join event that minted it: the first event in
    // the log, sequence 0, kind Joined, for this member and group.
    let joined = handle.joined_event();
    assert!(matches!(joined.kind(), GroupEventKind::Joined));
    assert_eq!(joined.member(), &m);
    assert_eq!(joined.group(), state.group());
    assert_eq!(joined.sequence(), 0, "first transition is event sequence 0");
    assert_eq!(joined.at(), Time::from_nanos(10));
    assert_eq!(
        joined,
        &state.event_log()[0],
        "handle's joined_event equals the logged join event",
    );

    // State reflects the join exactly once.
    assert_eq!(state.len(), 1);
    assert!(state.contains_member(&m));
    assert_eq!(state.event_log().len(), 1);
}

// -- the join/leave/death matrix ---------------------------------------------

#[test]
fn membership_handle_resolution_matrix_revokes_and_resolves_exactly_once() {
    let resolutions = [
        Resolution::Leave,
        Resolution::Down(DownReason::Normal),
        Resolution::Down(DownReason::Error("member task panicked".into())),
    ];

    for (i, res) in resolutions.iter().enumerate() {
        // Fresh group per matrix cell so cells are independent.
        let mut state = group("matrix");
        let m = member("node", i as u32);

        let mut handle = state
            .join_membership(m.clone(), Time::from_nanos(0))
            .expect("join_membership");
        assert!(handle.is_active());
        assert!(state.contains_member(&m));

        // Resolve the handle once: returns Some(terminal event), revokes
        // membership, deactivates the handle.
        let event = res
            .resolve(&mut handle, &mut state, Time::from_nanos(1))
            .expect("resolution must succeed")
            .expect("first resolution yields the terminal event");

        assert!(
            res.matches_terminal(event.kind()),
            "terminal event kind must match the resolution path",
        );
        assert_eq!(event.member(), &m);
        assert_eq!(event.group(), state.group());
        assert_eq!(
            event.sequence(),
            1,
            "terminal event follows the join (seq 1)"
        );

        // Membership is revoked structurally — the member no longer lingers.
        assert!(!handle.is_active(), "resolved handle must be inactive");
        assert!(
            !state.contains_member(&m),
            "resolved member must be revoked (no stale member leak)",
        );
        assert_eq!(state.len(), 0);

        // Obligation resolved exactly once: every later resolution attempt — of
        // EITHER kind — is an idempotent no-op (Ok(None)) and emits no event.
        assert_eq!(
            handle
                .leave(&mut state, Time::from_nanos(2))
                .expect("idempotent leave"),
            None,
            "leave after resolution is a no-op",
        );
        assert_eq!(
            handle
                .mark_down(&mut state, DownReason::Normal, Time::from_nanos(3))
                .expect("idempotent down"),
            None,
            "mark_down after resolution is a no-op",
        );

        // Exactly two events recorded: the join and its single terminal event.
        assert_eq!(
            state.event_log().len(),
            2,
            "exactly one join and one terminal event, no duplicates",
        );
        assert!(matches!(
            state.event_log()[0].kind(),
            GroupEventKind::Joined
        ));
        assert!(res.matches_terminal(state.event_log()[1].kind()));
    }
}

// -- fail-closed: GroupMismatch does not consume the obligation ---------------

#[test]
fn handle_used_with_wrong_group_fails_closed_without_consuming_obligation() {
    let mut alpha = group("alpha");
    let mut beta = group("beta");

    let m = member("node", 7);
    // Give beta an unrelated member so we can prove it is left untouched.
    let beta_member = member("node", 99);
    beta.join(beta_member.clone(), Time::from_nanos(0))
        .expect("seed beta");

    let mut handle = alpha
        .join_membership(m.clone(), Time::from_nanos(1))
        .expect("join_membership on alpha");

    // leave() against the wrong group is rejected with a precise mismatch error
    // that names both the handle's group and the target state's group.
    let err = handle
        .leave(&mut beta, Time::from_nanos(2))
        .expect_err("cross-group leave must be rejected");
    assert!(
        matches!(
            &err,
            ProcessGroupError::GroupMismatch { handle, state }
                if handle.as_str() == "alpha" && state.as_str() == "beta"
        ),
        "expected GroupMismatch{{handle: alpha, state: beta}}, got {err:?}",
    );

    // mark_down() against the wrong group is rejected identically.
    let err = handle
        .mark_down(&mut beta, DownReason::Normal, Time::from_nanos(3))
        .expect_err("cross-group mark_down must be rejected");
    assert!(matches!(err, ProcessGroupError::GroupMismatch { .. }));

    // The fail-closed guard fires BEFORE consuming the handle: it stays active
    // and beta is wholly unchanged (no spurious revoke / no leaked event).
    assert!(
        handle.is_active(),
        "rejected cross-group call must not consume handle"
    );
    assert!(beta.contains_member(&beta_member), "beta membership intact");
    assert_eq!(beta.len(), 1, "beta size unchanged");
    assert_eq!(beta.event_log().len(), 1, "beta emitted no extra events");

    // And the obligation is still dischargeable against its OWN group: the
    // earlier rejections did not silently lose it.
    let event = handle
        .leave(&mut alpha, Time::from_nanos(4))
        .expect("own-group leave succeeds")
        .expect("yields terminal event");
    assert!(matches!(event.kind(), GroupEventKind::Left));
    assert!(!handle.is_active());
    assert!(!alpha.contains_member(&m), "alpha member revoked");
    assert_eq!(alpha.len(), 0);
}

// -- structural revocation enables clean rejoin ------------------------------

#[test]
fn member_can_rejoin_after_down_with_a_fresh_independent_handle() {
    let mut state = group("rejoin");
    let m = member("node", 3);

    let mut first = state
        .join_membership(m.clone(), Time::from_nanos(0))
        .expect("first join");
    let first_join_seq = first.joined_event().sequence();

    // The member task "panics" -> down -> membership revoked structurally.
    first
        .mark_down(
            &mut state,
            DownReason::Error("crash".into()),
            Time::from_nanos(1),
        )
        .expect("down")
        .expect("terminal event");
    assert!(!first.is_active());
    assert!(!state.contains_member(&m));

    // Because the slot was freed structurally, the same member id can rejoin and
    // receives a brand-new, independent handle with a strictly later join event.
    let second = state
        .join_membership(m.clone(), Time::from_nanos(2))
        .expect("rejoin");
    assert!(second.is_active(), "rejoined handle is active");
    assert!(!first.is_active(), "the old handle stays resolved");
    assert!(
        second.joined_event().sequence() > first_join_seq,
        "rejoin's join event is strictly later than the original join",
    );
    assert!(matches!(
        second.joined_event().kind(),
        GroupEventKind::Joined
    ));
    assert_eq!(second.member(), &m);
    assert!(
        state.contains_member(&m),
        "member is live again after rejoin"
    );
    assert_eq!(state.len(), 1);

    // Event story is exactly: join, down, join — three contiguous transitions.
    let log = state.event_log();
    assert_eq!(log.len(), 3);
    assert!(matches!(log[0].kind(), GroupEventKind::Joined));
    assert!(matches!(
        log[1].kind(),
        GroupEventKind::Down(DownReason::Error(_))
    ));
    assert!(matches!(log[2].kind(), GroupEventKind::Joined));
    for (idx, ev) in log.iter().enumerate() {
        assert_eq!(ev.sequence(), idx as u64, "event sequence is contiguous");
    }
}
