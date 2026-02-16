//! Integration tests for session-typed obligation protocols (bd-3u5d3.6).
//!
//! Tests the typestate-encoded obligation protocols (SendPermit/Ack,
//! Lease/Release, Reserve/Commit) for compile-time safety, runtime
//! correctness, delegation, and backward compatibility.

mod common;

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::obligation::session_types::{
    Branch, End, Initiator, Select, Selected, Send, SessionProof, delegation, lease, send_permit,
    two_phase,
};
use asupersync::record::ObligationKind;
use common::{init_test_logging, test_proptest_config};
use proptest::prelude::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Helpers
// ============================================================================

/// Run a SendPermit commit (happy path) and return the proofs.
fn run_send_permit_commit(channel_id: u64) -> (SessionProof, SessionProof) {
    let (sender, receiver) = send_permit::new_session::<u64>(channel_id);

    // Sender: Reserve → select Send → send value → End.
    let sender = sender.send(send_permit::ReserveMsg);
    let sender = sender.select_left();
    let sender = sender.send(42u64);
    let sender_proof = sender.close();

    // Receiver: recv Reserve → offer Left → recv value → End.
    let (_, receiver) = receiver.recv(send_permit::ReserveMsg);
    let receiver_proof = match receiver.offer(Branch::Left) {
        Selected::Left(ch) => {
            let (val, ch) = ch.recv(42u64);
            assert_eq!(val, 42);
            ch.close()
        }
        Selected::Right(_) => panic!("expected Left (Send) branch"),
    };

    (sender_proof, receiver_proof)
}

/// Run a SendPermit abort path and return proofs.
fn run_send_permit_abort(channel_id: u64) -> (SessionProof, SessionProof) {
    let (sender, receiver) = send_permit::new_session::<String>(channel_id);

    let sender = sender.send(send_permit::ReserveMsg);
    let sender = sender.select_right();
    let sender = sender.send(send_permit::AbortMsg);
    let sender_proof = sender.close();

    let (_, receiver) = receiver.recv(send_permit::ReserveMsg);
    let receiver_proof = match receiver.offer(Branch::Right) {
        Selected::Right(ch) => {
            let (_, ch) = ch.recv(send_permit::AbortMsg);
            ch.close()
        }
        Selected::Left(_) => panic!("expected Right (Abort) branch"),
    };

    (sender_proof, receiver_proof)
}

/// Run a complete Lease protocol: Acquire → Release, returning proofs.
fn run_lease_simple(channel_id: u64) -> (SessionProof, SessionProof) {
    let (holder, resource) = lease::new_session(channel_id);

    let holder = holder.send(lease::AcquireMsg);
    let holder = holder.select_right(); // Release
    let holder = holder.send(lease::ReleaseMsg);
    let holder_proof = holder.close();

    let (_, resource) = resource.recv(lease::AcquireMsg);
    let resource_proof = match resource.offer(Branch::Right) {
        Selected::Right(ch) => {
            let (_, ch) = ch.recv(lease::ReleaseMsg);
            ch.close()
        }
        Selected::Left(_) => panic!("expected Release"),
    };

    (holder_proof, resource_proof)
}

/// Run a Lease with N renewals then release, returning holder proof.
fn run_lease_with_renewals(channel_id: u64, renewals: u32) -> SessionProof {
    let (holder, resource) = lease::new_session(channel_id);

    // Acquire
    let holder = holder.send(lease::AcquireMsg);
    let (_, resource) = resource.recv(lease::AcquireMsg);

    // First loop iteration: renew or release
    if renewals == 0 {
        // No renewals — release immediately
        let holder = holder.select_right();
        let holder = holder.send(lease::ReleaseMsg);
        match resource.offer(Branch::Right) {
            Selected::Right(ch) => {
                let (_, ch) = ch.recv(lease::ReleaseMsg);
                ch.close();
            }
            Selected::Left(_) => panic!("expected Release"),
        }
        return holder.close();
    }

    // Renew in first loop iteration
    let holder = holder.select_left();
    let holder = holder.send(lease::RenewMsg);
    let holder_proof_renew = holder.close();
    _ = holder_proof_renew; // consume proof

    match resource.offer(Branch::Left) {
        Selected::Left(ch) => {
            let (_, ch) = ch.recv(lease::RenewMsg);
            ch.close();
        }
        Selected::Right(_) => panic!("expected Renew"),
    }

    // Remaining renewal loops
    for _ in 1..renewals {
        let (h, r) = lease::renew_loop(channel_id);
        let h = h.select_left();
        let h = h.send(lease::RenewMsg);
        h.close();
        match r.offer(Branch::Left) {
            Selected::Left(ch) => {
                let (_, ch) = ch.recv(lease::RenewMsg);
                ch.close();
            }
            Selected::Right(_) => panic!("expected Renew"),
        }
    }

    // Final loop: release
    let (h, r) = lease::renew_loop(channel_id);
    let h = h.select_right();
    let h = h.send(lease::ReleaseMsg);
    let final_proof = h.close();
    match r.offer(Branch::Right) {
        Selected::Right(ch) => {
            let (_, ch) = ch.recv(lease::ReleaseMsg);
            ch.close();
        }
        Selected::Left(_) => panic!("expected final Release"),
    }

    final_proof
}

/// Run a two-phase commit path and return proofs.
fn run_two_phase_commit(channel_id: u64, kind: ObligationKind) -> (SessionProof, SessionProof) {
    let (initiator, executor) = two_phase::new_session(channel_id, kind);

    let reserve = two_phase::ReserveMsg { kind };
    let initiator = initiator.send(reserve.clone());
    let initiator = initiator.select_left(); // Commit
    let initiator = initiator.send(two_phase::CommitMsg);
    let init_proof = initiator.close();

    let (msg, executor) = executor.recv(reserve);
    assert_eq!(msg.kind, kind);
    let exec_proof = match executor.offer(Branch::Left) {
        Selected::Left(ch) => {
            let (_, ch) = ch.recv(two_phase::CommitMsg);
            ch.close()
        }
        Selected::Right(_) => panic!("expected Commit"),
    };

    (init_proof, exec_proof)
}

/// Run a two-phase abort path and return proofs.
fn run_two_phase_abort(
    channel_id: u64,
    kind: ObligationKind,
    reason: &str,
) -> (SessionProof, SessionProof) {
    let (initiator, executor) = two_phase::new_session(channel_id, kind);

    let reserve = two_phase::ReserveMsg { kind };
    let initiator = initiator.send(reserve.clone());
    let initiator = initiator.select_right(); // Abort
    let abort_msg = two_phase::AbortMsg {
        reason: reason.to_string(),
    };
    let initiator = initiator.send(abort_msg);
    let init_proof = initiator.close();

    let (_, executor) = executor.recv(reserve);
    let exec_proof = match executor.offer(Branch::Right) {
        Selected::Right(ch) => {
            let (msg, ch) = ch.recv(two_phase::AbortMsg {
                reason: reason.to_string(),
            });
            assert_eq!(msg.reason, reason);
            ch.close()
        }
        Selected::Left(_) => panic!("expected Abort"),
    };

    (init_proof, exec_proof)
}

// ============================================================================
// SendPermit/Ack protocol tests
// ============================================================================

#[test]
fn send_permit_commit_happy_path() {
    init_test_logging();
    let (sender_proof, receiver_proof) = run_send_permit_commit(100);
    assert_eq!(sender_proof.channel_id, 100);
    assert_eq!(sender_proof.obligation_kind, ObligationKind::SendPermit);
    assert_eq!(receiver_proof.channel_id, 100);
    assert_eq!(receiver_proof.obligation_kind, ObligationKind::SendPermit);
}

#[test]
fn send_permit_abort_happy_path() {
    init_test_logging();
    let (sender_proof, receiver_proof) = run_send_permit_abort(101);
    assert_eq!(sender_proof.channel_id, 101);
    assert_eq!(receiver_proof.channel_id, 101);
}

#[test]
fn send_permit_with_various_value_types() {
    init_test_logging();

    // String
    {
        let (s, r) = send_permit::new_session::<String>(200);
        let s = s.send(send_permit::ReserveMsg);
        let s = s.select_left();
        let s = s.send("hello world".to_string());
        s.close();
        std::mem::forget(r);
    }

    // u8
    {
        let (s, r) = send_permit::new_session::<u8>(201);
        let s = s.send(send_permit::ReserveMsg);
        let s = s.select_left();
        let s = s.send(255u8);
        s.close();
        std::mem::forget(r);
    }

    // Vec<u8>
    {
        let (s, r) = send_permit::new_session::<Vec<u8>>(202);
        let s = s.send(send_permit::ReserveMsg);
        let s = s.select_left();
        let s = s.send(vec![1, 2, 3]);
        s.close();
        std::mem::forget(r);
    }
}

#[test]
fn send_permit_channel_id_preserved_through_transitions() {
    init_test_logging();
    let (sender, receiver) = send_permit::new_session::<u32>(999);
    assert_eq!(sender.channel_id(), 999);
    assert_eq!(sender.obligation_kind(), ObligationKind::SendPermit);

    let sender = sender.send(send_permit::ReserveMsg);
    assert_eq!(sender.channel_id(), 999);

    let sender = sender.select_left();
    assert_eq!(sender.channel_id(), 999);

    let sender = sender.send(42u32);
    assert_eq!(sender.channel_id(), 999);

    let proof = sender.close();
    assert_eq!(proof.channel_id, 999);

    std::mem::forget(receiver);
}

// ============================================================================
// Lease/Release protocol tests
// ============================================================================

#[test]
fn lease_acquire_release_happy_path() {
    init_test_logging();
    let (holder_proof, resource_proof) = run_lease_simple(300);
    assert_eq!(holder_proof.channel_id, 300);
    assert_eq!(holder_proof.obligation_kind, ObligationKind::Lease);
    assert_eq!(resource_proof.obligation_kind, ObligationKind::Lease);
}

#[test]
fn lease_with_single_renewal() {
    init_test_logging();
    let proof = run_lease_with_renewals(301, 1);
    assert_eq!(proof.channel_id, 301);
    assert_eq!(proof.obligation_kind, ObligationKind::Lease);
}

#[test]
fn lease_with_multiple_renewals() {
    init_test_logging();
    for n in 2..=10 {
        let proof = run_lease_with_renewals(310 + u64::from(n), n);
        assert_eq!(proof.obligation_kind, ObligationKind::Lease);
    }
}

#[test]
fn lease_immediate_release_no_renewals() {
    init_test_logging();
    let proof = run_lease_with_renewals(320, 0);
    assert_eq!(proof.obligation_kind, ObligationKind::Lease);
}

// ============================================================================
// Reserve/Commit (Two-Phase) protocol tests
// ============================================================================

#[test]
fn two_phase_commit_happy_path() {
    init_test_logging();
    let (init_proof, exec_proof) = run_two_phase_commit(400, ObligationKind::SendPermit);
    assert_eq!(init_proof.channel_id, 400);
    assert_eq!(init_proof.obligation_kind, ObligationKind::SendPermit);
    assert_eq!(exec_proof.channel_id, 400);
}

#[test]
fn two_phase_abort_happy_path() {
    init_test_logging();
    let (init_proof, exec_proof) = run_two_phase_abort(401, ObligationKind::Lease, "timeout");
    assert_eq!(init_proof.channel_id, 401);
    assert_eq!(exec_proof.channel_id, 401);
}

#[test]
fn two_phase_all_obligation_kinds() {
    init_test_logging();
    let kinds = [
        ObligationKind::SendPermit,
        ObligationKind::Ack,
        ObligationKind::Lease,
        ObligationKind::IoOp,
    ];
    for (i, kind) in kinds.iter().enumerate() {
        let id = 410 + i as u64;
        let (init_proof, _) = run_two_phase_commit(id, *kind);
        assert_eq!(init_proof.obligation_kind, *kind);
    }
}

#[test]
fn two_phase_abort_with_various_reasons() {
    init_test_logging();
    let reasons = [
        "timeout",
        "cancelled",
        "conflict",
        "",
        "very long reason string that simulates a detailed error message",
    ];
    for (i, reason) in reasons.iter().enumerate() {
        let id = 420 + i as u64;
        let (_, exec_proof) = run_two_phase_abort(id, ObligationKind::IoOp, reason);
        assert_eq!(exec_proof.channel_id, id);
    }
}

// ============================================================================
// Drop bomb verification
// ============================================================================

#[test]
#[should_panic(expected = "SESSION LEAKED")]
fn drop_mid_send_permit_panics() {
    let (sender, receiver) = send_permit::new_session::<u32>(500);
    std::mem::forget(receiver);
    let sender = sender.send(send_permit::ReserveMsg);
    // Drop without reaching End — should panic.
    drop(sender);
}

#[test]
#[should_panic(expected = "SESSION LEAKED")]
fn drop_mid_lease_panics() {
    let (holder, resource) = lease::new_session(501);
    std::mem::forget(resource);
    let holder = holder.send(lease::AcquireMsg);
    drop(holder);
}

#[test]
#[should_panic(expected = "SESSION LEAKED")]
fn drop_mid_two_phase_panics() {
    let (initiator, executor) = two_phase::new_session(502, ObligationKind::SendPermit);
    std::mem::forget(executor);
    let reserve = two_phase::ReserveMsg {
        kind: ObligationKind::SendPermit,
    };
    let initiator = initiator.send(reserve);
    drop(initiator);
}

#[test]
#[should_panic(expected = "SESSION LEAKED")]
fn drop_fresh_channel_panics() {
    let (sender, receiver) = send_permit::new_session::<u32>(503);
    std::mem::forget(receiver);
    drop(sender); // Never started — still must not be dropped.
}

// ============================================================================
// Delegation tests
// ============================================================================

#[test]
fn delegation_channel_creation_and_types() {
    init_test_logging();

    // Verify delegation channel pairs can be created for different protocol states.
    // DelegatorSession = Send<Chan<R, S>, End>
    // DelegateeSession = Recv<Chan<R, S>, End>

    // Delegation of a SendPermit channel in Select state.
    let (delegator, delegatee) = delegation::new_delegation::<
        Initiator,
        Select<Send<u64, End>, Send<send_permit::AbortMsg, End>>,
    >(600, ObligationKind::SendPermit);

    assert_eq!(delegator.channel_id(), 600);
    assert_eq!(delegator.obligation_kind(), ObligationKind::SendPermit);
    assert_eq!(delegatee.channel_id(), 600);

    // Clean up without leaking (forget both to avoid drop bombs since
    // we're only testing creation, not protocol completion).
    std::mem::forget(delegator);
    std::mem::forget(delegatee);
}

#[test]
fn delegation_type_structure_compiles() {
    init_test_logging();

    // Verify delegation types compose correctly with obligation protocols.
    // DelegatorSession<R, S> = Send<Chan<R, S>, End>
    // DelegateeSession<R, S> = Recv<Chan<R, S>, End>
    //
    // The delegation channel pair can be created for any protocol state.
    // In a real system with transport, the delegator would send the obligation
    // channel via the transport and the delegatee would receive it. The typestate
    // encoding ensures type-level correctness; actual delegation transport is
    // tested via the async session::Endpoint in src/session.rs E2E tests.

    // Delegation pair for a two-phase Select state.
    let (d1, d2) = delegation::new_delegation::<
        Initiator,
        Select<Send<two_phase::CommitMsg, End>, Send<two_phase::AbortMsg, End>>,
    >(610, ObligationKind::IoOp);
    assert_eq!(d1.channel_id(), 610);
    assert_eq!(d2.channel_id(), 610);
    assert_eq!(d1.obligation_kind(), ObligationKind::IoOp);
    std::mem::forget(d1);
    std::mem::forget(d2);

    // Delegation pair for a lease loop state.
    let (d3, d4) = delegation::new_delegation::<
        Initiator,
        Select<Send<lease::RenewMsg, End>, Send<lease::ReleaseMsg, End>>,
    >(611, ObligationKind::Lease);
    assert_eq!(d3.obligation_kind(), ObligationKind::Lease);
    std::mem::forget(d3);
    std::mem::forget(d4);
}

// ============================================================================
// Concurrent sessions (multiple independent channels)
// ============================================================================

#[test]
fn concurrent_100_send_permit_sessions() {
    init_test_logging();
    let mut proofs = Vec::with_capacity(100);
    for i in 0..100u64 {
        let (sp, rp) = run_send_permit_commit(700 + i);
        assert_eq!(sp.channel_id, 700 + i);
        proofs.push((sp, rp));
    }
    assert_eq!(proofs.len(), 100);
}

#[test]
fn concurrent_50_lease_sessions_with_varying_renewals() {
    init_test_logging();
    for i in 0..50u32 {
        let renewals = i % 5; // 0..4 renewals
        let proof = run_lease_with_renewals(800 + u64::from(i), renewals);
        assert_eq!(proof.obligation_kind, ObligationKind::Lease);
    }
}

#[test]
fn concurrent_30_two_phase_mixed_outcomes() {
    init_test_logging();
    for i in 0..30u64 {
        let kind = match i % 4 {
            0 => ObligationKind::SendPermit,
            1 => ObligationKind::Ack,
            2 => ObligationKind::Lease,
            _ => ObligationKind::IoOp,
        };
        if i % 2 == 0 {
            let (p, _) = run_two_phase_commit(900 + i, kind);
            assert_eq!(p.obligation_kind, kind);
        } else {
            let (p, _) = run_two_phase_abort(900 + i, kind, "test abort");
            assert_eq!(p.obligation_kind, kind);
        }
    }
}

// ============================================================================
// Protocol composition — nested two-phase within a lease
// ============================================================================

#[test]
fn nested_two_phase_within_lease() {
    init_test_logging();

    // Acquire a lease.
    let (holder, resource) = lease::new_session(1000);
    let holder = holder.send(lease::AcquireMsg);
    let (_, resource) = resource.recv(lease::AcquireMsg);

    // While lease is active, run a two-phase commit.
    let (init_proof, exec_proof) = run_two_phase_commit(1001, ObligationKind::SendPermit);
    assert_eq!(init_proof.channel_id, 1001);
    assert_eq!(exec_proof.channel_id, 1001);

    // Release the lease.
    let holder = holder.select_right();
    let holder = holder.send(lease::ReleaseMsg);
    let lease_proof = holder.close();
    assert_eq!(lease_proof.channel_id, 1000);

    match resource.offer(Branch::Right) {
        Selected::Right(ch) => {
            let (_, ch) = ch.recv(lease::ReleaseMsg);
            ch.close();
        }
        Selected::Left(_) => panic!("expected Release"),
    }
}

// ============================================================================
// Determinism — same channel IDs produce same proofs
// ============================================================================

#[test]
fn deterministic_send_permit_100_runs() {
    init_test_logging();
    let first_proofs = run_send_permit_commit(1100);
    for _ in 1..100 {
        let proofs = run_send_permit_commit(1100);
        assert_eq!(proofs.0.channel_id, first_proofs.0.channel_id);
        assert_eq!(proofs.0.obligation_kind, first_proofs.0.obligation_kind);
        assert_eq!(proofs.1.channel_id, first_proofs.1.channel_id);
    }
}

#[test]
fn deterministic_two_phase_100_runs() {
    init_test_logging();
    let first = run_two_phase_commit(1200, ObligationKind::Lease);
    for _ in 1..100 {
        let run = run_two_phase_commit(1200, ObligationKind::Lease);
        assert_eq!(run.0.channel_id, first.0.channel_id);
        assert_eq!(run.0.obligation_kind, first.0.obligation_kind);
    }
}

// ============================================================================
// Session proof fields verification
// ============================================================================

#[test]
fn session_proof_contains_correct_fields() {
    init_test_logging();

    // SendPermit
    let (sp, _) = run_send_permit_commit(1300);
    assert_eq!(sp.channel_id, 1300);
    assert_eq!(sp.obligation_kind, ObligationKind::SendPermit);

    // Lease
    let (lp, _) = run_lease_simple(1301);
    assert_eq!(lp.channel_id, 1301);
    assert_eq!(lp.obligation_kind, ObligationKind::Lease);

    // Two-phase
    let (tp, _) = run_two_phase_commit(1302, ObligationKind::IoOp);
    assert_eq!(tp.channel_id, 1302);
    assert_eq!(tp.obligation_kind, ObligationKind::IoOp);
}

// ============================================================================
// Property-based tests
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(100))]

    /// Any valid channel ID produces a successful SendPermit commit path.
    #[test]
    fn proptest_send_permit_commit_any_channel_id(channel_id in 0u64..10000) {
        let (sp, rp) = run_send_permit_commit(channel_id);
        prop_assert_eq!(sp.channel_id, channel_id);
        prop_assert_eq!(rp.channel_id, channel_id);
        prop_assert_eq!(sp.obligation_kind, ObligationKind::SendPermit);
    }

    /// Any valid channel ID produces a successful SendPermit abort path.
    #[test]
    fn proptest_send_permit_abort_any_channel_id(channel_id in 0u64..10000) {
        let (sp, rp) = run_send_permit_abort(channel_id);
        prop_assert_eq!(sp.channel_id, channel_id);
        prop_assert_eq!(rp.channel_id, channel_id);
    }

    /// Lease with random number of renewals always completes successfully.
    #[test]
    fn proptest_lease_random_renewals(
        channel_id in 0u64..10000,
        renewals in 0u32..20,
    ) {
        let proof = run_lease_with_renewals(channel_id, renewals);
        prop_assert_eq!(proof.obligation_kind, ObligationKind::Lease);
    }

    /// Two-phase commit with any obligation kind succeeds.
    #[test]
    fn proptest_two_phase_commit_any_kind(
        channel_id in 0u64..10000,
        kind_idx in 0usize..4,
    ) {
        let kinds = [
            ObligationKind::SendPermit,
            ObligationKind::Ack,
            ObligationKind::Lease,
            ObligationKind::IoOp,
        ];
        let kind = kinds[kind_idx];
        let (ip, ep) = run_two_phase_commit(channel_id, kind);
        prop_assert_eq!(ip.channel_id, channel_id);
        prop_assert_eq!(ep.channel_id, channel_id);
        prop_assert_eq!(ip.obligation_kind, kind);
    }

    /// Two-phase abort with random reason string succeeds.
    #[test]
    fn proptest_two_phase_abort_random_reason(
        channel_id in 0u64..10000,
        reason in "[a-z]{0,50}",
    ) {
        let (ip, ep) = run_two_phase_abort(channel_id, ObligationKind::SendPermit, &reason);
        prop_assert_eq!(ip.channel_id, channel_id);
        prop_assert_eq!(ep.channel_id, channel_id);
    }

    /// Random protocol sequence: choose commit or abort for each run.
    #[test]
    fn proptest_random_protocol_sequence(
        channel_id in 0u64..10000,
        do_commit in proptest::bool::ANY,
        kind_idx in 0usize..4,
    ) {
        let kinds = [
            ObligationKind::SendPermit,
            ObligationKind::Ack,
            ObligationKind::Lease,
            ObligationKind::IoOp,
        ];
        let kind = kinds[kind_idx];
        if do_commit {
            let (ip, _) = run_two_phase_commit(channel_id, kind);
            prop_assert_eq!(ip.obligation_kind, kind);
        } else {
            let (ip, _) = run_two_phase_abort(channel_id, kind, "random_abort");
            prop_assert_eq!(ip.obligation_kind, kind);
        }
    }
}

// ============================================================================
// E2E tests with LabRuntime — async session-typed endpoints
// ============================================================================

#[test]
fn e2e_send_recv_session_under_lab() {
    type ClientP =
        asupersync::session::Send<u64, asupersync::session::Recv<u64, asupersync::session::End>>;

    init_test_logging();

    let mut runtime = LabRuntime::new(LabConfig::default());
    let region = runtime
        .state
        .create_root_region(asupersync::types::Budget::INFINITE);

    let (client_ep, server_ep) = asupersync::session::channel::<ClientP>();

    let client_result = Arc::new(AtomicU64::new(0));
    let cr = client_result.clone();

    let (client_id, _) = runtime
        .state
        .create_task(region, asupersync::types::Budget::INFINITE, async move {
            let cx = asupersync::cx::Cx::for_testing();
            let ep = client_ep.send(&cx, 42).await.expect("client send");
            let (val, ep) = ep.recv(&cx).await.expect("client recv");
            cr.store(val, Ordering::SeqCst);
            ep.close();
        })
        .unwrap();

    let (server_id, _) = runtime
        .state
        .create_task(region, asupersync::types::Budget::INFINITE, async move {
            let cx = asupersync::cx::Cx::for_testing();
            let (val, ep) = server_ep.recv(&cx).await.expect("server recv");
            let ep = ep.send(&cx, val * 3).await.expect("server send");
            ep.close();
        })
        .unwrap();

    runtime.scheduler.lock().unwrap().schedule(client_id, 0);
    runtime.scheduler.lock().unwrap().schedule(server_id, 0);
    runtime.run_until_quiescent();

    assert_eq!(client_result.load(Ordering::SeqCst), 126); // 42 * 3
}

#[test]
fn e2e_choose_offer_under_lab() {
    type ClientP = asupersync::session::Choose<
        asupersync::session::Send<u64, asupersync::session::End>,
        asupersync::session::Recv<u64, asupersync::session::End>,
    >;

    init_test_logging();

    let mut runtime = LabRuntime::new(LabConfig::default());
    let region = runtime
        .state
        .create_root_region(asupersync::types::Budget::INFINITE);

    let (client_ep, server_ep) = asupersync::session::channel::<ClientP>();

    let result = Arc::new(AtomicU64::new(0));
    let r = result.clone();

    let (client_id, _) = runtime
        .state
        .create_task(region, asupersync::types::Budget::INFINITE, async move {
            let cx = asupersync::cx::Cx::for_testing();
            // Choose right: receive a value from server.
            let ep = client_ep.choose_right(&cx).await.expect("choose right");
            let (val, ep) = ep.recv(&cx).await.expect("recv");
            r.store(val, Ordering::SeqCst);
            ep.close();
        })
        .unwrap();

    let (server_id, _) = runtime
        .state
        .create_task(region, asupersync::types::Budget::INFINITE, async move {
            let cx = asupersync::cx::Cx::for_testing();
            match server_ep.offer(&cx).await.expect("offer") {
                asupersync::session::Offered::Left(ep) => {
                    let (_, ep) = ep.recv(&cx).await.unwrap();
                    ep.close();
                }
                asupersync::session::Offered::Right(ep) => {
                    let ep = ep.send(&cx, 777).await.unwrap();
                    ep.close();
                }
            }
        })
        .unwrap();

    runtime.scheduler.lock().unwrap().schedule(client_id, 0);
    runtime.scheduler.lock().unwrap().schedule(server_id, 0);
    runtime.run_until_quiescent();

    assert_eq!(result.load(Ordering::SeqCst), 777);
}

#[test]
fn e2e_deterministic_session_replay() {
    fn run_with_seed(seed: u64) -> u64 {
        type P = asupersync::session::Send<
            u64,
            asupersync::session::Recv<u64, asupersync::session::End>,
        >;

        let config = LabConfig::new(seed);
        let mut runtime = LabRuntime::new(config);
        let region = runtime
            .state
            .create_root_region(asupersync::types::Budget::INFINITE);
        let (client_ep, server_ep) = asupersync::session::channel::<P>();

        let result = Arc::new(AtomicU64::new(0));
        let r = result.clone();

        let (cid, _) = runtime
            .state
            .create_task(region, asupersync::types::Budget::INFINITE, async move {
                let cx = asupersync::cx::Cx::for_testing();
                let ep = client_ep.send(&cx, 13).await.unwrap();
                let (val, ep) = ep.recv(&cx).await.unwrap();
                r.store(val, Ordering::SeqCst);
                ep.close();
            })
            .unwrap();

        let (sid, _) = runtime
            .state
            .create_task(region, asupersync::types::Budget::INFINITE, async move {
                let cx = asupersync::cx::Cx::for_testing();
                let (v, ep) = server_ep.recv(&cx).await.unwrap();
                let ep = ep.send(&cx, v * v).await.unwrap();
                ep.close();
            })
            .unwrap();

        runtime.scheduler.lock().unwrap().schedule(cid, 0);
        runtime.scheduler.lock().unwrap().schedule(sid, 0);
        runtime.run_until_quiescent();

        result.load(Ordering::SeqCst)
    }

    init_test_logging();

    // Run 10 times with same seed — must produce identical results.
    let first = run_with_seed(0xBEEF);
    assert_eq!(first, 169); // 13 * 13
    for _ in 1..10 {
        assert_eq!(run_with_seed(0xBEEF), first);
    }
}

// ============================================================================
// E2E: multiple concurrent sessions under LabRuntime
// ============================================================================

#[test]
fn e2e_10_concurrent_sessions_under_lab() {
    type P =
        asupersync::session::Send<u64, asupersync::session::Recv<u64, asupersync::session::End>>;

    init_test_logging();

    let mut runtime = LabRuntime::new(LabConfig::new(0xCAFE_BABE));
    let region = runtime
        .state
        .create_root_region(asupersync::types::Budget::INFINITE);

    let results: Vec<Arc<AtomicU64>> = (0..10).map(|_| Arc::new(AtomicU64::new(0))).collect();

    let mut task_ids = Vec::new();

    for i in 0..10u64 {
        let (client_ep, server_ep) = asupersync::session::channel::<P>();
        let r = results[i as usize].clone();

        let (cid, _) = runtime
            .state
            .create_task(region, asupersync::types::Budget::INFINITE, async move {
                let cx = asupersync::cx::Cx::for_testing();
                let ep = client_ep.send(&cx, i).await.unwrap();
                let (val, ep) = ep.recv(&cx).await.unwrap();
                r.store(val, Ordering::SeqCst);
                ep.close();
            })
            .unwrap();

        let (sid, _) = runtime
            .state
            .create_task(region, asupersync::types::Budget::INFINITE, async move {
                let cx = asupersync::cx::Cx::for_testing();
                let (v, ep) = server_ep.recv(&cx).await.unwrap();
                let ep = ep.send(&cx, v + 100).await.unwrap();
                ep.close();
            })
            .unwrap();

        task_ids.push(cid);
        task_ids.push(sid);
    }

    for &id in &task_ids {
        runtime.scheduler.lock().unwrap().schedule(id, 0);
    }
    runtime.run_until_quiescent();

    for i in 0..10u64 {
        assert_eq!(
            results[i as usize].load(Ordering::SeqCst),
            i + 100,
            "session {i} should return {}",
            i + 100
        );
    }
}

// ============================================================================
// Chan::new_raw access — verify public API surface
// ============================================================================

#[test]
fn chan_accessors_work() {
    init_test_logging();

    let (sender, receiver) = send_permit::new_session::<u32>(42);
    assert_eq!(sender.channel_id(), 42);
    assert_eq!(sender.obligation_kind(), ObligationKind::SendPermit);
    assert_eq!(receiver.channel_id(), 42);
    assert_eq!(receiver.obligation_kind(), ObligationKind::SendPermit);

    // Complete both to avoid drop bomb.
    let sender = sender.send(send_permit::ReserveMsg);
    let sender = sender.select_right();
    let sender = sender.send(send_permit::AbortMsg);
    sender.close();

    let (_, receiver) = receiver.recv(send_permit::ReserveMsg);
    match receiver.offer(Branch::Right) {
        Selected::Right(ch) => {
            let (_, ch) = ch.recv(send_permit::AbortMsg);
            ch.close();
        }
        Selected::Left(_) => panic!("expected abort"),
    }
}

// ============================================================================
// Mixed protocol interleaving (not composed, just independent)
// ============================================================================

#[test]
fn interleaved_protocols_independent() {
    init_test_logging();

    // Start a SendPermit session.
    let (sp_sender, sp_receiver) = send_permit::new_session::<u32>(2000);
    let sp_sender = sp_sender.send(send_permit::ReserveMsg);

    // Start a Lease session while SendPermit is in-flight.
    let (holder, resource) = lease::new_session(2001);
    let holder = holder.send(lease::AcquireMsg);

    // Start a Two-Phase session.
    let (initiator, executor) = two_phase::new_session(2002, ObligationKind::IoOp);
    let reserve = two_phase::ReserveMsg {
        kind: ObligationKind::IoOp,
    };
    let initiator = initiator.send(reserve.clone());

    // Complete two-phase first (commit).
    let initiator = initiator.select_left();
    let initiator = initiator.send(two_phase::CommitMsg);
    initiator.close();

    let (_, executor) = executor.recv(reserve);
    match executor.offer(Branch::Left) {
        Selected::Left(ch) => {
            let (_, ch) = ch.recv(two_phase::CommitMsg);
            ch.close();
        }
        Selected::Right(_) => panic!("expected commit"),
    }

    // Complete lease (release).
    let holder = holder.select_right();
    let holder = holder.send(lease::ReleaseMsg);
    holder.close();

    let (_, resource) = resource.recv(lease::AcquireMsg);
    match resource.offer(Branch::Right) {
        Selected::Right(ch) => {
            let (_, ch) = ch.recv(lease::ReleaseMsg);
            ch.close();
        }
        Selected::Left(_) => panic!("expected release"),
    }

    // Complete SendPermit last (send value).
    let sp_sender = sp_sender.select_left();
    let sp_sender = sp_sender.send(42u32);
    sp_sender.close();

    let (_, sp_receiver) = sp_receiver.recv(send_permit::ReserveMsg);
    match sp_receiver.offer(Branch::Left) {
        Selected::Left(ch) => {
            let (_, ch) = ch.recv(42u32);
            ch.close();
        }
        Selected::Right(_) => panic!("expected send"),
    }
}

// ============================================================================
// Backward compatibility — legacy and session-typed APIs share obligation kinds
// ============================================================================

#[test]
fn backward_compat_obligation_kinds_match() {
    init_test_logging();

    // Verify the session-typed protocols use the same ObligationKind values
    // as the runtime obligation system.
    let (sp, _) = run_send_permit_commit(3000);
    assert_eq!(sp.obligation_kind, ObligationKind::SendPermit);

    let (lp, _) = run_lease_simple(3001);
    assert_eq!(lp.obligation_kind, ObligationKind::Lease);

    // Two-phase can use any kind — verify all.
    for kind in &[
        ObligationKind::SendPermit,
        ObligationKind::Ack,
        ObligationKind::Lease,
        ObligationKind::IoOp,
    ] {
        let (tp, _) = run_two_phase_commit(3010, *kind);
        assert_eq!(tp.obligation_kind, *kind);
    }
}

#[test]
fn backward_compat_module_aliases_exist() {
    use asupersync::obligation::session_types::lease_compat;
    use asupersync::obligation::session_types::send_permit_compat;
    use asupersync::obligation::session_types::two_phase_compat;

    init_test_logging();

    // Verify compat aliases resolve. These type assertions compile only if
    // the aliases are correctly wired to the underlying session types.
    // SenderSession<T> should be the SendPermit initiator type.
    let _: Option<send_permit_compat::SenderSession<u32>> = None;
    let _: Option<send_permit_compat::ReceiverSession<u32>> = None;

    // Lease compat aliases.
    let _: Option<lease_compat::HolderSession> = None;
    let _: Option<lease_compat::ResourceSession> = None;

    // Two-phase compat alias.
    let _: Option<two_phase_compat::ExecutorSession> = None;
}

// ============================================================================
// Session type duality verification (async endpoints)
// ============================================================================

#[test]
fn session_duality_send_recv() {
    fn assert_dual<S: asupersync::session::Session>()
    where
        S::Dual: asupersync::session::Session<Dual = S>,
    {
    }

    init_test_logging();

    assert_dual::<asupersync::session::Send<u32, asupersync::session::End>>();
    assert_dual::<asupersync::session::Recv<u32, asupersync::session::End>>();
    assert_dual::<asupersync::session::Choose<asupersync::session::End, asupersync::session::End>>(
    );
    assert_dual::<asupersync::session::Offer<asupersync::session::End, asupersync::session::End>>();
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn channel_id_zero_is_valid() {
    init_test_logging();
    let (sp, rp) = run_send_permit_commit(0);
    assert_eq!(sp.channel_id, 0);
    assert_eq!(rp.channel_id, 0);
}

#[test]
fn channel_id_max_u64_is_valid() {
    init_test_logging();
    let (sp, rp) = run_send_permit_commit(u64::MAX);
    assert_eq!(sp.channel_id, u64::MAX);
    assert_eq!(rp.channel_id, u64::MAX);
}

#[test]
fn two_phase_reserve_msg_kind_preserved() {
    init_test_logging();

    let (initiator, executor) = two_phase::new_session(4000, ObligationKind::Ack);
    let reserve = two_phase::ReserveMsg {
        kind: ObligationKind::Ack,
    };
    let initiator = initiator.send(reserve.clone());
    let initiator = initiator.select_left();
    let initiator = initiator.send(two_phase::CommitMsg);
    initiator.close();

    let (msg, executor) = executor.recv(reserve);
    assert_eq!(msg.kind, ObligationKind::Ack);
    match executor.offer(Branch::Left) {
        Selected::Left(ch) => {
            let (_, ch) = ch.recv(two_phase::CommitMsg);
            ch.close();
        }
        Selected::Right(_) => panic!("expected Commit"),
    }
}

#[test]
fn two_phase_abort_msg_reason_preserved() {
    init_test_logging();

    let (initiator, executor) = two_phase::new_session(4001, ObligationKind::SendPermit);
    let reserve = two_phase::ReserveMsg {
        kind: ObligationKind::SendPermit,
    };
    let initiator = initiator.send(reserve.clone());
    let initiator = initiator.select_right();
    let abort = two_phase::AbortMsg {
        reason: "resource exhausted".to_string(),
    };
    let initiator = initiator.send(abort);
    initiator.close();

    let (_, executor) = executor.recv(reserve);
    match executor.offer(Branch::Right) {
        Selected::Right(ch) => {
            let (msg, ch) = ch.recv(two_phase::AbortMsg {
                reason: "resource exhausted".to_string(),
            });
            assert_eq!(msg.reason, "resource exhausted");
            ch.close();
        }
        Selected::Left(_) => panic!("expected Abort"),
    }
}
