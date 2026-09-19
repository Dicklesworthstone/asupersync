use super::*;
use crate::distributed::membership::authority::{MembershipControllerLimits, MembershipFloor, MembershipUpdate};
use crate::distributed::membership::{MembershipEvent, MembershipKind};
use crate::distributed::{TaskSnapshot, TaskState};
use crate::runtime::RuntimeBuilder;
use crate::types::RegionId;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

#[derive(Clone, Copy)]
struct Progress { next: u64, end: u64 }
#[derive(Default)]
struct Counter {
    decodes: AtomicUsize,
    resumes: AtomicUsize,
    effects: Mutex<Vec<u64>>,
    corrupt_decode: bool,
    refuse_decode: bool,
}
impl RestorableWorkload for Counter {
    const NAME: &'static str = "tests.resume-counter";
    const REVISION: u32 = 3;
    const STATE_SCHEMA: [u8; 32] = [7; 32];
    type State = Progress;
    type Output = (u64, RegionId);
    fn encode_state(&self, state: &Progress) -> Result<Vec<u8>, StateCodecError> {
        if state.next > state.end || state.end > 1000 { return Err(StateCodecError::Invalid); }
        Ok([state.next.to_le_bytes(), state.end.to_le_bytes()].concat())
    }
    fn decode_state(&self, bytes: &[u8]) -> Result<Progress, StateCodecError> {
        self.decodes.fetch_add(1, Ordering::Relaxed);
        if self.refuse_decode { return Err(StateCodecError::Unsupported); }
        if bytes.len() != 16 { return Err(StateCodecError::Invalid); }
        let state = Progress {
            next: u64::from_le_bytes(bytes[..8].try_into().unwrap())
                .checked_add(u64::from(self.corrupt_decode)).ok_or(StateCodecError::Invalid)?,
            end: u64::from_le_bytes(bytes[8..].try_into().unwrap()),
        };
        if state.next > state.end || state.end > 1000 { return Err(StateCodecError::Invalid); }
        Ok(state)
    }
    fn resume(self: Arc<Self>, cx: Cx, state: Progress) -> ContinuationFuture<Self::Output> {
        self.resumes.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move {
            let mut total = 0;
            for step in state.next..state.end {
                cx.checkpoint().unwrap();
                self.effects.lock().unwrap().push(step);
                total += step;
            }
            (total, cx.region_id())
        })
    }
}
fn limits() -> ContinuationLimits {
    ContinuationLimits { max_snapshot_bytes: 4096, max_state_bytes: 64 }
}
fn base() -> RegionSnapshot {
    let mut snapshot = RegionSnapshot::empty(RegionId::new_for_test(110, 7));
    snapshot.origin_id = 5; snapshot.epoch = 3; snapshot.sequence = 19;
    snapshot
}
fn fixture() -> (Arc<Counter>, RegionSnapshot) {
    let workload = Arc::new(Counter::default());
    let snapshot = checkpoint_workload(base(), workload.as_ref(), &Progress { next: 5, end: 12 },
        &AuthKey::from_seed(91), limits()).unwrap();
    workload.decodes.store(0, Ordering::Relaxed);
    (workload, snapshot)
}
fn prepare(workload: Arc<Counter>, snapshot: &RegionSnapshot) -> Result<PreparedContinuation<Counter>, ContinuationError> {
    prepare_workload(&snapshot.to_bytes(), identity(snapshot), &AuthKey::from_seed(91), limits(), workload)
}
fn changed(mut snapshot: RegionSnapshot, change: impl FnOnce(&mut RegionSnapshot)) -> RegionSnapshot {
    change(&mut snapshot); snapshot.sign(&AuthKey::from_seed(91)); snapshot
}
fn owner(cx: &Cx, alive: bool) -> OwnedMembershipController {
    let authority = NodeId::new("authority");
    let node = NodeId::new("worker");
    let owner = OwnedMembershipController::new(authority.clone(), 8, AuthKey::from_seed(33),
        vec![MembershipFloor { node: node.clone(), incarnation: 0, sequence: 0 }],
        MembershipControllerLimits { max_members: 1, max_lease_ids: 8 }, cx.timer_driver().unwrap()).unwrap();
    let bytes = MembershipUpdate { event: MembershipEvent { node, incarnation: 2,
        kind: if alive { MembershipKind::Alive } else { MembershipKind::Dead } }, sequence: 1 }
        .authenticated_bytes(&authority, 8, &AuthKey::from_seed(33)).unwrap();
    owner.apply_authenticated(&authority, &bytes).unwrap();
    owner
}

#[test]
fn checkpoint_roundtrip_is_canonical_and_preparation_does_not_execute() {
    let (workload, snapshot) = fixture();
    let other = checkpoint_workload(base(), workload.as_ref(), &Progress { next: 5, end: 12 },
        &AuthKey::from_seed(91), limits()).unwrap();
    assert_eq!(snapshot.to_bytes(), other.to_bytes());
    let prepared = prepare(Arc::clone(&workload), &snapshot).unwrap();
    assert_eq!(prepared.source(), identity(&snapshot));
    assert_eq!(prepared.state_digest(), state_hash(&[5_u64.to_le_bytes(), 12_u64.to_le_bytes()].concat()).unwrap());
    assert_eq!(workload.resumes.load(Ordering::Relaxed), 0);
    assert!(workload.effects.lock().unwrap().is_empty());
    assert!(!format!("{prepared:?}").contains(Counter::NAME));
}

#[test]
fn invalid_snapshot_key_and_zero_tag_refuse_before_codec() {
    let (workload, mut snapshot) = fixture();
    assert!(matches!(prepare_workload(&snapshot.to_bytes(), identity(&snapshot), &AuthKey::from_seed(92),
        limits(), Arc::clone(&workload)), Err(ContinuationError::Snapshot(_))));
    snapshot.auth_tag = crate::security::AuthenticationTag::zero();
    assert!(matches!(prepare(Arc::clone(&workload), &snapshot), Err(ContinuationError::Snapshot(_))));
    assert_eq!(workload.decodes.load(Ordering::Relaxed), 0);
}

#[test]
fn exact_source_generation_branch_and_sequence_are_required() {
    let (workload, snapshot) = fixture();
    let expected = identity(&snapshot);
    for field in 0..5 {
        let mut wrong = expected;
        match field {
            0 => wrong.region_id = RegionId::new_for_test(111, 7),
            1 => wrong.region_id = RegionId::new_for_test(110, 8),
            2 => wrong.origin_id += 1,
            3 => wrong.epoch += 1,
            _ => wrong.sequence += 1,
        }
        assert!(matches!(prepare_workload(&snapshot.to_bytes(), wrong, &AuthKey::from_seed(91),
            limits(), Arc::clone(&workload)), Err(ContinuationError::Identity)));
    }
    assert_eq!(workload.decodes.load(Ordering::Relaxed), 0);
}

#[test]
fn signed_workload_revision_schema_and_name_mismatches_do_not_select_other_code() {
    let (workload, snapshot) = fixture();
    for offset in [12, 20, HEADER] {
        let bad = changed(snapshot.clone(), |s| s.metadata[offset] ^= 1);
        assert!(matches!(prepare(Arc::clone(&workload), &bad), Err(ContinuationError::Workload)));
    }
    assert_eq!(workload.decodes.load(Ordering::Relaxed), 0);
    assert_eq!(workload.resumes.load(Ordering::Relaxed), 0);
}

#[test]
fn all_truncated_snapshots_and_single_bit_mutations_fail_before_application_decode() {
    let (workload, snapshot) = fixture();
    let bytes = snapshot.to_bytes();
    for end in 0..bytes.len() {
        assert!(prepare_workload(&bytes[..end], identity(&snapshot), &AuthKey::from_seed(91),
            limits(), Arc::clone(&workload)).is_err(), "prefix {end}");
    }
    for index in 0..bytes.len() {
        for bit in 0..8 {
            let mut bad = bytes.clone(); bad[index] ^= 1 << bit;
            assert!(prepare_workload(&bad, identity(&snapshot), &AuthKey::from_seed(91),
                limits(), Arc::clone(&workload)).is_err(), "byte {index} bit {bit}");
        }
    }
    assert_eq!(workload.decodes.load(Ordering::Relaxed), 0);
}

#[test]
fn resigned_malformed_framing_digest_lengths_and_flags_are_refused() {
    let (workload, snapshot) = fixture();
    for case in 0..9 {
        let bad = changed(snapshot.clone(), |s| match case {
            0 => s.metadata[0] ^= 1,
            1 => s.metadata[8] = 2,
            2 => s.metadata[18] = 1,
            3 => s.metadata[16..18].copy_from_slice(&0_u16.to_le_bytes()),
            4 => s.metadata[16..18].copy_from_slice(&256_u16.to_le_bytes()),
            5 => s.metadata[52..60].copy_from_slice(&u64::MAX.to_le_bytes()),
            6 => s.metadata[60] ^= 1,
            7 => s.metadata.push(0),
            _ => { s.metadata.pop(); }
        });
        assert!(prepare(Arc::clone(&workload), &bad).is_err(), "case {case}");
    }
    assert_eq!(workload.decodes.load(Ordering::Relaxed), 0);
}

#[test]
fn task_stacks_children_finalizers_cancellation_and_budget_restore_are_not_silently_ignored() {
    let (workload, snapshot) = fixture();
    for case in 0..10 {
        let bad = changed(snapshot.clone(), |s| match case {
            0 => s.tasks.push(TaskSnapshot { task_id: crate::types::TaskId::new_for_test(1, 1), state: TaskState::Pending, priority: 0 }),
            1 => s.tasks.push(TaskSnapshot { task_id: crate::types::TaskId::new_for_test(1, 1), state: TaskState::Running, priority: 0 }),
            2 => s.children.push(RegionId::new_for_test(2, 1)),
            3 => s.finalizer_count = 1,
            4 => s.state = RegionState::Closed,
            5 => s.parent = Some(RegionId::new_for_test(2, 1)),
            6 => s.cancel_reason = Some("do not resume".into()),
            7 => s.budget.deadline_nanos = Some(99),
            8 => s.budget.polls_remaining = Some(3),
            _ => s.budget.cost_remaining = Some(5),
        });
        assert!(matches!(prepare(Arc::clone(&workload), &bad), Err(ContinuationError::UnsupportedSnapshot)), "case {case}");
    }
    assert_eq!(workload.decodes.load(Ordering::Relaxed), 0);
}

#[test]
fn capture_refuses_existing_metadata_without_running_a_codec() {
    let workload = Counter::default();
    let mut snapshot = base(); snapshot.metadata = b"existing application contract".to_vec();
    assert!(matches!(checkpoint_workload(snapshot, &workload, &Progress { next: 5, end: 12 },
        &AuthKey::from_seed(91), limits()), Err(ContinuationError::ExistingMetadata)));
    assert_eq!(workload.decodes.load(Ordering::Relaxed), 0);
}

#[test]
fn exact_byte_budgets_succeed_and_smaller_budgets_refuse_before_decode() {
    let (workload, snapshot) = fixture();
    let bytes = snapshot.to_bytes();
    let exact = ContinuationLimits { max_snapshot_bytes: bytes.len(), max_state_bytes: 16 };
    prepare_workload(&bytes, identity(&snapshot), &AuthKey::from_seed(91), exact, Arc::clone(&workload)).unwrap();
    workload.decodes.store(0, Ordering::Relaxed);
    for bounds in [ContinuationLimits { max_snapshot_bytes: bytes.len() - 1, ..exact },
        ContinuationLimits { max_state_bytes: 15, ..exact }]
    {
        assert!(matches!(prepare_workload(&bytes, identity(&snapshot), &AuthKey::from_seed(91), bounds,
            Arc::clone(&workload)), Err(ContinuationError::Limit(_))));
    }
    assert_eq!(workload.decodes.load(Ordering::Relaxed), 0);
    let recaptured = checkpoint_workload(base(), workload.as_ref(), &Progress { next: 5, end: 12 },
        &AuthKey::from_seed(91), exact).unwrap();
    assert_eq!(recaptured.to_bytes(), bytes);
}

#[test]
fn application_codec_refusal_and_noncanonical_state_cannot_create_runnable_work() {
    let (_, snapshot) = fixture();
    let refusing = Arc::new(Counter { refuse_decode: true, ..Default::default() });
    assert!(matches!(prepare(Arc::clone(&refusing), &snapshot), Err(ContinuationError::State(StateCodecError::Unsupported))));
    let drifting = Arc::new(Counter { corrupt_decode: true, ..Default::default() });
    assert!(matches!(prepare(Arc::clone(&drifting), &snapshot), Err(ContinuationError::NonCanonical)));
    assert_eq!(refusing.resumes.load(Ordering::Relaxed), 0);
    assert_eq!(drifting.resumes.load(Ordering::Relaxed), 0);
}

#[test]
fn empty_or_arbitrary_metadata_is_not_a_supported_continuation() {
    let workload = Arc::new(Counter::default());
    for metadata in [Vec::new(), vec![0; HEADER + 16]] {
        let mut snapshot = base(); snapshot.metadata = metadata; snapshot.sign(&AuthKey::from_seed(91));
        assert!(matches!(prepare(Arc::clone(&workload), &snapshot), Err(ContinuationError::Format)));
    }
    assert_eq!(workload.decodes.load(Ordering::Relaxed), 0);
}

#[test]
fn native_execution_resumes_remaining_effects_in_a_fresh_child_and_commits_real_lease() {
    for workers in [1, 2] {
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        let (workload, snapshot) = fixture();
        let prepared = prepare(Arc::clone(&workload), &snapshot).unwrap();
        drop(snapshot);
        runtime.block_on(async {
            let cx = Cx::current().unwrap(); let owner = owner(&cx, true);
            let report = prepared.run(&owner, &cx, &NodeId::new("worker"), 2,
                Duration::from_secs(5), ChildRegionSpec::inherit()).await.unwrap();
            assert!(report.is_success(), "{report:?}");
            let (value, executing_region) = report.task.unwrap();
            assert_eq!(value, (5_u64..12).sum::<u64>());
            assert_ne!(executing_region, cx.region_id());
            assert_eq!(owner.live_leases(), 0); assert!(!cx.is_cancel_requested()); owner.close();
        });
        assert_eq!(workload.resumes.load(Ordering::Relaxed), 1);
        assert_eq!(*workload.effects.lock().unwrap(), (5_u64..12).collect::<Vec<_>>());
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn valid_prepared_state_cannot_bypass_destination_membership_admission() {
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    let (workload, snapshot) = fixture();
    let prepared = prepare(Arc::clone(&workload), &snapshot).unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap(); let owner = owner(&cx, false);
        let result = prepared.run(&owner, &cx, &NodeId::new("worker"), 2,
            Duration::from_secs(5), ChildRegionSpec::inherit()).await;
        assert!(matches!(result, Err(MembershipWorkError::Lease(_))));
        assert_eq!(owner.live_leases(), 0); owner.close();
    });
    assert_eq!(workload.resumes.load(Ordering::Relaxed), 0);
    assert!(workload.effects.lock().unwrap().is_empty());
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}
