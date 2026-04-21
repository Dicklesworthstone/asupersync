#![no_main]

use arbitrary::Arbitrary;
use asupersync::distributed::snapshot::{
    BudgetSnapshot, RegionSnapshot, SnapshotMergeError, TaskSnapshot, TaskState,
};
use asupersync::record::region::RegionState;
use asupersync::types::{RegionId, TaskId, Time};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

const MAX_DELTAS: usize = 12;
const MAX_TASKS: usize = 8;
const MAX_CHILDREN: usize = 8;
const MAX_METADATA: usize = 32;
const MAX_MUTATIONS: usize = 4;
const MAX_APPEND_BYTES: usize = 16;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    base_region_slot: u8,
    deltas: Vec<DeltaInput>,
}

#[derive(Arbitrary, Debug)]
struct DeltaInput {
    same_region: bool,
    region_slot: u8,
    region_generation: u8,
    state: RegionStateInput,
    timestamp_secs: u16,
    sequence: u16,
    finalizer_count: u8,
    tasks: Vec<TaskInput>,
    children: Vec<ChildInput>,
    budget: BudgetInput,
    cancel_reason: Option<String>,
    metadata: Vec<u8>,
    mutations: Vec<WireMutation>,
}

#[derive(Arbitrary, Debug)]
struct TaskInput {
    task_slot: u8,
    task_generation: u8,
    state: TaskStateInput,
    priority: u8,
}

#[derive(Arbitrary, Debug)]
struct ChildInput {
    region_slot: u8,
    region_generation: u8,
}

#[derive(Arbitrary, Debug)]
struct BudgetInput {
    deadline_nanos: Option<u32>,
    polls_remaining: Option<u16>,
    cost_remaining: Option<u32>,
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum RegionStateInput {
    Open,
    Closing,
    Draining,
    Finalizing,
    Closed,
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum TaskStateInput {
    Pending,
    Running,
    Completed,
    Cancelled,
    Panicked,
}

#[derive(Arbitrary, Debug)]
enum WireMutation {
    Truncate(u16),
    Append(Vec<u8>),
    FlipByte { index: u8, mask: u8 },
    CorruptVersion(u8),
    CorruptState(u8),
}

fuzz_target!(|input: FuzzInput| {
    if input.deltas.len() > MAX_DELTAS {
        return;
    }

    let base_region = RegionId::new_for_test(u32::from(input.base_region_slot % 8), 0);
    let mut same_region = Vec::new();
    let mut mismatched_region = Vec::new();

    for delta in input.deltas {
        let snapshot = build_snapshot(base_region, &delta);
        let mut bytes = snapshot.to_bytes();
        apply_mutations(&mut bytes, &delta.mutations);

        if let Ok(parsed) = RegionSnapshot::from_bytes(&bytes) {
            let reparsed = RegionSnapshot::from_bytes(&parsed.to_bytes())
                .expect("serialized parsed snapshot must round-trip");
            assert_eq!(parsed.to_bytes(), reparsed.to_bytes());

            if parsed.region_id == base_region {
                same_region.push(parsed);
            } else {
                mismatched_region.push(parsed);
            }
        }
    }

    if let Some(seed) = same_region.first() {
        for other in &mismatched_region {
            assert!(
                matches!(
                    seed.merge_crdt(other),
                    Err(SnapshotMergeError::RegionMismatch { .. })
                ),
                "region mismatch should be reported without panicking",
            );
        }
    }

    if same_region.is_empty() {
        return;
    }

    let forward = fold_merge(&same_region).expect("same-region merge must succeed");
    let mut reverse_inputs = same_region.clone();
    reverse_inputs.reverse();
    let reverse = fold_merge(&reverse_inputs).expect("same-region reverse merge must succeed");

    assert_eq!(
        forward.to_bytes(),
        reverse.to_bytes(),
        "CRDT merge should converge under reordering",
    );

    if same_region.len() > 2 {
        let mut rotated_inputs = same_region.clone();
        rotated_inputs.rotate_left(1);
        let rotated = fold_merge(&rotated_inputs).expect("rotated merge must succeed");
        assert_eq!(
            forward.to_bytes(),
            rotated.to_bytes(),
            "CRDT merge should converge across alternate fold orders",
        );
    }

    let idempotent = forward
        .merge_crdt(&forward)
        .expect("self-merge must succeed for canonical snapshots");
    assert_eq!(forward.to_bytes(), idempotent.to_bytes());
    assert_unique_tasks(&forward);
    assert_unique_children(&forward);
});

fn build_snapshot(base_region: RegionId, delta: &DeltaInput) -> RegionSnapshot {
    let region_id = if delta.same_region {
        base_region
    } else {
        distinct_region(base_region, delta.region_slot, delta.region_generation)
    };

    RegionSnapshot {
        region_id,
        state: delta.state.into_region_state(),
        timestamp: Time::from_secs(u64::from(delta.timestamp_secs)),
        sequence: u64::from(delta.sequence),
        tasks: normalize_tasks(&delta.tasks),
        children: normalize_children(&delta.children),
        finalizer_count: u32::from(delta.finalizer_count),
        budget: BudgetSnapshot {
            deadline_nanos: delta.budget.deadline_nanos.map(u64::from),
            polls_remaining: delta.budget.polls_remaining.map(u32::from),
            cost_remaining: delta.budget.cost_remaining.map(u64::from),
        },
        cancel_reason: delta
            .cancel_reason
            .as_deref()
            .map(|reason| reason.chars().take(24).collect()),
        parent: Some(RegionId::new_for_test(0, 1)),
        metadata: normalize_metadata(&delta.metadata),
    }
}

fn distinct_region(base_region: RegionId, slot: u8, generation: u8) -> RegionId {
    let candidate = RegionId::new_for_test(u32::from(slot % 8), u32::from(generation % 4 + 1));
    if candidate == base_region {
        RegionId::new_for_test(u32::from((slot + 1) % 8), u32::from(generation % 4 + 1))
    } else {
        candidate
    }
}

fn normalize_tasks(tasks: &[TaskInput]) -> Vec<TaskSnapshot> {
    let mut merged: BTreeMap<(u32, u32), TaskSnapshot> = BTreeMap::new();
    for task in tasks.iter().take(MAX_TASKS) {
        let key = (
            u32::from(task.task_slot % 8),
            u32::from(task.task_generation % 4),
        );
        let candidate = TaskSnapshot {
            task_id: TaskId::new_for_test(key.0, key.1),
            state: task.state.into_task_state(),
            priority: task.priority,
        };
        merged
            .entry(key)
            .and_modify(|current| {
                if task_state_rank(candidate.state) >= task_state_rank(current.state) {
                    current.state = candidate.state;
                }
                current.priority = current.priority.max(candidate.priority);
            })
            .or_insert(candidate);
    }
    merged.into_values().collect()
}

fn normalize_children(children: &[ChildInput]) -> Vec<RegionId> {
    let mut merged = BTreeMap::new();
    for child in children.iter().take(MAX_CHILDREN) {
        let key = (
            u32::from(child.region_slot % 8),
            u32::from(child.region_generation % 4),
        );
        merged
            .entry(key)
            .or_insert_with(|| RegionId::new_for_test(key.0, key.1));
    }
    merged.into_values().collect()
}

fn normalize_metadata(metadata: &[u8]) -> Vec<u8> {
    let mut normalized: Vec<u8> = metadata.iter().copied().take(MAX_METADATA).collect();
    normalized.sort_unstable();
    normalized.dedup();
    normalized
}

fn apply_mutations(bytes: &mut Vec<u8>, mutations: &[WireMutation]) {
    for mutation in mutations.iter().take(MAX_MUTATIONS) {
        match mutation {
            WireMutation::Truncate(keep) => {
                bytes.truncate(usize::from(*keep).min(bytes.len()));
            }
            WireMutation::Append(extra) => {
                bytes.extend(extra.iter().copied().take(MAX_APPEND_BYTES));
            }
            WireMutation::FlipByte { index, mask } => {
                let len = bytes.len();
                if let Some(byte) = bytes.get_mut(usize::from(*index) % len.max(1)) {
                    *byte ^= *mask;
                }
            }
            WireMutation::CorruptVersion(version) => {
                if bytes.len() > 4 {
                    bytes[4] = *version;
                }
            }
            WireMutation::CorruptState(state) => {
                if bytes.len() > 13 {
                    bytes[13] = *state;
                }
            }
        }
    }
}

fn fold_merge(snapshots: &[RegionSnapshot]) -> Result<RegionSnapshot, SnapshotMergeError> {
    let mut iter = snapshots.iter();
    let first = iter.next().expect("non-empty snapshots").clone();
    iter.try_fold(first, |current, next| current.merge_crdt(next))
}

fn assert_unique_tasks(snapshot: &RegionSnapshot) {
    let mut seen = BTreeMap::new();
    for task in &snapshot.tasks {
        assert!(seen.insert(task.task_id.as_u64(), ()).is_none());
    }
}

fn assert_unique_children(snapshot: &RegionSnapshot) {
    let mut seen = BTreeMap::new();
    for child in &snapshot.children {
        assert!(seen.insert(child.as_u64(), ()).is_none());
    }
}

fn task_state_rank(state: TaskState) -> u8 {
    match state {
        TaskState::Pending => 0,
        TaskState::Running => 1,
        TaskState::Completed => 2,
        TaskState::Cancelled => 3,
        TaskState::Panicked => 4,
    }
}

impl RegionStateInput {
    fn into_region_state(self) -> RegionState {
        match self {
            Self::Open => RegionState::Open,
            Self::Closing => RegionState::Closing,
            Self::Draining => RegionState::Draining,
            Self::Finalizing => RegionState::Finalizing,
            Self::Closed => RegionState::Closed,
        }
    }
}

impl TaskStateInput {
    fn into_task_state(self) -> TaskState {
        match self {
            Self::Pending => TaskState::Pending,
            Self::Running => TaskState::Running,
            Self::Completed => TaskState::Completed,
            Self::Cancelled => TaskState::Cancelled,
            Self::Panicked => TaskState::Panicked,
        }
    }
}
