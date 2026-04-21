//! Structure-aware fuzz target for `RegionHeap`.
//!
//! Exercises mixed-size and high-alignment allocation patterns, stale-handle
//! reuse, and eager reclamation. The invariants are:
//! - no two live handles overlap on the same slot
//! - stale handles never become valid again after slot reuse
//! - `reclaim_all` clears every live handle and restores accounting
//! - mixed-size and high-alignment values remain retrievable and mutable

#![no_main]

use arbitrary::Arbitrary;
use asupersync::runtime::region_heap::{global_alloc_count, HeapIndex, RegionHeap};
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;

const MAX_OPS: usize = 96;
const MAX_BYTES: usize = 96;
const MAX_CAPACITY: usize = 64;

#[repr(align(64))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct AlignedBlock([u8; 64]);

#[derive(Arbitrary, Clone, Debug)]
struct FuzzInput {
    initial_capacity: u8,
    ops: Vec<HeapOp>,
}

#[derive(Arbitrary, Clone, Debug)]
enum HeapOp {
    AllocByte { value: u8 },
    AllocWord { value: u64 },
    AllocBytes { bytes: Vec<u8> },
    AllocAligned { bytes: Vec<u8> },
    CheckHandle { handle_slot: u8 },
    MutateHandle { handle_slot: u8, delta: u8 },
    DeallocHandle { handle_slot: u8 },
    ReclaimAll,
}

#[derive(Clone, Debug)]
enum ValueModel {
    Byte(u8),
    Word(u64),
    Bytes(Vec<u8>),
    Aligned([u8; 64]),
}

#[derive(Clone, Debug)]
struct HandleRecord {
    handle: HeapIndex,
    value: ValueModel,
    live: bool,
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = arbitrary::Unstructured::new(data).arbitrary::<FuzzInput>() else {
        return;
    };

    exercise(input);
});

fn exercise(input: FuzzInput) {
    let baseline = global_alloc_count();
    let capacity = usize::from(input.initial_capacity).min(MAX_CAPACITY);
    let mut heap = RegionHeap::with_capacity(capacity);
    let mut records = Vec::new();

    for op in input.ops.into_iter().take(MAX_OPS) {
        match op {
            HeapOp::AllocByte { value } => {
                let handle = heap.alloc(value);
                insert_live_record(&heap, &mut records, handle, ValueModel::Byte(value));
            }
            HeapOp::AllocWord { value } => {
                let handle = heap.alloc(value);
                insert_live_record(&heap, &mut records, handle, ValueModel::Word(value));
            }
            HeapOp::AllocBytes { bytes } => {
                let value = truncate_bytes(&bytes);
                let handle = heap.alloc(value.clone());
                insert_live_record(&heap, &mut records, handle, ValueModel::Bytes(value));
            }
            HeapOp::AllocAligned { bytes } => {
                let value = fill_aligned(&bytes);
                let handle = heap.alloc(AlignedBlock(value));
                insert_live_record(&heap, &mut records, handle, ValueModel::Aligned(value));
            }
            HeapOp::CheckHandle { handle_slot } => {
                if let Some(record) = pick_record(&records, handle_slot) {
                    assert_record_state(&heap, record);
                }
            }
            HeapOp::MutateHandle { handle_slot, delta } => {
                if let Some(record) = pick_record_mut(&mut records, handle_slot) {
                    mutate_record(&mut heap, record, delta);
                }
            }
            HeapOp::DeallocHandle { handle_slot } => {
                if let Some(record) = pick_record_mut(&mut records, handle_slot) {
                    let deallocated = heap.dealloc(record.handle);
                    assert_eq!(
                        deallocated, record.live,
                        "dealloc result must match liveness"
                    );
                    if record.live {
                        record.live = false;
                        assert!(!heap.contains(record.handle));
                    }
                }
            }
            HeapOp::ReclaimAll => {
                heap.reclaim_all();
                for record in &mut records {
                    record.live = false;
                }
            }
        }

        assert_heap_invariants(&heap, &records, baseline);
    }

    heap.reclaim_all();
    for record in &records {
        assert!(!heap.contains(record.handle));
    }
    assert_heap_invariants(&heap, &records, baseline);
    drop(heap);
    assert_eq!(
        global_alloc_count(),
        baseline,
        "region heap fuzz run must not leak allocations"
    );
}

fn insert_live_record(
    heap: &RegionHeap,
    records: &mut Vec<HandleRecord>,
    handle: HeapIndex,
    value: ValueModel,
) {
    assert!(
        records
            .iter()
            .filter(|record| record.live)
            .all(|record| record.handle != handle),
        "fresh handle must not duplicate an existing live handle"
    );
    records.push(HandleRecord {
        handle,
        value,
        live: true,
    });
    assert_record_state(heap, records.last().expect("just pushed"));
}

fn assert_heap_invariants(heap: &RegionHeap, records: &[HandleRecord], baseline: u64) {
    let live_records: Vec<&HandleRecord> = records.iter().filter(|record| record.live).collect();
    let mut live_handles = HashSet::new();
    let mut live_slots = HashSet::new();

    for record in &live_records {
        assert!(live_handles.insert(record.handle));
        assert!(
            live_slots.insert(record.handle.index()),
            "two live handles must not share a slot"
        );
        assert_record_state(heap, record);
    }

    for record in records.iter().filter(|record| !record.live) {
        assert!(!heap.contains(record.handle));
    }

    let live_count = live_records.len();
    assert_eq!(heap.len(), live_count);
    assert_eq!(heap.is_empty(), live_count == 0);
    assert_eq!(heap.stats().live, live_count as u64);
    assert_eq!(
        global_alloc_count(),
        baseline + live_count as u64,
        "global allocation count must track live region heap entries"
    );
}

fn assert_record_state(heap: &RegionHeap, record: &HandleRecord) {
    if !record.live {
        assert!(!heap.contains(record.handle));
        match &record.value {
            ValueModel::Byte(_) => assert!(heap.get::<u8>(record.handle).is_none()),
            ValueModel::Word(_) => assert!(heap.get::<u64>(record.handle).is_none()),
            ValueModel::Bytes(_) => assert!(heap.get::<Vec<u8>>(record.handle).is_none()),
            ValueModel::Aligned(_) => assert!(heap.get::<AlignedBlock>(record.handle).is_none()),
        }
        return;
    }

    assert!(heap.contains(record.handle));
    match &record.value {
        ValueModel::Byte(value) => {
            assert_eq!(heap.get::<u8>(record.handle), Some(value));
            assert!(heap.get::<u64>(record.handle).is_none());
        }
        ValueModel::Word(value) => {
            assert_eq!(heap.get::<u64>(record.handle), Some(value));
            assert!(heap.get::<u8>(record.handle).is_none());
        }
        ValueModel::Bytes(bytes) => {
            assert_eq!(heap.get::<Vec<u8>>(record.handle), Some(bytes));
            assert!(heap.get::<AlignedBlock>(record.handle).is_none());
        }
        ValueModel::Aligned(bytes) => {
            let expected = AlignedBlock(*bytes);
            assert_eq!(heap.get::<AlignedBlock>(record.handle), Some(&expected));
            assert!(heap.get::<Vec<u8>>(record.handle).is_none());
        }
    }
}

fn mutate_record(heap: &mut RegionHeap, record: &mut HandleRecord, delta: u8) {
    if !record.live {
        assert!(heap.get_mut::<u8>(record.handle).is_none());
        return;
    }

    match &mut record.value {
        ValueModel::Byte(value) => {
            let mutated = value.wrapping_add(delta);
            *heap.get_mut::<u8>(record.handle).expect("live byte handle") = mutated;
            *value = mutated;
        }
        ValueModel::Word(value) => {
            let mutated = value.rotate_left(u32::from(delta & 31)) ^ u64::from(delta);
            *heap.get_mut::<u64>(record.handle).expect("live word handle") = mutated;
            *value = mutated;
        }
        ValueModel::Bytes(bytes) => {
            let slot = usize::from(delta) % (bytes.len().saturating_add(1).max(1));
            let stored = heap
                .get_mut::<Vec<u8>>(record.handle)
                .expect("live bytes handle");
            if slot == stored.len() && stored.len() < MAX_BYTES {
                stored.push(delta);
                bytes.push(delta);
            } else if !stored.is_empty() {
                let index = slot % stored.len();
                stored[index] ^= delta;
                bytes[index] ^= delta;
            }
        }
        ValueModel::Aligned(bytes) => {
            let slot = usize::from(delta) % bytes.len();
            let stored = heap
                .get_mut::<AlignedBlock>(record.handle)
                .expect("live aligned handle");
            stored.0[slot] ^= delta;
            bytes[slot] ^= delta;
        }
    }
}

fn pick_record(records: &[HandleRecord], handle_slot: u8) -> Option<&HandleRecord> {
    if records.is_empty() {
        None
    } else {
        records.get(usize::from(handle_slot) % records.len())
    }
}

fn pick_record_mut(records: &mut [HandleRecord], handle_slot: u8) -> Option<&mut HandleRecord> {
    if records.is_empty() {
        None
    } else {
        let index = usize::from(handle_slot) % records.len();
        records.get_mut(index)
    }
}

fn truncate_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().copied().take(MAX_BYTES).collect()
}

fn fill_aligned(bytes: &[u8]) -> [u8; 64] {
    let mut aligned = [0u8; 64];
    if bytes.is_empty() {
        return aligned;
    }
    for (dst, src) in aligned.iter_mut().zip(bytes.iter().copied().cycle()) {
        *dst = src;
    }
    aligned
}
