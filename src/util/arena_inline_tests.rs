    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    #[test]
    fn insert_and_get() {
        let mut arena = Arena::new();
        let idx = arena.insert(42);
        assert_eq!(arena.get(idx), Some(&42));
        assert_eq!(arena.len(), 1);
    }

    #[test]
    fn remove_and_reuse() {
        let mut arena = Arena::new();
        let idx1 = arena.insert(1);
        let idx2 = arena.insert(2);

        assert_eq!(arena.remove(idx1), Some(1));
        assert_eq!(arena.len(), 1);

        // Old index should be invalid
        assert_eq!(arena.get(idx1), None);

        // New insert should reuse the slot
        let idx3 = arena.insert(3);
        assert_eq!(idx3.index(), idx1.index());
        assert_ne!(idx3.generation(), idx1.generation());

        // Both remaining indices should work
        assert_eq!(arena.get(idx2), Some(&2));
        assert_eq!(arena.get(idx3), Some(&3));
    }

    #[test]
    fn generation_prevents_aba() {
        let mut arena = Arena::new();
        let idx1 = arena.insert(1);
        arena.remove(idx1);
        let idx2 = arena.insert(2);

        // Same slot, different generation
        assert_eq!(idx1.index(), idx2.index());
        assert_ne!(idx1.generation(), idx2.generation());

        // Old index should not work
        assert_eq!(arena.get(idx1), None);
        assert_eq!(arena.get(idx2), Some(&2));
    }

    #[test]
    fn insert_with_passes_assigned_index() {
        let mut arena = Arena::new();
        let idx = arena.insert_with(super::ArenaIndex::index);
        assert_eq!(arena.get(idx), Some(&idx.index()));
    }

    #[test]
    fn insert_with_panic_keeps_arena_empty_when_no_free_slots() {
        let mut arena = Arena::new();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = arena.insert_with(|_| -> u32 { panic!("boom") });
        }));
        assert!(result.is_err());
        assert!(arena.is_empty());
        assert_eq!(arena.len(), 0);

        let idx = arena.insert(7);
        assert_eq!(idx.index(), 0);
        assert_eq!(arena.get(idx), Some(&7));
    }

    #[test]
    fn insert_with_panic_preserves_free_list_when_reusing_slot() {
        let mut arena = Arena::new();
        let idx1 = arena.insert(10);
        let idx2 = arena.insert(20);
        assert_eq!(arena.remove(idx1), Some(10));
        assert_eq!(arena.len(), 1);

        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = arena.insert_with(|_| -> u32 { panic!("boom") });
        }));
        assert!(result.is_err());
        assert_eq!(arena.len(), 1);
        assert_eq!(arena.get(idx2), Some(&20));

        // The next insert should still reuse the previously freed slot.
        let idx3 = arena.insert(30);
        assert_eq!(idx3.index(), idx1.index());
        assert_eq!(arena.len(), 2);
    }

    #[test]
    fn retain_panic_preserves_invariants() {
        let mut arena = Arena::new();
        arena.insert(10);
        let idx2 = arena.insert(20);
        let idx3 = arena.insert(30);

        let result = catch_unwind(AssertUnwindSafe(|| {
            arena.retain(|v| {
                assert!(*v != 20, "boom");
                false // 10 is deleted before panic
            });
        }));

        assert!(result.is_err());

        // Before the fix, arena.len() would be 3 (unchanged) but element 0 was deleted
        assert_eq!(
            arena.len(),
            2,
            "len must reflect deletions that happened before the panic"
        );

        // Element 20 and 30 should still be accessible
        assert_eq!(arena.get(idx2), Some(&20));
        assert_eq!(arena.get(idx3), Some(&30));

        // Inserting a new element should reuse the freed slot (index 0)
        let new_idx = arena.insert(40);
        assert_eq!(new_idx.index(), 0, "must reuse freed slot");
    }

    #[test]
    fn test_retain() {
        let mut arena = Arena::new();
        let idx0 = arena.insert(0);
        let idx1 = arena.insert(1);
        let idx2 = arena.insert(2);
        let idx3 = arena.insert(3);

        assert_eq!(arena.len(), 4);

        // Remove odd numbers
        arena.retain(|&mut val| val % 2 == 0);

        assert_eq!(arena.len(), 2);
        assert_eq!(arena.get(idx0), Some(&0));
        assert_eq!(arena.get(idx1), None);
        assert_eq!(arena.get(idx2), Some(&2));
        assert_eq!(arena.get(idx3), None);

        // Insert new items - should reuse slots of 1 and 3 (indices 1 and 3)
        // Free list order is linear (0..N) after retain rebuilds it.
        // So first free should be 1, then 3.

        let idx_new_a = arena.insert(10);
        let idx_new_b = arena.insert(30);

        assert_eq!(idx_new_a.index(), 1);
        assert_eq!(idx_new_b.index(), 3);
        assert_eq!(arena.len(), 4);

        // Generations should be bumped
        assert_ne!(idx_new_a.generation(), idx1.generation());
        assert_ne!(idx_new_b.generation(), idx3.generation());
    }

    #[test]
    fn arena_index_debug() {
        let idx = ArenaIndex::new(5, 3);
        let dbg = format!("{idx:?}");
        assert_eq!(dbg, "ArenaIndex(5:3)");
    }

    #[test]
    fn arena_index_clone_copy() {
        let idx = ArenaIndex::new(1, 0);
        let idx2 = idx;
        let idx3 = idx;
        assert_eq!(idx2, idx3);
    }

    #[test]
    fn arena_index_eq_ne() {
        let a = ArenaIndex::new(1, 0);
        let b = ArenaIndex::new(1, 0);
        let c = ArenaIndex::new(1, 1);
        let d = ArenaIndex::new(2, 0);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn arena_index_ord() {
        let a = ArenaIndex::new(1, 0);
        let b = ArenaIndex::new(2, 0);
        let c = ArenaIndex::new(1, 1);
        assert!(a < b);
        assert!(a < c);
    }

    #[test]
    fn arena_index_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ArenaIndex::new(1, 0));
        set.insert(ArenaIndex::new(2, 0));
        set.insert(ArenaIndex::new(1, 0)); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn arena_index_accessors() {
        let idx = ArenaIndex::new(42, 7);
        assert_eq!(idx.index(), 42);
        assert_eq!(idx.generation(), 7);
    }

    #[test]
    fn arena_debug() {
        let arena: Arena<i32> = Arena::new();
        let dbg = format!("{arena:?}");
        assert!(dbg.contains("Arena"));
    }

    #[test]
    fn arena_default() {
        let arena: Arena<i32> = Arena::default();
        assert!(arena.is_empty());
        assert_eq!(arena.len(), 0);
    }

    #[test]
    fn arena_with_capacity() {
        let arena: Arena<i32> = Arena::with_capacity(16);
        assert!(arena.is_empty());
        assert_eq!(arena.len(), 0);
    }

    #[test]
    fn arena_reserved_bytes_track_slot_capacity() {
        let arena: Arena<i32> = Arena::with_capacity(16);
        assert_eq!(arena.capacity(), 16);
        assert_eq!(
            arena.reserved_bytes(),
            Arena::<i32>::estimated_bytes_for_capacity(16)
        );
    }

    #[test]
    fn arena_get_mut() {
        let mut arena = Arena::new();
        let idx = arena.insert(10);
        if let Some(val) = arena.get_mut(idx) {
            *val = 20;
        }
        assert_eq!(arena.get(idx), Some(&20));
    }

    #[test]
    fn arena_contains() {
        let mut arena = Arena::new();
        let idx = arena.insert(1);
        assert!(arena.contains(idx));
        arena.remove(idx);
        assert!(!arena.contains(idx));
    }

    #[test]
    fn arena_iter() {
        let mut arena = Arena::new();
        let idx1 = arena.insert(10);
        let idx2 = arena.insert(20);
        let items: Vec<_> = arena.iter().collect();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], (idx1, &10));
        assert_eq!(items[1], (idx2, &20));
    }

    #[test]
    fn arena_drain_values() {
        let mut arena = Arena::new();
        arena.insert(1);
        arena.insert(2);
        arena.insert(3);
        assert_eq!(arena.len(), 3);
        let drained: Vec<_> = arena.drain_values().collect();
        assert_eq!(drained, vec![1, 2, 3]);
        assert!(arena.is_empty());
    }

    #[test]
    fn arena_drain_values_partial_drop() {
        let mut arena = Arena::new();
        arena.insert(1);
        arena.insert(2);
        arena.insert(3);
        {
            let mut drain = arena.drain_values();
            let _ = drain.next(); // take one
            // drop drain - should drain remaining
        }
        assert!(arena.is_empty());
    }

    /// br-asupersync-lh4z78 L3: a drain hands the lowest indices out first
    /// and stops scanning at the last occupied slot, so an arena that once
    /// held many entries does not cost its peak size on every later drain.
    #[test]
    fn drain_reuses_the_lowest_indices_and_stops_at_the_last_value() {
        let mut arena = Arena::new();
        let peak: Vec<_> = (0..64).map(|value| arena.insert(value)).collect();
        assert_eq!(arena.drain_values().count(), 64);

        let first = arena.insert(100);
        let second = arena.insert(101);
        assert_eq!(
            (first.index(), second.index()),
            (0, 1),
            "lowest slots first"
        );

        let mut drain = arena.drain_values();
        assert_eq!(drain.next(), Some(100));
        assert_eq!(drain.next(), Some(101));
        assert_eq!(drain.next(), None);
        assert_eq!(
            drain.pos, 2,
            "the scan stopped after slot 1, not at slot 63"
        );
        drop(drain);

        assert!(peak.iter().all(|index| arena.get(*index).is_none()));
        let reused: Vec<u32> = (0..64).map(|value| arena.insert(value).index()).collect();
        assert_eq!(
            reused,
            (0..64).collect::<Vec<u32>>(),
            "every slot is reusable"
        );
    }

    /// br-asupersync-rvz1tq — generation-overflow safety: removing a slot
    /// whose current generation is `u32::MAX` retires the slot permanently
    /// (it must not return to the free list and be reissued at generation 0,
    /// which would alias the very first ArenaIndex ever issued for that
    /// slot). In debug builds this case also `debug_assert!`s — verified
    /// here by skipping the assertion path and operating directly on a
    /// hand-poisoned slot.
    #[test]
    fn remove_at_generation_max_retires_slot_permanently() {
        let mut arena: Arena<u32> = Arena::new();
        let idx = arena.insert(7);

        // Hand-poison the slot's generation to u32::MAX - 1 so that one more
        // remove cycle reaches u32::MAX. The first remove brings cur_gen to
        // u32::MAX; the slot is now Vacant at generation u32::MAX. Insert
        // again: cur_gen on the next Occupied is u32::MAX. Now remove —
        // this is the case the rvz1tq guard catches.
        if let Some(Slot::Occupied { generation, .. }) = arena.slots.get_mut(idx.index() as usize) {
            *generation = u32::MAX;
        }
        let recovered = ArenaIndex {
            index: idx.index(),
            generation: u32::MAX,
        };

        // In a release build this hits the retirement path; in debug it
        // also fires `debug_assert!`. We only check the side effect: after
        // removal the slot must NOT be on the free list.
        let prev_free_head = arena.free_head;
        let val =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| arena.remove(recovered)));
        // Whether or not the debug assertion fired, the operation either
        // panicked OR completed without re-adding the slot to the free list.
        match val {
            Ok(Some(7)) => {
                // Release-style behavior: slot was removed and retired.
                assert_eq!(
                    arena.free_head, prev_free_head,
                    "retired slot must not be added to the free list"
                );
            }
            Ok(Some(v)) => panic!("expected 7, got {v}"),
            Ok(None) => panic!("expected to remove the value"),
            Err(_) => {
                // Debug-style behavior: debug_assert fired. Acceptable.
            }
        }
    }

    /// br-asupersync-njd135 — `iter()` constructs ArenaIndex via an explicit
    /// `u32::try_from` rather than a silent `i as u32` cast. Sanity-check
    /// the happy path: indices yielded match what insert returned.
    #[test]
    fn iter_yields_well_formed_indices() {
        let mut arena: Arena<u32> = Arena::new();
        let a = arena.insert(1);
        let b = arena.insert(2);
        let c = arena.insert(3);
        let observed: Vec<ArenaIndex> = arena.iter().map(|(i, _)| i).collect();
        assert_eq!(observed, vec![a, b, c]);
        // The cast is `u32::try_from(usize) -> Result<u32, _>`, so a hidden
        // truncation would now error rather than silently produce a bogus
        // ArenaIndex. We can't construct a 2^32-slot arena in a unit test,
        // but the panic message is part of the contract.
    }

    /// br-asupersync-01oghn L2: removing a slot whose generation reaches
    /// `ARENA_MAX_GENERATION` (2^31 - 1) retires the slot permanently so that
    /// no future arena index is minted with bit 31 set. Debug builds flag the
    /// retirement with a panic; release builds keep the value and never reuse
    /// the slot.
    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(expected = "ArenaIndex generation wrap detected")
    )]
    fn remove_at_generation_max_2_to_31_minus_1_retires_slot() {
        let mut arena: Arena<u32> = Arena::new();
        let idx = arena.insert(42);

        if let Some(Slot::Occupied { generation, .. }) = arena.slots.get_mut(idx.index() as usize) {
            *generation = ARENA_MAX_GENERATION;
        }
        let recovered = ArenaIndex {
            index: idx.index(),
            generation: ARENA_MAX_GENERATION,
        };

        let prev_free_head = arena.free_head;
        assert_eq!(arena.remove(recovered), Some(42));
        assert_eq!(
            arena.free_head, prev_free_head,
            "slot retired at ARENA_MAX_GENERATION must not be added to free list"
        );
        assert_ne!(
            arena.insert(7).index(),
            idx.index(),
            "a retired slot is never reused"
        );
    }

    /// br-asupersync-01oghn L2: verify that valid arena indices never collide
    /// with provisional spawn mailbox IDs (which reserve bit 31).
    #[test]
    fn arena_issued_indices_never_satisfy_is_spawn_mailbox_id() {
        use crate::runtime::spawn_mailbox::is_spawn_mailbox_id;
        use crate::types::TaskId;

        let mut arena: Arena<u32> = Arena::new();
        let idx = arena.insert(100);
        assert!(!is_spawn_mailbox_id(TaskId::from_arena(idx)));

        // The last generation a slot is ever issued with: removed one below
        // the cap (not yet retired), the slot comes back at the cap itself.
        if let Some(Slot::Occupied { generation, .. }) = arena.slots.get_mut(idx.index() as usize) {
            *generation = ARENA_MAX_GENERATION - 1;
        }
        let below_cap = ArenaIndex {
            index: idx.index(),
            generation: ARENA_MAX_GENERATION - 1,
        };
        assert_eq!(arena.remove(below_cap), Some(100));
        let last = arena.insert(101);
        assert_eq!(last.index(), idx.index(), "the slot is reused once more");
        assert_eq!(last.generation(), ARENA_MAX_GENERATION);
        assert!(!is_spawn_mailbox_id(TaskId::from_arena(last)));
    }
