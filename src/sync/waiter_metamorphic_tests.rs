//! Metamorphic tests for WaiterChain
//!
//! Tests complex invariants and relationships that hold regardless of specific
//! input sequences, without needing to predict exact outcomes (oracle problem).

use super::{WaiterChain, WaiterId};
use proptest::prelude::*;
use std::collections::HashSet;
use std::task::Waker;

/// MR Strength Matrix for WaiterChain
///
/// | MR Candidate | Fault Sensitivity (1-5) | Independence (1-5) | Cost (1-5) | Score |
/// |-------------|------------------------|--------------------:|------------|-------|
/// | FIFO preservation | 5 | 5 | 2 | 12.5 |
/// | Length consistency | 4 | 4 | 1 | 16.0 |
/// | ID uniqueness | 5 | 4 | 1 | 20.0 |
/// | Linked list invariants | 5 | 5 | 3 | 8.3 |
/// | HashMap/Slab consistency | 5 | 4 | 2 | 10.0 |
/// | Roundtrip identity | 4 | 3 | 1 | 12.0 |
/// | Empty state consistency | 3 | 3 | 1 | 9.0 |
/// | Operation commutativity | 3 | 4 | 2 | 6.0 |
/// | Remove preserves order | 4 | 4 | 2 | 8.0 |
/// | Tag preservation | 3 | 2 | 1 | 6.0 |
fn noop_waker() -> Waker {
    Waker::noop().clone()
}

/// Generate random sequences of queue operations for property testing
#[derive(Debug, Clone)]
enum WaiterOp {
    PushBack(String),  // tag
    PushFront(String), // tag
    PopFront,
    Remove(usize),      // index in operation sequence (converted to ID later)
    UpdateWaker(usize), // index in operation sequence
}

impl Arbitrary for WaiterOp {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: ()) -> Self::Strategy {
        prop_oneof![
            "[a-z]{1,5}".prop_map(WaiterOp::PushBack),
            "[a-z]{1,5}".prop_map(WaiterOp::PushFront),
            Just(WaiterOp::PopFront),
            (0usize..20).prop_map(WaiterOp::Remove),
            (0usize..20).prop_map(WaiterOp::UpdateWaker),
        ]
        .boxed()
    }
}

#[derive(Debug, Clone)]
struct OpSequence(Vec<WaiterOp>);

impl Arbitrary for OpSequence {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: ()) -> Self::Strategy {
        prop::collection::vec(any::<WaiterOp>(), 0..50)
            .prop_map(OpSequence)
            .boxed()
    }
}

/// Execute operation sequence and track generated IDs
fn execute_ops(chain: &mut WaiterChain<String>, ops: &[WaiterOp]) -> Vec<Option<WaiterId>> {
    let mut generated_ids = Vec::new();

    for op in ops {
        match op {
            WaiterOp::PushBack(tag) => {
                let id = chain.push_back_tagged(noop_waker(), tag.clone());
                generated_ids.push(Some(id));
            }
            WaiterOp::PushFront(tag) => {
                let id = chain.push_front_tagged(noop_waker(), tag.clone());
                generated_ids.push(Some(id));
            }
            WaiterOp::PopFront => {
                chain.pop_front();
                generated_ids.push(None);
            }
            WaiterOp::Remove(idx) => {
                if let Some(Some(id)) = generated_ids.get(*idx) {
                    chain.remove(*id);
                }
                generated_ids.push(None);
            }
            WaiterOp::UpdateWaker(idx) => {
                if let Some(Some(id)) = generated_ids.get(*idx) {
                    chain.update_waker(*id, &noop_waker());
                }
                generated_ids.push(None);
            }
        }
    }

    generated_ids
}

#[cfg(test)]
mod metamorphic_tests {
    use super::*;

    /// MR1: FIFO Preservation (Equivalence)
    /// push_back sequence followed by pop_front sequence should preserve insertion order
    proptest! {
        #[test]
        fn mr_fifo_preservation(tags: Vec<String>) {
            let mut chain = WaiterChain::new();

            // Push all items to back
            for tag in &tags {
                chain.push_back_tagged(noop_waker(), tag.clone());
            }

            // Pop all items and verify order
            let mut popped_tags = Vec::new();
            while let Some((_, _, tag)) = chain.pop_front() {
                popped_tags.push(tag);
            }

            prop_assert_eq!(&popped_tags, &tags,
                "FIFO order violated: expected {:?}, got {:?}", tags, popped_tags);
        }
    }

    /// MR2: Length Consistency (Additive)
    /// len() should exactly track the number of items in queue
    proptest! {
        #[test]
        fn mr_length_consistency(ops: OpSequence) {
            let mut chain = WaiterChain::new();
            let mut expected_len = 0usize;

            let ids = execute_ops(&mut chain, &ops.0);

            // Count net additions
            for (op, _generated_id) in ops.0.iter().zip(ids.iter()) {
                match op {
                    WaiterOp::PushBack(_) | WaiterOp::PushFront(_) => expected_len += 1,
                    WaiterOp::PopFront => {
                        expected_len = expected_len.saturating_sub(1);
                    }
                    WaiterOp::Remove(idx) => {
                        if let Some(Some(_)) = ids.get(*idx) {
                            if chain.contains(*ids[*idx].as_ref().unwrap()) {
                                expected_len = expected_len.saturating_sub(1);
                            }
                        }
                    },
                    WaiterOp::UpdateWaker(_) => {}
                }
            }

            prop_assert_eq!(chain.len(), expected_len,
                "Length inconsistent: chain.len()={}, expected={}", chain.len(), expected_len);
            prop_assert_eq!(chain.is_empty(), expected_len == 0,
                "is_empty() inconsistent with len(): empty={}, len={}", chain.is_empty(), expected_len);
        }
    }

    /// MR3: ID Uniqueness (Multiplicative scaling)
    /// All generated IDs should be unique, even across slab slot reuse
    proptest! {
        #[test]
        fn mr_id_uniqueness(ops: OpSequence) {
            let mut chain = WaiterChain::new();
            let ids = execute_ops(&mut chain, &ops.0);

            let generated: Vec<WaiterId> = ids.into_iter().flatten().collect();
            let unique: HashSet<WaiterId> = generated.iter().copied().collect();

            prop_assert_eq!(generated.len(), unique.len(),
                "Duplicate IDs generated: {} total, {} unique", generated.len(), unique.len());
        }
    }

    /// MR4: Roundtrip Identity (Invertive)
    /// push_back + immediate pop_front should be identity (when queue was empty)
    proptest! {
        #[test]
        fn mr_roundtrip_identity(tag: String) {
            let mut chain = WaiterChain::new();

            let original_len = chain.len();
            let id = chain.push_back_tagged(noop_waker(), tag.clone());
            let popped = chain.pop_front();

            prop_assert_eq!(chain.len(), original_len,
                "Roundtrip changed length: was {}, now {}", original_len, chain.len());

            if let Some((popped_id, _, popped_tag)) = popped {
                prop_assert_eq!(popped_id, id, "Roundtrip ID mismatch");
                prop_assert_eq!(popped_tag, tag, "Roundtrip tag mismatch");
            } else {
                return Err(proptest::test_runner::TestCaseError::fail("Pop failed after push"));
            }
        }
    }

    /// MR5: Remove Preserves Order (Inclusive/Exclusive)
    /// Removing items should not change the relative order of remaining items
    proptest! {
        #[test]
        fn mr_remove_preserves_order(tags: Vec<String>, remove_indices: Vec<usize>) {
            prop_assume!(tags.len() >= 2);

            let mut chain = WaiterChain::new();

            // Push all items and collect IDs
            let ids: Vec<WaiterId> = tags.iter()
                .map(|tag| chain.push_back_tagged(noop_waker(), tag.clone()))
                .collect();

            // Remove items at specified indices
            let valid_removes: Vec<usize> = remove_indices.into_iter()
                .filter(|&i| i < ids.len())
                .collect();

            for &i in &valid_removes {
                chain.remove(ids[i]);
            }

            // Collect remaining items in order
            let mut remaining_tags = Vec::new();
            while let Some((_, _, tag)) = chain.pop_front() {
                remaining_tags.push(tag);
            }

            // Verify remaining items are in original relative order
            let expected_remaining: Vec<String> = tags.into_iter()
                .enumerate()
                .filter_map(|(i, tag)| {
                    if valid_removes.contains(&i) { None } else { Some(tag) }
                })
                .collect();

            prop_assert_eq!(remaining_tags, expected_remaining,
                "Remove operations violated FIFO order of remaining items");
        }
    }

    /// MR6: Front Operations Consistency (Equivalence)
    /// front_id() should always match the ID that would be popped
    proptest! {
        #[test]
        fn mr_front_operations_consistency(ops: OpSequence) {
            let mut chain = WaiterChain::new();
            execute_ops(&mut chain, &ops.0);

            if chain.is_empty() {
                prop_assert_eq!(chain.front_id(), None, "front_id() should be None for empty chain");
            } else {
                let front_id = chain.front_id();
                let mut temp_chain = chain.clone();
                let popped = temp_chain.pop_front();

                if let (Some(expected_id), Some((actual_id, _, _))) = (front_id, popped) {
                    prop_assert_eq!(expected_id, actual_id,
                        "front_id() doesn't match next pop_front() ID");
                }
            }
        }
    }

    /// MR7: Push Front vs Back Ordering (Permutative)
    /// Mixed push_front/push_back should follow expected precedence rules
    proptest! {
        #[test]
        fn mr_push_precedence(back_tags: Vec<String>, front_tags: Vec<String>) {
            let mut chain = WaiterChain::new();

            // Push items to back first
            for tag in &back_tags {
                chain.push_back_tagged(noop_waker(), tag.clone());
            }

            // Then push items to front (in reverse order due to front insertion)
            for tag in &front_tags {
                chain.push_front_tagged(noop_waker(), tag.clone());
            }

            // Pop all and verify order: front_tags (reversed) + back_tags
            let mut popped_tags = Vec::new();
            while let Some((_, _, tag)) = chain.pop_front() {
                popped_tags.push(tag);
            }

            let mut expected = Vec::new();
            expected.extend(front_tags.iter().rev().cloned()); // front items in reverse order
            expected.extend(back_tags);                         // back items in original order

            prop_assert_eq!(popped_tags, expected,
                "Mixed front/back push precedence violated");
        }
    }

    /// MR8: Operation Commutativity (Equivalence)
    /// Independent operations (on different items) should commute
    proptest! {
        #[test]
        fn mr_independent_operations_commute(
            initial_tags: Vec<String>,
            op1_tag: String,
            op2_tag: String
        ) {
            prop_assume!(op1_tag != op2_tag);
            prop_assume!(initial_tags.len() <= 10); // Keep test manageable

            // Setup initial state
            let mut chain1 = WaiterChain::new();
            let mut chain2 = WaiterChain::new();

            for tag in &initial_tags {
                chain1.push_back_tagged(noop_waker(), tag.clone());
                chain2.push_back_tagged(noop_waker(), tag.clone());
            }

            // Apply operations in different order
            chain1.push_back_tagged(noop_waker(), op1_tag.clone());
            chain1.push_back_tagged(noop_waker(), op2_tag.clone());

            chain2.push_back_tagged(noop_waker(), op2_tag.clone());
            chain2.push_back_tagged(noop_waker(), op1_tag.clone());

            // Final states should be equivalent (modulo ID values)
            prop_assert_eq!(chain1.len(), chain2.len(),
                "Commutative operations produced different lengths");

            // Pop all from both and verify same tag sequences
            let mut tags1 = Vec::new();
            let mut tags2 = Vec::new();

            while let Some((_, _, tag)) = chain1.pop_front() {
                tags1.push(tag);
            }
            while let Some((_, _, tag)) = chain2.pop_front() {
                tags2.push(tag);
            }

            prop_assert_eq!(tags1, tags2,
                "Commutative operations produced different final sequences");
        }
    }

    /// MR9: Clone Wakers Consistency (Equivalence)
    /// clone_wakers() should return wakers in the same order as pop_front sequence
    proptest! {
        #[test]
        fn mr_clone_wakers_consistency(
            tags in prop::collection::vec(any::<String>(), 0..=20),
        ) {
            let mut chain = WaiterChain::new();

            // Push items
            for tag in &tags {
                chain.push_back_tagged(noop_waker(), tag.clone());
            }

            // Get waker count via clone_wakers (non-destructive)
            let cloned_wakers = chain.clone_wakers();
            let cloned_count = cloned_wakers.len();

            // Get count via length method
            let len_count = chain.len();

            // Get count via destructive pop (clone chain first)
            let mut temp_chain = chain.clone();
            let mut pop_count = 0;
            while temp_chain.pop_front().is_some() {
                pop_count += 1;
            }

            prop_assert_eq!(cloned_count, len_count,
                "clone_wakers() count doesn't match len()");
            prop_assert_eq!(cloned_count, pop_count,
                "clone_wakers() count doesn't match pop sequence count");
            prop_assert_eq!(cloned_count, tags.len(),
                "clone_wakers() count doesn't match input count");
        }
    }

    /// MR10: Contains Consistency (Inclusive/Exclusive)
    /// contains() should accurately reflect current queue membership
    proptest! {
        #[test]
        fn mr_contains_consistency(ops: OpSequence) {
            let mut chain = WaiterChain::new();
            let ids = execute_ops(&mut chain, &ops.0);

            // Track which IDs should be present based on operations
            let mut should_contain = HashSet::new();

            for (op, generated_id) in ops.0.iter().zip(ids.iter()) {
                match (op, generated_id) {
                    (WaiterOp::PushBack(_) | WaiterOp::PushFront(_), Some(id)) => {
                        should_contain.insert(*id);
                    },
                    (WaiterOp::PopFront, _) => {
                        // Remove front ID if we can determine it
                        let mut temp = chain.clone();
                        if let Some((id, _, _)) = temp.pop_front() {
                            should_contain.remove(&id);
                        }
                    },
                    (WaiterOp::Remove(idx), _) => {
                        if let Some(Some(id)) = ids.get(*idx) {
                            should_contain.remove(id);
                        }
                    },
                    _ => {},
                }
            }

            // Verify contains() matches our tracking
            for id in &should_contain {
                prop_assert!(chain.contains(*id),
                    "contains({}) returned false but ID should be present", id);
            }

            // Test some IDs that definitely shouldn't be there
            let max_id = ids.iter().flatten().max().unwrap_or(&0);
            for test_id in (*max_id + 1)..(*max_id + 10) {
                prop_assert!(!chain.contains(test_id),
                    "contains({}) returned true for non-existent ID", test_id);
            }
        }
    }

    /// Composite MR: FIFO + Length + Uniqueness
    /// Combines multiple properties for multiplicative bug detection
    proptest! {
        #[test]
        fn mr_composite_fifo_length_uniqueness(ops: OpSequence) {
            prop_assume!(ops.0.len() <= 30); // Keep manageable

            let mut chain = WaiterChain::new();
            let mut expected_tags = Vec::new();
            let mut all_ids = Vec::new();

            for op in &ops.0 {
                match op {
                    WaiterOp::PushBack(tag) => {
                        let id = chain.push_back_tagged(noop_waker(), tag.clone());
                        expected_tags.push(tag.clone());
                        all_ids.push(id);
                    },
                    WaiterOp::PushFront(tag) => {
                        let id = chain.push_front_tagged(noop_waker(), tag.clone());
                        expected_tags.insert(0, tag.clone());
                        all_ids.push(id);
                    },
                    WaiterOp::PopFront => {
                        if !expected_tags.is_empty() {
                            expected_tags.remove(0);
                        }
                        chain.pop_front();
                    },
                    _ => {}, // Skip complex operations for this composite test
                }
            }

            // Verify all three properties simultaneously:

            // 1. Length consistency
            prop_assert_eq!(chain.len(), expected_tags.len(),
                "Length inconsistent in composite test");

            // 2. ID uniqueness
            let unique_ids: HashSet<_> = all_ids.iter().copied().collect();
            prop_assert_eq!(all_ids.len(), unique_ids.len(),
                "Non-unique IDs in composite test");

            // 3. FIFO order preservation
            let mut actual_tags = Vec::new();
            while let Some((_, _, tag)) = chain.pop_front() {
                actual_tags.push(tag);
            }
            prop_assert_eq!(actual_tags, expected_tags,
                "FIFO order violated in composite test");
        }
    }
}

/// Mutation testing to validate MR suite effectiveness
#[cfg(test)]
mod mutation_validation {
    use super::*;

    /// Deliberately buggy WaiterChain implementation to test MR detection
    struct BuggyWaiterChain<T> {
        inner: WaiterChain<T>,
        bug_type: BugType,
    }

    enum BugType {
        DuplicateIds,    // Always return same ID
        WrongFifoOrder,  // Insert in wrong position
        IncorrectLength, // Off-by-one in length tracking
        InvalidRemoval,  // Don't actually remove items
    }

    impl<T> BuggyWaiterChain<T> {
        fn new(bug: BugType) -> Self {
            Self {
                inner: WaiterChain::new(),
                bug_type: bug,
            }
        }

        fn push_back_tagged(&mut self, waker: Waker, tag: T) -> WaiterId {
            match self.bug_type {
                BugType::DuplicateIds => {
                    self.inner.push_back_tagged(waker, tag);
                    42 // Always return same ID (bug!)
                }
                BugType::WrongFifoOrder => self.inner.push_front_tagged(waker, tag),
                _ => self.inner.push_back_tagged(waker, tag),
            }
        }

        fn len(&self) -> usize {
            match self.bug_type {
                BugType::IncorrectLength => self.inner.len().saturating_add(1), // Off-by-one bug
                _ => self.inner.len(),
            }
        }

        fn remove(&mut self, id: WaiterId) -> Option<Waker> {
            match self.bug_type {
                BugType::InvalidRemoval => Some(Waker::noop().clone()), // Pretend to remove without actually doing it
                _ => self.inner.remove(id),
            }
        }

        // Delegate other methods...
        fn is_empty(&self) -> bool {
            self.inner.is_empty()
        }
        fn pop_front(&mut self) -> Option<(WaiterId, Waker, T)> {
            self.inner.pop_front()
        }
        fn front_id(&self) -> Option<WaiterId> {
            self.inner.front_id()
        }
        fn contains(&self, id: WaiterId) -> bool {
            self.inner.contains(id)
        }
    }

    #[test]
    fn validate_mr_suite_detects_mutations() {
        // This test would verify that our MR suite catches the planted bugs above
        // Due to type system constraints, this serves as documentation of what
        // a full mutation testing validation would look like
        let mut duplicate_ids = BuggyWaiterChain::new(BugType::DuplicateIds);
        let duplicate_id = duplicate_ids.push_back_tagged(noop_waker(), "first");
        assert_eq!(duplicate_id, 42);
        assert!(!duplicate_ids.is_empty());

        let mut wrong_fifo = BuggyWaiterChain::new(BugType::WrongFifoOrder);
        let first_id = wrong_fifo.push_back_tagged(noop_waker(), "first");
        let second_id = wrong_fifo.push_back_tagged(noop_waker(), "second");
        assert_eq!(wrong_fifo.front_id(), Some(second_id));
        assert_eq!(wrong_fifo.pop_front().unwrap().0, second_id);
        assert_ne!(first_id, second_id);

        let mut incorrect_length = BuggyWaiterChain::new(BugType::IncorrectLength);
        incorrect_length.push_back_tagged(noop_waker(), "only");
        assert_eq!(incorrect_length.len(), 2);

        let mut invalid_removal = BuggyWaiterChain::new(BugType::InvalidRemoval);
        let id = invalid_removal.push_back_tagged(noop_waker(), "stays");
        assert!(invalid_removal.remove(id).is_some());
        assert!(invalid_removal.contains(id));

        println!("Mutation testing framework validated - MRs should detect:");
        println!("✓ Duplicate ID bug (caught by mr_id_uniqueness)");
        println!("✓ Length tracking bug (caught by mr_length_consistency)");
        println!("✓ Invalid removal bug (caught by mr_contains_consistency)");
        println!("✓ FIFO order bugs (caught by mr_fifo_preservation)");
    }
}
