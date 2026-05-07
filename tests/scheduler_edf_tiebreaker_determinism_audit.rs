//! Audit + regression test for `src/runtime/scheduler/priority.rs`
//! `TimedEntry` (deadline-monotone / EDF lane) ordering and
//! tiebreaker determinism.
//!
//! Operator's question: "when two tasks have identical deadlines,
//! what is the tiebreaker (task-id? FIFO insertion order?)? Per
//! scheduler invariant, must be deterministic."
//!
//! Audit findings:
//!
//!   `TimedEntry::cmp` (priority.rs:61-75) implements a
//!   three-level deterministic ordering:
//!
//!   1. **Earliest deadline first**. The outer comparison is
//!      `other.deadline.cmp(&self.deadline)` — reversed
//!      because `BinaryHeap` is a max-heap and we want
//!      min-deadline-first dispatch.
//!
//!   2. **Earliest insertion first** (FIFO within same
//!      deadline). When deadlines tie, the next comparison
//!      uses a `wrapping_sub` of the `generation: u64` field:
//!
//!        ```ignore
//!        let diff = other.generation
//!            .wrapping_sub(self.generation)
//!            .cast_signed();
//!        diff.cmp(&0)
//!        ```
//!
//!      The `wrapping_sub` correctly handles `u64` overflow
//!      (if generation ever rolls over after 2^64 inserts —
//!      implausible but defensively bounded). For inserts in
//!      the same epoch (which is the common case), the lower
//!      generation pops first → FIFO.
//!
//!   3. **Lowest TaskId first**. When BOTH deadline AND
//!      generation tie (only possible with synthetic /
//!      fixture-built entries; real inserts always advance
//!      generation), the final tiebreaker is `other.task.
//!      cmp(&self.task)` — lowest TaskId pops first.
//!
//!   The full chain produces a TOTAL ORDER. There is no path
//!   where two distinct entries compare equal but pop in
//!   undefined order.
//!
//!   The struct doc-comment (priority.rs:50-52) explicitly
//!   documents the chain: "Ordering: earlier deadline first,
//!   then earlier generation (FIFO within same deadline)."
//!
//!   For lab-determinism tests, an alternative path
//!   `Scheduler::pop_timed_only_with_hint(rng_hint)` uses
//!   `tie_break_index(rng_hint, scratch.len())`
//!   (priority.rs:384) to permute among equal-priority equal-
//!   generation entries based on a seed. This path is
//!   ALSO deterministic — same seed → same pop order — but
//!   the order varies with the seed for testing different
//!   schedule interleavings.
//!
//! Verdict: **SOUND**. The EDF tiebreaker chain is fully
//! deterministic at the BinaryHeap level (the default `pop`
//! path) and at the RNG-hinted path (`pop_with_rng_hint`).
//! Both satisfy the scheduler invariant.
//!
//! A regression that:
//!   - removed any of the three tiebreaker levels (would
//!     introduce non-determinism for entries that tie on
//!     remaining levels — e.g. dropping the generation level
//!     would make FIFO order non-deterministic for synthetic
//!     same-deadline entries),
//!   - swapped `wrapping_sub` for plain `cmp` (would invert
//!     FIFO on `u64` wraparound — pathological but possible
//!     in long-running deployments),
//!   - replaced `cast_signed()` with another conversion that
//!     doesn't preserve sign (would break the FIFO ordering
//!     on the wraparound branch),
//!   - removed the doc comment (operators rely on the
//!     documented contract for predictable scheduling),
//! would all be caught here.

use std::path::PathBuf;

fn read_priority_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/runtime/scheduler/priority.rs");
    std::fs::read_to_string(&path).expect("read priority.rs")
}

fn timed_entry_cmp_body(source: &str) -> &str {
    let impl_marker = "impl Ord for TimedEntry {";
    let start = source.find(impl_marker).expect("impl Ord for TimedEntry");
    let end_rel = source[start..].find("\n}\n").expect("impl close");
    &source[start..start + end_rel]
}

#[test]
fn timed_entry_struct_carries_deadline_and_generation() {
    // Pin: TimedEntry has BOTH a deadline AND a generation
    // field. Removing generation would force the tiebreaker
    // to fall back to TaskId only — losing FIFO semantics for
    // bursts of inserts that share a deadline.
    let source = read_priority_source();

    let struct_marker = "struct TimedEntry {";
    let start = source.find(struct_marker).expect("TimedEntry struct");
    let end_rel = source[start..].find("\n}\n").expect("struct close");
    let body = &source[start..start + end_rel];

    assert!(
        body.contains("deadline: Time,"),
        "REGRESSION: TimedEntry no longer has a `deadline: Time` \
         field. Without it, EDF ordering is impossible.\n\n\
         struct body:\n{body}",
    );
    assert!(
        body.contains("generation: u64,"),
        "REGRESSION: TimedEntry no longer has a `generation: u64` \
         field. Without it, FIFO tie-breaking on equal deadlines \
         falls back to TaskId only — losing insertion order.\n\n\
         struct body:\n{body}",
    );
    assert!(
        body.contains("task: TaskId,"),
        "REGRESSION: TimedEntry no longer has a `task: TaskId` \
         field. The TaskId is the final tiebreaker AND the \
         identity carried to dispatch.\n\nstruct body:\n{body}",
    );
}

#[test]
fn timed_entry_ord_compares_deadline_first() {
    // Pin AUDIT-CRITICAL: the OUTER comparison is on deadline.
    // EDF correctness requires that earliest deadline always
    // wins over later deadline regardless of generation /
    // TaskId. A regression that swapped the order would break
    // EDF entirely.
    let source = read_priority_source();
    let body = timed_entry_cmp_body(&source);

    // Match either the single-line or multi-line form (the
    // formatter may wrap `other.deadline.cmp(&self.deadline)`
    // onto separate lines).
    let single_line = body.contains("other.deadline.cmp(&self.deadline)");
    let multi_line = body.contains(".deadline\n") && body.contains(".cmp(&self.deadline)");
    assert!(
        single_line || multi_line,
        "REGRESSION: TimedEntry::cmp no longer starts with \
         the deadline comparison `other.deadline.cmp(&self.\
         deadline)` (single- or multi-line form). The reverse \
         comparison is what gives BinaryHeap min-heap-by-\
         deadline behavior; without it, EDF inverts to LDF \
         (latest-deadline-first) — catastrophic for deadline-\
         critical scheduling.\n\nimpl body:\n{body}",
    );

    // Defense-in-depth: forbid the SELF-FIRST comparison form
    // which would invert EDF.
    assert!(
        !body.contains("self.deadline.cmp(&other.deadline)"),
        "REGRESSION: TimedEntry::cmp now uses `self.deadline.\
         cmp(&other.deadline)` — the WRONG direction for a \
         max-heap min-deadline-first ordering. Latest deadline \
         would pop first.\n\nimpl body:\n{body}",
    );
}

#[test]
fn timed_entry_ord_uses_generation_as_secondary_tiebreaker() {
    // Pin AUDIT-CRITICAL: the SECONDARY tiebreaker (after
    // deadline) is generation, via .then_with() chaining.
    // A regression that dropped this would force two same-
    // deadline tasks to fall back to TaskId-only ordering —
    // breaking FIFO insertion-order semantics that operators
    // and dashboards rely on.
    let source = read_priority_source();
    let body = timed_entry_cmp_body(&source);

    assert!(
        body.contains(".then_with(|| {")
            && body.contains("other.generation.wrapping_sub(self.generation)"),
        "REGRESSION: TimedEntry::cmp no longer includes the \
         generation tiebreaker via `.then_with` + \
         `wrapping_sub`. Without this, equal-deadline tasks \
         pop in TaskId order — losing FIFO semantics. The \
         wrapping_sub specifically handles u64 generation \
         wraparound (after 2^64 inserts).\n\nimpl body:\n{body}",
    );

    // The cast to signed integer must be preserved — without
    // it, the wraparound branch produces wrong ordering.
    assert!(
        body.contains(".cast_signed();"),
        "REGRESSION: the wrapping_sub result is no longer \
         cast_signed(). Without the signed cast, the diff \
         comparison treats the wraparound branch as a huge \
         positive number — inverting FIFO order on the rare \
         wraparound case.",
    );
}

#[test]
fn timed_entry_ord_uses_task_id_as_final_tiebreaker() {
    // Pin: the THIRD-level tiebreaker is TaskId — guarantees
    // a TOTAL ORDER. A regression that dropped this would
    // leave entries that tie on deadline AND generation in
    // undefined heap order — non-determinism.
    let source = read_priority_source();
    let body = timed_entry_cmp_body(&source);

    assert!(
        body.contains(".then_with(|| other.task.cmp(&self.task))"),
        "REGRESSION: TimedEntry::cmp no longer has the \
         TaskId-cmp final tiebreaker. Without this, two \
         entries that tie on BOTH deadline AND generation pop \
         in undefined order — non-deterministic scheduling, \
         breaking the operator's invariant.\n\nimpl body:\n{body}",
    );
}

#[test]
fn timed_entry_doc_documents_the_ordering_chain() {
    // Pin: the struct's doc comment documents the ordering
    // semantics ("earlier deadline first, then earlier
    // generation (FIFO within same deadline)"). A regression
    // that changed the doc to imply a different tiebreaker
    // would mislead operators.
    let source = read_priority_source();

    let struct_marker = "struct TimedEntry {";
    let start = source.find(struct_marker).expect("TimedEntry struct");
    let mut doc_start = start;
    for _ in 0..15 {
        match source[..doc_start].rfind('\n') {
            Some(p) => doc_start = p,
            None => {
                doc_start = 0;
                break;
            }
        }
    }
    let doc_window = &source[doc_start..start];

    let required_phrases = [
        "earlier deadline first",
        "earlier generation",
        "FIFO within same deadline",
    ];
    for phrase in &required_phrases {
        assert!(
            doc_window.contains(phrase),
            "REGRESSION: TimedEntry doc no longer mentions \
             `{phrase}`. The doc is the public contract; if \
             the implementation changed, the doc must too.\n\n\
             doc window:\n{doc_window}",
        );
    }
}

#[test]
fn timed_entry_partial_ord_delegates_to_ord() {
    // Pin: PartialOrd::partial_cmp delegates to Ord::cmp via
    // Some(self.cmp(other)). A regression that implemented
    // a separate (and possibly inconsistent) PartialOrd would
    // make BinaryHeap behave inconsistently between
    // total-ordered and partial-ordered contexts.
    let source = read_priority_source();

    let impl_marker = "impl PartialOrd for TimedEntry {";
    let start = source
        .find(impl_marker)
        .expect("impl PartialOrd for TimedEntry");
    let end_rel = source[start..].find("\n}\n").expect("impl close");
    let body = &source[start..start + end_rel];

    assert!(
        body.contains("Some(self.cmp(other))"),
        "REGRESSION: TimedEntry's PartialOrd no longer delegates \
         to `Some(self.cmp(other))`. A divergent PartialOrd \
         could let `<`/`>` operators see different ordering \
         than the BinaryHeap.\n\npartial_ord body:\n{body}",
    );
}

#[test]
fn timed_lane_uses_binary_heap_with_timed_entry() {
    // Pin: the timed lane is a `BinaryHeap<TimedEntry>` —
    // applying TimedEntry::cmp determines pop order. A
    // regression to a different container (e.g. Vec sorted
    // separately) could lose the cmp-driven ordering.
    let source = read_priority_source();

    assert!(
        source.contains("timed_lane: BinaryHeap<TimedEntry>"),
        "REGRESSION: timed_lane is no longer \
         BinaryHeap<TimedEntry>. The TimedEntry::cmp \
         tiebreaker chain is what enforces deterministic EDF; \
         a different container would need to apply the same \
         ordering manually.",
    );
}

#[test]
fn rng_hinted_pop_uses_deterministic_tie_break_index() {
    // Pin: the RNG-hinted pop path uses tie_break_index
    // (a deterministic function of rng_hint and len). Same
    // seed → same index → same pop. A regression to a non-
    // deterministic primitive (rand::thread_rng,
    // SystemTime::now, etc.) would break replay tests.
    let source = read_priority_source();

    let fn_marker = "fn tie_break_index(rng_hint: u64, len: usize) -> usize {";
    let start = source.find(fn_marker).expect("tie_break_index fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("tie_break_index close");
    let body = &source[start..start + body_end];

    // The body must NOT use any non-deterministic source.
    let suspect_nondet = [
        "rand::thread_rng",
        "rand::random",
        "SystemTime::now",
        "Instant::now",
        "std::time::SystemTime",
    ];
    for pat in &suspect_nondet {
        assert!(
            !body.contains(pat),
            "REGRESSION: tie_break_index now contains `{pat}` — \
             a non-deterministic source. The RNG-hinted pop \
             path MUST be deterministic per seed for replay \
             tests to work.\n\nfn body:\n{body}",
        );
    }
}

// ─── Behavioral end-to-end pin (gated on test-internals) ────────────

#[cfg(feature = "test-internals")]
mod behavioral {
    use asupersync::runtime::scheduler::priority::Scheduler;
    use asupersync::types::{TaskId, Time};
    use asupersync::util::ArenaIndex;

    fn task(n: u64) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n as u32, 1))
    }

    #[test]
    fn equal_deadlines_pop_in_fifo_insertion_order() {
        // Pin AUDIT-CRITICAL: when two tasks share a deadline,
        // the EARLIER-INSERTED one pops first. This is the
        // generation tiebreaker at work.
        let mut sched = Scheduler::new();
        let deadline = Time::from_secs(10);

        sched.schedule_timed(task(5), deadline);
        sched.schedule_timed(task(3), deadline);
        sched.schedule_timed(task(7), deadline);

        let first = sched.pop();
        let second = sched.pop();
        let third = sched.pop();

        assert_eq!(
            (first, second, third),
            (Some(task(5)), Some(task(3)), Some(task(7))),
            "REGRESSION: equal-deadline tasks no longer pop in \
             insertion order. Expected (5, 3, 7) — the order \
             they were scheduled. If the order is sorted by \
             TaskId, generation tiebreaker was dropped.",
        );
    }

    #[test]
    fn earlier_deadline_wins_over_later_regardless_of_insertion() {
        // Pin: deadline is the PRIMARY ordering — earlier
        // deadline wins even if inserted later. A regression
        // that flipped the order would break EDF entirely.
        let mut sched = Scheduler::new();

        sched.schedule_timed(task(1), Time::from_secs(20)); // later deadline, inserted first
        sched.schedule_timed(task(2), Time::from_secs(10)); // earlier deadline, inserted second

        let first = sched.pop();
        let second = sched.pop();

        assert_eq!(
            first,
            Some(task(2)),
            "REGRESSION: later-deadline task popped before \
             earlier-deadline. EDF requires earliest deadline \
             first regardless of insertion order.",
        );
        assert_eq!(second, Some(task(1)));
    }

    #[test]
    fn deterministic_pop_order_across_runs() {
        // Pin: the same insertion sequence always produces the
        // same pop sequence. We construct two identical
        // schedulers and compare their drain output.
        fn run() -> Vec<TaskId> {
            let mut sched = Scheduler::new();
            sched.schedule_timed(task(7), Time::from_secs(5));
            sched.schedule_timed(task(3), Time::from_secs(10));
            sched.schedule_timed(task(5), Time::from_secs(5));
            sched.schedule_timed(task(1), Time::from_secs(10));
            sched.schedule_timed(task(9), Time::from_secs(2));

            let mut out = Vec::new();
            while let Some(t) = sched.pop() {
                out.push(t);
            }
            out
        }

        let a = run();
        let b = run();
        assert_eq!(
            a, b,
            "REGRESSION: identical insertion sequences produced \
             different pop sequences. The EDF tiebreaker chain \
             must be deterministic. a={a:?}, b={b:?}",
        );

        // Expected order:
        // - task(9) at deadline=2 (earliest)
        // - task(7) at deadline=5 (inserted first among d=5)
        // - task(5) at deadline=5 (inserted second among d=5)
        // - task(3) at deadline=10 (inserted first among d=10)
        // - task(1) at deadline=10 (inserted second among d=10)
        assert_eq!(
            a,
            vec![task(9), task(7), task(5), task(3), task(1)],
            "REGRESSION: pop order does not match the documented \
             tiebreaker chain (deadline → insertion). Got {a:?}",
        );
    }

    #[test]
    fn equal_deadlines_with_repeated_inserts_preserve_fifo() {
        // Pin: a long burst of inserts at the same deadline
        // pops in strict insertion order.
        let mut sched = Scheduler::new();
        let deadline = Time::from_secs(5);

        // Insert 100 tasks in a non-monotone TaskId order.
        let order: Vec<u64> = vec![
            42, 7, 99, 1, 50, 33, 88, 12, 64, 25, 76, 19, 5, 80, 14, 67, 30, 95, 8, 56, 71, 3, 84,
            22, 47, 91, 16, 60, 38, 73, 27, 6, 53, 11, 78, 4, 36, 89, 21, 65, 45, 13, 82, 29, 70,
            2, 58, 41, 86, 17, 74, 28, 9, 62, 35, 90, 18, 51, 77, 24, 10, 83, 39, 66, 20, 54, 92,
            15, 48, 87, 26, 79, 32, 61, 96, 23, 69, 40, 85, 31, 44, 75, 49, 93, 34, 81, 57, 98, 43,
            68, 55, 37, 100, 46, 72, 94, 52, 63, 59, 97,
        ];
        for &n in &order {
            sched.schedule_timed(task(n), deadline);
        }

        let mut popped = Vec::with_capacity(order.len());
        while let Some(t) = sched.pop() {
            popped.push(t);
        }

        let expected: Vec<TaskId> = order.iter().map(|&n| task(n)).collect();
        assert_eq!(
            popped, expected,
            "REGRESSION: 100-task FIFO insertion at the same \
             deadline did not produce strict insertion-order \
             pop. The generation tiebreaker is broken.\n\n\
             popped: {popped:?}\nexpected: {expected:?}",
        );
    }

    #[test]
    fn rng_hinted_pop_with_same_seed_is_deterministic() {
        // Pin: the RNG-hinted pop path is deterministic per
        // seed. Same seed sequence → same pop sequence.
        fn run_with_seed(seed: u64) -> Vec<TaskId> {
            let mut sched = Scheduler::new();
            // 5 tasks, all same deadline, all same generation
            // would be impossible — but with insertion-order
            // varying we can still exercise the RNG path.
            for i in 1..=10u64 {
                sched.schedule_timed(task(i), Time::from_secs(5));
            }
            let mut out = Vec::new();
            while let Some(t) = sched.pop_with_rng_hint(seed) {
                out.push(t);
            }
            out
        }

        let a = run_with_seed(0xdeadbeef);
        let b = run_with_seed(0xdeadbeef);
        assert_eq!(
            a, b,
            "REGRESSION: RNG-hinted pop with same seed produced \
             different sequences. The RNG-hinted path MUST be \
             deterministic per seed for replay-test guarantees \
             to hold. a={a:?}, b={b:?}",
        );
    }
}
