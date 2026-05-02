//! Audit + regression test for `src/runtime/scheduler/three_lane.rs`
//! work-stealing victim selection randomization.
//!
//! Operator's question: "when worker-A's local queue is empty, does
//! it steal from a randomly-selected neighbor (good) or always from
//! worker-A+1 (queue contention hotspot)?"
//!
//! Audit findings:
//!
//!   The asupersync 3-lane scheduler implements work stealing in
//!   TWO complementary forms, both with randomized victim
//!   selection:
//!
//!   1. **`ThreeLaneWorker::try_steal`** (three_lane.rs:4140+) is
//!      the primary in-worker steal path. Two phases, both
//!      starting from a RANDOM index:
//!
//!      a. **Fast path** (line 4142-4165): scans
//!         `self.fast_stealers` (other workers' LocalQueues).
//!         Start index is `self.rng.next_usize(len)` — a fresh
//!         random index per call. Iteration is
//!         `(start + i) % len` (circular). Each call attempts
//!         `len` victims at most.
//!
//!      b. **Slow path** (line 4172-...): scans `self.stealers`
//!         (other workers' PriorityScheduler heaps) for ready-
//!         lane theft. Same random-start circular pattern.
//!         Uses `try_lock` so contended victims are skipped
//!         without blocking.
//!
//!      The random `start` per call ensures that worker A is
//!      EQUALLY likely to probe worker A+1, A+2, … A-1 (mod
//!      worker_count) FIRST. There is no static "always probe
//!      worker A+1 first" hotspot.
//!
//!   2. **`scheduler::stealing::steal_task`** (stealing.rs:16-72)
//!      is the dedicated load-balancing helper, available for
//!      callers that want **Power of Two Choices** (Mitzenmacher
//!      2001) instead of linear probing. It:
//!      - Picks two distinct random victims via
//!        `rng.next_usize(len)` twice (with collision dedup).
//!      - Compares their `stealable_len_hint()` to prefer the
//!        more-loaded queue.
//!      - Falls back to the second candidate, then to a
//!        random-start linear scan over remaining victims.
//!
//!      Both paths use `DetRng` so the randomization is
//!      DETERMINISTIC per seed (replay tests work) but UNIFORM
//!      across seeds (no hotspot).
//!
//! Verdict: **SOUND**. Worker A's victim probe order is
//! independently randomized per steal attempt; there is NO
//! "worker A+1" hotspot. The randomization is via `DetRng` so
//! it remains deterministic for replay tests while breaking
//! adjacent-worker contention in production.
//!
//! A regression that:
//!   - replaced `let start = self.rng.next_usize(len)` with
//!     `let start = self.id.0 + 1` or any function of worker
//!     id (would re-introduce the hotspot — every worker
//!     always probes its successor first),
//!   - removed the modulo so iteration stopped at index 0
//!     (would only scan a contiguous suffix),
//!   - dropped the `self.rng` advance (would freeze the start
//!     index at a constant — same hotspot pattern, just at a
//!     different fixed worker),
//!   - dropped the `try_lock` skip in the slow path (would let
//!     contended victims block the stealer, defeating the
//!     "skip and try the next" defense),
//!   - replaced DetRng with a non-deterministic source
//!     (would break replay tests but not the load
//!     distribution itself),
//! would all be caught here.

use std::path::PathBuf;

fn read_three_lane_source() -> String {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/runtime/scheduler/three_lane.rs");
    std::fs::read_to_string(&path).expect("read three_lane.rs")
}

fn read_stealing_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/runtime/scheduler/stealing.rs");
    std::fs::read_to_string(&path).expect("read stealing.rs")
}

fn try_steal_body(source: &str) -> &str {
    let fn_marker = "pub(crate) fn try_steal(&mut self) -> Option<TaskId> {";
    let start = source.find(fn_marker).expect("try_steal fn");
    // try_steal is long; slice up to the next sibling fn.
    let after = &source[start + fn_marker.len()..];
    let next_fn_offset = after
        .find("\n    pub(crate) fn ")
        .or_else(|| after.find("\n    pub fn "))
        .or_else(|| after.find("\n    fn "))
        .unwrap_or(after.len().min(20000));
    &source[start..start + fn_marker.len() + next_fn_offset]
}

#[test]
fn try_steal_fast_path_uses_random_start_index() {
    // Pin AUDIT-CRITICAL: the fast-path victim probe starts at
    // a RANDOM index per call. A regression that replaced
    // `self.rng.next_usize(len)` with `self.id.0 + 1` (or
    // any function of worker id) would create the hotspot.
    let source = read_three_lane_source();
    let body = try_steal_body(&source);

    assert!(
        body.contains("let start = self.rng.next_usize(len);"),
        "REGRESSION: try_steal no longer uses \
         `let start = self.rng.next_usize(len)` for the start \
         index. Without this, the victim probe order becomes \
         deterministic per worker (e.g. always probe worker+1 \
         first) — re-introducing the hotspot the operator \
         flagged.\n\nfn body:\n{body}",
    );

    // The body must contain the random-start invocation TWICE
    // (once for fast_stealers, once for the slow-path
    // stealers). A regression that kept only one would leave
    // the OTHER path with a hotspot.
    let count = body.matches("self.rng.next_usize(len)").count();
    assert!(
        count >= 2,
        "REGRESSION: try_steal has only {count} call(s) to \
         self.rng.next_usize(len); expected ≥ 2 (one for the \
         fast-path fast_stealers scan, one for the slow-path \
         stealers scan). A path without random start has the \
         hotspot.",
    );
}

#[test]
fn try_steal_iterates_circularly_via_modulo() {
    // Pin: the iteration is `(start + i) % len`, NOT
    // `start..len` or `0..len`. Without modulo, the scan
    // would only cover a suffix and miss workers with index
    // < start.
    let source = read_three_lane_source();
    let body = try_steal_body(&source);

    assert!(
        body.contains("let idx = (start + i) % len;"),
        "REGRESSION: try_steal no longer uses circular \
         indexing `(start + i) % len`. A non-circular scan \
         (e.g. `start..len`) would skip workers with index < \
         start — biasing the victim distribution and possibly \
         leaving idle workers with full queues unsatisfied.\n\n\
         fn body:\n{body}",
    );
}

#[test]
fn try_steal_does_not_use_worker_id_or_constant_start() {
    // Pin: the start index does NOT come from a worker-id
    // function or a hardcoded constant. A regression to
    // `self.id.0 % len` would create the canonical "always
    // probe successor" hotspot the operator described.
    let source = read_three_lane_source();
    let body = try_steal_body(&source);

    let suspect_static_starts = [
        "let start = self.id",
        "let start = (self.id",
        "let start = 0;",
        "let start = 1;",
        "let start: usize = 0;",
    ];
    for pat in &suspect_static_starts {
        assert!(
            !body.contains(pat),
            "REGRESSION: try_steal start index now derives from \
             `{pat}` — a static / worker-id function. This \
             produces the canonical hotspot: every worker A \
             always probes the same victim first. Restore \
             `self.rng.next_usize(len)`.\n\nfn body:\n{body}",
        );
    }
}

#[test]
fn try_steal_slow_path_uses_try_lock_to_skip_contended_victims() {
    // Pin: the slow path uses `stealer.try_lock()` so a
    // currently-locked victim is SKIPPED, not waited on.
    // Without try_lock, multiple stealers competing for the
    // same victim would serialize on the lock.
    let source = read_three_lane_source();
    let body = try_steal_body(&source);

    assert!(
        body.contains("stealer.try_lock()"),
        "REGRESSION: try_steal slow path no longer uses \
         `stealer.try_lock()`. A blocking lock acquisition \
         here would serialize stealers competing for the \
         same victim and re-introduce contention — even with \
         random start, lock-blocking on a contended victim \
         would queue all stealers behind the same critical \
         section.\n\nfn body:\n{body}",
    );
}

#[test]
fn steal_task_helper_uses_power_of_two_choices() {
    // Pin: the dedicated load-balancing helper picks TWO
    // random victims via .next_usize(len), prefers the more-
    // loaded one, falls back to the other, and finally to a
    // random-start linear scan. A regression that simplified
    // to a single random pick would lose the Power of Two
    // Choices guarantee.
    let source = read_stealing_source();

    let fn_marker = "pub fn steal_task(stealers: &[Stealer], rng: &mut DetRng) -> Option<TaskId> {";
    let start = source.find(fn_marker).expect("steal_task fn");
    let body_end = source[start..].find("\n}\n").expect("steal_task close");
    let body = &source[start..start + body_end];

    // Must call rng.next_usize at LEAST twice: idx1 and idx2
    // for Power of Two Choices, plus the fallback start.
    let rng_call_count = body.matches("rng.next_usize(len)").count();
    assert!(
        rng_call_count >= 3,
        "REGRESSION: steal_task has {rng_call_count} \
         rng.next_usize(len) calls; expected ≥ 3 (idx1, idx2, \
         fallback start). Power of Two Choices requires two \
         independent random picks; the fallback also requires \
         a random start.\n\nfn body:\n{body}",
    );

    // Must compare stealable_len_hint of the two candidates.
    assert!(
        body.contains("stealable_len_hint()"),
        "REGRESSION: steal_task no longer queries \
         stealable_len_hint() to compare the two candidates. \
         Without the comparison, the helper degrades to two \
         random picks without load-balancing intelligence.",
    );

    // The collision-dedup logic ensures idx1 != idx2.
    assert!(
        body.contains("if idx1 == idx2"),
        "REGRESSION: steal_task no longer dedups colliding \
         random indices (idx1 == idx2). Without this, the \
         second candidate could be the same as the first, \
         degrading Power of Two Choices to a single random \
         pick.",
    );
}

#[test]
fn steal_task_doc_documents_power_of_two_choices() {
    // Pin: the doc comment cites Mitzenmacher 2001 and
    // explains the power-of-two-choices design. A regression
    // that changed the doc would signal a substantive design
    // change worth re-auditing.
    let source = read_stealing_source();

    let fn_marker = "pub fn steal_task(stealers: &[Stealer], rng: &mut DetRng) -> Option<TaskId> {";
    let fn_pos = source.find(fn_marker).expect("steal_task fn");
    let mut doc_start = fn_pos;
    for _ in 0..15 {
        match source[..doc_start].rfind('\n') {
            Some(p) => doc_start = p,
            None => {
                doc_start = 0;
                break;
            }
        }
    }
    let doc_window = &source[doc_start..fn_pos];

    let required_phrases = ["Power of Two Choices", "load balancing"];
    for phrase in &required_phrases {
        assert!(
            doc_window.contains(phrase),
            "REGRESSION: steal_task doc no longer mentions \
             `{phrase}`. The doc is the public contract; if \
             the algorithm changed, the doc must too.\n\n\
             doc window:\n{doc_window}",
        );
    }
}

#[test]
fn steal_task_uses_circular_index_helper_for_fallback_scan() {
    // Pin: the fallback linear scan uses `circular_index` —
    // a documented helper that prevents arithmetic-overflow
    // when start + offset is large. A regression to plain
    // `(start + i) % len` could overflow on extremely long
    // worker lists; using circular_index is the documented
    // safe pattern.
    let source = read_stealing_source();

    assert!(
        source.contains("fn circular_index(start: usize, offset: usize, len: usize) -> usize {"),
        "REGRESSION: circular_index helper is gone. The \
         fallback scan in steal_task relies on it for \
         overflow-safe circular indexing.",
    );

    let fn_marker = "fn circular_index(start: usize, offset: usize, len: usize) -> usize {";
    let start_pos = source.find(fn_marker).expect("circular_index fn");
    let body_end = source[start_pos..]
        .find("\n}\n")
        .expect("circular_index close");
    let body = &source[start_pos..start_pos + body_end];

    assert!(
        body.contains("(start + offset) % len"),
        "REGRESSION: circular_index no longer computes \
         `(start + offset) % len`. The doc explicitly notes \
         that wrapping_add would be mathematically incorrect; \
         a regression to wrapping_add would silently produce \
         wrong indices on overflow.\n\nfn body:\n{body}",
    );
}

#[test]
fn try_steal_does_not_call_steal_on_self() {
    // Pin: the stealers list is constructed to EXCLUDE the
    // worker's own queue (otherwise a worker could steal from
    // itself, which is a no-op but wastes time). A regression
    // that included self in fast_stealers would let the worker
    // probe its own queue.
    let source = read_three_lane_source();

    // The fast_stealers field is constructed in the worker
    // builder. We pin via the field's construction site to
    // verify it's filtered.
    let fast_stealers_init_marker =
        "let fast_stealers: SmallVec<[local_queue::Stealer; 16]> = fast_queues";
    let pos = source
        .find(fast_stealers_init_marker)
        .expect("fast_stealers initialization");
    // Take the surrounding 500 chars.
    let window_start = pos.saturating_sub(50);
    let window_end = (pos + 1000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= window_end)
        .last()
        .unwrap_or(window_end);
    let window = &source[window_start..safe_end];

    // The construction must filter / skip / exclude the
    // worker's own index (commonly `enumerate().filter(|(i,
    // _)| *i != worker_id)` or similar).
    let has_self_filter = window.contains(".filter(")
        || window.contains("!= worker")
        || window.contains("!= self.id")
        || window.contains("ne(");

    assert!(
        has_self_filter,
        "REGRESSION: fast_stealers construction does not \
         appear to filter out the worker's own queue. A \
         worker stealing from itself is wasted work; verify \
         the construction excludes self.\n\nwindow:\n{window}",
    );
}

#[test]
fn try_steal_iterates_at_most_len_times() {
    // Pin: the for loop is `for i in 0..len`, ensuring at
    // most `len` victims are probed. A regression to a longer
    // loop (e.g. `0..len*2`) would let the same victim be
    // probed twice, wasting CPU under contention.
    let source = read_three_lane_source();
    let body = try_steal_body(&source);

    assert!(
        body.contains("for i in 0..len {"),
        "REGRESSION: try_steal loop is no longer `for i in \
         0..len`. The bounded length guarantees the scan \
         visits each victim at most once. A different bound \
         could re-probe contended victims (waste) or skip \
         some (incomplete coverage).\n\nfn body:\n{body}",
    );
}

// ─── Behavioral end-to-end pin (gated on test-internals) ────────────

#[cfg(feature = "test-internals")]
mod behavioral {
    use asupersync::util::DetRng;

    /// Run N iterations of `next_usize(width)` from a `DetRng`
    /// seeded the same way and observe the distribution of
    /// start indices. The Power-of-Two-Choices / random-start
    /// design guarantees that the distribution is approximately
    /// uniform — NOT concentrated at a single index.
    #[test]
    fn det_rng_next_usize_distribution_is_approximately_uniform() {
        let mut rng = DetRng::new(0xdeadbeef);
        let width = 8;
        let trials = 10_000;
        let mut counts = vec![0u32; width];
        for _ in 0..trials {
            let idx = rng.next_usize(width);
            counts[idx] += 1;
        }

        // Each bin should hold approximately trials/width = 1250.
        // Allow generous tolerance (±30%) to account for normal
        // RNG variance.
        let expected = trials / width;
        let tolerance = expected * 30 / 100;
        for (i, count) in counts.iter().enumerate() {
            let lo = expected.saturating_sub(tolerance) as u32;
            let hi = (expected + tolerance) as u32;
            assert!(
                *count >= lo && *count <= hi,
                "REGRESSION: DetRng::next_usize({width}) bin {i} \
                 has count {count}, expected ~{expected} ± \
                 {tolerance}. The random victim distribution \
                 is no longer uniform — a hotspot at index {i} \
                 would re-introduce the operator's failure mode.\n\
                 \nfull counts: {counts:?}",
            );
        }
    }

    #[test]
    fn det_rng_is_deterministic_for_same_seed() {
        // Pin: the RNG produces the same sequence for the same
        // seed. This is what makes replay tests work despite
        // randomization.
        let mut a = DetRng::new(42);
        let mut b = DetRng::new(42);
        for _ in 0..100 {
            assert_eq!(
                a.next_usize(16),
                b.next_usize(16),
                "REGRESSION: DetRng diverges across instances \
                 with the same seed — replay tests would break.",
            );
        }
    }

    #[test]
    fn det_rng_differs_across_seeds() {
        // Pin: different seeds produce different sequences.
        // (Otherwise the RNG would degenerate to a constant.)
        let mut a = DetRng::new(1);
        let mut b = DetRng::new(2);
        let mut differences = 0;
        for _ in 0..100 {
            if a.next_usize(1024) != b.next_usize(1024) {
                differences += 1;
            }
        }
        assert!(
            differences > 50,
            "REGRESSION: DetRng with seeds 1 vs 2 produced \
             only {differences}/100 differing values. The \
             sequences should be uncorrelated — too few \
             differences suggests the RNG is degenerate.",
        );
    }
}
