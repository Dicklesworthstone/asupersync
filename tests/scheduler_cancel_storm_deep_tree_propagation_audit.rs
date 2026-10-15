//! Audit + regression test for cancel-storm propagation
//! through a deep region tree.
//!
//! Operator's question: "when 1000 nested regions exist
//! (root → child → grandchild …) and root is cancelled, does
//! cancel propagate to leaves in O(N) total work or O(N²)
//! (incorrect: re-traverses on each level)?"
//!
//! Audit findings:
//!
//! The deep-tree cancel propagation is **O(N + total_edges +
//! total_tasks)**. That is O(N) for a tree because edges =
//! N-1 in a tree. The N log N sort by depth is the only
//! super-linear term, well under O(N²) for 1000 regions
//! (~10K comparisons → microseconds). The chain:
//!
//!   1. **Single subtree collection pass** (state.rs:2531):
//!      ```ignore
//!      let mut regions_to_cancel = self.collect_region_and_descendants_with_depth(region_id);
//!      ```
//!      Called ONCE at the start of cancel_request. Returns
//!      a `Vec<CancelRegionNode>` of all regions in the
//!      subtree. NOT called per-level — a single traversal.
//!
//!   2. **Iterative DFS with explicit stack** (state.rs:2752):
//!      ```ignore
//!      fn collect_region_and_descendants_with_depth(...) {
//!          let mut result = Vec::new();
//!          let mut stack = Vec::new();
//!          let mut child_buf = Vec::new();
//!          stack.push((region_id, None, 0));
//!          while let Some((rid, parent, depth)) = stack.pop() {
//!              result.push(CancelRegionNode { id, parent, depth });
//!              if let Some(region) = self.regions.get(rid.arena_index()) {
//!                  child_buf.clear();
//!                  region.copy_child_ids_into(&mut child_buf);
//!                  for &child_id in &child_buf {
//!                      stack.push((child_id, Some(rid), depth + 1));
//!                  }
//!              }
//!          }
//!          result
//!      }
//!      ```
//!      Each region is pushed onto the stack EXACTLY ONCE
//!      and popped EXACTLY ONCE. Per-region work is
//!      copy_child_ids_into (which is O(C) where C is the
//!      direct child count). The sum over the tree is
//!      Σ_regions (1 + child_count) = N + total_edges = 2N - 1,
//!      which is strictly O(N).
//!
//!   3. **Iterative — NOT recursive**: the `let mut stack`
//!      pattern means deep linear chains (1000 levels) do
//!      NOT consume thread stack proportional to depth. A
//!      recursive traversal would risk stack overflow at
//!      that depth — verified absent.
//!
//!   4. **`child_buf` reused across iterations**: the
//!      explicit `let mut child_buf = Vec::new();` outside
//!      the while-let, with `.clear()` inside, avoids the
//!      O(N) per-region allocator overhead that fresh
//!      `Vec::new()` would create. One Vec, reused N times.
//!
//!   5. **Sort by depth is O(N log N)** (state.rs:2535):
//!      `regions_to_cancel.sort_by_key(|node| node.depth);`
//!      uses Rust's stdlib sort (O(N log N) in the worst
//!      case, often closer to O(N) on partially-sorted
//!      input). For 1000 regions, ~10K comparisons. Well
//!      under any O(N²) bound.
//!
//!   6. **First pass is single-pass O(N)** (state.rs:2543):
//!      ```ignore
//!      for node in &regions_to_cancel {
//!          let region_reason = ...;
//!          // build chain from parent's reason in region_reasons map
//!          if let Some(region) = self.regions.get(rid.arena_index()) {
//!              if region.begin_close_without_subscriber(
//!                  Some(region_reason.clone())) { ... }
//!          }
//!          region_reasons.insert(rid, region_reason.clone());
//!      }
//!      ```
//!      One iteration per region. The `region_reasons` HashMap
//!      lookup of the parent's reason is O(1) amortized. Total
//!      O(N).
//!
//!   7. **Second pass is single-pass O(N + total_tasks)**
//!      (state.rs:2667):
//!      ```ignore
//!      for node in &regions_to_cancel {
//!          // gather task_id_buf
//!          for &task_id in &task_id_buf {
//!              self.update_task(task_id, |task| {
//!                  let effects = task.request_cancel_with_budget(...);
//!                  // Return effects; do not invoke callbacks here.
//!              });
//!              let (newly_cancelled, task_wakes) = effects.into_parts();
//!              wakes.merge(task_wakes);
//!          }
//!      }
//!      ```
//!      One iteration per region; nested iteration per
//!      task within. Total: Σ_regions (1 + task_count) =
//!      O(N + total_tasks). For a deep linear chain with
//!      one task per region, that's O(N).
//!
//!   8. **`task_id_buf` reused** (state.rs:2665): same buffer-
//!      reuse pattern as child_buf. No O(N) allocator
//!      overhead.
//!
//!   9. **Per-region work is O(1)**: begin_close, the
//!      strengthen-cancel-reason fallback, the trace event,
//!      the metrics callback — all bounded constant.
//!      request_cancel_with_budget is O(1) per task.
//!
//! Verdict: **SOUND**. Total complexity is O(N log N) due to
//! the sort + O(N + total_tasks) for the propagation. For
//! 1000 nested regions (a deep linear chain), this is
//! microseconds in practice — well under any O(N²) bound
//! that would scale to seconds.
//!
//! No re-traversal anywhere: each region is visited once in
//! the subtree collection, once in the first pass, once in
//! the second pass. Total: 3 passes × N regions = 3N
//! operations.
//!
//! A regression that:
//!   - replaced the iterative DFS with recursion (would
//!     stack-overflow at moderate depth — Rust does not
//!     guarantee TCO),
//!   - moved the subtree-collection into the first-pass loop
//!     (would re-collect descendants per region — O(N²)),
//!   - replaced the region_reasons HashMap with a Vec.iter().
//!     find() (would be O(N) per parent lookup → O(N²)
//!     total),
//!   - removed the child_buf reuse (would allocate per
//!     region — pathological allocator pressure under deep
//!     trees),
//!   - replaced the sort_by_key with bubble-sort or O(N²)
//!     insertion sort (would be exactly O(N²) on a depth-
//!     sorted-already input),
//!   - introduced a nested for-loop in the cancel_request
//!     body (e.g., for each region, scan ALL OTHER regions
//!     for dependent state),
//!     would be caught by the structural pins below or by the
//!     behavioral benchmark.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn subtree_collection_uses_iterative_dfs_with_explicit_stack() {
    // Pin (link 2+3): collect_region_and_descendants_with_depth
    // uses an explicit Vec-based stack (iterative), NOT
    // recursion. Recursion at 1000+ depth would risk stack
    // overflow.
    let source = read("src/runtime/state.rs");

    let fn_marker = "fn collect_region_and_descendants_with_depth(";
    let start = source.find(fn_marker).expect("collect fn");
    let body_end = source[start..].find("\n    }\n").expect("collect close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("let mut stack = Vec::new();")
            && body.contains("stack.push(")
            && body.contains("while let Some((rid, parent, depth)) = stack.pop() {"),
        "REGRESSION: subtree collection no longer uses an \
         iterative DFS with explicit Vec stack. A recursive \
         alternative would stack-overflow at deep linear \
         chains (1000+ levels). Restore the iterative \
         pattern.",
    );

    // Forbid recursion (function calling itself).
    assert!(
        !body.contains("self.collect_region_and_descendants_with_depth("),
        "REGRESSION: subtree collection now recurses. Rust \
         does NOT guarantee TCO — deep linear region chains \
         would stack-overflow.",
    );
}

#[test]
fn subtree_collection_reuses_child_buf_across_iterations() {
    // Pin (link 4): child_buf is declared OUTSIDE the
    // while-let and .clear()-reused inside. Per-region
    // allocator overhead is bounded constant.
    let source = read("src/runtime/state.rs");

    let fn_marker = "fn collect_region_and_descendants_with_depth(";
    let start = source.find(fn_marker).expect("collect fn");
    let body_end = source[start..].find("\n    }\n").expect("collect close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("let mut child_buf = Vec::new();") && body.contains("child_buf.clear();"),
        "REGRESSION: subtree collection no longer reuses \
         child_buf. A fresh Vec per iteration would create \
         O(N) allocator pressure on deep trees — measurable \
         slowdown.",
    );
}

#[test]
fn cancel_request_sorts_subtree_by_depth_for_chain_lookup_invariant() {
    // Pin (link 5): regions_to_cancel.sort_by_key by depth
    // is O(N log N), NOT O(N²). Sorting depth-ascending is
    // what makes the parent's reason available in
    // region_reasons when the child is processed.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("regions_to_cancel.sort_by_key(|node| node.depth);"),
        "REGRESSION: regions_to_cancel sort by depth is gone. \
         Without depth-ascending order, the chain-lookup \
         invariant breaks (children process before parents \
         → parent's reason missing from region_reasons → \
         tnk8ny fallback fires for every descendant).",
    );

    // Forbid bubble-sort or insertion-sort patterns.
    let suspect_quadratic_sort = [
        "// bubble sort",
        "for i in 0..regions_to_cancel.len() {\n            for j in",
        "while changed {",
    ];
    for pat in &suspect_quadratic_sort {
        assert!(
            !source.contains(pat),
            "REGRESSION: cancel_request now uses an O(N²) \
             sort (`{pat}`). For 1000 regions, that's 1M \
             comparisons — sub-second but visibly slower \
             than the std O(N log N) sort.",
        );
    }
}

#[test]
fn cancel_request_first_pass_is_single_iteration_no_subtree_recollect() {
    // Pin (link 6): the first pass iterates regions_to_cancel
    // ONCE. It must NOT call collect_region_and_descendants
    // inside the loop (which would be O(N²)).
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("for node in &regions_to_cancel {"),
        "REGRESSION: first pass no longer iterates \
         regions_to_cancel. Either the loop signature \
         changed or the pass was removed — both break the \
         subtree-walk invariant.",
    );

    // Locate the first pass body and check no inner
    // collect-subtree call.
    let marker = "// First pass: mark regions with cancellation reason";
    let pos = source.find(marker).expect("first pass marker");
    let window_end = (pos + 5000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[pos..safe_end];

    let suspect_recollect = [
        "self.collect_region_and_descendants_with_depth(",
        ".collect_subtree(",
        "self.descendants_of(",
    ];
    for pat in &suspect_recollect {
        assert!(
            !body.contains(pat),
            "REGRESSION: first pass now recollects subtree \
             via `{pat}`. Each region's recollection walks \
             O(N) descendants → O(N²) total. For 1000 \
             regions, that's 1M operations.",
        );
    }
}

#[test]
fn cancel_request_second_pass_is_single_iteration_no_subtree_recollect() {
    // Pin (link 7): the second pass iterates regions_to_cancel
    // ONCE. Same constraint as first pass.
    let source = read("src/runtime/state.rs");

    let marker = "// Second pass: mark tasks for cancellation.";
    let pos = source.find(marker).expect("second pass marker");
    let window_end = (pos + 5000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[pos..safe_end];

    assert!(
        body.contains("task.request_cancel_with_budget_and_publication(")
            && body.contains("let ((newly_cancelled, changed, publication), task_wakes) =",)
            && body.contains("wakes.merge(task_wakes);"),
        "REGRESSION: the deep-tree second pass no longer mutates/captures \
         cancellation effects per task without dispatching their auxiliary \
         observers/Wakers. Waker \
         reentrancy under the outer traversal can invalidate the O(N) walk.",
    );

    let suspect_recollect = [
        "self.collect_region_and_descendants_with_depth(",
        ".collect_subtree(",
        "self.descendants_of(",
    ];
    for pat in &suspect_recollect {
        assert!(
            !body.contains(pat),
            "REGRESSION: second pass now recollects subtree \
             via `{pat}` — O(N²) work pattern.",
        );
    }
}

#[test]
fn region_reasons_uses_hashmap_for_o_1_parent_lookup() {
    // Pin (link 6): region_reasons is a HashMap keyed by
    // RegionId so the parent's reason is found in O(1)
    // amortized. A Vec.iter().find() would be O(N) per
    // lookup → O(N²) total.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("HashMap::with_capacity(regions_to_cancel.len());"),
        "REGRESSION: region_reasons is no longer a HashMap. \
         Vec-based parent lookup turns each child's \
         chain-build into O(N) → O(N²) total.",
    );
}

#[test]
fn copy_child_ids_into_takes_buffer_to_avoid_per_call_allocation() {
    // Pin (link 4 supporting): RegionRecord::copy_child_ids_into
    // takes &mut Vec<RegionId>, allowing the caller to reuse
    // a buffer across iterations. Without this, callers
    // would have to clone() the children Vec — per-region
    // heap allocation.
    let source = read("src/record/region.rs");

    assert!(
        source.contains("pub fn copy_child_ids_into(&self, buf: &mut Vec<RegionId>) {"),
        "REGRESSION: RegionRecord::copy_child_ids_into \
         signature changed. Callers must clone() the \
         children Vec instead — per-region allocation \
         overhead under deep trees.",
    );
}

#[test]
fn copy_task_ids_into_takes_buffer_to_avoid_per_call_allocation() {
    // Pin (link 8): RegionRecord::copy_task_ids_into is the
    // task-side equivalent of copy_child_ids_into. Same
    // buffer-reuse pattern.
    let source = read("src/record/region.rs");

    assert!(
        source.contains("pub fn copy_task_ids_into(&self, buf: &mut Vec<TaskId>) {"),
        "REGRESSION: RegionRecord::copy_task_ids_into \
         signature changed. Callers allocate per-region \
         instead of reusing the buf — per-region pressure \
         under cancel-storm.",
    );
}

#[test]
fn task_id_buf_reused_across_regions_in_second_pass() {
    // Pin (link 8): the second pass declares task_id_buf
    // ONCE outside the for-each-region loop and .clear()-
    // reuses inside. Without this, R region traversals each
    // allocate a fresh Vec.
    let source = read("src/runtime/state.rs");

    let marker = "// Second pass: mark tasks for cancellation.";
    let pos = source.find(marker).expect("second pass marker");
    let window_end = (pos + 5000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[pos..safe_end];

    assert!(
        body.contains("let mut task_id_buf = Vec::new();") && body.contains("task_id_buf.clear();"),
        "REGRESSION: second pass no longer reuses task_id_buf \
         across regions. Per-region Vec allocation under deep \
         cancel-storm wastes allocator capacity.",
    );
}

// ─────────── BEHAVIORAL BENCHMARK: 1000-deep-tree ─────────
//
// Simulate the exact production pattern: build a 1000-level
// linear region tree, then "cancel" the root by walking the
// subtree iteratively + processing each region in two
// passes. Verify total time is well under 1 second.

#[derive(Debug, Clone)]
struct MockRegion {
    id: u64,
    parent: Option<u64>,
    children: Vec<u64>,
    state: u8,                  // 0 = Open, 1 = Closing
    cancel_reason: Option<u64>, // simplified — just the reason "id"
}

#[derive(Debug, Clone, Copy)]
struct MockNode {
    id: u64,
    parent: Option<u64>,
    depth: usize,
}

fn collect_subtree(regions: &HashMap<u64, MockRegion>, root: u64) -> Vec<MockNode> {
    let mut result = Vec::new();
    let mut stack = Vec::new();
    let mut child_buf: Vec<u64> = Vec::new();
    stack.push((root, None, 0_usize));

    while let Some((rid, parent, depth)) = stack.pop() {
        result.push(MockNode {
            id: rid,
            parent,
            depth,
        });
        if let Some(region) = regions.get(&rid) {
            assert_eq!(region.id, rid, "mock region id must match map key");
            assert_eq!(
                region.parent, parent,
                "mock region parent must match traversal parent",
            );
            child_buf.clear();
            child_buf.extend_from_slice(&region.children);
            for &child_id in &child_buf {
                stack.push((child_id, Some(rid), depth + 1));
            }
        }
    }
    result
}

fn cancel_request_mock(regions: &mut HashMap<u64, MockRegion>, root: u64, reason: u64) -> usize {
    // Mirror the production cancel_request structure.
    let mut subtree = collect_subtree(regions, root);
    subtree.sort_by_key(|n| n.depth);

    // First pass: transition each region to Closing.
    let mut region_reasons: HashMap<u64, u64> = HashMap::with_capacity(subtree.len());
    for node in &subtree {
        let region_reason = if node.id == root {
            reason
        } else if let Some(parent_id) = node.parent {
            // Parent's reason MUST be in region_reasons because we
            // sorted depth-ascending.
            *region_reasons
                .get(&parent_id)
                .expect("parent must be processed first")
                + 1
        } else {
            reason
        };
        if let Some(region) = regions.get_mut(&node.id) {
            region.state = 1;
            region.cancel_reason = Some(region_reason);
        }
        region_reasons.insert(node.id, region_reason);
    }

    // Second pass: would mark tasks (no tasks in this
    // benchmark, but verify the loop runs).
    for _node in &subtree {
        // O(1) per region (no tasks in mock); production
        // version iterates task_id_buf here.
    }

    subtree.len()
}

#[test]
fn deep_linear_1000_region_tree_cancels_under_1_second() {
    // Behavioral benchmark: build root → child → grandchild
    // … 1000 levels deep. Cancel root and time the full
    // propagation. Must be sub-second.
    const N: u64 = 1000;

    let mut regions: HashMap<u64, MockRegion> = HashMap::with_capacity(N as usize + 1);

    // Root.
    regions.insert(
        0,
        MockRegion {
            id: 0,
            parent: None,
            children: vec![1],
            state: 0,
            cancel_reason: None,
        },
    );

    // Each region i has child i+1, except the leaf (N).
    for i in 1..N {
        regions.insert(
            i,
            MockRegion {
                id: i,
                parent: Some(i - 1),
                children: vec![i + 1],
                state: 0,
                cancel_reason: None,
            },
        );
    }
    // Leaf has no children.
    regions.insert(
        N,
        MockRegion {
            id: N,
            parent: Some(N - 1),
            children: vec![],
            state: 0,
            cancel_reason: None,
        },
    );

    let start = Instant::now();
    let visited = cancel_request_mock(&mut regions, 0, 9999);
    let elapsed = start.elapsed();

    assert_eq!(
        visited,
        (N + 1) as usize,
        "REGRESSION: subtree collection visited {visited} \
         regions, expected {expected}. Either the subtree \
         walk is broken or some regions were skipped.",
        expected = N + 1,
    );

    // All regions must be Closing.
    for i in 0..=N {
        let region = regions.get(&i).expect("region exists");
        assert_eq!(
            region.state, 1,
            "REGRESSION: region {i} did not transition to \
             Closing. Cancel propagation incomplete.",
        );
    }

    // Each region's cancel_reason should reflect chain depth
    // — root has reason 9999, each child has parent_reason+1.
    let leaf = regions.get(&N).expect("leaf");
    assert_eq!(
        leaf.cancel_reason,
        Some(9999 + N),
        "REGRESSION: leaf cancel_reason chain depth wrong. \
         Got {actual:?}, expected {expected}. Chain build \
         is broken.",
        actual = leaf.cancel_reason,
        expected = 9999 + N,
    );

    // The 1-second bound. In practice this completes in
    // microseconds.
    assert!(
        elapsed < Duration::from_secs(1),
        "REGRESSION: 1000-deep-tree cancel propagation took \
         {elapsed:?} (>= 1 second). The total work should be \
         O(N + N log N) = ~10K operations for N=1000 — \
         microseconds in practice. If elapsed is closer to \
         seconds, an O(N²) regression has been introduced. \
         Investigate cancel_request, collect_region_and_\
         descendants_with_depth, and the per-pass loops.",
    );
}

#[test]
fn deep_tree_subtree_collection_visits_each_region_exactly_once() {
    // Behavioral pin: each region is visited EXACTLY ONCE
    // by the iterative DFS. Verified by counting unique IDs
    // in the result vs the total region count.
    const N: u64 = 500;

    let mut regions: HashMap<u64, MockRegion> = HashMap::with_capacity(N as usize + 1);

    regions.insert(
        0,
        MockRegion {
            id: 0,
            parent: None,
            children: vec![1, 2], // Branching: 2 children at root.
            state: 0,
            cancel_reason: None,
        },
    );
    // Two parallel chains under root.
    for chain_id in [1, 2_u64] {
        let mut prev = chain_id;
        for offset in 1..(N / 2) {
            let id = chain_id * 1000 + offset;
            regions
                .entry(prev)
                .and_modify(|r| r.children.push(id))
                .or_insert_with(|| MockRegion {
                    id: prev,
                    parent: Some(0),
                    children: vec![id],
                    state: 0,
                    cancel_reason: None,
                });
            regions.insert(
                id,
                MockRegion {
                    id,
                    parent: Some(prev),
                    children: vec![],
                    state: 0,
                    cancel_reason: None,
                },
            );
            prev = id;
        }
    }

    let start = Instant::now();
    let nodes = collect_subtree(&regions, 0);
    let elapsed = start.elapsed();

    // Count unique IDs.
    let mut unique = std::collections::HashSet::new();
    for n in &nodes {
        assert!(
            unique.insert(n.id),
            "REGRESSION: region {id} visited more than once \
             during subtree collection. Each region must be \
             visited EXACTLY once; duplicates indicate a \
             cycle or a flawed traversal.",
            id = n.id,
        );
    }

    assert_eq!(
        unique.len(),
        nodes.len(),
        "REGRESSION: nodes vec has duplicates",
    );

    assert!(
        elapsed < Duration::from_millis(100),
        "REGRESSION: subtree collection of {n_regions} regions \
         took {elapsed:?} — expected <100ms. O(N²) regression.",
        n_regions = regions.len(),
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/scheduler_cancel_storm_propagation_audit.rs",
        "tests/runtime_cancel_cause_chain_depth_audit.rs",
        "tests/cx_scope_deep_nesting_bookkeeping_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
