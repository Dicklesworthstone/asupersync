# Correctness review — transport_rq source-first path (commit `22bbddb59`)

Lane: **cc_2 cross-review** of cod_2/BluePike's source-first AUTH + FEC-fallback work
(`br-asupersync-atp-dataplane-redesign-317hxr.6.1`, commits `7bb77d971` + `22bbddb59`).
Scope: the CRITICAL benchmark finding "50M @ 3% loss / 50 ms = 123 s **AND sha MISS**"
(docs/atp_bench_matrix_spec.md §Lessons.1). Read-only review; all fixes are for the
owning lane (transport_rq + adaptive.rs), reported here, not applied.

Evidence cites `src/net/atp/transport_rq/mod.rs:<line>` at the reviewed commit.

---

## Verdict

| Property | Status |
|---|---|
| Fail-closed (never commit mismatched/incomplete data) | ✅ **VERIFIED SOUND** |
| The benchmark "sha MISS" is silent partial-commit | ❌ **NO** — it is fail-closed *non-convergence* |
| Adaptive FEC fallback under loss is wired | ⚠️ **PARTIAL** — engages ≤1 round, then disables (Finding 1) |
| Sparse source retransmit is targeted (not whole-entry) | ✅ sound for source rounds |
| FEC-fallback *repair* is targeted | ⚠️ per-entry, not per-block (Finding 2) |
| Benchmark can tell non-convergence apart from corruption | ❌ harness gap (Finding 3) |

**Headline:** the fail-closed guarantee holds — atp can never commit corrupt or partial
data, so the spec's open question ("silent partial-commit, or a transfer error scored as
MISS?") is answered: **it is a fail-closed non-convergence, not corruption.** The residual
123 s + MISS is a *convergence* problem, and Finding 1 is the most likely root cause: the
aggressive FEC fallback that was added to fix exactly this case is effectively switched off
during the repair-only rounds where it is needed.

---

## Fail-closed is verified sound (positive)

The commit path cannot persist unverified data:

* `verify_and_commit` (`mod.rs:3393`) re-hashes every staged entry with
  `hash_file_streaming` and compares `size` + `sha256_hex` (`mod.rs:3422-3429`), independently
  re-checks `decoder.complete && bytes_written == e.size` (`mod.rs:3419-3421`), and rebuilds
  the merkle root (`mod.rs:3439`). `committed = sha_ok && merkle_ok` (`mod.rs:3441`); the
  atomic staging→dest `rename` happens **only inside `if committed`** (`mod.rs:3443-3473`).
  A stale/buggy `complete` flag cannot cause a bad commit because the file is re-hashed.
* The receiver only reaches `verify_and_commit` when `pending.is_empty()` (`mod.rs:2829`).
  On `committed == false` it returns `RqError::Integrity` without committing (`mod.rs:2848`).
  On exhausted rounds it returns `RqError::NoConvergence` with `committed_paths: Vec::new()`
  (`mod.rs:2871-2889`) — nothing is written.
* The sender mirrors this: a Proof with `committed == false` makes `send_path` return
  `RqError::Integrity` (`mod.rs:1988`), so a transfer never reports success unless the
  receiver actually committed.

So in the failing 50M cell the receiver hit `max_feedback_rounds` (16,
`DEFAULT_MAX_FEEDBACK_ROUNDS`, `mod.rs:138`) with entries still pending, returned
`NoConvergence`, left the dest empty, and the harness scored the empty dest as a sha MISS.
**No mismatched bytes were ever committed.**

---

## Finding 1 — FEC fallback disables itself during the repair-only rounds (HIGH)

The adaptive-FEC fallback (`source_fec_fallback_tuning` → `adaptive::overhead_for_target`,
`mod.rs:525-537`) is the mechanism added per the spec to converge "when source-retransmit
isn't converging." It does not sustain:

* **Receiver** stops requesting sparse source symbols after the source phase.
  `source_symbols = source_retransmit_request_limit(config, feedback_rounds).map_or_else(Vec::new, …)`
  (`mod.rs:2892`), and `source_retransmit_request_limit` returns `Some` only while
  `feedback_round <= source_retransmit_rounds` (=2, `mod.rs:2142-2148`). So for round **≥ 3**
  the receiver sends `source_symbols = []`.
* **Sender** then refuses the fallback. `source_retransmit_needs_fec_fallback`
  early-returns `false` when `requested_sources == 0` (`mod.rs:2158-2162`):

  ```rust
  if config.repair_overhead > 1.0
      || config.source_retransmit_rounds == 0
      || requested_sources == 0          // ← round-3+ state: source_symbols is empty
  { return false; }
  ```

  With `requested_sources == 0` it returns `false`, so `round_tuning =
  adaptive.round_tuning(&config)` (plain, `mod.rs:2036-2040`) and the empty-source branch
  sprays repair with that plain tuning (`mod.rs:2041-2062`).

**Net effect:** the K-aware fallback overhead (`overhead_for_target`, capped at +50 %,
floored at +3 %, `mod.rs:180-181, 529-535`) engages for at most the single boundary round
`feedback_round == source_retransmit_rounds` (round 2, while source symbols are still
present), then **switches off for every repair round 3..16**. Those later rounds fall back to
the milder controller/loss-detector overhead (`plan.overhead` + `loss_fec_floor`,
`mod.rs:500-503`), which the ledger already measured as insufficient on 50M under loss.

### Fix recipe (transport_rq lane — not applied here)

Trigger the fallback on the *stall condition*, independent of `requested_sources`:

```rust
fn source_retransmit_needs_fec_fallback(config, feedback_round, requested_sources) -> bool {
    if config.repair_overhead > 1.0 || config.source_retransmit_rounds == 0 {
        return false;
    }
    let past_source_phase = feedback_round >= config.source_retransmit_rounds;
    let saturated = config.max_source_retransmit_requests != 0
        && requested_sources >= config.max_source_retransmit_requests;
    past_source_phase || saturated   // drop the `requested_sources == 0 → false` guard
}
```

This keeps the aggressive overhead engaged across the repair-only rounds (3..16) where
convergence actually happens. Recommend a focused A/B on 50M/3%/50 ms (Phase-2, orchestrator):
keep only if `feedback_rounds` drops and sha/merkle stay OK.

---

## Finding 2 — FEC-fallback repair is per-entry, not per-block (MEDIUM)

`NeedMore { pending: Vec<u32>, source_symbols: … }` (`mod.rs:919`) carries **entry indices**
in `pending`; it has no per-block granularity. Once in repair, `spray_round(…, &pending, …,
with_source=false)` (`mod.rs:2047`) emits fresh repair across **all blocks of each pending
entry**. For a large multi-block entry (50M at `max_block_size` ⇒ ~13 blocks) where only one
block is short a few symbols, ~12/13 of every repair round is wasted bandwidth. This is the
ledger's observed "each feedback round re-sprays repair for every block of that entry."

**Fix (transport_rq lane):** extend `NeedMore` to carry per-block deficits (block SBN →
missing-symbol count) so repair targets only incomplete blocks. Larger change than Finding 1;
file as a follow-up. Finding 1 is the higher-EV, lower-risk fix.

---

## Finding 3 — harness cannot distinguish non-convergence from corruption (MEDIUM, cc_1/score lane)

`ReceiveReceipt.reason` already separates the cases —
`"no convergence after N rounds, M entries pending"` (`mod.rs:2880-2883`) vs
`"per-entry SHA-256 mismatch"` / `"merkle-root mismatch"` (`mod.rs:3485-3488`) — and the
`RqError` variants differ (`NoConvergence` vs `Integrity`). But the benchmark scores any
non-zero exit / empty dest as a generic failure, so a fail-closed non-convergence reads the
same as a (never-actually-occurring) data-integrity violation.

**Recommendation (matrix_bench.sh / score_matrix.py — cc_1 lane, not edited here):** capture
the receiver `RqError` variant or `receipt.reason` into the JSONL and have `score_matrix.py`
classify `non_convergence` separately from `integrity_violation`. A fail-closed
non-convergence is a *performance* miss (the engine correctly refused bad data); a true
integrity violation would be a correctness emergency. They must never be conflated — this is
the spec's "Determine + fix" item, and the determination is: integrity is sound, convergence
is the work.

---

## Summary for the swarm

1. **Fail-closed is proven sound** — no silent/partial commit is reachable. Stop treating the
   sha MISS as a possible corruption bug; it is non-convergence.
2. **Finding 1 (HIGH, transport_rq):** the FEC fallback is off during repair rounds 3+; drop
   the `requested_sources == 0` early-return so `overhead_for_target` sustains. Most likely
   root cause of the 50M non-convergence; smallest, safest fix.
3. **Finding 2 (MED, transport_rq):** make repair per-block, not per-entry (follow-up).
4. **Finding 3 (MED, cc_1 harness):** record + classify non-convergence vs integrity so the
   scorecard never conflates a fail-closed refusal with corruption.
