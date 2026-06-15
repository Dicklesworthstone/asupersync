# Certified plan rewrites

> Bead `asupersync-plan-rewrites-runtime-tjrmwz.2`, AC6.
> Source: `src/plan/{mod,rewrite,analysis,certificate,execute}.rs`.

Asupersync can capture a combinator tree as a plan DAG, restructure it under an
algebraic rewrite policy, and **attach a machine-checkable certificate** proving
the restructuring preserves the program's cancellation and obligation semantics.
The certificate is a public, versioned artifact: it names the rules that fired,
the before/after plan hashes, and the node-count change, and it is surfaced on
the execution's trace events and queryable from the result.

The differentiator is the certificate plus its *fail-closed* discipline:
optimization is always optional, so a plan that cannot be proven safe to rewrite
simply runs unrewritten with a logged reason — never a hard error.

## The fail-closed ladder

`plan::execute::capture_optimized(cx, build)` (and the policy-parameterized
`capture_optimized_with_policy(cx, build, policy)`) run this ladder:

```text
capture (tjrmwz.1)  ->  rewrite pass  ->  side-condition verify  ->  execute
   PlanDag             plan/rewrite.rs    plan/analysis.rs           plan/execute.rs
                                              |
                              ok: execute the rewritten DAG + emit certificate
                              fail: log the reason + execute the ORIGINAL DAG
```

Every outcome obeys the same postcondition invariants (pinned in
`tests/plan_capture_optimized_equivalence_contract.rs`):

- a non-identity certificate ⇒ the rewritten DAG ran *and* there is no
  fallback reason;
- a fallback reason (or identity certificate) ⇒ the original DAG ran;
- the executed value is identical to the unoptimized run (equivalence) — this is
  proven oracle-free over a family of nested shapes, not asserted on one fixture.

## The rewrite rule menu and policy gate

`REWRITE_RULE_MENU` (`src/plan/rewrite.rs`) holds six rules; the policy gates
which may *fire*, the side-condition checker gates whether a permitted firing is
*safe*.

| Rule            | Pattern → replacement                              | Conservative | Aggressive |
|-----------------|----------------------------------------------------|:------------:|:----------:|
| `JoinAssoc`     | `Join[Join[a,b],c] → Join[a,b,c]`                  | ✅ | ✅ |
| `RaceAssoc`     | `Race[Race[a,b],c] → Race[a,b,c]`                  | ✅ | ✅ |
| `TimeoutMin`    | `Timeout(d1,Timeout(d2,f)) → Timeout(min(d1,d2),f)`| ✅ | ✅ |
| `DedupRaceJoin` | dedupe a shared child across a race of joins       | ✅¹ | ✅ |
| `JoinCommute`   | join children → canonical order                    | ❌ | ✅ |
| `RaceCommute`   | race children → canonical order                    | ❌ | ✅ |

¹ Conservative restricts `DedupRaceJoin` to binary joins with leaf shared
children (`require_binary_joins`). The conservative policy deliberately refuses
commutativity: reordering a `Join`'s children permutes its aggregate and
reordering a `Race`'s children can flip the winner.

`RewritePolicy::conservative()` is the default; `RewritePolicy::assume_all()` is
the aggressive policy. The aggressive policy is **not** outcome-preserving
through capture (see "Honest scoping") and must clear the differential gate
(tjrmwz.3 / I3) before any default-on discussion.

## The model (galaxy-brain card)

The side-condition checker (`plan/analysis.rs::SideConditionChecker`, applied by
`rewrite.rs::check_side_conditions`) is an **abstract interpreter over two safety
lattices and one min-plus deadline semiring**. A rewrite is admitted only if the
*after* plan is no less safe than the *before* plan on all three.

### 1. Obligation safety — "are permits/acks/leases still resolved?"

`ObligationSafety` is a four-point lattice (`is_safe` ⟺ `Clean`):

```text
        Unknown          (top: insufficient information — poisons everything)
       /       \
    Clean    MayLeak
       \       /
       Leaked            (bottom: a cleanup path is unreachable)
```

`join` is "the least-safe of two states": `Leaked` dominates `MayLeak` dominates
`Clean`, and `Unknown` poisons to `Unknown`. A node's effective safety is the
`join` over its children, so one leaky subtree makes the whole tree leaky. An
`ObligationFlow` carries the *named* obligations through `join`/`race`
composition so the diagnostics can say *which* obligation is at risk, not just
yes/no.

### 2. Cancel safety — "are race losers still drained?"

`CancelSafety` is the identical four-point shape for the loser-drain invariant
(`is_safe` ⟺ `Safe`):

```text
        Unknown
       /       \
     Safe    MayOrphan
       \       /
       Orphan            (a race definitely leaves orphan tasks)
```

This is the lattice that makes commutativity dangerous: any rule touching a
`Race` (`RaceAssoc`, `RaceCommute`, `DedupRaceJoin`) must satisfy
`cancel_safe(before) && cancel_safe(after)`, or the checker rejects with
`"rewrite violates loser-drain preservation"`.

### 3. Deadline algebra — "is the budget still at least as tight?"

`DeadlineMicros` is a min-plus semiring element: `None = +∞` (unbounded),
`Some(n) = n µs`. Sequential composition `add`s, parallel composition takes the
`min`, and `is_at_least_as_tight_as` / `preserves_deadline_guarantee` are the
order. A rewrite that loosened a deadline (`budget monotonicity violated`) is
rejected; `TimeoutMin` is admitted precisely because `min(d1, d2)` is never
looser than either input.

### The verification gate, in order

`check_side_conditions(rule, before, after, checker, policy)` rejects (returns a
logged reason, triggering fallback) on the first failure of:

1. `obligations_safe(before)` and `obligations_safe(after)`;
2. for race-affecting rules: `cancel_safe(before)` and `cancel_safe(after)`;
3. budget monotonicity (the after-deadline is not looser);
4. `rewrite_no_new_obligation_leaks(before, after)` — no *new* leak candidates;
5. for join-affecting rules: finalize-ordering preservation;
6. per-rule structural checks (policy permits the law *and* the shapes match).

### Worked example

```text
plan:   timeout(60s, timeout(20s, leaf f))
policy: conservative   rule: TimeoutMin
```

- **Obligation lattice:** `f` is `Clean`; the two `Timeout` wrappers add no
  obligations ⇒ before and after both `join` to `Clean`. Gate 1 passes.
- **Cancel lattice:** no `Race` nodes ⇒ `Safe` throughout. Gate 2 is N/A
  (TimeoutMin is not race-affecting) and trivially holds.
- **Deadline semiring:** before = `min`-nest of `{60s, 20s}` over `f`; after =
  `Timeout(min(60s,20s)=20s, f)`. `20s ≤ 20s` ⇒ `preserves_deadline_guarantee`.
  Gate 3 passes.
- Gate 4/5/6 pass (no new obligations, no join reorder, policy permits timeout
  simplification, shapes match) ⇒ the rewrite is admitted.

Result: interior nodes `2 → 1` (one fewer `Box::pin`'d evaluation future and
poll layer per execution), the surviving deadline is the tighter `20s`, the leaf
set is conserved, and the certificate records one `TimeoutMin` step with matching
before/after hashes.

## The certificate as a public artifact

`RewriteCertificate` (`src/plan/certificate.rs`) is the surfaced proof:

| Field                                   | Meaning |
|-----------------------------------------|---------|
| `version: CertificateVersion`           | Schema version (bump on encoding change). |
| `policy: RewritePolicy`                  | Policy the rewrite ran under. |
| `before_hash` / `after_hash: PlanHash`  | SHA-256 (256-bit, 64-hex) of the DAG before/after. |
| `before_node_count` / `after_node_count`| Node counts (the committed structural win). |
| `steps: Vec<CertifiedStep>`             | Fired rules in application order, with per-step hashes. |

The hash is **collision-resistant SHA-256** (`br-asupersync-eyb1s5`): an
adversarial extractor cannot forge two distinct plans that share a certificate.
Helpers: `is_identity()`, `fingerprint()` (stable dedup key), `minimize()`
(drop inverse pairs / no-ops), and `compact()` →  `CompactCertificate`, a fixed
`81 + 9·steps`-byte wire form that preserves the fired-rule list (pinned by
`tests/plan_certificate_compact_serialization_conformance.rs`). The full-form
golden lives in `tests/plan_certificate_format_golden.rs`.

## Honest scoping

What is proven, and where:

- **Equivalence + fail-closed ladder** — `plan_capture_optimized_equivalence_contract.rs` (7/7).
- **Aggressive policy is gated-risk, not inert** — `plan_capture_optimized_policy_invariance_contract.rs` (8/8). `assume_all` agrees with conservative only on order-stable shapes; a node-replacing rewrite (`TimeoutMin`/`JoinAssoc`/`RaceAssoc`) installs a fresh higher-id node whose `Join`/`Race` parent is now non-canonical, after which commutativity permutes a `Join`'s aggregate or flips a `Race`'s index-0 winner. This is the concrete reason the aggressive policy must clear the I3 differential gate before default-on.
- **Measurable wins (AC3)** — `plan_capture_optimized_rewrite_savings_contract.rs` (7/7). `JoinAssoc`, `RaceAssoc`, `TimeoutMin` each commit an interior-node reduction (= one fewer `Box::pin`'d eval future + poll layer) while conserving the leaf set.
- **Documented negative result** — `DedupRaceJoin` is the only rule that would reduce executed *work* (run a shared subtree once), but it is structurally unreachable through one-shot capture: capture rejects any node referenced twice (`PlanExecError::SharedNode`), so a captured plan is a tree of one-shot futures and never offers a shared subtree to dedupe. Through capture the rewrites shrink interpreter overhead, not redundant leaf execution.

Remaining: **AC4** — the I3 differential-equivalence gate (rewritten vs baseline
across seeds, outcomes, and obligations) lives in the dependent bead
`asupersync-plan-rewrites-runtime-tjrmwz.3` and is the safety net the aggressive
policy must pass before any default-on.
