# CALM Analysis: Saga Obligation Operations (bd-2wrsc.1)

Classification of Asupersync saga operations as monotone or non-monotone per the
CALM theorem (Hellerstein & Alvaro, "Keeping CALM: When Distributed Consistency is Easy", 2020).

**Methodology:** For each operation, we determine whether its effect on shared state
is monotone (only adds information, lattice-join-compatible) or non-monotone (depends
on negation, absence, or thresholds over incomplete data). Monotone operations can execute
coordination-free; non-monotone operations require synchronization barriers.

**Lattice domain:** The obligation system's state lattice is:
```
Unknown < Reserved < {Committed, Aborted} < Conflict
```
where `{Committed, Aborted}` are incomparable terminal states and `Conflict` is
the top element (join of conflicting terminals).

## Classification Table

| # | Operation | Protocol | Side Effects | Classification | Justification |
|---|-----------|----------|-------------|---------------|---------------|
| 1 | **Reserve** | All | Creates obligation record, sets state=Reserved, increments M[k,r] | **Monotone** | Pure insertion into obligation set. Monotone in the marking vector (counter increment). No read-dependency on other obligations. |
| 2 | **Commit** | TwoPhase, SendPermit | Transitions Reserved->Committed, records timestamp | **Non-monotone** | Requires reading current state=Reserved (negation of "already resolved"). State flip is a non-monotone lattice transition from the caller's perspective (though monotone in the lattice join order). |
| 3 | **Abort** | TwoPhase, SendPermit | Transitions Reserved->Aborted, records reason | **Non-monotone** | Same as Commit: requires guard on current state. Abort reason is a conditional assignment. |
| 4 | **Send** | SendPermit | Delivers message to receiver channel | **Monotone** | Appending to a channel is a set-union-like operation. Message delivery is grow-only. |
| 5 | **Recv** | SendPermit | Removes message from channel head | **Non-monotone** | Destructive read (dequeue) depends on presence/absence of messages. Classic non-monotone operation. |
| 6 | **Acquire** | Lease | Creates lease record, starts timer | **Monotone** | Lease creation is an insertion. Timer start is a side effect that doesn't depend on absence. |
| 7 | **Renew** | Lease | Extends lease deadline | **Monotone** | Deadline extension is a max operation (lattice join on timestamps). Renew(t') = max(current_deadline, t'). |
| 8 | **Release** | Lease | Transitions lease to released state | **Non-monotone** | Requires current state = active. State transition depends on negation (not already released). |
| 9 | **RegionClose** | Structured Concurrency | Checks M[*,r]=0, then closes region | **Non-monotone** | **Critical coordination point.** Requires testing that ALL obligations in a region have reached terminal state. This is a threshold/aggregation over incomplete data (quintessential non-monotone). |
| 10 | **Delegate** | Composition | Transfers channel ownership to child task | **Monotone** | Channel transfer is a reassignment that doesn't depend on absence. The delegation itself is a send-like operation (monotone information flow). |
| 11 | **CRDT Merge** | Distributed | Componentwise join of obligation entries | **Monotone** | By construction: join-semilattice merge with GCounter max. This is the canonical CALM-safe operation. |
| 12 | **Leak Detection** | Analysis | Marks obligation as leaked at region close | **Non-monotone** | Depends on negation: obligation is leaked *because* it was NOT resolved before region close. |
| 13 | **Cancellation Request** | Runtime | Sets cancel flag on Cx, propagates to children | **Monotone** | Cancel flag is a monotone latch (false -> true, never reverts). Propagation is downward-only information flow. |
| 14 | **Cancellation Drain** | Runtime | Waits for pending obligations to resolve | **Non-monotone** | Waiting for ALL obligations to reach terminal state is a barrier (non-monotone aggregation). |
| 15 | **Mark Leaked** | Obligation | Reserved -> Leaked (error state) | **Non-monotone** | Depends on timeout/absence of resolution. |
| 16 | **Budget Check** | Cx | Reads remaining budget, rejects if exhausted | **Non-monotone** | Threshold check on a depleting counter. |

## Summary Statistics

| Category | Count | Percentage |
|----------|-------|------------|
| **Monotone** | 7 | 43.8% |
| **Non-monotone** | 9 | 56.2% |
| **Total** | 16 | 100% |

## Minimum Coordination Points

Non-monotone operations that require synchronization barriers:

1. **RegionClose** (most critical): Must coordinate with all tasks in the region
   to ensure quiescence. This is the primary coordination bottleneck.

2. **Commit/Abort**: Must ensure exclusive state transition (no concurrent
   resolution of the same obligation). In practice, obligations have a single
   holder, so this is local coordination.

3. **Recv**: Channel dequeue requires coordination between sender and receiver.
   Already handled by the channel's internal synchronization.

4. **Cancellation Drain**: Must wait for pending work. This is inherently
   non-monotone but is bounded by structured concurrency.

5. **Budget Check**: Threshold on depleting resource. Could be replaced with
   a monotone "cost accumulator" checked post-hoc, but current design uses
   eager checking.

## Optimization Opportunities

### Already Coordination-Free (No Changes Needed)
- **Reserve**: Can execute entirely locally without coordination.
- **Send**: Channel append is naturally monotone.
- **Acquire/Renew**: Lease operations that only extend state.
- **Cancel Propagation**: Downward-only flag propagation.
- **CRDT Merge**: Already designed for coordination-free convergence.
- **Delegate**: Channel transfer is information flow.

### Candidates for CALM Optimization

1. **Batch Commit/Abort**: Group multiple obligation resolutions and apply
   as a single monotone "batch resolution" event. The batch is monotone
   (set of resolutions only grows); individual items may have conflicts
   detected lazily via CRDT merge.

2. **Lazy RegionClose**: Instead of synchronous barrier, use a monotone
   "close intent" flag and let obligations self-report resolution. Region
   close completes when the obligation counter reaches zero (monotone
   convergence of a GCounter delta).

3. **Speculative Recv**: Replace blocking dequeue with a monotone "claim"
   on a message, followed by lazy confirmation. This converts Recv from
   non-monotone (absence check) to monotone (claim insertion) with
   conflict resolution via CRDT.

4. **Budget Accumulator**: Replace eager budget threshold check with a
   monotone cost accumulator. Check budget exhaustion at coordination
   points only, not on every operation. This amortizes the non-monotone
   check.

## Critical Path Analysis

The minimum coordination points form the critical path for saga execution:

```
Reserve (M) -> [work] -> Commit/Abort (NM) -> RegionClose (NM)
   |                          |                      |
   v                          v                      v
  Local                  Local (single             Barrier
  (no coord)             holder owns it)        (must wait)
```

The critical coordination bottleneck is **RegionClose**, which blocks on
quiescence of all obligations in the region. All other non-monotone operations
are either local (single-holder Commit/Abort) or already synchronized
(channel Recv).

## Monotonicity Markers (Runtime Contract)

For future runtime integration, each operation should emit a monotonicity
marker in its trace span:

```rust
// Proposed tracing field for CALM classification
info!(
    saga = saga_name,
    step = step_name,
    classification = "monotone", // or "non_monotone"
    justification = reason,
);
```

Metrics (for future runtime validation):
- `saga_step_monotonicity` (gauge by saga and step, 1=monotone 0=non-monotone)
- `saga_monotone_ratio` (gauge by saga)
- `calm_coordination_barriers_total` (counter by saga)
