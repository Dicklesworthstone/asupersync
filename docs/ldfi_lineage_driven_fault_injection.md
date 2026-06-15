# Lineage-Driven Fault Injection (LDFI)

> Bead: `asupersync-adaptive-control-plane-yj2nxx.4`
> Code: [`src/lab/ldfi.rs`](../src/lab/ldfi.rs) (pure core),
> [`src/lab/ldfi_trace.rs`](../src/lab/ldfi_trace.rs) (lab-runtime trace adapter)

## Galaxy-brain card

**Problem.** Chaos mode injects faults blindly — seeded, but undirected. To gain
confidence that a distributed/cancellation invariant survives faults, blind chaos
must try every fault on every event: one experiment per fault-able event, per
depth. That is exponential and mostly wasted on faults that could never have
mattered.

**Insight (LDFI).** A *successful* run's trace already tells you which events the
outcome causally depended on. A fault can only break the outcome if it removes
some event from **every** independent way the outcome was produced. So the faults
worth trying are exactly the **minimal hitting sets** (transversals) of the family
of *derivations* (each derivation = the fault-able causal cone of one production
of the outcome). Enumerate those, inject them, and you either find a real bug or
build a per-corpus certificate that no `≤k`-fault counterexample exists — with
orders of magnitude fewer experiments than blind chaos.

**Pipeline.**

```
lab trace ──► CausalLineage ──► SupportGraph ──► minimal hitting sets ──► experiment loop ──► LdfiReport (JSON)
  (TraceEvent)   happens-before    derivations      fault hypotheses        inject + re-run     operator output
```

## Why it beats blind chaos

For a delivery whose outcome depends on a single shared send plus two independent
acks, blind chaos runs **3** single-fault experiments (one per fault-able event)
and only the send actually breaks delivery. LDFI extracts the lineage, computes
the minimal breaking hypothesis `{send}`, and confirms the violation in **one**
experiment. `blind_chaos_single_fault_count()` records the baseline so the saving
is committed alongside the result.

## The pure core — `asupersync::lab::ldfi`

The core reasons over an abstract happens-before relation; it has no trace, I/O,
clock, or chaos dependency, so the algorithm is independently testable.

| Type / fn | Role |
|-----------|------|
| `FaultEventId(u64)` | Opaque ordered token for a fault-able event. |
| `CausalLineage` | Happens-before relation + fault-ability flags; `causal_cone`, `support_of`. |
| `SupportGraph` | Family of derivations; `from_causal_cone(s)`, `minimal_hitting_sets`. |
| `HittingSetBudget { max_depth, max_hypotheses }` | Bounds the NP-hard enumeration. |
| `HittingSetResult` | Hypotheses (smallest-first), `exhausted`, `unbreakable`, `coverage_certificate()`, `run_experiments()`. |
| `LdfiExperimentBudget` / `…Observation` / `…Status` / `…Report` | The deterministic experiment-loop state machine. |

A **coverage certificate** `Some(k)` means: for *this* support graph, no fault
hypothesis of size `≤ k` can break the outcome (the bounded space was exhausted
with no hypothesis, or a derivation had no fault-able support). It is honestly
scoped — per trace corpus, never a universal claim.

## The lab-runtime adapter — `asupersync::lab::ldfi_trace`

`build_causal_lineage(events, config)` fills the pure `CausalLineage` from a
recorded `&[TraceEvent]`; `support_graph_for(events, config, predicate)` composes
the whole `trace → lineage → SupportGraph` path in one call.

### Event identity

Every `TraceEvent` becomes `FaultEventId(event.seq)`. Trace seq numbers are
monotonic and unique, so the mapping is total and stable.

### Fault taxonomy — `default_faultable(kind)`

A fault can only be injected on the **deliveries, fires, grants, and acks** the
chaos/fault machinery can actually remove. Everything else propagates causality
but carries no injectable fault.

| Classification | `TraceEventKind`s |
|----------------|-------------------|
| **Fault-able** | `Wake`, `CancelAck`, `WorkerCancelAcknowledged`, `WorkerDrainCompleted`, `WorkerFinalizeCompleted`, `TimerFired`, `IoReady`, `IoResult`, `ObligationReserve`, `ObligationCommit`, `DownDelivered`, `ExitDelivered`, `ChaosInjection` |
| **Structural** | spawn / schedule / yield / poll / complete, region & time lifecycle, `IoRequested`, `TimerScheduled` / `TimerCancelled`, RNG, checkpoints, futurelock, monitor/link create-drop, `UserTrace` (the outcome assertion), budgets, … |

Per the soundness note below, the classifier **leans fault-able**: mis-labelling a
structural event fault-able only adds a hypothesis the experiment loop refutes;
mis-labelling a fault-able event structural is unsafe (it hides a real fault).

### Happens-before extraction rules (per event type)

Edges are recovered from three independent, **additive** sources:

1. **Per-task program order.** Consecutive events that name a single owning task
   (`Task` / `Cancel` / `Futurelock` / `Obligation` / `Worker` / `Budget` data)
   form a chain — a thread of execution is totally ordered.
2. **Per-resource correlation** (`config.correlate_resources`). Events sharing a
   resource handle are linked, request/grant happens-before later delivery:
   - **I/O token** — `IoRequested → IoReady → IoResult/IoError` on the same token.
   - **Obligation id** — `ObligationReserve → Commit/Abort/Leak` on the same id.
   - **Timer id** — `TimerScheduled → TimerFired/TimerCancelled`.
   - **Monitor ref** — `MonitorCreated → DownDelivered/MonitorDropped`.
   - **Link ref** — `LinkCreated → ExitDelivered/LinkDropped`.
3. **Logical clocks** (`config.use_logical_time`). For events carrying a
   `LogicalTime`, every strictly-`Before` pair becomes an edge (the same
   happens-before machinery as `trace/causality`). Precise for **vector** clocks;
   a sound over-approximation for **Lamport** clocks (which collapse to a total
   order, pulling every earlier event into the cone). This pass is `O(n²)` in the
   number of clock-carrying events.

### Soundness contract

*Over-approximating* the happens-before relation — adding edges, enlarging cones,
or over-classifying fault-ability — is **safe**: it only yields extra hypotheses
the experiment loop refutes. *Under-approximation* is **unsafe**: a missing edge
or a fault-able event marked structural can hide the very fault that breaks the
outcome. All three edge sources are therefore additive and the classifier errs
toward inclusion. With vector clocks the extraction is precise; with no clocks the
structural sources alone still assemble the cone.

## The JSON report — `LdfiReport`

`ldfi_report(&HittingSetResult, blind_chaos_baseline)` builds a deterministic,
serde-serializable report (schema `ldfi-report-v1`); `with_experiment(&report)`
attaches the experiment-loop verdict. Hypotheses render as sorted event-id lists,
so the JSON is byte-stable across runs of the same input.

```jsonc
{
  "schema": "ldfi-report-v1",
  "max_depth": 3,
  "exhausted": true,
  "unbreakable": false,
  "hypotheses": [[1], [2, 3]],          // smallest-first; {send}, then {ack_a, ack_b}
  "coverage_certificate": null,          // Some(k) iff no <=k-fault counterexample
  "blind_chaos_single_fault_experiments": 3,
  "experiment": {                        // present once hypotheses have been executed
    "status": "found_violation",         // | refuted_up_to_depth | experiment_budget_exhausted | hypothesis_search_truncated
    "experiments_run": 1,
    "violating_hypothesis": [1],
    "refuted": [],
    "remaining_hypotheses": null,
    "max_depth": null,
    "coverage_certificate": null
  }
}
```

## Status and honest scoping

Shipped and certified (`tests/ldfi_fault_hypothesis_proof.rs`,
`tests/ldfi_lineage_extraction_proof.rs`, `tests/ldfi_trace_adapter_proof.rs`):

- the pure hitting-set core and experiment-loop state machine;
- the abstract lineage extractor (`CausalLineage` → `SupportGraph`);
- the lab-runtime trace adapter (this document's extraction rules);
- the deterministic JSON report.

Remaining for the bead:

- the **chaos/fault re-run adapter** — execute each hypothesis by injecting via the
  live `channel/fault.rs` + `lab/chaos.rs` machinery in a real lab run (today the
  experiment loop takes a caller-supplied executor);
- the **`frankenlab ldfi` CLI** — drive the pipeline over a recorded trace and emit
  the `LdfiReport` as `--json` (the report is ready to serialize);
- **C3 auto-crashpack** wiring on a found violation.
