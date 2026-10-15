-------------------------------- MODULE Asupersync --------------------------------
\* Bounded model of the asupersync runtime state machines (bd-11g3i).
\* Aligned with canonical semantic contract (SEM-07.1, br-asupersync-3cddg.7.1).
\*
\* Models three interacting state machines:
\*   1. Task lifecycle:    Spawned → Running → [CancelRequested → CancelMasked →
\*                         CancelAcknowledged → Finalizing →] Completed
\*   2. Region lifecycle:  Open → Closing → ChildrenDone → Finalizing →
\*                         Quiescent → Closed
\*   3. Obligation lifecycle: Reserved → Committed | Aborted | Leaked
\*
\* Canonical contract docs (SEM-04):
\*   - docs/semantic_contract_schema.md
\*   - docs/semantic_contract_glossary.md
\*   - docs/semantic_contract_transitions.md
\*   - docs/semantic_contract_invariants.md
\*   Cancel rules:     #1-12 (rule.cancel.*)
\*   Obligation rules: #13-21 (rule.obligation.*)
\*   Region rules:     #22-28 (rule.region.*)
\*   Outcome rules:    #29-32 (def.outcome.*) — abstracted: see ADR-008
\*   Ownership rules:  #33-36 (inv.ownership.*, rule.ownership.*)
\*   Combinator rules: #37-43 (comb.*, law.*) — not modeled: see ADR-005
\*   Capability rules: #44-45 (inv.capability.*) — type-system only
\*   Determinism:      #46-47 (inv.determinism.*) — not modeled: see ADR-007
\*
\* Cross-reference to Lean spec: formal/lean/Asupersync.lean
\*   TaskState (line 80), RegionState (line 89), ObligationState (line 97),
\*   Step inductive (lines 300-570), WellFormed (line 1144)
\*
\* Cross-reference to Rust implementation:
\*   src/record/task.rs (TaskState enum, lines 21-50)
\*   src/record/region.rs (RegionState enum, lines 22-36; transitions 659-720)
\*   src/record/obligation.rs (ObligationState enum, lines 125-130)
\*
\* Documented abstraction decisions:
\*   ADR-003: Cancel propagation (#6) is projected to direct children only;
\*            subregion propagation + severity strengthening are abstracted
\*   ADR-004: Region finalizer body (#25) abstracted — state transitions modeled.
\*            Note: despite ADR-004, the TLA+ model DOES model the Finalizing and
\*            Quiescent intermediate states (ChildrenDone → Finalizing → Quiescent →
\*            Closed). The abstraction applies to the finalizer BODY, not the state
\*            transitions. SEM-04.3 §6 NOTE ("TLA+ models close_children_done →
\*            Closed directly") is outdated — this model includes the full ladder.
\*   ADR-005: Combinator rules (#37-43) not modeled — tested via runtime oracles
\*   ADR-007: Determinism/seed (#46-47) not modeled — tested via lab runtime
\*   ADR-008: Outcome severity (#29-31) abstracted — no severity tags on tasks
\*
\* Assumption envelope (model assumptions, not safety guarantees):
\*   - Finite task/region/obligation sets (configurable via constants)
\*   - Mask depth bounded by MAX_MASK (default 2 for tractable checking)
\*   - CancelReason abstracted to a single symbolic value (ADR-003)
\*   - No wall-clock/deadline modeling (abstracted away)
\*   - Obligation kinds not distinguished (only state matters)
\*   - Region finalizer body is abstracted; state transitions are modeled
\*   - Outcome severity not modeled; tasks complete without severity tag (ADR-008)
\*
\* Checked properties (canonical rule IDs in parentheses):
\*   TypeInvariant:                All state variables in expected domains
\*   WellFormedInvariant:          Structural consistency (Lean WellFormed)
\*   NoOrphanTasks:                Closed regions have no non-completed tasks (#34)
\*   NoLeakedObligations:          Closed regions have no reserved obligations (#17, #20)
\*   CloseImpliesQuiescent:        Closed regions are quiescent (#27)
\*   MaskBoundedInvariant:         Mask depth always in 0..MAX_MASK (#11)
\*   MaskMonotoneInvariant:        Non-zero mask implies cancel-processing state (#12)
\*   CancelIdempotenceStructural:  Cancel only applies to Running tasks (#5)
\*   ReplyLinearityInvariant:      Spork SINV-1 — obligations resolved on close
\*   RegistryLeaseInvariant:       Spork SINV-3 — ledger empty on close
\*   AssumptionEnvelopeInvariant:  Bounded model envelope for reproducible checking
\*   CancelTerminates (TEMPORAL):  Cancel eventually reaches Completed (needs LiveSpec)
\*
\* Usage:
\*   tlc Asupersync.tla -config Asupersync_MC.cfg -workers auto
\*   or: scripts/run_model_check.sh

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    TaskIds,        \* Set of task identifiers, e.g. {1, 2}
    RegionIds,      \* Set of region identifiers, e.g. {1, 2}
    ObligationIds,  \* Set of obligation identifiers, e.g. {1}
    RootRegion,     \* Distinguished root region
    MAX_MASK        \* Maximum mask depth for cancel deferral

VARIABLES
    \* ===================================================================
    \* Task state variables
    \*   Canonical rules: #33 inv.ownership.single_owner,
    \*                    #34 inv.ownership.task_owned,
    \*                    #36 rule.ownership.spawn
    \*   Glossary: SEM-04.2 §3 (Task lifecycle states)
    \* ===================================================================
    taskState,      \* TaskIds → TaskState (lifecycle position; SEM-04.2 §3.1)
    taskRegion,     \* TaskIds → RegionId (owner region; #33 single-owner)
    taskMask,       \* TaskIds → 0..MAX_MASK (cancel deferral depth; #11 inv.cancel.mask_bounded,
                    \*                         #12 inv.cancel.mask_monotone)
    taskAlive,      \* TaskIds → BOOLEAN (spawned flag; meaningful iff TRUE)
    \* Lifecycle counter note: Cardinality({t ∈ TaskIds : taskAlive[t]}) corresponds
    \* to the RT's live task count. The TLA+ model uses explicit membership sets
    \* (regionChildren) rather than counters, so count-based invariants are expressed
    \* as set cardinality predicates.
    \*
    \* Abstracted fields (documented per ADR):
    \*   - cancel_kind: abstracted to symbolic value (ADR-003, #7 def.cancel.reason_kinds)
    \*   - budget: not modeled (ADR-008, no deadline/cost semantics)
    \*   - outcome: abstracted to "Completed" terminal state (ADR-008, #29 def.outcome.four_valued)
    \* ===================================================================
    \* Region state variables
    \*   Canonical rules: #22-28 rule.region.*, inv.region.*
    \*                    #35 def.ownership.region_tree
    \*   Glossary: SEM-04.2 §4 (Region lifecycle states)
    \* ===================================================================
    regionState,    \* RegionIds → RegionState (lifecycle position; SEM-04.2 §4.1)
    regionParent,   \* RegionIds → RegionId ∪ {0} (tree parent; 0 = root/unlinked; #35)
    regionCancel,   \* RegionIds → BOOLEAN (cancel signal propagated; #6 inv.cancel.propagates_down)
    regionChildren, \* RegionIds → SUBSET TaskIds (child tasks; #34 inv.ownership.task_owned)
                    \* Lifecycle counter: Cardinality(regionChildren[r]) = live task count in r
    regionSubs,     \* RegionIds → SUBSET RegionIds (child regions; #35 def.ownership.region_tree)
    regionLedger,   \* RegionIds → SUBSET ObligationIds (active reserved obligations;
                    \*   #20 inv.obligation.ledger_empty_on_close, #17 inv.obligation.no_leak)
                    \* Lifecycle counter: Cardinality(regionLedger[r]) = pending obligation count
    \*
    \* Abstracted fields (documented per ADR):
    \*   - finalizers: body abstracted (ADR-004, #25 rule.region.close_run_finalizer)
    \*     State transitions for finalizer phase are modeled; body effects are not.
    \* ===================================================================
    \* Obligation state variables
    \*   Canonical rules: #13-21 rule.obligation.*, inv.obligation.*
    \*   Glossary: SEM-04.2 §2.4 (Obligation)
    \* ===================================================================
    \* NOTE: obState/obHolder/obRegion are only meaningful when obAlive[o] = TRUE.
    \* For unborn obligations (obAlive = FALSE), these hold don't-care placeholder values.
    \* All invariants guard on obAlive before inspecting obligation state.
    obState,        \* ObligationIds → ObligationState (lifecycle; #18 inv.obligation.linear)
    obHolder,       \* ObligationIds → TaskId (owning task; structural ownership)
    obRegion,       \* ObligationIds → RegionId (owning region; ledger membership)
    obAlive         \* ObligationIds → BOOLEAN (created flag; #13 rule.obligation.reserve)
    \* Abstracted fields: obligation kind not distinguished (only state matters)

vars == <<taskState, taskRegion, taskMask, taskAlive,
          regionState, regionParent, regionCancel,
          regionChildren, regionSubs, regionLedger,
          obState, obHolder, obRegion, obAlive>>

\* ---- Model Assumption Envelope (SEM-07.3) ----
\*
\* This invariant captures bounded-check assumptions that are part of the
\* model-check contract and should not be misread as runtime guarantees.
\* Non-checkable assumptions (ADR-003/004/005/007/008 abstractions) are
\* documented in module header comments and docs/semantic_inventory_tla.md.
AssumptionEnvelopeInvariant ==
    /\ RootRegion \in RegionIds
    /\ Cardinality(TaskIds) \in 1..3
    /\ Cardinality(RegionIds) \in 1..3
    /\ Cardinality(ObligationIds) \in 0..2
    /\ MAX_MASK \in 1..2

\* ---- State Domains (canonical: docs/semantic_contract_glossary.md) ----

\* Task lifecycle states (Lean: TaskState, Rust: src/record/task.rs)
\* Spawned → Running → [CancelRequested → CancelMasked* → CancelAcknowledged →
\*                       Finalizing →] Completed
\* Note: CancelReason and Budget are abstracted away (ADR-003, ADR-008).
TaskStates == {"Spawned", "Running", "CancelRequested",
               "CancelMasked", "CancelAcknowledged", "Finalizing", "Completed"}

\* Region lifecycle states (Lean: RegionState, Rust: src/record/region.rs)
\* Open → Closing → ChildrenDone → Finalizing → Quiescent → Closed
\* Note: Finalizer body is abstracted; the Finalizing→Quiescent transition
\* represents execution completion (ADR-004, #25 rule.region.close_run_finalizer).
RegionStates == {"Open", "Closing", "ChildrenDone", "Finalizing", "Quiescent", "Closed"}

\* Obligation lifecycle states (Lean: ObligationState, Rust: src/record/obligation.rs)
\* Reserved → Committed | Aborted | Leaked
\* Linear: exactly one terminal transition per obligation (#18 inv.obligation.linear).
ObStates == {"Reserved", "Committed", "Aborted", "Leaked"}

\* ---- Type Invariant ----

TypeInvariant ==
    /\ \A t \in TaskIds : taskState[t] \in TaskStates
    /\ \A t \in TaskIds : taskRegion[t] \in RegionIds
    /\ \A t \in TaskIds : taskMask[t] \in 0..MAX_MASK
    /\ \A t \in TaskIds : taskAlive[t] \in BOOLEAN
    /\ \A r \in RegionIds : regionState[r] \in RegionStates
    /\ \A r \in RegionIds : regionParent[r] \in RegionIds \cup {0}
    /\ \A r \in RegionIds : regionCancel[r] \in BOOLEAN
    /\ \A r \in RegionIds : regionChildren[r] \subseteq TaskIds
    /\ \A r \in RegionIds : regionSubs[r] \subseteq RegionIds
    /\ \A r \in RegionIds : regionLedger[r] \subseteq ObligationIds
    /\ \A o \in ObligationIds : obState[o] \in ObStates
    /\ \A o \in ObligationIds : obHolder[o] \in TaskIds
    /\ \A o \in ObligationIds : obRegion[o] \in RegionIds
    /\ \A o \in ObligationIds : obAlive[o] \in BOOLEAN

\* ---- WellFormed Invariant (matches Lean WellFormed) ----

\* Every alive task's region exists (is not in initial/dead state)
TaskRegionExists ==
    \A t \in TaskIds : taskAlive[t] =>
        regionState[taskRegion[t]] /= "Closed" \/ taskState[t] = "Completed"

\* Every alive obligation's region exists
ObRegionExists ==
    \A o \in ObligationIds : obAlive[o] =>
        regionState[obRegion[o]] \in RegionStates

\* Every alive obligation's holder task exists
ObHolderExists ==
    \A o \in ObligationIds : obAlive[o] => taskAlive[obHolder[o]]

\* Every obligation in a ledger is reserved
LedgerReserved ==
    \A r \in RegionIds :
        \A o \in regionLedger[r] :
            obAlive[o] /\ obState[o] = "Reserved" /\ obRegion[o] = r

\* Every child task in a region exists
ChildrenExist ==
    \A r \in RegionIds :
        \A t \in regionChildren[r] : taskAlive[t]

\* Every subregion referenced exists
SubregionsExist ==
    \A r \in RegionIds :
        \A r2 \in regionSubs[r] :
            regionState[r2] \in RegionStates

WellFormedInvariant ==
    /\ LedgerReserved
    /\ ChildrenExist
    /\ SubregionsExist
    /\ ObHolderExists

\* ---- Safety Properties ----

\* No orphan tasks: closed regions have all tasks completed
NoOrphanTasks ==
    \A r \in RegionIds :
        regionState[r] = "Closed" =>
            \A t \in regionChildren[r] : taskState[t] = "Completed"

\* No leaked obligations: closed regions have empty ledger
NoLeakedObligations ==
    \A r \in RegionIds :
        regionState[r] = "Closed" => regionLedger[r] = {}

\* Close implies quiescent (Lean: close_implies_quiescent)
CloseImpliesQuiescent ==
    \A r \in RegionIds :
        regionState[r] = "Closed" =>
            /\ \A t \in regionChildren[r] : taskState[t] = "Completed"
            /\ \A r2 \in regionSubs[r] : regionState[r2] = "Closed"
            /\ regionLedger[r] = {}

\* ---- Initial State (canonical contract initialization semantics) ----
\*
\* SEM-07.1 alignment: canonical initialization from SEM-04.2 glossary.
\*
\* Canonical initialization assumptions (SEM-04.2 §3.1, §4.1, §2.4):
\*   - Tasks: not yet spawned (taskAlive = FALSE). The canonical glossary
\*     defines Spawned as "Task created, not yet polled"; unborn tasks use
\*     Spawned as a placeholder overwritten by Spawn (#36). All task invariants
\*     guard on taskAlive[t] = TRUE before inspecting taskState.
\*   - Regions: RootRegion starts Open (SEM-04.2 §4.1: "Region is active.
\*     Tasks can be spawned into it."). Other regions start Closed (dead pool —
\*     revived by CreateSubregion). This models the canonical requirement that
\*     only the root region exists at boot. Closed is the absorbing state
\*     (SEM-04.2 §4.1), but dead-pool regions are reusable via CreateSubregion.
\*   - Obligations: not yet created (obAlive = FALSE). The "Aborted" sentinel
\*     makes explicit that unborn obligations are NOT in the Reserved state,
\*     avoiding confusion with the LedgerReserved invariant (SEM-04.2 §2.4:
\*     "must be resolved (committed or aborted)"). All invariants guard on obAlive.
\*   - Region ownership fields: regionChildren, regionSubs, regionLedger all
\*     start empty (no children, no subregions, no obligations at boot).
\*     regionParent = 0 for all regions (tree root has no parent; dead-pool
\*     regions have no parent until CreateSubregion assigns one).

Init ==
    \* Task init: all tasks unborn; state is placeholder until Spawn (#36)
    /\ taskState = [t \in TaskIds |-> "Spawned"]
    /\ taskRegion = [t \in TaskIds |-> RootRegion]
    /\ taskMask = [t \in TaskIds |-> 0]
    /\ taskAlive = [t \in TaskIds |-> FALSE]
    \* Region init: root Open, others in dead pool (Closed) awaiting CreateSubregion
    /\ regionState = [r \in RegionIds |->
        IF r = RootRegion THEN "Open" ELSE "Closed"]
    /\ regionParent = [r \in RegionIds |-> 0]
    /\ regionCancel = [r \in RegionIds |-> FALSE]
    /\ regionChildren = [r \in RegionIds |-> {}]
    /\ regionSubs = [r \in RegionIds |-> {}]
    /\ regionLedger = [r \in RegionIds |-> {}]
    \* Obligation init: all obligations unborn (obAlive = FALSE).
    \* obState uses "Aborted" sentinel — a terminal state that cannot be confused
    \* with an active obligation. The value is meaningless until ReserveObligation
    \* sets obAlive = TRUE and obState = "Reserved" (#13 rule.obligation.reserve).
    /\ obState = [o \in ObligationIds |-> "Aborted"]
    /\ obHolder = [o \in ObligationIds |-> CHOOSE t \in TaskIds : TRUE]
    /\ obRegion = [o \in ObligationIds |-> RootRegion]
    /\ obAlive = [o \in ObligationIds |-> FALSE]

\* ---- Transition Actions (canonical rule IDs in comments) ----

\* SPAWN: create a task in an open region (#36 rule.ownership.spawn)
\* Precondition: task unborn, region Open. Postcondition: task alive, Spawned, owned by r.
\* Lean: Step.spawn | Rust: src/cx/scope.rs
Spawn(t, r) ==
    /\ ~taskAlive[t]
    /\ regionState[r] = "Open"
    /\ taskAlive' = [taskAlive EXCEPT ![t] = TRUE]
    /\ taskState' = [taskState EXCEPT ![t] = "Spawned"]
    /\ taskRegion' = [taskRegion EXCEPT ![t] = r]
    /\ taskMask' = [taskMask EXCEPT ![t] = 0]
    /\ regionChildren' = [regionChildren EXCEPT ![r] = @ \cup {t}]
    /\ UNCHANGED <<regionState, regionParent, regionCancel,
                   regionSubs, regionLedger,
                   obState, obHolder, obRegion, obAlive>>

\* COMPLETE: running task completes successfully (Lean: Step.complete)
\* Note: outcome severity abstracted (#29 def.outcome.four_valued, ADR-008).
Complete(t) ==
    /\ taskAlive[t]
    /\ taskState[t] = "Running"
    /\ taskState' = [taskState EXCEPT ![t] = "Completed"]
    /\ UNCHANGED <<taskRegion, taskMask, taskAlive,
                   regionState, regionParent, regionCancel,
                   regionChildren, regionSubs, regionLedger,
                   obState, obHolder, obRegion, obAlive>>

\* START: task transitions from Spawned to Running (implicit in canonical; scheduler picks up)
Start(t) ==
    /\ taskAlive[t]
    /\ taskState[t] = "Spawned"
    /\ taskState' = [taskState EXCEPT ![t] = "Running"]
    /\ UNCHANGED <<taskRegion, taskMask, taskAlive,
                   regionState, regionParent, regionCancel,
                   regionChildren, regionSubs, regionLedger,
                   obState, obHolder, obRegion, obAlive>>

\* CANCEL-REQUEST: mark a running task for cancellation (#1 rule.cancel.request)
\* Precondition: task alive and Running (enforces #5 inv.cancel.idempotence structurally).
\* CancelKind abstracted to symbolic value (ADR-003).
\* Lean: Step.cancelRequest | Rust: src/cancel/
CancelRequest(t) ==
    /\ taskAlive[t]
    /\ taskState[t] = "Running"
    /\ taskState' = [taskState EXCEPT ![t] = "CancelRequested"]
    /\ taskMask' = [taskMask EXCEPT ![t] = MAX_MASK]
    /\ regionCancel' = [regionCancel EXCEPT ![taskRegion[t]] = TRUE]
    /\ UNCHANGED <<taskRegion, taskAlive,
                   regionState, regionParent,
                   regionChildren, regionSubs, regionLedger,
                   obState, obHolder, obRegion, obAlive>>

\* CANCEL-MASKED: defer cancellation by consuming one mask unit (#10 rule.cancel.checkpoint_masked)
\* Mask decrements monotonically (#12 inv.cancel.mask_monotone); transitions to
\* CancelAcknowledged when mask reaches 0.
\* Lean: Step.cancelMasked | Rust: src/cancel/
CancelMasked(t) ==
    /\ taskAlive[t]
    /\ taskState[t] \in {"CancelRequested", "CancelMasked"}
    /\ taskMask[t] > 0
    /\ taskMask' = [taskMask EXCEPT ![t] = @ - 1]
    /\ taskState' = [taskState EXCEPT ![t] =
        IF taskMask[t] = 1 THEN "CancelAcknowledged" ELSE "CancelMasked"]
    /\ UNCHANGED <<taskRegion, taskAlive,
                   regionState, regionParent, regionCancel,
                   regionChildren, regionSubs, regionLedger,
                   obState, obHolder, obRegion, obAlive>>

\* CANCEL-ACKNOWLEDGE: explicit acknowledge when mask=0 (#2 rule.cancel.acknowledge)
\* Lean: Step.cancelAcknowledge | Rust: src/cancel/
CancelAcknowledge(t) ==
    /\ taskAlive[t]
    /\ taskState[t] = "CancelRequested"
    /\ taskMask[t] = 0
    /\ taskState' = [taskState EXCEPT ![t] = "CancelAcknowledged"]
    /\ UNCHANGED <<taskRegion, taskMask, taskAlive,
                   regionState, regionParent, regionCancel,
                   regionChildren, regionSubs, regionLedger,
                   obState, obHolder, obRegion, obAlive>>

\* CANCEL-FINALIZE: acknowledged cancellation enters finalization (#3 rule.cancel.drain)
\* Lean: Step.cancelFinalize | Rust: src/cancel/
CancelFinalize(t) ==
    /\ taskAlive[t]
    /\ taskState[t] = "CancelAcknowledged"
    /\ taskState' = [taskState EXCEPT ![t] = "Finalizing"]
    /\ UNCHANGED <<taskRegion, taskMask, taskAlive,
                   regionState, regionParent, regionCancel,
                   regionChildren, regionSubs, regionLedger,
                   obState, obHolder, obRegion, obAlive>>

\* CANCEL-COMPLETE: finalizing → completed (#4 rule.cancel.finalize)
\* Lean: Step.cancelComplete | Rust: src/cancel/
CancelComplete(t) ==
    /\ taskAlive[t]
    /\ taskState[t] = "Finalizing"
    /\ taskState' = [taskState EXCEPT ![t] = "Completed"]
    /\ UNCHANGED <<taskRegion, taskMask, taskAlive,
                   regionState, regionParent, regionCancel,
                   regionChildren, regionSubs, regionLedger,
                   obState, obHolder, obRegion, obAlive>>

\* CLOSE-BEGIN: region starts closing (#22 rule.region.close_begin)
\* Lean: Step.closeBegin | Rust: src/record/region.rs
CloseBegin(r) ==
    /\ regionState[r] = "Open"
    /\ regionState' = [regionState EXCEPT ![r] = "Closing"]
    /\ UNCHANGED <<taskState, taskRegion, taskMask, taskAlive,
                   regionParent, regionCancel,
                   regionChildren, regionSubs, regionLedger,
                   obState, obHolder, obRegion, obAlive>>

\* CLOSE-CANCEL-CHILDREN: cancel active children (#23 rule.region.close_cancel_children, #6 ADR-003)
\* Canonical alignment:
\*   - Newly active children (Spawned/Running) transition to CancelRequested with MAX_MASK.
\*   - In-flight cancel states keep their existing mask depth (no reset), matching
\*     idempotent strengthen semantics from rule #5.
CloseCancelChildren(r) ==
    /\ regionState[r] = "Closing"
    /\ \E t \in regionChildren[r] : taskState[t] \in {"Spawned", "Running"}
    /\ regionCancel' = [regionCancel EXCEPT ![r] = TRUE]
    /\ taskState' = [t \in TaskIds |->
        IF t \in regionChildren[r] /\ taskState[t] \in {"Spawned", "Running"}
            THEN "CancelRequested"
            ELSE taskState[t]]
    /\ taskMask' = [t \in TaskIds |->
        IF t \in regionChildren[r] /\ taskState[t] \in {"Spawned", "Running"}
            THEN MAX_MASK
            ELSE taskMask[t]]
    /\ UNCHANGED <<taskRegion, taskAlive,
                   regionState, regionParent,
                   regionChildren, regionSubs, regionLedger,
                   obState, obHolder, obRegion, obAlive>>

\* CLOSE-CHILDREN-DONE: all children complete (#24 rule.region.close_children_done)
CloseChildrenDone(r) ==
    /\ regionState[r] = "Closing"
    /\ \A t \in regionChildren[r] : taskState[t] = "Completed"
    /\ \A r2 \in regionSubs[r] : regionState[r2] = "Closed"
    /\ regionState' = [regionState EXCEPT ![r] = "ChildrenDone"]
    /\ UNCHANGED <<taskState, taskRegion, taskMask, taskAlive,
                   regionParent,
                   regionCancel, regionChildren, regionSubs, regionLedger,
                   obState, obHolder, obRegion, obAlive>>

\* CLOSE-RUN-FINALIZER: abstract finalizer execution (#25 rule.region.close_run_finalizer, ADR-004)
CloseRunFinalizer(r) ==
    /\ regionState[r] = "ChildrenDone"
    /\ regionState' = [regionState EXCEPT ![r] = "Finalizing"]
    /\ UNCHANGED <<taskState, taskRegion, taskMask, taskAlive,
                   regionParent, regionCancel,
                   regionChildren, regionSubs, regionLedger,
                   obState, obHolder, obRegion, obAlive>>

\* CLOSE-QUIESCE: finalizer done, quiescence met (#27 inv.region.quiescence)
CloseQuiesce(r) ==
    /\ regionState[r] = "Finalizing"
    /\ \A t \in regionChildren[r] : taskState[t] = "Completed"
    /\ \A r2 \in regionSubs[r] : regionState[r2] = "Closed"
    /\ regionLedger[r] = {}
    /\ regionState' = [regionState EXCEPT ![r] = "Quiescent"]
    /\ UNCHANGED <<taskState, taskRegion, taskMask, taskAlive,
                   regionParent, regionCancel,
                   regionChildren, regionSubs, regionLedger,
                   obState, obHolder, obRegion, obAlive>>

\* CLOSE: close a quiescent region (#26 rule.region.close_complete)
Close(r) ==
    /\ regionState[r] = "Quiescent"
    /\ \A t \in regionChildren[r] : taskState[t] = "Completed"
    /\ \A r2 \in regionSubs[r] : regionState[r2] = "Closed"
    /\ regionLedger[r] = {}
    /\ regionState' = [regionState EXCEPT ![r] = "Closed"]
    /\ UNCHANGED <<taskState, taskRegion, taskMask, taskAlive,
                   regionParent, regionCancel,
                   regionChildren, regionSubs, regionLedger,
                   obState, obHolder, obRegion, obAlive>>

\* RESERVE-OBLIGATION: create an obligation (#13 rule.obligation.reserve)
\* Canonical alignment:
\*   - Region may be Open or Closing.
\*   - Holder task may be Running or in active cancel processing.
\*   - Obligation region matches holder task region.
ReserveObligation(o, t, r) ==
    /\ ~obAlive[o]
    /\ taskAlive[t]
    /\ taskState[t] \in {"Running", "CancelRequested", "CancelMasked"}
    /\ taskRegion[t] = r
    /\ regionState[r] \in {"Open", "Closing"}
    /\ obAlive' = [obAlive EXCEPT ![o] = TRUE]
    /\ obState' = [obState EXCEPT ![o] = "Reserved"]
    /\ obHolder' = [obHolder EXCEPT ![o] = t]
    /\ obRegion' = [obRegion EXCEPT ![o] = r]
    /\ regionLedger' = [regionLedger EXCEPT ![r] = @ \cup {o}]
    /\ UNCHANGED <<taskState, taskRegion, taskMask, taskAlive,
                   regionState, regionParent, regionCancel,
                   regionChildren, regionSubs>>

\* COMMIT-OBLIGATION: resolve obligation as committed (#14 rule.obligation.commit)
CommitObligation(o) ==
    /\ obAlive[o]
    /\ obState[o] = "Reserved"
    /\ obState' = [obState EXCEPT ![o] = "Committed"]
    /\ regionLedger' = [regionLedger EXCEPT ![obRegion[o]] = @ \ {o}]
    /\ UNCHANGED <<taskState, taskRegion, taskMask, taskAlive,
                   regionState, regionParent, regionCancel,
                   regionChildren, regionSubs,
                   obHolder, obRegion, obAlive>>

\* ABORT-OBLIGATION: resolve obligation as aborted (#15 rule.obligation.abort)
AbortObligation(o) ==
    /\ obAlive[o]
    /\ obState[o] = "Reserved"
    /\ obState' = [obState EXCEPT ![o] = "Aborted"]
    /\ regionLedger' = [regionLedger EXCEPT ![obRegion[o]] = @ \ {o}]
    /\ UNCHANGED <<taskState, taskRegion, taskMask, taskAlive,
                   regionState, regionParent, regionCancel,
                   regionChildren, regionSubs,
                   obHolder, obRegion, obAlive>>

\* LEAK-OBLIGATION: completed task leaks obligation (#16 rule.obligation.leak)
LeakObligation(o) ==
    /\ obAlive[o]
    /\ obState[o] = "Reserved"
    /\ taskState[obHolder[o]] = "Completed"
    /\ obState' = [obState EXCEPT ![o] = "Leaked"]
    /\ regionLedger' = [regionLedger EXCEPT ![obRegion[o]] = @ \ {o}]
    /\ UNCHANGED <<taskState, taskRegion, taskMask, taskAlive,
                   regionState, regionParent, regionCancel,
                   regionChildren, regionSubs,
                   obHolder, obRegion, obAlive>>

\* CREATE-SUBREGION: create a child region (#35 def.ownership.region_tree)
\* Revives a Closed region from dead pool into an Open child of parent.
CreateSubregion(parent, child) ==
    /\ parent /= child
    /\ regionState[parent] = "Open"
    /\ regionState[child] = "Closed"
    /\ child \notin regionSubs[parent]
    /\ regionParent[child] = 0           \* child has no existing parent (tree)
    /\ parent \notin regionSubs[child]   \* prevent mutual parent-child
    /\ regionState' = [regionState EXCEPT ![child] = "Open"]
    /\ regionParent' = [regionParent EXCEPT ![child] = parent]
    /\ regionSubs' = [regionSubs EXCEPT ![parent] = @ \cup {child}]
    /\ UNCHANGED <<taskState, taskRegion, taskMask, taskAlive,
                   regionCancel,
                   regionChildren, regionLedger,
                   obState, obHolder, obRegion, obAlive>>

\* ---- Next-State Relation ----

Next ==
    \/ \E t \in TaskIds, r \in RegionIds : Spawn(t, r)
    \/ \E t \in TaskIds : Start(t)
    \/ \E t \in TaskIds : Complete(t)
    \/ \E t \in TaskIds : CancelRequest(t)
    \/ \E t \in TaskIds : CancelMasked(t)
    \/ \E t \in TaskIds : CancelAcknowledge(t)
    \/ \E t \in TaskIds : CancelFinalize(t)
    \/ \E t \in TaskIds : CancelComplete(t)
    \/ \E r \in RegionIds : CloseBegin(r)
    \/ \E r \in RegionIds : CloseCancelChildren(r)
    \/ \E r \in RegionIds : CloseChildrenDone(r)
    \/ \E r \in RegionIds : CloseRunFinalizer(r)
    \/ \E r \in RegionIds : CloseQuiesce(r)
    \/ \E r \in RegionIds : Close(r)
    \/ \E o \in ObligationIds, t \in TaskIds, r \in RegionIds :
        ReserveObligation(o, t, r)
    \/ \E o \in ObligationIds : CommitObligation(o)
    \/ \E o \in ObligationIds : AbortObligation(o)
    \/ \E o \in ObligationIds : LeakObligation(o)
    \/ \E p \in RegionIds, c \in RegionIds : CreateSubregion(p, c)

\* ---- Specification ----

\* Safety specification (no fairness — checking invariants only).
\* AssumptionEnvelopeInvariant is checked separately in Asupersync_MC.cfg.
Spec == Init /\ [][Next]_vars

\* ---- Liveness / Progress (documented, not checked in safety-only config) ----
\*
\* CancelTerminates: every task that enters cancel processing eventually
\* reaches Completed. This requires fairness assumptions, which the safety-only
\* Spec does not include. LiveSpec documents the fairness-enabled envelope.
\*
\* Note: Asupersync_MC.cfg uses Spec (safety-only, no fairness clauses).
\* To model-check liveness, use LiveSpec with PROPERTY CancelTerminates.
CancelTerminates ==
    \A t \in TaskIds :
        taskAlive[t] /\ taskState[t] \in {"CancelRequested", "CancelMasked",
                                           "CancelAcknowledged"} ~>
            (taskState[t] = "Completed" \/ ~taskAlive[t])

LivenessFairnessAssumptions == WF_vars(Next)

LiveSpec == Init /\ [][Next]_vars
           /\ AssumptionEnvelopeInvariant
           /\ LivenessFairnessAssumptions

\* ---- Canonical Mask Properties (SEM-07.1) ----

\* #11 inv.cancel.mask_bounded: mask depth is always within 0..MAX_MASK.
\* This is already part of TypeInvariant (taskMask[t] \in 0..MAX_MASK) but
\* stated explicitly for canonical traceability.
MaskBoundedInvariant ==
    \A t \in TaskIds : taskMask[t] \in 0..MAX_MASK

\* #12 inv.cancel.mask_monotone: mask only decrements during cancel processing.
\* Structurally enforced: CancelMasked is the only action that modifies taskMask
\* for alive tasks in cancel states, and it always decrements by exactly 1.
\* CancelRequest sets mask to MAX_MASK (initial assignment, not an increment
\* of an existing cancel mask). No action ever increments an active mask.
\* Stated as: non-zero mask implies task is in a cancel-processing state.
MaskMonotoneInvariant ==
    \A t \in TaskIds :
        taskAlive[t] /\ taskMask[t] > 0 =>
            taskState[t] \in {"CancelRequested", "CancelMasked"}

\* ---- Cancel Idempotence (#5 inv.cancel.idempotence) ----
\*
\* Canonical rule #5 states: cancel(T, k1); cancel(T, k2) ≡ cancel(T, strengthen(k1, k2)).
\* In the bounded model, CancelKind is abstracted away (ADR-003), so strengthening
\* is not modeled. However, the structural enforcement is:
\*   CancelRequest(t) requires taskState[t] = "Running"
\* This means a second cancel request on an already-cancelling task is impossible —
\* the precondition blocks it. Idempotence is enforced by construction.
CancelIdempotenceStructural ==
    \A t \in TaskIds :
        taskAlive[t] /\ taskState[t] \in {"CancelRequested", "CancelMasked",
                                           "CancelAcknowledged", "Finalizing"} =>
            \* A task already in cancel processing cannot enter CancelRequest again.
            \* This is trivially true because CancelRequest requires state = "Running".
            taskState[t] /= "Running"

\* ---- Core Invariants (checked by TLC) ----

CoreInv == TypeInvariant /\ WellFormedInvariant /\ NoOrphanTasks
           /\ NoLeakedObligations /\ CloseImpliesQuiescent
           /\ MaskBoundedInvariant /\ MaskMonotoneInvariant
           /\ CancelIdempotenceStructural

\* ===========================================================================
\* SPORK PROOF HOOKS (bd-3s5mw)
\*
\* Invariant specifications for three key Spork properties:
\*   SINV-1: Reply linearity (no dropped replies)
\*   SINV-2: Supervision severity monotonicity
\*   SINV-3: Registry lease resolution on region close
\*
\* These are expressed in terms of the existing obligation lifecycle model.
\* In the bounded model, obligations abstract over both call-reply tokens
\* and registry name leases — both use the same Reserve → Commit|Abort|Leak
\* state machine. The invariants below confirm that the obligation lifecycle
\* correctly enforces Spork's linearity guarantees.
\*
\* Cross-references:
\*   Runtime oracles:  src/lab/oracle/spork.rs
\*   Formal spec:      docs/spork_operational_semantics.md (S3, S4, S5, S8)
\*   Lean proofs:      formal/lean/Asupersync.lean (SporkProofHooks section)
\* ===========================================================================

\* ---- SINV-1: Reply Linearity ----
\*
\* GenServer calls create obligations (Reserve). The Reply<R> token is
\* the commitment mechanism: sending the reply is Commit, explicit drop
\* is Abort, and failure to send is Leak (detected by oracle).
\*
\* In the bounded model, this reduces to: no alive obligation can remain
\* in Reserved state when its holder's region is Closed.
\* This is a strengthening of NoLeakedObligations applied per-obligation.

ReplyLinearityInvariant ==
    \A o \in ObligationIds :
        obAlive[o] =>
            (regionState[obRegion[o]] = "Closed" =>
                obState[o] \in {"Committed", "Aborted", "Leaked"})

\* ---- SINV-3: Registry Lease Resolution ----
\*
\* Registry name leases are obligations. When a region closes, all leases
\* belonging to that region must be resolved. This is equivalent to
\* SINV-1 but stated from the region's perspective.
\*
\* In the bounded model, this is: the ledger of any Closed region is empty.
\* Already covered by NoLeakedObligations and CloseImpliesQuiescent,
\* but stated explicitly for the Spork invariant cross-reference.

RegistryLeaseInvariant ==
    \A r \in RegionIds :
        regionState[r] = "Closed" =>
            /\ regionLedger[r] = {}
            /\ \A o \in ObligationIds :
                   (obAlive[o] /\ obRegion[o] = r) =>
                       obState[o] \in {"Committed", "Aborted", "Leaked"}

\* ---- SINV-2: Severity Monotonicity (proof sketch) ----
\*
\* The severity lattice Ok < Err < Cancelled < Panicked determines
\* supervision restart eligibility:
\*   - Ok:        Normal exit, never restart
\*   - Err:       Transient fault, may restart (if policy allows)
\*   - Cancelled: External directive, never restart
\*   - Panicked:  Programming error, never restart
\*
\* This invariant cannot be directly model-checked in the current bounded
\* model because the TLA+ spec abstracts away outcome severity (tasks
\* simply transition to "Completed" without a severity tag).
\*
\* However, the structural property is verifiable:
\*   - The severity lattice is a total order (proved in Lean: Severity.le_total)
\*   - Restart eligibility is monotone: only Err maps to Restart
\*     (proved in Lean: panicked_never_restartable, cancelled_never_restartable)
\*   - The oracle SupervisionOracle in src/lab/oracle/actor.rs verifies
\*     restart decisions at runtime
\*
\* For future model extension, the invariant would be:
\*
\* SeverityMonotonicityInvariant ==
\*     \A t \in TaskIds :
\*         taskAlive[t] /\ taskState[t] = "Completed" =>
\*             LET sev == taskSeverity[t]
\*             IN  (sev \in {"Cancelled", "Panicked"}) =>
\*                     supervisorDecision[t] \in {"Stop", "Escalate"}

\* ---- Combined Spork Invariant ----

SporkInv == ReplyLinearityInvariant /\ RegistryLeaseInvariant

\* ---- Combined Invariant (core + Spork) ----

Inv == CoreInv /\ SporkInv

\* Explicit alias to separate guarantees from assumptions in docs/tooling.
SafetyGuaranteesInvariant == Inv

\* ===========================================================================
\* SEM-07.1 ALIGNMENT VERIFICATION (br-asupersync-3cddg.7.1)
\*
\* State Variable → Canonical Rule Cross-Reference Matrix:
\*
\*   Variable         | Canonical Rule IDs           | Glossary Ref
\*   -----------------+------------------------------+-----------------
\*   taskState        | #1-4, #10 (transitions)      | SEM-04.2 §3.1
\*   taskRegion       | #33 inv.ownership.single_own  | SEM-04.2 §2.1
\*   taskMask         | #11, #12 (mask invariants)   | SEM-04.2 §5.3
\*   taskAlive        | #36 rule.ownership.spawn      | SEM-04.2 §2.1
\*   regionState      | #22-26 (transitions)          | SEM-04.2 §4.1
\*   regionParent     | #35 def.ownership.region_tree | SEM-04.2 §2.2
\*   regionCancel     | #6, #23 (cancel propagation) | SEM-04.2 §5.1
\*   regionChildren   | #34 inv.ownership.task_owned  | SEM-04.2 §2.2
\*   regionSubs       | #35 def.ownership.region_tree | SEM-04.2 §2.2
\*   regionLedger     | #17, #20 (obligation inv)    | SEM-04.2 §2.4
\*   obState          | #13-16, #18 (lifecycle)      | SEM-04.2 §2.4
\*   obHolder         | structural ownership          | SEM-04.2 §2.4
\*   obRegion         | ledger membership             | SEM-04.2 §2.4
\*   obAlive          | #13 rule.obligation.reserve   | SEM-04.2 §2.4
\*
\* Initialization Alignment (canonical → TLA+):
\*
\*   Canonical Requirement         | TLA+ Init Encoding       | Status
\*   ------------------------------+-------------------------+---------
\*   Tasks unborn at boot          | taskAlive = FALSE        | ALIGNED
\*   Root region Open at boot      | regionState[Root]="Open" | ALIGNED
\*   Non-root regions unborn       | regionState[other]="Closed" (dead pool) | ALIGNED
\*   Empty ownership sets          | regionChildren/Subs = {} | ALIGNED
\*   Empty obligation ledger       | regionLedger = {}        | ALIGNED
\*   Obligations unborn            | obAlive = FALSE          | ALIGNED
\*   No parent links at boot       | regionParent = 0         | ALIGNED
\*   No cancel signals at boot     | regionCancel = FALSE     | ALIGNED
\*
\* Abstraction Decisions (documented):
\*   ADR-003: CancelKind severity   → symbolic, not enumerated
\*   ADR-004: Finalizer body        → state transitions modeled, body abstracted
\*   ADR-005: Combinators           → not modeled (tested via RT oracles)
\*   ADR-007: Determinism/seed      → not modeled (tested via lab runtime)
\*   ADR-008: Outcome severity      → "Completed" terminal, no severity tag
\*
\* Bounded Assumptions:
\*   - |TaskIds| = 2, |RegionIds| = 2, |ObligationIds| = 1 (MC config)
\*   - MAX_MASK = 2 (tractable bounded checking)
\*   - AssumptionEnvelopeInvariant enforces bounded envelope in TLC runs
\*   - Safety-only (no fairness/liveness clauses in Spec)
\*   - Liveness model-checking requires LiveSpec + fairness assumptions
\*
\* Model Check Reproduction:
\*   scripts/run_model_check.sh --ci
\*   scripts/run_tla_scenarios.sh --json --scenario standard
\*   Prerequisite: Java 11+ and TLC (tla2tools.jar)
\* ===========================================================================

================================================================================
