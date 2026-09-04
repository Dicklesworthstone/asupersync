# Asupersync Bridge Plan — reality check refreshed 2026-09-04

## Current assessment and execution plan

**Verdict: substantial working runtime, incomplete end-to-end vision.** The
kernel, transports, and protocol clients contain real implementations. Recent
root draining, channel obligation registration, production trace projection,
platform repairs, and real-server CI wiring are substantive progress. They do
not establish complete production replay, distributed structured concurrency,
Browser Edition scheduling, universal cleanup bounds, or an aggregate green
release. Finishing the pre-existing backlog would still leave uncovered goals
and several incorrectly specified acceptance criteria.

This refresh governs execution. Sections 0–15 below preserve the September 1
baseline for comparison, **not executable marching orders**. In particular,
their deletion quotas, branch/PR examples, automatic dependency removals,
warning-only API breaks, default-state flip, and relabel-as-feature-completion
alternatives are superseded. No deletion, feature removal, public compatibility
break, or owner decision is authorized by this assessment. Work stays on shared
`main` with exact reservations. Existing passing implementations are retained.

### Evidence and scope

- Root read the complete AGENTS.md and README.md, core v4 plan, existing bridge
  plan, and testing guides. Three read-only archaeology lanes read the formal,
  distributed, browser/server/ATP, dependency, and RABS plans and specifications
  in full, then traced implementation and test call sites. RABS is a separate
  build-system design: its CAS, action cache, and build scheduler are not missing
  Asupersync runtime features. Authored plan/spec/design documents were included;
  deliberately stale fixtures are test inputs, not competing specifications.
- Initial source baseline: `4d1981015cd496b42e6dca90a98443ecc52343d4`.
  Shared `main` subsequently advanced to `b442149fcb6ee2e989e5fc02d7b814566e1d62fc`.
  Findings are static source observations unless a specific execution is cited.
  A source file, closed bead, compiled target, model test, admission receipt, and
  terminal native test are different evidence classes.
- Fresh strict-remote proof on the initial baseline: installed RCH supported
  `--base`, `--clean-overlay`, `--overlay-path`, and `--no-overlay`; the native
  `runtime_abort_vs_cancel_semantics_audit` executed on `hz3`, **34 passed,
  0 failed, 0 ignored, 0 filtered**, exit 0 at 2026-09-04 21:53:38 UTC.
  Log: `/tmp/asupersync-reality-native-20260904.log`. This proves the selected
  native parked-task cancellation contract, not subsequent commits or the whole
  runtime. The deliberate panic sentinel is an expected test input.
- Actual application runs on the same baseline also exited 0 remotely:
  `onramp_level0` printed `hello from asupersync` at 22:00:17 UTC;
  `onramp_level3` completed at 22:08:46 UTC. Logs are
  `/tmp/asupersync-reality-onramp0-20260904.log` and
  `/tmp/asupersync-reality-onramp3-20260904.log`. Level 3 currently injects a
  manual RuntimeState obligation and forces a closed region; it proves that
  illustrative assertion, not the new automatic-permit admission requirement.
- Inspected GitHub CI run `33908913396`, source
  `ead00ca8b4f3920e1802939a9204fd712f99ea34`,
  has actual failures, not merely a dispatch problem: Check/no-mock, lint,
  Linux/Windows tests, full Lean profile, and additional gates. `lake build` and
  TLC passed. Real-server logs show PostgreSQL, MySQL, Redis, NATS, and JetStream
  successes and the intended wrong-password refusal; Kafka times out without a
  terminal suite result. The success-filtered CI API returned zero runs. Later
  pending/cancelled runs are not evidence that these failures remain at HEAD or
  have been fixed. Reproduce each against the revision being promoted.
- Shipped: crates.io `0.4.10`, published 2026-09-01 19:08:29 UTC, checksum
  `7e8b505d6aadb778c9c4b0ae174966641f11d578d253b7786f2407b17d5045ec`.
  The release-train bead records its source tag at `997e8d116ae864789f2cb47be90bfd4be5985c4f`.
  GitHub Releases still lists `v0.4.9` as latest. September 4 runtime changes are
  source progress, not a new published crate. Browser package integrity is not
  proof of a running Rust-future scheduler or a current browser-engine run.
- Initial `br` inventory: 11,103 closed, 376 open, 142 in progress, 31 blocked;
  549 unfinished. `bv` found 228 actionable. These are inventory counts, not a
  completion percentage. Deduplication searched the full titles/descriptions/
  notes/acceptance of unfinished issues and inspected relevant closed issues.

### Vision checklist and gap coverage

`PARTIAL` means meaningful implementation with remaining scope; `UNPROVEN`
means the stated claim lacks adequate execution evidence here; `STUB` means
the named public path deliberately refuses or does no requested work.
`WORKING_SCOPED` is reserved for an actual exercised journey. `NO_BEAD` records
coverage before this refresh and is resolved by the new tasks below.

| Goal and measuring stick | Reality and concrete remaining gap | Execution owner |
|---|---|---|
| 1. Cooperative cancellation preserves typed results and cleanup (README §§Cancellation; AGENTS native contract) | WORKING_SCOPED: fresh 34-case native audit; arbitrary non-cooperative code remains outside bounds | Keep native contract first in every runtime-changing lane |
| 2. Root closure drains children/finalizers/obligations (v4 §§6–9) | PARTIAL: explicit root drain and entry macros landed; `block_on`/explicit Runtime Drop retain compatibility; teardown timeout is not quiescence | Existing `0sd3cp` implementation retained; obligation and remote follow-through below |
| 3. Stock permits obey runtime obligation admission (v4 §8) | PARTIAL: channel gateway exists; it returns tickets before `create_obligation` can reject limits/closed regions; refused posts only increment a counter | NEW R1 admission + R1T tests; existing `cv5sqe`, `bi2462.15/.16/.17` |
| 4. Cleanup bounds are inspectable for stock primitives (v4 §7.6; README:249) | PARTIAL / NO_BEAD: no complete primitive responsiveness registry; fairness alone cannot bound arbitrary futures | NEW R2 bounds + R2T tests |
| 5. Pipeline/map-reduce execute structured work (v4 §12) | PARTIAL / NO_BEAD: modules reduce already-collected outcomes; no stage executor/backpressure or spawned map phase | NEW R3 execution + R3T tests; retain existing folds |
| 6. Region allocation has a real runtime consumer (v4 §10) | PARTIAL / NO_BEAD: generation-safe heap/RRef exist; observed heap allocations are examples/tests, not task placement | NEW R4 design, implementation, and lifetime/performance tests |
| 7. Scheduler scaling preserves fairness and cancellation (v4 §11) | PARTIAL / UNPROVEN: unified remains default; current scheduler work is benchmark-gated; a lab policy is not native parallel proof | `sched-hot-path-perf-bt4y5f`, `m9wsza`, their existing benchmark/test children |
| 8. Production failures replay locally (v4 §18) | PARTIAL: projection/driver landed; end-to-end production capture absent; exhausted replay falls back to normal scheduling | Strengthen `bi2462.8`, then `.9`; retain `.6/.7` work |
| 9. DPOR explores causally distinct schedules (v4 §18) | PARTIAL: clock merge exists; seed derivation does not force an exact alternative prefix or prove completeness | NEW R11/R11T; verify original `vemwug` scope separately; preserve `lab-dx-v2-n2v2fi.7` forensic journey |
| 10. Formal claims match executable assumptions (formal semantics §§6,8) | PARTIAL: Lean model/TLC lanes exist; fairness-only termination and exact lab-refinement wording overclaim | NEW R9 reconciliation; actual proof extension remains separate from wording |
| 11. HTTP/body/WS/gRPC/H3 work against independent peers (README network sections) | PARTIAL: real listeners and streaming paths exist; external h2spec result absent, several protocol/CI gates red | Existing `server-stack-hardening-eeexl1`; NEW R8 external HTTP/2 proof |
| 12. File/database clients and telemetry work for consumers (README IO/data) | PARTIAL: blocking/file/client/exporter implementations exist; five real service families ran successfully in inspected CI, Kafka did not terminate | `bi2462.19`, existing data/OTLP/Kafka children; no duplicate service harness |
| 13. Remote handles follow region ownership (v4 §8.4/§16) | PARTIAL: real mTLS named-computation transport; parent region does not yet own every remote lease/drain | Strengthen `bi2462.16`; preserve strict V1–V3 wire |
| 14. Snapshot distribution survives failed peers (v4 §16) | PARTIAL: encode/assign/recover model; only test-double DistributorTransport; sequential waits ignore timeout/concurrency knobs | Strengthen `bi2462.10`, native two-process faults and bounds |
| 15. Membership drives discovery and lease revocation (v4 §16) | PARTIAL: lease-reactor logic is called by manager sync; production orchestration and incarnation-aware rejoin remain | Correct `bi2462.11`, integrate in `.12` |
| 16. Supervisor trees restart and escalate (v4 §14/AppSpec) | PARTIAL / NO_BEAD prerequisite: per-actor loops exist; compiled tree driver missing; dynamic-child bead assumes a running supervisor | NEW R5 driver + R5T; then `dist-otp-completeness-8y37kz.2` |
| 17. Secure ATP moves real files with bounded resources (ATP architecture) | PARTIAL: native transfer exists; WAN performance, bounded memory, incremental/multi-donor behavior still have open acceptance | Existing `bi2462.5`, ATP data-plane/bonding/RaptorQ roots and children |
| 18. ATP SDK and CLI expose the promised workflows (ATP CLI/architecture) | STUB / NO_BEAD: closed SDK/CLI feature tasks coexist with explicit NotImplemented send/receive/resume/cancel/stream and sync/mirror/share/watch paths | NEW R6 SDK + R6T; R7 CLI + R7T; do not reopen the successful fake-success refusal fix |
| 19. ATP performance promises are measured and mathematically justified (ATP adaptive/matrix specs) | UNPROVEN in this audit: no fresh benchmark; adaptive regret example is vacuous at its given horizon; dynamic-reset claim lacks its stated theorem | Existing `j91wza`, `bi2462.5`, adaptive-control and benchmark children |
| 20. Browser users run, cancel, and ship supported workloads (browser plan/WASM) | PARTIAL: shipped ABI manages handles; it does not itself poll Rust futures; browser-engine/package publication freshness missing | Existing decision `94g51y` and publication `yxwno1`; retain feature goal until owner chooses |
| 21. Dependency sovereignty loses no capability (dependency plan/ADRs) | PARTIAL: KEEP/additive decisions and substantial owned components; old removal paragraphs conflict with current parity-gated DAG | `ir2uf0` and existing Rev-5 children; NEW R9 doc reconciliation |
| 22. RABS can consume a sound generic substrate (RABS master plan §44) | PARTIAL / external acceptance: ATP framing, managed QUIC, backpressure, timer regression matter; CAS/action/build ownership belongs to RABS | R10/R10T, R14/R14T, R15/R15T; retain existing nested-timer test; RABS owner runs adapter acceptance |
| 23. Default, stable, feature and platform promises compile independently (AGENTS profiles) | UNPROVEN as an aggregate; integration dev-dep cycle contaminates feature proof; platform CI still has failures | `z2kt29`, stable track, `bi2462.19/.20/.21` |
| 24. Release consumers receive the proved source (release checklist) | PARTIAL: package/source tag repair done; publish workflow depends only on planning, not aggregate behavioral/compatibility gates | Strengthen `yqlhh7` with next-release enforcement and packaged canaries |
| 25. Examples/docs/gates describe reachable behavior (README/testing/plan corpus) | PARTIAL / NO_BEAD for cross-document reconciliation: stale untracked-permit statements, infallible-send prose, unregistered supervision E2Es, strict-JSON/CBOR contradictions | NEW R9 + R9T; use existing docs/tests, no new dashboard |
| 26. Canonical ATP frames bind reproducible transcripts (ATP codec/RABS substrate) | REGRESSED contract / uncovered follow-up: extension HashMap is emitted unsorted and duplicate decoded IDs overwrite; closed `ovjee1` promised canonical/reject-duplicate behavior | NEW R10 fix + R10T; preserve public HashMap type |
| 27. AppSpec manifests enact services and resource authority (AppSpec compiler/reference docs) | PARTIAL / uncovered execution: compiler stores metadata, factories supply empty demo tasks; no actual route/budget/capability enforcement | NEW R12 runtime binding + R12T after live supervision |
| 28. Snapshot restore resumes supported work, not only metadata (snapshot-restore design) | PARTIAL / uncovered execution: proof sketch names absent restore API; suspended arbitrary Rust futures are not serializable | NEW R13 explicit supported-continuation design/implementation + R13T; reject unsupported futures |
| 29. Managed QUIC progresses on packets, deadlines and cancellation (RABS §44.5/QUIC design) | PARTIAL / NO_BEAD: serial receive/timer waits and 1ms polling; remaining duration is passed as an absolute Sleep deadline | NEW R14/R14T; retain engine/Initial-reroute work |
| 30. Remote admission protects peers and lifecycle control (RABS §44.4/v4 admission) | PARTIAL / NO_BEAD: global max-in-flight and coalesced control exist; generic per-peer byte/message/priority/async admission is missing | NEW R15/R15T, distinct from snapshot credit and region-lease tasks |

### Bridge work packages

Each package is a bounded feature or defect with a separate test companion when
it changes runtime behavior. IDs are recorded below after Phase 3a. No package
may close by deleting a promise or changing a test into a source-string check.
No source change is performed by this reality-check session.
Implementation closure means landed code and focused unit/compatibility evidence.
Its independent behavior-test companion runs afterward; the feature pair and
product parent require both. There is no reciprocal implementation-to-test edge.
Design tasks close only their reviewed design and concrete owned prerequisites.

- **R1 — Admit obligations before publishing success (P1, 3–5 days, high risk).**
  `obligation_mailbox.rs:252–278,384–410` mints/posts before admission;
  `state.rs:5018–5044` can reject region/holder/limit. Design a bounded,
  lock-order-safe admission permit or equivalent acknowledgement with rollback;
  retain pending-post credit until resolution, safe state-less Cx behavior, and
  existing channel signatures. Accepted tokens must always resolve exactly once;
  rejected admission must not silently become an untracked success. Explicitly
  settle cross-task holder transfer, late resolution, region close, zero permits,
  queue pressure and runtime teardown. Normal SendPermit drop aborts, it is not
  a planted leak. R1T drives native and lab limits 0/1/N, reserve-vs-close and
  cancel-vs-commit schedules with exact counts, reclamation and deadlock checks.
- **R2 — Publish justified responsiveness bounds (P2, 3–5 days, medium risk).**
  Inventory stock await/commit/mask surfaces with preconditions, unit (polls vs
  time), blocking/IO assumptions, budget composition and explicit unbounded cases.
  Connect real primitive implementations to those bounds; do not infer a time
  bound from scheduler fairness. R2T tests boundaries and deliberately withheld
  progress, including genuinely parked native cancellation and mask-depth cases.
- **R3 — Execute pipeline and map-reduce additively (P2, 4–7 days, medium risk).**
  Preserve fold APIs; add Scope-based execution with bounded interstage capacity,
  deterministic output ordering, four-way Outcome aggregation, loser cancellation
  and drain. No task detachment. R3T covers slow consumers, errors/panics/cancel at
  each stage, empty input, noncommutative reducers, exact cleanup, and a public
  consumer with queue high-water marks and reproducible failure logs.
- **R4 — Give the region heap a safe real consumer (P2, design before code).**
  First settle Pin/address stability, destructor ordering, escaped-handle refusal,
  generation reuse, finalizer/obligation relationships and task/region ownership.
  Keep the current allocator/default untouched. An additive opt-in implementation
  must actually place runtime-owned work/data in the heap, then prove quiescent
  reclamation through public APIs. Separate tests use drop counters, stale handles,
  cancellation, panic and failed admission; compare allocation counts and latency
  against the current path before any default proposal. No automatic unsafe waiver.
- **R5 — Run compiled supervisor trees (P1, 5–8 days, high risk).**
  Consume CompiledSupervisor plans in a region-owned live driver; preserve each
  child's restart policy, topology, intensity window, backoff, and parent escalation.
  Start with a complete bounded static-tree slice; publish which strategies are
  supported, retain unimplemented strategy tasks, and do not call dynamic child
  management complete. R5T covers child panic, sibling restart sets, escalation,
  cancellation during restart/backoff and stable child order in both lab and native
  runs. Dynamic supervision depends on this driver and its behavioral proof.
- **R6/R7 — Finish actual ATP SDK/CLI workflows (P2, decompose by operation).**
  SDK methods must delegate to the maintained native transfer engine through Cx,
  with authenticated transport, progress/backpressure, cancellation and resumable
  session ownership. CLI sync/mirror/share/watch must preserve their documented
  semantics and use that same engine. Mirror planning is read-only by default;
  destructive application requires the existing explicit operator policy. Retain
  the existing typed refusal for unsupported cases. Test companions exercise real
  two-process transfer, byte hashes, interruption/resume, wrong peer/auth, slow
  readers, finite retry budgets and no silent partial-file success. Per-operation
  implementation and tests are split into the following bounded pairs:
  R6A authenticated real-peer session admission (the current helper constructs
  both negotiators locally); R6B file/directory/object transfer with verified
  publication; R6C progress/terminal handle state; R6D streaming; R6E durable
  checkpoint/resume/cancel; R6F authenticated daemon IPC and restart reconciliation.
  Temporary queue emptiness is neither completion nor EOF. `is_complete` must not
  consume progress. Stream close waits for verified final acknowledgement before
  commit and drains its worker; a full queue applies backpressure. R6B/D/E depend
  on admitted sessions and corrected handle lifecycle, not socket reachability.
  R7A covers get/inbox/status/resume/cancel/serve and the existing send routes;
  R7B covers genuinely bidirectional sync/conflicts; R7C mirror plan/apply;
  R7D redeemable share/pairing with expiry/revocation; R7E watch with overflow
  recovery; R7F covers the remaining advertised seed/bench/diagnostic/config/proof
  commands by a complete command-to-handler inventory, reusing working handlers.
  Preserve `ProtocolError::NotImplemented`, `ASUP-E701`, validation precedence,
  exit codes, JSON schemas and old signatures on still-unavailable paths. Each
  operation's proof uses delayed progress/data, lost acknowledgement, wrong peer,
  stale checkpoint, destination conflict and cancel-at-commit where applicable.
- **R8 — Independent HTTP/2 conformance (P1, 2–4 days, proof-first).**
  Existing internal frame assertions and a blocked build did not execute h2spec.
  Pin an independent h2spec binary/version, start the real native H2 listener,
  run the required suite, retain exact failures and fix them in the owning code.
  Empty selection, listener startup failure or harness-only assertions cannot
  pass. Include a known-invalid listener/response negative control and cancellation/
  teardown evidence. This does not prove HTTP/3, browser behavior or all RFCs.
- **R9 — Reconcile the controlling docs with reachable examples (P1, 2–3 days).**
  Revise existing docs in place: permit registration versus no-Cx try paths;
  send-disconnect outcomes; root drain versus teardown; strict JSON V1–V3 versus
  aspirational CBOR; formal fairness/progress assumptions; WASM ledger scope;
  dependency KEEP/parity decisions; ATP mathematical assumptions. Register/fix or
  explicitly mark unreachable channel/signal supervision recipes; the signal
  sketch's Tokio sleep must not be wired into core. R9T compiles/runs the real
  examples with nonzero selection, validates advertised invocation paths, and
  plants a disconnect and missing-test selection. Text agreement alone is not
  behavioral proof. Keep unsupported goals visible and linked to implementation.

### Corrections to existing work, without duplicate feature epics

- `bi2462.8`: distinguish complete replay from an explicitly requested prefix;
  validate trace identity, coverage/gaps and terminal outcomes. Reject tail and
  interior truncation, extra unrecorded work and outcome drift. Do not silently
  switch to normal scheduling and report success. Capture from real production
  workers, then replay the same workload in the lab; handcrafted lab traces do
  not satisfy this acceptance. `.9` waits for this proof before widening claims.
- `bi2462.10`: preserve V1–V3 tags/fields/goldens. Prefer a versioned named
  snapshot computation within the existing envelope; any new transport message
  requires a deliberately versioned negotiated protocol. Honor ack_timeout,
  max_concurrent, hedging, quorum cancellation and parent Cx; a blocked first peer
  must not serialize every replica. Test two actual processes and failed peers.
- `bi2462.11`: MembershipLeaseManager already calls the reactor. Connect real
  discovery events, authenticate membership authority and reject stale incarnation
  replay. A revoked lease stays revoked; higher-incarnation rejoin requires fresh
  lease identity. `.12` composes transport/discovery/lease ownership only after
  their individual tests, then proves restart/partition/heal with public APIs.
- `bi2462.16`: bind remote spawn/lease/result/cancel to the owning region; never
  forge success from transport loss. Preserve JSON compatibility; documentation
  reconciliation is not a substitute for region-close/lease-expiry execution.
- `bi2462.19/.20/.21`: use actual CI failures and platform receipts, not the old
  no-runners premise. Kafka timed out in the inspected run. Required service tests
  must have terminal nonzero results; wrong-password rejection is expected evidence.
  Fix root causes on the selected revision, preserve old failures and first-attempt
  results, and distinguish quarantine/advisory jobs from enforced gates.
- `vemwug`: current source merges vector clocks, so do not implement that obsolete
  fix again. Audit the original synchronization coverage and its test receipt
  before deciding closure. NEW R11/R11T separately owns exact-prefix backtracking;
  it must not silently convert the old clock bug into a different algorithm task.
- `yqlhh7`: enforce release checklist before publishing, including v0.4.3 API/
  behavior comparison, independently resolved default/stable/feature canaries,
  packaged artifact/source/lockfile identity, native cancellation and required CI
  results. A green package dry-run is not a green runtime. Existing `pzpol4` tag
  repair stays closed; its expressly deferred workflow work remains here.
- `ir2uf0`/`62jqi3`: current Rev-5 is no-loss/parity-gated. KEEP and additive
  implementations are valid dispositions; do not automatically remove hex,
  base64, Kafka, SQLite, TOML, YAML, generic Protobuf, regex or CLI dependencies.
  Full generic/public interoperability remains a prerequisite to any cutover.

### Original-workstream coverage and completion rule

| September 1 items | Current disposition |
|---|---|
| A1–A3 | Preserve evidence-based tracker and ownership correction; remove count/one-epic quotas; retain unique ATP acceptance when linking roots |
| A4–A6 | R9/R9T plus existing proof freshness `iwwj4z` and release `yqlhh7`; no separate dashboard required |
| B1–B3 | Retain root drain and channel work; R1/R1T, `.15–.17`, R9; no new warning behavior under 0.4.x |
| B4 | R3/R3T plus existing cancel/drain combinator and plan-rewrite work; low-level drop semantics remain explicit |
| B5–B7 | Retain UCB1 fixes; replay `.8`; existing scheduler performance gates; R4 heap consumer |
| C1–C6 | `.19/.20/.21/.24`, `z2kt29`, `yqlhh7`; actual failed stages and skip refusal, not recreated harnesses |
| D1–D6 | Retain trace export, TLC and oracle improvements; `.8/.9`, corrected `vemwug`, existing adaptive-control/forensics work; R9 proof scope |
| F1–F6 | Existing server-stack implementation and tests; R8 independent H2; R9 current DNS/TLS/WS/H3 scope |
| G1–G6 | Existing file/data/telemetry work, `.19`, Rev-5 dependency tasks; no self-referential conformance promoted as interoperability |
| H1–H4 | `.10/.11/.12/.16`, R5/R5T, R9 strict wire reconciliation |
| I1–I5 | Existing WAN/bonding/RaptorQ proof tasks; R6/R7 implementations; no unapproved file/subcommand removal |
| E1–E5 | Existing browser owner decision and npm publication tasks; retain rebuild, engine CI and Rust IO reachability acceptance |
| J1–J6 | Correct misleading/stale consumers and ship useful proof; do not optimize LOC ratios or delete artifacts as a proxy for product progress |
| K1–K2 | Retain complete Rev-5 capability/parity DAG, strengthen doc joins; no automatic dependency exit |
| L1–L3 | Existing release hardening and canary tasks; no 0.5 default/API decision implied by this plan |

The finish line is a user journey at a named source/package revision with its
failure path, cleanup, compatibility and performance evidence. A documented
limitation is honest communication; it does not complete the original feature.
Unbounded external behavior must produce a scoped refusal/timeout with retained
ownership, not a fabricated bounded-completion claim. Implementation agents pick
up dependency-ready slices via `br ready`; this session supplies the revised plan
and executable backlog, not an assertion that those features have been built.

### Cross-component acceptance added by ambition pass 2

The following boundaries are feature work with companion tests, not additional
signoff metadata. No green component substitutes for a missing join:

- **R10:** serialize ATP extension entries in stable ID order without changing
  `FrameHeader.extensions: HashMap`; reject duplicate IDs under the existing
  canonical-frame contract. Test insertion-order permutations, malformed duplicate
  bytes, transcript equality, round trips and interoperability with old valid
  frames. Closed `ovjee1` is provenance for the promised behavior, not fresh proof.
- **R11:** extend the explorer with opt-in exact-prefix execution and an enabled
  alternative transition. Reuse ForcedSchedule and proven synchronization edges;
  preserve current seeded exploration. Compare explored equivalence classes to
  an exhaustive tiny-state oracle; report unsupported effects and search limits.
- **R12:** bind AppSpec factories to real capability/budget authority and route/
  trigger/service lifecycle, including nested groups through the managed supervisor.
  One real HTTP route, actor and trigger must produce outputs and refuse missing
  capabilities/expired budgets. Empty factories plus quiescence are not acceptance.
  Preserve the existing pure-data compiler and its honest unsupported cases.
- **R13:** specify a versioned workload factory/continuation codec for the finite
  set of supported restorable tasks; validate source/workload/state identity and
  restore resumed effects, outcomes and obligations. Reject arbitrary futures,
  stale generations and unsupported external effects. Metadata validation alone
  remains useful but is not continuation execution. The design is a prerequisite;
  no unsafe rehydration or universal crash-recovery guarantee is implied.
- **R14:** replace the managed QUIC fixed-poll/serial-wait loop with competition
  between actual socket readiness, due deadlines and cancellation. Preserve
  public Instant-taking APIs through a checked same-clock mapping; a relative
  duration is not an absolute runtime Time. Test nonzero epochs, overdue/earlier/
  removed timers, no lost wake, idle-to-burst transitions, saturated send/cancel
  and cross-connection fairness against the actual managed endpoint over UDP.
- **R15:** provide additive per-peer/global message, byte and waiter admission,
  cancellation-aware local reserve/commit, bounded retry-owned state and protected
  authenticated lifecycle-control capacity. Retain current max_in_flight and
  coalesced controls. Two independently controlled remote peers prove isolation,
  bounded memory and cancel/renew/drain progress under data saturation. No user
  priority can impersonate control authority; local commit is not remote
  exactly-once execution. Shared remote.rs work requires exact reservations.

Snapshot transport receipts must bind object digest, attempt, replica and peer
authority; wrong-object/stale acknowledgements cannot satisfy quorum. Complete
production replay must prove outcomes and event coverage as well as poll order,
and preserve legacy prefix replay as an explicit compatibility mode. Membership
cannot promote unauthenticated UDP observations into TLS/capability authority.
The integration tests connect these exact boundaries rather than constructing
matching structs on both sides.

### Quantitative and proof discipline added by ambition pass 3

- Use obligation conservation as the R1 oracle: admitted reservations equal
  committed + aborted + explicitly leaked + still-live records; queued admission
  credits and generation identity must prevent an apparent zero during handoff.
  Rejected admission consumes neither capacity nor an accepted-token claim.
  Exercise the actual queue/state boundary with a finite state-machine model and
  native schedules; a model theorem alone does not prove the implementation.
- R11 compares Mazurkiewicz equivalence classes only for a declared finite
  transition system with sound dependency edges. Include a planted missing
  happens-before edge and a spurious independence edge. A search budget ending
  early is `incomplete`, not exhaustive success or a probabilistic guarantee.
- R2 composes only justified finite bounds and explicit environmental premises.
  An infinite cooperative loop is a counterexample to fairness-only termination;
  a thread stuck inside one poll is a counterexample to universal cleanup time.
  Formal docs must distinguish safety, conditional liveness and Rust refinement.
- The ATP adaptive-design regret expression yields about 324 loss units for
  T=200, where normalized cumulative loss is at most 200. That instance is a
  vacuous bound, not evidence of a few-percent overhead. A reset detector does
  not by itself establish the stated dynamic-regret theorem. Existing `j91wza`
  work must define loss/units, admissible process, change budget, tuning and
  finite-horizon comparator, then show paired real goodput/repair/latency/memory
  results. Retain current safe fallback if either assumptions or measurements fail.
- Performance remains a distinct acceptance dimension: reuse the maintained
  benchmark gates, hold payload/security/feature/hardware/worker count fixed,
  record raw before/after distributions and allocation/queue/byte high-water
  marks. Do not substitute a clean-link win for WAN/loss/multi-file behavior or
  silently relax the existing regression threshold. No fresh performance result
  was produced in this assessment. Heap/default/codec/SDK optimizations do not
  ship solely because their design sounds mathematically attractive.
- Release acceptance consumes the actual tested package and exact source/lockfile
  identity, not an independently regenerated lockfile or green metadata job.
  Reuse existing compatibility and consumer gates; test a deliberately mismatched
  package/source identity and a required-stage skip. No new release ceremony is
  needed beyond enforcing those existing conditions on the publishing path.

### Phase execution record

Phase 1 source/vision/coverage audit and Phase 2 bridge revision are complete.
Phase 3a created R1/R1T, R2/R2T, R3/R3T, R5/R5T, R8, R9/R9T as
`bi2462.28–.38`, using the frozen generation instructions and only `br` writes.
Ambition pass 1 expanded feature completion into full SDK/CLI operation pairs,
exposing session self-negotiation, destructive progress peeks, early EOF and
premature stream commit as prerequisites. It preserved the original eleven CLI
workflows and their routing/security modes instead of reducing the goal to send.
Further ambition/refinement and graph results are recorded as they execute.
Ambition pass 2 added canonical ATP transcript repair, exact-prefix DPOR,
AppSpec runtime enforcement and supported continuation restoration, with causal
cross-component proofs and explicit compatibility boundaries. Existing closed
schema/honesty work is preserved; missing execution is tracked separately.
Ambition pass 3 added conservation/generation oracles, exhaustive finite DPOR
comparison, conditional-liveness counterexamples, non-vacuous adaptive-FEC
acceptance and paired performance/package-identity gates. These are concrete
test obligations; no new theorem, benchmark win or release readiness is claimed.
Phase 3a regeneration created 36 more tasks, `bi2462.39–.74`: 47 new tasks
total at this checkpoint. Seventeen existing issues were revised with current
evidence/scope; conflicting original descriptions were retained as explicitly
historical context rather than discarded.
Refinement pass 1 reviewed every core work package and changed nine boundaries:
no denial-to-untracked fallback; complete stock wait inventory; bounded retained
ordered outputs; explicit task-placement ownership; late-generation fencing;
authenticated old/new codec compatibility; fresh-workload prefix reconstruction;
AppSpec authority/budget attenuation; coordinated snapshot cuts and single-owner
recovery. These are recorded in the affected beads' acceptance criteria.
Refinement pass 2 reviewed all 24 SDK/CLI tasks and actual graph edges. It split
implementation closure (code plus focused unit evidence) from feature-pair
completion (implementation plus independent behavior proof), avoiding procedural
cycles. It added missing real-engine/stream/command-proof prerequisites, bounded
optional progress, precise publication granularity, source-aware resume fencing,
complete delegated API/authority coverage, causal relay/mailbox tests, shared sync
semantics and persistent revocation. Unsupported command rows need named children
before the inventory can close; they do not pass the final product gate.
Refinement pass 3 found that generic transport epics did not own managed QUIC
wake/deadline correctness or generic per-peer remote admission. R14/R14T and
R15/R15T became `bi2462.75–.78`, bringing new tasks to **51**. It also corrected
four active dependency API/cutover instructions and strengthened the existing
release task: immutable dispatched candidate, tested lockfile/archive identity,
required terminal stage provenance, and refusal before any registry write.

### Created task index

All IDs below have prefix `asupersync-bi2462.`. Implementations include focused
unit tests; the paired proof task is independently required for product completion.

| Work package | Implementation/design | Independent proof |
|---|---|---|
| R1 obligation admission | 28 | 29 |
| R2 responsiveness bounds | 30 | 31 |
| R3 executing combinators | 32 | 33 |
| R5 live supervisor | 34 | 35 |
| R8 external h2spec | 36 (proof and discovered fixes) | 36 |
| R9 controlling docs/recipes | 37 | 38 |
| R4 safe runtime heap | 39 design, 40 implementation | 41 |
| R10 canonical ATP extensions | 42 | 43 |
| R11 exact-prefix DPOR | 44 | 45 |
| R12 AppSpec runtime bindings | 46 | 47 |
| R13 supported continuation restore | 48 design, 49 implementation | 50 |
| R6A real peer session | 51 | 52 |
| R6C progress/terminal lifecycle | 53 | 54 |
| R6B file/directory/object transfer | 55 | 56 |
| R6D streaming | 57 | 58 |
| R6E checkpoint/resume/cancel | 59 | 60 |
| R6F daemon IPC | 61 | 62 |
| R7A persistent control/routes | 63 | 64 |
| R7B bidirectional sync | 65 | 66 |
| R7C mirror plan/application | 67 | 68 |
| R7D share/pairing | 69 | 70 |
| R7E watch | 71 | 72 |
| R7F remaining command coverage | 73 | 74 |
| R14 managed QUIC wake/deadline | 75 | 76 |
| R15 protected peer admission | 77 | 78 |

---

## September 1 historical baseline (superseded execution instructions)

**Purpose.** This is the Phase 2 deliverable of the reality check run on
2026-09-01: a complete, granular plan to close every gap between what
README.md promises and what the code delivers, so that the README becomes
literally true and the project reaches its stated goals with the highest
quality, reliability, and performance. It is written so that Phase 3a can
turn it into beads without consulting any other document: every item carries
its own WHY (the observed gap with file:line evidence), WHAT (the change),
HOW (design constraints), ACCEPTANCE (a positive observable, a planted
negative, and a no-claim line), DEPENDS, SIZE, and RISK.

**How this plan was grounded.** Eleven read-only auditors covered every
README section with file:line citations; pristine-HEAD lanes ran on the rch
fleet; the tracker (12,506 beads) was analysed in full; crates.io, npm,
GitHub Pages, and CI were checked. The Phase 1 report is at
`/data/tmp/asupersync_reality_check_2026-09-01.md`. Beads already filed from
Phase 1 are referenced by id where an item maps to one.

**Binding rules for anyone executing this plan.**
- Real code + real tests in the same unit of work. No `todo!()`, no
  weakened assertions, no golden regeneration to force green, no
  fixtures/mocks presented as live proof. Every test names its planted
  negative and its no-claim line.
- No new process artifacts (contracts, ledgers, signoff packets, dashboards)
  unless the item names the feature they gate, their consumer, the observed
  defect class, and their deletion condition. Workstream J is a deletion
  workstream, not an authoring one.
- Additive public API only until a deliberate semver boundary; v0.4.3
  compatibility is a hard gate (AGENTS.md). Items that need a break say so
  and are parked behind the 0.5 boundary (Workstream L).
- Closure comes from an independent verifier citing green evidence bound to
  an exact revision. Beads whose owner has left are closed by the verifier
  or reopened with an incident comment, never by the author.
- Commit rate is not a KPI. Land coherent, verified units.

---

## 0. Ground truth at the start of this plan

Verified on pristine HEAD on 2026-09-01 (rch, clean overlay, remote required):

| Lane | Result |
|---|---|
| `onramp_level0`, `onramp_level3` | pass |
| `runtime_abort_vs_cancel_semantics_audit` | 34/34 |
| `e2e_web` | 40/40 behavioral rows; the one README-marker row fixed |
| `cargo check --all-targets` (default features) | clean except the lib-test target, healed in `b5dd9f8aa` |
| `cargo test --lib --features test-internals` (in-source unit tests) | 22,197 passed, 4 failed, 24 ignored (first full run in weeks) |

The four lib-test failures at HEAD `b5dd9f8aa`: two ambient-audit governance
drifts (`audit::ambient::tests::{known_findings_reference_real_code,
ambient_authority_does_not_regress}`), and two body-lifecycle tests in the
active server-stack area
(`http::h1::server::tests::streaming_server_refuses_actual_chunked_bytes_over_limit`,
`web::multipart::tests::streaming_multipart_refuses_metadata_before_body_ownership_and_observes_cancellation`).

Landed on 2026-09-01 during the follow-through (all with behavioral tests):
entry-macro runtime defaults (`#[main]` multi-thread + on-demand blocking
pool), `Runtime::task_inspector`/`Runtime::diagnostics` +
`Diagnostics::explain_cancellation`, executable `Scope::quorum` and
`Scope::first_ok`, MySQL `mysql_native_password` behind the existing opt-in,
`HttpClientBuilder::add_root_certificate` so the pooled client can do HTTPS
against a private root, README/WASM doc truth corrections, the lib-test
target heal, 15 lib clippy lints for the CI lint job.

Shipped reality: crates.io 0.4.10 (published 2026-09-01), 68 reverse
dependencies, about 30 sibling consumers on the development host, almost all
with `default-features = false`.

---

## 1. Program structure

Twelve workstreams, ordered by leverage. A and C are prerequisites for
trusting anything else. B, D, F, G are the product core. E, H, I are
decisions first, then work. J is deletion. K and L are governance of the
program itself.

| WS | Name | Why it comes where it does |
|---|---|---|
| A | Truth reset (tracker + docs) | Without it nobody can see what is undone |
| C | One green pipeline | Without it regressions are invisible |
| B | Kernel promises made structural | The README's headline guarantees |
| D | Lab and production converge | "Deterministic testing is default" |
| F | Server stack | Where most consumers live |
| G | Data and observability | Second-most used surfaces |
| H | Distributed and actors | Phase 4 of the roadmap |
| I | ATP and RaptorQ | The largest sub-project by LOC |
| E | Browser Edition | Decision-gated; wrong claims today |
| J | Governance diet | Reclaim effort; keep only gates that gate |
| K | Dependency Sovereignty decision | Half the backlog |
| L | Release train and semver boundary | Where breaks and tags live |

Dependency graph (coarse): A.1 -> everything (tracker legible); C.1 -> C.2..C.6
and every "green in CI" acceptance; B.1 -> B.4 (shutdown drain uses root
cancel); B.2 -> D.6 (obligations visible to oracles); D.2 -> D.3 (replay
needs the production scheduler in lab); E.1 decision -> E.2..E.5; K decision
-> J.3; L.1 -> every future release.

---

## 2. Workstream A: truth reset (tracker and docs)

### A.1 Close landed-but-open beads with evidence
- WHY: 161 of 177 in-progress beads have a landing commit on main; 113 carry a "shipped <hash>" comment; 98 belong to agents unseen for 45+ days. The tracker hygiene pass on 2026-09-01 closed only 2 under a strict protocol and classified 84 as SHIPPED_PARTIAL and 48 as "code on main, proof never ran" (BronzeHill's July 15 sync-primitive fixes). The full lib-test run at HEAD now provides that proof for the in-source tests.
- WHAT: for each of the 48 "proof never ran" beads, map the bead to the in-source tests its landing commit added (`git show --stat <hash>`), confirm those tests are in the 22,197 passing set of the 2026-09-01 lib-test run (or rerun the target), and close with reason "shipped at <hash>; <test names> green in lib-test run <log>". For the 84 SHIPPED_PARTIAL, split: close those whose remaining note is only "pending proof" once the proof exists; leave those with real remaining scope open but re-assign to nobody with a dated note.
- HOW: no closes without a test name and a run receipt; a close comment must cite both.
- ACCEPTANCE: in-progress count drops below 60; every remaining in-progress bead has an assignee active in the last 14 days or is unassigned with a dated "why still open" comment. Planted negative: a bead whose landing commit's tests are not in the passing set must not be closed by this pass.
- DEPENDS: none. SIZE: 1 day. RISK: low. BEAD: none yet (filed as part of Phase 3a).

### A.2 Blocked labels and orphan epics
- WHY: all 31 "blocked" beads have zero blocking edges (the 2026-08-10 DB recovery pruned 264 edges); 294 non-blocked beads have open blockers; `asupersync-ir2uf0` (Dependency Sovereignty root) has zero children; `asupersync-86fe9v` has all children closed but sits blocked under a signoff artifact that says `parent_close_allowed=false`.
- WHAT: for each blocked bead, either add the real blocking edge or flip to open with a note; parent the dep-plan phase epics under `ir2uf0` or delete the empty root (Workstream K decides); close `86fe9v` once its signoff artifact is either refreshed or retired (J.5).
- ACCEPTANCE: `bv --robot-alerts` shows zero blocked beads without an edge; no epic with zero children.
- DEPENDS: K.1 for the dep-plan epics. SIZE: half a day. RISK: low.

### A.3 Merge the three rsync-killer roots
- WHY: `rmk81s` (open), `arq-quic-epic-b0k8qo` (in progress, no assignee, 76 days), `317hxr` (open) are three competing roots for the same goal ("atp beats rsync"), each with its own done-criteria; bv flags the missing links.
- WHAT: one root with one done-criterion per tier (nocrypto, auth, encrypted), children re-parented, the other two closed as superseded with pointers.
- ACCEPTANCE: exactly one open epic titled with "rsync" and one dependency chain; the encrypted-tier criterion names the exact cell table it must win.
- DEPENDS: none. SIZE: half a day.

### A.4 README one-page truth block
- WHY: README is 189 KB with 36 lines over 600 characters; the Limitations and Roadmap tables are the closest thing to "what works" and they were wrong in six places until 2026-09-01. Newcomers and agents need one screen.
- WHAT: a "What works, what does not, what is next" block of at most 40 lines at the top of the Limitations section, regenerated from a checked list (not prose): each row = surface, status word (WORKING/PARTIAL/PREVIEW/NOT_STARTED), the single test or lane that proves it, and the bead if open. Keep the long no-claim prose below it.
- HOW: the block is checked by an existing contract test only if that test also fails when the named proof lane is red (otherwise it is ceremony; see J.1). Prefer a script that generates the block from a small JSON list committed next to the README and a test that the generated bytes match.
- ACCEPTANCE: block present; every WORKING row names a test file that exists and ran green in the latest CI run; a planted stale row (test file removed) fails the check.
- DEPENDS: C.1 (so "ran green in CI" is meaningful). SIZE: 1 day.

### A.5 Remaining README corrections
- WHY: after the 2026-09-01 doc batch, these remain wrong or stale: the FAQ "Is this production-ready?" still describes browser and RFC6455 coverage in older terms; the Documentation table lists `docs/api_audit.md` which is at "Version 0.1" from January and lists ~45 modules against 121 `pub mod` today; `docs/replay-debugging.md` claims "Production debugging: Yes" with a `regression_issue_123` placeholder; `docs/WASM.md` still contains the "cooperative scheduler" paragraph at lines 661-676 in older copies of the doc (corrected 2026-09-01 at the Runtime Model heading; re-check the whole file); TESTING.md lists 11 oracles where the code has 26 modules and contradicts itself on obligation_leak test counts (823 vs 754).
- WHAT: correct each; delete `docs/api_audit.md` content that is stale in favor of `artifacts/api_surface_map_v1.json` (or regenerate it from the map).
- ACCEPTANCE: a grep for `regression_issue_123` returns nothing; TESTING.md oracle list equals `ls src/lab/oracle`; api_audit is either regenerated with a date or reduced to a pointer.
- SIZE: half a day.

### A.6 CHANGELOG and version drift guard
- WHY: README said 0.4.9 while crates.io had 0.4.10; CHANGELOG dated v0.4.10 to 08-30 with no tag; the Version Timeline lacked the bullet until 2026-09-01.
- WHAT: a release-time check (part of L.1) that README's crates.io snippet, Cargo.toml version, the CHANGELOG timeline, and the git tag agree.
- ACCEPTANCE: running the check at HEAD passes; bumping Cargo.toml without the others fails it.
- DEPENDS: L.1. SIZE: hours.

---

## 3. Workstream B: kernel promises made structural

### B.1 Root region closes to quiescence on entry-future return
- BEAD: asupersync-gap-root-region-quiescence-0sd3cp (P1).
- WHY: `block_on` returns as soon as the main future completes (src/runtime/builder.rs ~3520-3535) and `RuntimeInner::drop` (~4862-4915) joins workers and drops state without cancelling or draining the root region; `shutdown_timeout` is a teardown bound only. Tasks that outlive `main` are abort-by-dropped: finalizers, cleanup budgets, and the request/drain/finalize protocol never run for them. This is the README's headline "no orphan tasks / cancellation is a protocol" not holding at the top of the tree.
- WHAT: (1) `Runtime::shutdown_with_drain(bound)`: request cancellation on the root region, drive the scheduler until the root region reports quiescence (no live tasks in unified state and dispatch table, no pending obligations, finalizers done) or the bound elapses, then perform today's teardown. (2) The entry macros call it after `block_on` returns with a default bound (2 s, configurable via a new `drain = "2s"` macro argument; `drain = "0"` restores drop). (3) `Runtime` drop for explicit `RuntimeBuilder` users is unchanged (compat) until the 0.5 boundary (L.3), where drain-by-default becomes the rule.
- HOW: reuse `cancel_request` on the root region and the existing `advance_region_state` machinery; the wait loop must yield the state lock between checks (never hold B across a park); non-cooperative tasks are dropped at the bound and their handles observe `CancelReason::shutdown()`; record `drain_completed`/`drain_timed_out` in trace and in the runtime's terminal report.
- ACCEPTANCE: native-runtime test: a task that checkpoints in a loop with a cleanup counter must have its cleanup run before the process reaches the end of `main` (counter == 1 observed after `main` returns through the macro); a planted non-cooperative task (never checkpoints) is dropped only after the bound elapses and the report says `drain_timed_out`; LabRuntime oracle shows no obligation leak in the cooperative case. No-claim: non-cooperative code is not bounded; LabRuntime semantics unchanged.
- DEPENDS: none. SIZE: 3-4 days. RISK: medium (shutdown paths are the most hardened code in the crate; every step needs the abort-vs-cancel contract green).

### B.2 Stock permits are runtime obligations
- BEAD: asupersync-gap-permits-as-obligations-cv5sqe (P1).
- WHY: mpsc/oneshot/broadcast `SendPermit`s and `SemaphorePermit`s never register an `ObligationKind` record (zero references in src/channel/{mpsc,oneshot,broadcast}.rs and src/sync/semaphore.rs); only session-tracked permits and `IoOp` do. The lab futurelock and leak oracles are blind to the most common permits, and the README says they are tracked.
- WHAT: when a permit is reserved through a `Cx` that carries runtime state, mint an obligation id from the existing arena and resolve it on send/abort/drop; a state-less `Cx` keeps today's untracked behaviour. Same for `Semaphore::acquire`. Public signatures unchanged.
- HOW: no allocation on the fast path (obligation ids are indices; the record lives in the existing table); the mpsc reserve/send benchmark rows in `methodology_baselines` must not regress beyond the gate; obligations resolved on the send path must not take the state lock inside the channel's own lock (lock order C after A/B).
- ACCEPTANCE: LabRuntime test: reserve an mpsc permit inside a task, complete the task without sending, and the obligation-leak oracle names the permit kind; a semaphore permit held across a task that stops being polled triggers futurelock; planted negative: a permit that is sent is never reported; baseline bench rows within the gate.
- DEPENDS: none. SIZE: 3 days. RISK: medium (hot path).

### B.3 `Outcome` misuse guard
- WHY: `mpsc::SendPermit::send` returns `Outcome<(), SendError<T>>` and `Outcome` has no `#[must_use]`, so the README's own `permit.send(i);` silently drops `Disconnected`.
- WHAT: `#[must_use]` on `SendPermit::send` (and the oneshot/broadcast equivalents), not on `Outcome` itself (which would warn in every consumer). Update the README examples to `let _ = permit.send(i);` where ignoring is intended, or to handle the outcome.
- ACCEPTANCE: a doc-test or UI test shows the warning fires for an ignored send; consumers using `default-features = false` compile without new warnings for other `Outcome` uses. No-claim: does not make loss impossible, only visible.
- SIZE: hours. RISK: low (warning only; a consumer with `deny(warnings)` and an ignored send would break, so note it in CHANGELOG).

### B.4 Executable pipeline and map_reduce, drain-correct hedge and timeout
- BEAD: asupersync-gap-loser-drop-combinators-1pupkj (P2) covers hedge/timeout.
- WHY: after 2026-09-01, quorum and first_ok execute (`Scope::quorum`, `Scope::first_ok`); pipeline and map_reduce are still folders only; `hedge()` (src/combinator/hedge.rs:19-21) and `time::timeout` (src/time/timeout_future.rs ~278-296) drop losers while docs claim drain; plan-execute race nodes drop (~781).
- WHAT: `Scope::pipeline(stages)` with bounded channels between stages and cancel/drain of downstream stages; `Scope::map_reduce(inputs, map, monoid)` spawning the map phase and folding; `hedge()` and plan-execute race nodes protocol-cancel and join losers when a spawn-capable `Cx` is available, else document drop explicitly; fix the src/combinator/timeout.rs header to describe what `time::timeout` does.
- ACCEPTANCE: tests mirroring the quorum/first_ok suite: losers' cleanup counters equal the loser count immediately after return; pipeline backpressure test proves a slow stage bounds the fast producer (queue depth never exceeds capacity); planted negative: a loser that ignores cancellation is reported after the bound rather than silently dropped.
- DEPENDS: none. SIZE: 3 days.

### B.5 UCB1 policy in lab replay and the ignored determinism golden
- BEAD: asupersync-gap-ucb1-lab-replay-my2vov (P2).
- WHY: README says the default-on discounted-UCB1 policy is "part of replay"; LabRuntime uses a fixed limit (src/lab/runtime.rs ~5221-5251); the only replay-determinism golden has been `#[ignore]` since 2026-04-22 (three_lane_tests.rs ~9737); the surviving test ignores its seed.
- WHAT: either carry adaptive policy state through the lab scheduler (D.2 makes this natural) or state in README that the policy is production-only; repair and un-ignore the golden or replace it with a same-seed-twice diff of the arm-choice trace.
- ACCEPTANCE: the golden runs (not ignored) in `cargo test --lib`; a one-line perturbation of the discount factor makes it fail.
- DEPENDS: D.2 preferred. SIZE: 1-2 days.

### B.6 State shape default
- WHY: README describes sharded state as the runtime's structure; the default is `StateShape::Unified` (src/runtime/config.rs ~2238); the flip is gated on the E1.3 perf dossier (bt4y5f.2.3, m9wsza, both stale).
- WHAT: finish the dossier (rerun the four lever benches with the Phase 6 gate) and flip the default, or keep Unified and reword README's "Sharded Runtime State" section to "available shape".
- ACCEPTANCE: either the default is Sharded with the bench gate green and the abort-vs-cancel contract green on both shapes, or README no longer implies sharding is the default.
- DEPENDS: C.1. SIZE: 2 days (bench time dominated).

### B.7 Region heap consumer or relabel
- WHY: `RegionHeap`/`RRef` is real and tested but nothing outside `src/types/rref.rs` tests allocates into it (`RegionRecord::heap_alloc` has no runtime caller).
- WHAT: decide: wire region-scoped allocation for task futures (a real design, several weeks) or mark the README section "implemented, not yet used by the runtime". Recommendation: relabel now, open a design bead for the wiring.
- ACCEPTANCE: README sentence matches; a bead exists with the design sketch.
- SIZE: hours (relabel).

---

## 4. Workstream C: one green pipeline

### C.1 `ci.yml` green on ubuntu
- WHY: the CI workflow has never had a green run. Last completed run: the lint job failed inside the lib (12 clippy errors, fixed 2026-09-01 in the working tree along with 3 newer ones and 4 in files outside the helper's scope), the Check job failed on rustfmt of a governance test (fixed), the Test job was killed at 7 minutes (runner shutdown mid-compile).
- WHAT: land the lint fixes; split the test job into shards (lib tests; integration tests by name prefix) each under the runner limit; cache the target directory; make the workflow required.
- ACCEPTANCE: three consecutive green runs on main; a planted failing test in a PR turns the run red.
- DEPENDS: none. SIZE: 2 days. BEAD: none yet.

### C.2 Non-Linux jobs
- BEAD: asupersync-gap-nonlinux-reactor-ci-gxv3dy (P1).
- WHY: Windows rustc crashed compiling the lib; macOS lib suite had 234 failures (net socket-option and GSO/sendmmsg "supported targets" rows, tls::acceptor, runtime); kqueue "conformance" runs a Linux-side model.
- WHAT: required `cargo check --lib` and `cargo test --lib` on macos-latest and windows-latest; triage the Windows crash (toolchain/target-feature) and gate Linux-only assertions with cfg.
- ACCEPTANCE: both jobs green three times; README platform matrix updated to the exact status.
- SIZE: 3-5 days. RISK: medium (unknown platform bugs).

### C.3 Real-server services in CI
- BEAD: asupersync-gap-real-server-ci-aoovsx (P1).
- WHY: no workflow sets REAL_POSTGRES_TESTS / REAL_MYSQL_TESTS / REAL_KAFKA_TESTS / REDIS_URL; NATS tests skip without a server; drift against real servers is undetectable.
- WHAT: a job with `services:` containers (postgres, mysql, redis, nats, redpanda) running those exact suites with the matching features.
- ACCEPTANCE: all five suites report nonzero tests and pass; a planted wrong password fails.
- SIZE: 2 days.

### C.4 Remote, chaos, and Lean lanes in CI
- BEAD: asupersync-gap-lean-tla-receipts-48ukyp (P2) for Lean.
- WHY: the 38-test remote-transport lifecycle suite runs only under a script outside CI; the server-stack chaos e2e (`examples/production_service.rs` + `scripts/run_server_stack_e2e.sh`) is in no workflow; `lake build` never runs in CI.
- WHAT: add the three as jobs (the Lean job caches the toolchain and uploads the build log).
- ACCEPTANCE: green jobs with artifacts; a planted `sorry` fails the Lean job.
- SIZE: 1-2 days.

### C.5 Fix the four lib-test failures at HEAD
- WHY: see section 0. Two are server-stack tests in FuchsiaSnow's active area (body-lifecycle diagnostics changed the error text and the chunked-limit accounting on 2026-09-01); two are ambient-audit drift (a KNOWN_FINDINGS line reference at metadata.rs:2546 and an insta inventory snapshot).
- WHAT: coordinate with the server-stack owner for the two behavioral tests; update the ambient-audit entry and accept the snapshot only after reviewing the diff (new TcpListener/TcpStream sites in h1/h2 listener and grpc client are real ambient-authority additions and must be justified or capability-routed).
- ACCEPTANCE: `cargo test --lib --features test-internals` fully green at HEAD.
- SIZE: 1 day.

### C.6 Stub and no-mock gates trusted again
- WHY: `check_no_mock_policy.py` and `scan_stubs.sh` are both red on false positives (a variable named `placeholder`, a gRPC status constructor, a doc comment); a `#[path = "mo\u{63}k.rs"]` escape hides "mock" from the scanner (src/transport/mod.rs:8).
- WHAT: rename the variable, allowlist the constructor by symbol not by substring, remove the unicode escape and register the test double honestly in the policy.
- ACCEPTANCE: both gates exit 0 at HEAD; a planted `todo!()` in src fails them.
- SIZE: hours.

---

## 5. Workstream D: lab and production converge

### D.1 Production trace export
- BEAD: asupersync-gap-prod-trace-export-ro6zzy (P1).
- WHY: "debug production issues locally" has no path: no public runtime trace export (`RuntimeState::trace_handle` is internal); `LabConfig::replay_trace(path)` is a metadata string; docs/replay-debugging.md example is a placeholder.
- WHAT: `RuntimeBuilder::trace_sink(sink)` and `Runtime::export_trace() -> Trace` writing the canonical event schema the lab records; a `LabRuntime::analyze_trace(trace)` entry that runs canonicalization, the DPOR race report, and crashpack assembly on an imported trace.
- ACCEPTANCE: e2e: production runtime with sink -> export -> lab analysis reports the same task/region events; docs example uses real APIs; planted negative: a truncated trace is rejected with a typed error.
- SIZE: 3 days.

### D.2 The production scheduler under lab control
- WHY: `LabScheduler` is a separate single-threaded model (src/lab/runtime.rs ~5234-5246); production is `ThreeLaneScheduler`. "Same seed, same behavior holds end-to-end, not just for a demo scheduler" is true only for the lab model. Lab-vs-live differential tests run the live side as `current_thread` only.
- WHAT: a deterministic driver mode for `ThreeLaneScheduler` (single OS thread, seeded tie-breaks, virtual time) usable by LabRuntime, so lab schedules exercise the production dispatch, steal, cancel-lane, and UCB1 code; keep `LabScheduler` as a policy until parity is proven, then retire it.
- ACCEPTANCE: the lab determinism suite passes with the three-lane driver; a deliberately injected nondeterministic tie-break makes the same-seed test fail; the lab-vs-live differential adds a multi-worker live side.
- DEPENDS: none hard; enables B.5 and D.3. SIZE: 2 weeks. RISK: high (core).

### D.3 Replay re-execution
- WHY: replay today is same-seed rerun plus diff; an exported production trace cannot be re-executed.
- WHAT: forced-schedule replay from a trace (`ForcedSchedule` receipts exist as lab-only; extend to imported traces) using D.2's driver.
- ACCEPTANCE: import a production trace of a real race, replay it in the lab, observe the same interleaving (event sequence equality) and the same outcome.
- DEPENDS: D.1, D.2. SIZE: 1 week.

### D.4 DPOR race detection stops over-reporting
- WHY: LabRuntime hardcodes `LogicalClockMode::Lamport` (src/lab/runtime.rs ~2075) while `dpor.rs:183-185` accepts only vector clocks as happens-before evidence, so every conflicting cross-task pair is a race; `from_trace` is O(n^2). Bead vemwug is blocked on a TraceEvent schema break.
- WHAT: vector clocks in LabRuntime (or Lamport-aware happens-before), the schema change behind a versioned trace format, and an O(n log n) race extraction.
- ACCEPTANCE: a trace with two independent tasks reports zero races; a real race is reported; explorer seed count for a known-race scenario drops (recorded before/after).
- DEPENDS: trace schema version (D.1). SIZE: 1 week.

### D.5 Inert statistical machinery: feed it or delete it
- WHY: `OracleSuite::report_and_observe` (e-process monitor) has zero callers; `ConformalCalibrator` is used by no oracle; `LabRunReport::export_tla` has zero callers and no exported trace has ever been fed to TLC; `check_sheaf_consistency` is uncalled outside its test. About 5.7k LOC of README-advertised machinery with no runtime consumer.
- WHAT: e-process: LabRuntime calls `report_and_observe` after each oracle evaluation and the explorer stops early when the e-process rejects (the actual README claim); conformal: calibrate the futurelock idle threshold from prior seeds (one real consumer); TLA+: one e2e that exports and runs TLC in CI (C.4); sheaf: wire into the saga runner's consistency check or delete the module and the README section.
- ACCEPTANCE: each mechanism has one production or lab call site with a test that fails when the mechanism is disabled; README table "Current status" column updated per mechanism.
- SIZE: 1 week.

### D.6 Oracle determinism in user builds
- WHY: four oracles stamp `SystemTime::now()` into `detected_at` unless `cfg(test)`/`deterministic-mode`, so violation records are not byte-stable in user builds; `VirtualTimerWheel` is advertised "in the hot path" but unwired (LabReactor uses a BinaryHeap).
- WHAT: stamp lab virtual time; either wire `VirtualTimerWheel` into LabReactor or delete the README sentence.
- ACCEPTANCE: two runs of the same seed produce byte-identical crashpacks in a plain release build.
- SIZE: 1-2 days.

---

## 6. Workstream F: server stack

### F.1 Per-request child region with body obligation
- BEAD: asupersync-server-stack-hardening-eeexl1.6.10 (P1, open, claimed 2026-09-01).
- WHY: handlers run under a clone of the connection Cx; the epic's headline "client disconnect -> 499 + DB cancel + obligation-clean region close" depends on a real request region.
- WHAT/ACCEPTANCE: as the bead states; the acceptance must include a real-socket test where the client disconnects mid-handler and the handler's DB-style obligation is aborted and the region closes clean.
- SIZE: 1 week (owner active).

### F.2 HTTPS client proof and H2 client
- WHY: the pooled `HttpClient` could not trust any root until 2026-09-01 (fixed: `add_root_certificate`); there is no general HTTP/2 client (gRPC owns a private channel); pooling is H1-client only.
- WHAT: (done) HTTPS through the pooled client with an installed root; (todo) HTTPS with the `tls-webpki-roots` feature against a public host in an opt-in network test; an `Http2Client` built on the gRPC channel's H2 framing with the same fluent API, or an explicit README line that H2 is server-only.
- ACCEPTANCE: HTTPS e2e green under `tls` and under `tls-webpki-roots`; H2 client fetches a body from the in-repo H2 listener with flow control exercised (body larger than the initial window).
- SIZE: 1 week for the H2 client.

### F.3 WebSocket production gaps
- BEADS: eeexl1.11 (blocked 79 days), it4lr2 (parser bug, in progress 6 weeks).
- WHAT: keepalive (ping/pong timers), permessage-deflate, write backpressure; land the parser fix with the RFC6455 registry green.
- ACCEPTANCE: autobahn-style fragmentation and close cases in the registry plus a keepalive timeout test and a backpressure test (slow reader bounds writer memory).
- SIZE: 1 week.

### F.4 gRPC server streaming over real H2 and the H2 recv-window bug
- BEADS: eeexl1.10 (stale), v1fa8y (in progress since 06-18).
- ACCEPTANCE: server-streaming call over a real socket delivers N messages with flow control; the recv-window regression test from v1fa8y passes.
- SIZE: 1 week.

### F.5 Multi-connection H3 listener
- BEAD: eeexl1.23 (filed 2026-09-01), after the cwnd fix (bi6url, landed ccb5af622).
- ACCEPTANCE: two concurrent QUIC clients complete requests against one listener; a third client's handshake failure does not affect the first two.
- SIZE: 1-2 weeks.

### F.6 DNS truth
- WHY: "async DNS with address-family selection" is a blocking std UDP query on a spawned thread with post-hoc family filtering; `tests/dns_real_upstream.rs` hits public resolvers with no env gate.
- WHAT: either a reactor-driven UDP resolver or a README sentence saying it is blocking-pool-backed; gate the upstream test behind an env var.
- SIZE: hours (docs + gate) or 1 week (async resolver).

---

## 7. Workstream G: data and observability

### G.1 `File` poll traits through the blocking pool
- BEAD: asupersync-gap-file-poll-blocks-executor-lop0ul (P2).
- ACCEPTANCE: on a current-thread runtime a large `BufReader<File>` read must not stall a second task's checkpoint counter.
- SIZE: 3 days.

### G.2 Inspector reachability (done) and poll accounting
- WHY: done 2026-09-01: `Runtime::task_inspector`/`diagnostics`, `explain_cancellation`. Finding while doing it: `TaskRecord::total_polls` is not advanced on the production dispatch path, so the inspector's `poll_count` is 0 in production.
- WHAT: either advance the counter on the hot path (one relaxed increment per poll; benchmark it) or document `poll_count` as lab-only in `TaskDetails`.
- ACCEPTANCE: inspector e2e asserts `poll_count >= 1` after the task ran (if advanced) and the baseline bench gate is green; or the doc states the limitation and the e2e keeps the flag-based liveness proof.
- SIZE: hours.

### G.3 OTLP exporter composable in `MultiExporter`
- WHY: `impl MetricsExporter for OtlpHttpExporter::export()` always returns Err (src/observability/otel.rs ~7134), so OTLP cannot join the composition the README describes.
- WHAT: an async `MetricsExporter` path or a blocking bridge that submits to the blocking pool with a bounded queue.
- ACCEPTANCE: a `MultiExporter` of in-memory + OTLP delivers to a loopback OTLP listener (the existing prost-decoding test pattern) and the in-memory exporter simultaneously.
- SIZE: 2 days.

### G.4 Real-server suites green and MySQL native auth (done)
- WHY: MySQL native auth landed 2026-09-01 behind the opt-in with KATs; real-server proof depends on C.3.
- ACCEPTANCE: C.3's job green; `tests/integration/mysql_real_server.rs` gains a native-password case against a server configured for it.
- SIZE: with C.3.

### G.5 Self-referential conformance suites
- WHY: `tests/nats_core_protocol.rs`, `tests/conformance/postgres_logical_replication.rs`, `postgres_extended_query.rs`, `tests/conformance/kafka_record_batch_v2/*` import nothing from the crate (about 4.3k LOC testing local reimplementations); PostgreSQL has no logical-replication implementation in src while README claims coverage.
- WHAT: point each suite at the crate's codec (or delete the suite and the README bullet); implement logical replication or remove the claim.
- ACCEPTANCE: each surviving suite has at least one `asupersync::` import and fails when the crate codec is sabotaged.
- SIZE: 2-3 days.

### G.6 Kafka: decide native vs rdkafka (see K)
- WHY: zero native wire code in src; 13 epics and 91 tasks open; ADR-009 says KEEP rdkafka.
- WHAT: K.1 decides; if native proceeds, the first deliverable is a real broker round-trip in C.3's job, not a plan.

---

## 8. Workstream H: distributed and actors

### H.1 Remote handles region-owned; leases as obligations
- BEAD: asupersync-gap-remote-handles-region-owned-udjmtx (P2).
- ACCEPTANCE: region close drains a running remote computation (cancel/terminal exchange observed) with no obligation leak; a never-answering remote is reported lease-expired at the bound.
- SIZE: 1 week.

### H.2 Snapshot distribution transport, SWIM wiring, PBFT stub
- BEAD: asupersync-gap-snapshot-transport-swim-pbft-e6drlx (P2).
- ACCEPTANCE: two-process snapshot distribute/recover with one peer down; SWIM-driven route refresh on loopback; PBFT unreachable from the default public API or marked experimental.
- SIZE: 2 weeks.

### H.3 Spork tree-level restart
- BEAD: asupersync-dist-otp-completeness-8y37kz.2 (blocked, stale owner).
- WHAT: the live restart loop over `CompiledSupervisor` plans (one-for-one first), with intensity/backoff, wired to actor failures.
- ACCEPTANCE: a supervised child that panics is restarted according to the compiled plan; exceeding intensity escalates to the parent; the minimal Spork example demonstrates a restart (today it uses `SupervisionStrategy::Stop`).
- SIZE: 1 week.

### H.4 Wire format decision (JSON vs CBOR)
- WHY: the design bible mandates canonical CBOR; the code ships strict JSON with goldens.
- WHAT: record the decision in asupersync_plan_v4.md (JSON kept, or CBOR at the 0.5 boundary).
- SIZE: hours.

---

## 9. Workstream I: ATP and RaptorQ

### I.1 Bench receipts in git and an honest encrypted-tier table
- BEAD: asupersync-gap-atp-bench-receipts-xwyrr2 (P2).
- ACCEPTANCE: `git ls-files artifacts/atp_bench_matrix` nonempty; ledger entry dated; README cell table equals the committed scorecard.
- SIZE: 1 day plus bench time.

### I.2 Cross-machine QUIC receipt
- WHY: no QUIC or bonded transfer has ever been recorded between two real hosts (only atp-tcp plaintext 2026-06-13).
- ACCEPTANCE: one dated Hetzner-to-Contabo QUIC transfer with SHA-256 verification committed under artifacts.
- SIZE: 1 day (fleet access exists).

### I.3 Encrypted tier beats rsync on clean links, or the claim is retired
- WHY: encrypted tier loses 50M/perfect 1.48x and tree_big/perfect 2.46x; the MATRIX-235 lever claims were never banked.
- WHAT: profile the encrypted sender duty cycle on a perfect link (the ledger's own diagnosis was sender-side), land the pipeline lever, re-run the matrix; if it still loses, the merged epic (A.3) states the loss explicitly and the "beats rsync" phrase is qualified to the tiers where it holds.
- ACCEPTANCE: committed scorecard; README/ledger match; the epic's done criterion is met or rewritten.
- SIZE: 1-2 weeks.

### I.4 RaptorQ K=2048 interop and independent vectors
- BEAD: asupersync-gap-raptorq-k2048-interop-creh6g (P2).
- ACCEPTANCE: the K=2048 encoder differential passes un-ignored; independent vectors for K in {10, 100, 1000, 2048, 10000}; a planted single-byte vector corruption fails.
- SIZE: 3 days.

### I.5 ATP dead code
- WHY: 3.7k LOC unreachable files (src/net/atp/bonding.rs shadowed, compress/, sink/, src/atp/{adaptive_raptorq,cas,telemetry}.rs), 1.2k LOC `cfg(any())` tombstones, 14 `atp` CLI subcommands returning not-implemented, 8 `doctor` subcommands emitting constant JSON.
- WHAT: with owner permission (AGENTS.md forbids agent-initiated deletion) wire or delete the unreachable files; remove tombstones; either implement or remove the placeholder CLI subcommands from the help text (a subcommand that cannot work must not be listed as available).
- ACCEPTANCE: no `.rs` file under src is unreachable from the module tree (a script enumerates and the count is zero); `atp --help` lists only working subcommands.
- SIZE: 2 days after permission.

---

## 10. Workstream E: Browser Edition

### E.1 Decision: real scheduler or ledger
- BEAD: asupersync-decision-browser-scheduler-or-ledger-94g51y (P1).
- WHY: the wasm ABI is a handle ledger (`task_spawn` takes no future); README was corrected on 2026-09-01; the served wasm is from 06-19 and predates security fixes; last browser-engine runs were March; npm publish never succeeded.
- WHAT: owner chooses (A) a wasm-side scheduler polling Rust futures via a microtask/MessageChannel pump with the single-threaded three-lane policy, or (B) keep the ledger and remove "runtime/scheduler" language from packages, docs, and the demo.
- SIZE: decision: hours; (A) 3-4 weeks; (B) 2 days.

### E.2 Rebuild and pin the wasm from HEAD
- ACCEPTANCE: `packages/browser-core/asupersync_bg.wasm` hash equals a reproducible build from HEAD; the GA signoff hash follows the build; Pages serves the new binary.
- SIZE: 1 day.

### E.3 Browser-engine tests in CI
- ACCEPTANCE: the existing Playwright fixtures run headless in a workflow on push; dedicated-worker, native-stream, react, next rows get their first recorded runs.
- SIZE: 2 days.

### E.4 npm publish
- BEAD: yxwno1 (blocked, P1).
- ACCEPTANCE: `@asupersync/browser` resolves on the registry or a dated manual publish receipt is committed.
- SIZE: 1 day.

### E.5 Fix or drop the Rust browser modules nobody reaches
- WHY: `src/io/browser_storage.rs` and `browser_stream.rs` are unreachable from the exported ABI; four open BrowserStorage bugs fix code no consumer can call.
- WHAT: after E.1, either export them through the ABI (A) or close the bugs as unreachable (B).
- SIZE: with E.1.

---

## 11. Workstream J: governance diet

### J.1 Freeze and audit contract tests
- WHY: 306 of 396 `*_contract.rs` files never import the crate; 521 of 1,431 test files never import asupersync; 44.5% of test LOC is meta; zero commits show a contract failure leading to a runtime fix.
- WHAT: freeze creation of new contract tests and artifact JSON; audit each existing contract test against the creation gate (consumer, feature gated, defect class, deletion condition) and delete those that fail it (with owner permission per AGENTS.md); keep the unsafe ledger and the no-stub discipline (the two with a record of catching real drift).
- ACCEPTANCE: test LOC that never touches the runtime falls below 20%; every surviving contract test names in its module doc the feature it gates.
- SIZE: 1 week (mostly deletion review).

### J.2 Proof snapshot replaced by CI receipts
- WHY: 27 of 37 proof claims are rerun-required; 41 of 64 lanes have no dated evidence; the snapshot's fresh rows expire on 2026-09-22.
- WHAT: generate the claim dashboard from CI job results (job name = lane id) instead of hand-maintained JSON; delete claims nobody re-runs.
- ACCEPTANCE: the dashboard is a build artifact of C.1, not a tracked JSON; README links to it.
- SIZE: 2 days after C.1.

### J.3 Retire obsolete program artifacts
- WHY: swarm-governor, proof-traffic, clean-overlay, memory-residency contracts and runbooks describe swarm process, not the runtime, and consume README space (three H2 sections are pure governance).
- WHAT: move their README sections to docs/proof/ with one index line in README; retire artifacts whose lanes never ran.
- ACCEPTANCE: README under 120 KB; no README H2 section whose only subject is agent process.
- SIZE: 1 day.

### J.4 Unsafe ledger regenerated in CI
- WHY: complete (40/40 files) but 574 commits stale with 18 stale locators.
- WHAT: regenerate on a clean tree in a CI job; fail on drift.
- ACCEPTANCE: contract green at HEAD; a planted unsafe block without a row fails.
- SIZE: hours.

### J.5 Signoff artifacts that block closure
- WHY: `86fe9v` is held blocked by `parent_close_allowed=false` in a signoff JSON nobody refreshes.
- WHAT: refresh or retire; closure decisions live in beads, not in JSON.
- SIZE: hours.

### J.6 `rch exec` strings in the shipped crate
- WHY: 49 src files embed the literal `rch exec` (the private build fleet) in doc/help strings shipped to consumers.
- WHAT: move operator hints to docs; keep the crate free of fleet-specific text.
- SIZE: half a day.

---

## 12. Workstream K: Dependency Sovereignty decision

### K.1 Decide the program against its ADRs
- BEAD: asupersync-decision-dependency-sovereignty-62jqi3 (P1).
- WHY: 217 of 565 open beads; all 12 ADRs terminal KEEP; 3 crates cut over, 4 owned-alongside, about 25 untouched; native Kafka has zero src code against 13 epics.
- OPTIONS: close as superseded; re-scope to cutovers with measured benefit (hex/base64 owned engines exist: remove the crates; decide sqlite/fsqlite); or keep the status quo.
- ACCEPTANCE: a decision comment on the bead; A.2 executes the parenting/closing that follows.

### K.2 If re-scoped: the two cheap cutovers
- WHAT: replace `hex` and `base64` crate usage (45 and 18 src files) with the owned codecs; measure binary size and compile time before/after.
- ACCEPTANCE: crates removed from Cargo.toml; all tests green; numbers recorded in the ADR.
- SIZE: 2 days.

---

## 13. Workstream L: release train and semver boundary

### L.1 Every release is a bead with receipts
- BEAD: asupersync-gap-release-train-pzpol4 (P1).
- WHAT: tag v0.4.10 on the published commit (verify with `cargo package --list` against the crates.io tarball); a release checklist bead template: compat comparison against v0.4.3, `cargo publish --dry-run`, tag, CHANGELOG bullet, downstream canary result; fix or retire publish.yml.
- ACCEPTANCE: `git tag -l v0.4.10` nonempty on the right commit; the next release uses the template.
- SIZE: 1 day.

### L.2 Downstream canary
- WHY: AGENTS.md requires an opted-in consumer canary; ~30 local consumers exist and most pin `default-features = false`.
- WHAT: a job that builds three representative consumers (one `default-features = false`, one with `proc-macros`, one with `tls`) against HEAD.
- ACCEPTANCE: job green; a planted public-API removal fails it.
- SIZE: 1 day.

### L.3 The 0.5 boundary list
- WHY: several truths need a break: drain-by-default on `Runtime` drop (B.1), `#[must_use]` on `Outcome` (B.3 wider form), CBOR (H.4), removal of the not-implemented CLI subcommands (I.5), retiring `LabScheduler` (D.2).
- WHAT: a single tracked list with migration notes; nothing on it ships in 0.4.x.
- SIZE: hours to start; maintained.

---

## 14. Milestones

| Milestone | Contents | Exit criterion |
|---|---|---|
| M1 Truth and green (2 weeks) | A.1-A.6, C.1, C.5, C.6, J.4, J.5, L.1 | CI green three times; tracker in-progress < 60; README one-page block present and checked |
| M2 Kernel promises (3 weeks) | B.1-B.4, G.2, G.3 | headline README guarantees each have a native-runtime test with a planted negative |
| M3 Lab/prod convergence (4 weeks) | D.1-D.6, B.5 | a production trace replays in the lab; DPOR reports zero races on independent tasks |
| M4 Platforms and data (2 weeks) | C.2, C.3, C.4, G.1, G.4, G.5 | non-Linux and real-server jobs green |
| M5 Server stack (3 weeks) | F.1-F.6 | request region real; HTTPS/H2 client; WS gaps closed; multi-connection H3 |
| M6 Distributed (3 weeks) | H.1-H.4 | remote work region-owned; snapshot distribution across two processes; tree restart |
| M7 ATP honesty (2 weeks) | I.1-I.5 | committed receipts; cross-machine QUIC; encrypted claim true or retired |
| M8 Browser (decision + 1-4 weeks) | E.1-E.5 | per decision |
| M9 Diet and decisions (1 week, parallel) | J.1-J.3, J.6, K.1-K.2, L.2, L.3 | meta test LOC < 20%; program decision recorded |

Total: roughly 20 engineer-weeks of product work plus decisions, with M1 and
M9 runnable by a small number of agents in parallel with M2.

---

## 15. Definition of done for the whole plan

The plan is done when every row of the Phase 1 vision checklist is WORKING
or carries an explicit PARTIAL/PREVIEW label in the README one-page block
with a named test, the CI workflow has been green for a month, the tracker's
open beads are all either actively owned or explicitly parked with a date,
and a fresh reality check by an auditor who has not read this plan finds no
README claim without a behavioral test behind it.
