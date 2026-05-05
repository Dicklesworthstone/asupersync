# Proposal To Integrate Ideas From NATS Into Asupersync

## Executive Thesis

Borrowing pub/sub from NATS would be too small.

The opportunity is to combine:

- NATS's subject-centric worldview
- NATS's account/import-export trust graph
- NATS's operationally legible stream and consumer model
- NATS's edge-to-core topology instincts

with:

- Asupersync's region ownership
- cancel/drain/finalize as actual protocol
- obligation tracking
- capability-secure `Cx`
- deterministic replay, DPOR, and oracles
- FrankenSuite evidence and decision machinery
- Rust's ownership and typestate as a zero-cost capability layer beneath `Cx`
- session-typed distributed protocol contracts
- mergeable control surfaces for non-authoritative metadata
- privacy-budgeted metadata summaries and selective private-compliance proofs at the hardest trust boundaries

Done properly, this would define a new systems category:

**a semantic subject fabric: NATS-small on the packet path, capability-safe on the authority path, and reasoning-native on the replay path.**

Long form:

**a subject operating fabric with certificate-carrying messaging, session-typed protocol contracts, quiescent durable streams, capability-compiled federation, recoverable mobility, mergeable non-authoritative control surfaces, and replayable control-plane behavior.**

The proposal works better when it is framed as **a fabric compiler**:

- the **packet plane** keeps the common case NATS-small and fast
- the **authority plane** owns obligations, leases, fencing, durability, and cutover
- the **reasoning plane** owns evidence, replay, certified cuts, and counterfactual control

Not every message should pay for every invariant. Most traffic should stay on the packet plane and only escalate into the authority or reasoning planes when the declared service class actually requires it.

There are also three correctness layers:

- the **static layer**: Rust ownership, typestate, and capability tokens prevent large classes of in-process misuse before tests run
- the **runtime layer**: `Cx`, obligations, control capsules, and region quiescence govern distributed behavior that the compiler cannot close
- the **evidence layer**: FrankenSuite, certified cuts, and replayable traces explain what the system believed, why it believed it, and whether that belief held up under counterfactual replay

This is a much larger target than "NATS ideas, but in Asupersync." It is only plausible because some of the substrate already exists on the Asupersync side; the messaging, federation, control-capsule, and peer-steering semantics are still mostly greenfield. The proposal is stronger when it states the end state plainly: **a compiled distributed-systems substrate whose runtime artifacts, cuts, policy decisions, and protocol contracts are inspectable by design.**

## Strategic North Star

The document should say more explicitly what must be true for this to be worth building:

- the public mental model must remain NATS-small even as the internal semantics get much richer
- stronger guarantees must be **named service classes**, not hidden taxes on the common case
- every radical behavior must lower into small, inspectable artifacts: tokens, certificates, leases, cut records, session contracts, key contexts, or explain plans
- autonomous policy loops must always run inside declared safety envelopes with replay, evidence, and rollback
- the first product wedge should be systems that need sovereignty, durable partial progress, and post-incident explanation at the same time

A grand unified fabric that makes the common case slower, the rare case magical, and the operator story less legible than NATS would be a mistake. The target is a fabric whose default path is simpler than today's stack, while its stronger paths are dramatically more auditable and compositional.

## Research Basis

I cloned `nats-server` into `/tmp/nats-server` and pinned the research copy to:

- `nats-server v2.12.5`
- commit `0f6c831ec1df25bc3dc81d25faae0ed0bac15a96`

This deeper proposal is grounded in direct reading of:

- lifecycle and bootstrap: `main.go`, `server/server.go`, `server/reload.go`
- connection and parser path: `server/client.go`, `server/parser.go`
- routing structures: `server/sublist.go`, `server/gateway.go`, `server/leafnode.go`
- account/import-export graph: `server/accounts.go`
- subject rewrite system: `server/subject_transform.go`
- system advisories and control subjects: `server/events.go`
- stream and consumer semantics: `server/stream.go`, `server/consumer.go`
- persistence and snapshotting: `server/memstore.go`, `server/filestore.go`
- official concept docs: NATS overview, Core NATS, JetStream, security/accounts, subject mapping, gateways, and leaf nodes at `docs.nats.io`

It is also grounded in direct reading of the Asupersync substrate this would build on:

- high-level design docs: `README.md`, `asupersync_plan_v4.md`, `asupersync_v4_formal_semantics.md`
- region-owned service machinery: `src/actor.rs`, `src/gen_server.rs`
- cancel-correct channels and sessions: `src/channel/mpsc.rs`, `src/channel/session.rs`
- obligation tracking: `src/obligation/ledger.rs`
- bridge, snapshot, and assignment surfaces: `src/distributed/bridge.rs`, `src/distributed/snapshot.rs`, `src/distributed/assignment.rs`
- transport and routing surfaces: `src/transport/router.rs`
- deterministic runtime and oracle model: `src/lab/*`, `tests/*`
- FrankenSuite evidence and decisions: `franken_evidence`, `franken_decision`, `franken_kernel`

## Background: What Asupersync Is

Asupersync is a spec-first async runtime and concurrency substrate for Rust. It is more than an executor with a few helpers, and it is not trying to be a drop-in Tokio clone. The core claim is that concurrency correctness should be structural: if code is built out of native Asupersync primitives, important classes of bugs become impossible, explicitly tracked, or mechanically testable instead of being left to convention and code review.

It is a semantic concurrency kernel with full-stack runtime surfaces built on top.

### 1. Kernel Execution Model

The kernel has a small set of ideas that show up everywhere in the codebase:

- **`Cx` as explicit capability context**: async operations take `&Cx` instead of reading ambient executor state from thread-locals. This is how cancellation, budgets, tracing, and authority flow through the system.
- **regions and scopes as the ownership tree for live work**: every spawned task belongs to exactly one region; regions form a tree; region close implies quiescence rather than "best effort shutdown."
- **`Outcome<T, E>` as a four-valued result**: `Ok`, `Err`, `Cancelled`, and `Panicked` are distinct runtime states, and combinators aggregate them through a severity ordering rather than flattening them into a plain `Result`.
- **`Budget` as an explicit cleanup bound**: cleanup and shutdown are not vague hopes; the runtime carries explicit budgets used in close, drain, timeout, and escalation decisions.
- **cancellation as a protocol**: request, drain, finalize. A task does not simply disappear because a future was dropped.
- **obligations as linear runtime facts**: permits, acks, leases, reservations, and related "must eventually resolve" entities are tracked explicitly and must be committed or aborted.

Those pieces are the semantic backbone for everything else in the runtime.

### 2. How Asupersync Actually Works

At runtime, Asupersync coordinates user futures through a scheduler, region tree, cancellation machinery, obligation ledger, and trace system. The architecture is intentionally explicit:

- a `Scope` creates child regions and spawns child tasks
- the scheduler runs those tasks under structured ownership rather than detached handles
- cancellation propagates through the ownership tree and triggers bounded drain/finalize behavior
- channel, sync, network, and stream primitives participate in that protocol instead of pretending cancellation is someone else's problem
- traces and runtime records make the state transitions visible enough for deterministic replay and invariant checking

That design stance explains why the codebase has so many "full-stack" runtime surfaces under one roof:

- channels use reserve/commit patterns to prevent data loss on cancellation
- synchronization primitives such as `Mutex`, `RwLock`, `Semaphore`, `Barrier`, and `OnceCell` are cancel-aware
- actors, `GenServer`, supervision trees, and Spork all inherit the region/quiescence guarantees rather than layering a separate concurrency model on the side
- the networking stack, transport routing, HTTP stack, distributed bridge/snapshot/assignment surfaces, and browser/WASM lane all try to preserve the same kernel semantics

The proposal in this document matters because it is trying to extend those same kernel guarantees into a messaging substrate, not bolt an unrelated broker onto the side of the runtime.

### 3. What Makes Asupersync Special

What stands out about Asupersync is not feature count; it is the correctness posture.

- **correctness is structural, not conventional**: "no orphan tasks," "close means quiescence," and "losers are drained" are runtime contracts, not team customs
- **cancel-correctness is a first-class design goal**: reserve/commit, request/drain/finalize, and explicit checkpoints are used to make cancellation semantics legible and safe
- **authority is explicit**: `Cx` makes side effects and privileges visible in function signatures instead of ambient
- **debugging is deterministic by design**: the lab runtime provides virtual time, deterministic scheduling, replay, and schedule exploration rather than treating concurrency bugs as heisenbugs
- **the runtime is math-forward where it pays off**: laws for combinators, budget algebra, DPOR-style exploration, canonical trace representations, spectral monitors, conformal calibration, e-processes, and similar machinery exist to make concurrency behavior more analyzable
- **FrankenSuite gives decision/evidence surfaces**: important control decisions can become typed decision contracts and evidence records rather than only logs and metrics

The repeated emphasis on algebra, proofs, obligations, and replay is deliberate. Those are not decorative aspirations; they match the actual design center of the project.

### 4. Determinism, Verification, And Replay

Another model reviewing this proposal needs to understand that Asupersync already has unusually rich testing and verification ambitions for a runtime:

- `LabRuntime` gives deterministic execution with virtual time
- DPOR-style schedule exploration and trace canonicalization reduce the number of schedules that must be reasoned about independently
- runtime oracles can check invariants such as leaked obligations, leaked tasks, quiescent shutdown, and redelivery behavior
- traces and evidence surfaces make it possible to ask both "what happened?" and "why does the system believe this execution is correct or incorrect?"

The messaging design proposed here leans directly on those capabilities because it is trying to be replayable and auditable in a way ordinary broker architectures usually are not.

### 5. Distributed And Data-Movement Surfaces

Asupersync is already more than a local task runtime. It has distributed and data-movement primitives that matter directly for this proposal:

- distributed bridge, snapshot, recovery, and assignment surfaces
- transport routing and multipath delivery machinery
- RaptorQ fountain coding used for recoverable distributed snapshot distribution
- actor/supervision infrastructure that can host region-owned service loops
- browser/WASM support, which matters because some parts of the future messaging substrate may need to cross browser, edge, and server environments

The RaptorQ point is especially important. In Asupersync today, fountain coding is not a theoretical curiosity; it already exists as a mechanism for recoverable distributed state movement. That is a key reason the later brokerless and data-capsule sections in this proposal are even plausible.

### 6. Soundness Frontier And Non-Magical Assumptions

Asupersync is ambitious, but it is not magic. A reviewer should keep the following boundaries in mind:

- guarantees are strongest inside the Asupersync capability boundary, where the runtime owns the task tree, obligations, and cancellation protocol
- the runtime still assumes cooperative progress properties such as checkpoints and bounded masking
- external peers, external clocks, and arbitrary side effects still need explicit modeling if they are to participate in deterministic replay claims
- the project cares more about getting the semantics right than about preserving compatibility with existing Rust async conventions
- some lanes relevant to this proposal, especially native messaging/federation and the brokerless fabric, are still greenfield relative to the more mature kernel/scheduler/channel/lab substrate

That combination matters: the proposal is radical, but it is not trying to claim that the whole system is already solved.

## Background: What NATS Is

NATS is a subject-based messaging system built around a client-server architecture. At the simplest level, clients connect to a NATS server, publish messages to subjects, and subscribe to subjects. Under the hood, that simple interface scales into clusters, superclusters, edge topologies, request/reply services, and persistent streams.

NATS is one consistent subject-space communication fabric with optional durability and explicit topology roles.

### 1. Core NATS

Core NATS is the low-latency messaging substrate:

- messages are addressed by **subjects**, usually dot-separated token paths, not by queue objects or broker-specific exchange names
- subscriptions express interest in literal subjects or wildcard subject languages rather than predeclared broker topics
- queue groups let multiple subscribers share work under one subject, with one eligible member in the group receiving each message
- request/reply is implemented using ordinary subjects and inbox subjects rather than a separate RPC stack
- servers route messages based on interest, so publishers do not need to know where subscribers live

Core NATS is intentionally simple and fast. The important tradeoff is that Core NATS delivery is fundamentally at-most-once unless the application or a higher layer adds retries, persistence, or stronger coordination.

### 2. JetStream

JetStream is NATS's built-in persistence and stateful delivery layer. It adds:

- **streams** that capture messages for configured subject sets
- **consumers** that track delivery state and can be push- or pull-driven
- acknowledgements, redelivery, flow control, heartbeats, max waiting, ack-pending limits, pause/unpause, and related delivery policy
- deduplication windows, mirrors, sources, snapshots, and restoration flows
- higher-level facilities such as key-value and object-store abstractions built on stream primitives

JetStream matters here because it shows that NATS is more than transient pub/sub. It already has a serious model for persistence, state capture, and delivery coordination while preserving the same operational mental model.

### 3. Accounts, Security, And Namespace Sharing

NATS is also a multi-tenant trust graph, not only a message router.

- accounts partition namespace and authority
- users, credentials, NKeys/JWT-based auth, and TLS govern who may connect and what they may do
- subject permissions can allow or deny publish/subscribe rights
- exports and imports let one account expose stream or service surfaces to another under explicit policy
- response permissions and service-latency reporting make request/reply crossing points first-class operational objects
- subject mapping lets namespaces be transformed rather than treated as immutable raw strings

One of the strongest reasons to take NATS seriously is that it already treats cross-boundary communication as a graph of explicit namespace edges, not just raw socket reachability.

### 4. Topology And Deployment Model

NATS is operationally compelling partly because its topology model is simple but flexible:

- a single server can be enough for small systems
- clusters provide horizontal scale and fault tolerance
- gateways link clusters into larger superclusters
- leaf nodes connect edge or remote domains while preserving local connectivity and reducing central round trips
- clients usually connect to one or a few known servers, and the server fabric handles wider routing

This is still a broker architecture, but it is a very well-designed one. NATS has a good story from laptop to datacenter to edge.

### 5. What Makes NATS Special

NATS is compelling because it combines several properties that are hard to get at once:

- **a very small public mental model**: connect, publish, subscribe, request, reply
- **subject-based addressing** that scales from simple pub/sub to service patterns and policy-rich imports/exports
- **operational legibility**: one binary, straightforward topology roles, and a strong bias toward understandable runtime behavior
- **performance and footprint** that make it credible from cloud to edge
- **optional persistence**: Core NATS stays lightweight while JetStream provides durability when needed
- **edge-to-core coherence**: clusters, gateways, and leaf nodes all preserve the same high-level subject mental model

Many systems are individually strong on one or two of those axes. NATS is unusual because it keeps the whole package cohesive.

### 6. Limits And Tradeoffs Relevant To This Proposal

A self-contained reviewer should also understand where this proposal is deliberately trying to go beyond NATS:

- NATS is still fundamentally client-server even when the server tier is clustered
- most of NATS's guarantees are expressed through server protocol, configuration, and operational discipline rather than through a richer concurrency substrate
- consumer state, delivery policy, and durability are strong, but they are not naturally expressed as runtime-wide obligations shared with application concurrency primitives
- NATS does not natively provide the same style of deterministic replay, algebraic plan reasoning, or capability-threaded effect model that Asupersync is aiming for
- this proposal is not trying to replace NATS by reimplementing it verbatim in Rust; it is trying to use NATS's best architectural ideas as inputs to a stronger semantic system

## What NATS Is Deeper Than It First Appears

At first glance NATS looks like "subjects, streams, and clusters." Reading the code shows a richer system.

### 1. Accounts Do More Than ACLs

`server/accounts.go` reveals that NATS accounts are really a programmable trust and routing graph:

- stream exports and service exports
- stream imports and service imports
- response tracking and cleanup
- limited requestor-info and service-latency sharing across service boundaries
- service latency reporting attached to exports/imports
- cycle detection on import graphs

The operational meaning is important: NATS treats cross-tenant connectivity as explicit graph edges, not as an afterthought.

### 2. Subject transforms are a small routing calculus

`server/subject_transform.go` is not a simple rename helper. It supports a real transformation vocabulary:

- wildcard capture
- deterministic hash-based partitioning
- split and slice operations
- left and right extraction
- strict mode for reversible import mappings

The lesson is that subject namespaces can be programmable without becoming arbitrary string spaghetti, if the transform algebra is constrained. For Asupersync, the main caveat is that randomized or one-way transforms cannot live in the same authority-bearing core as reversible reply-space, capability, or replay obligations.

### 3. The control plane is itself expressed as subjects

`server/events.go` shows a powerful pattern: control and observability live inside the same messaging fabric.

Examples:

- `$SYS.ACCOUNT.*.CONNECT`
- `$SYS.ACCOUNT.*.DISCONNECT`
- `$SYS.SERVER.*.LAMEDUCK`
- `$SYS.SERVER.*.SHUTDOWN`
- `$SYS.SERVER.*.CLIENT.AUTH.ERR`
- `$SYS.LATENCY.*`
- `$SYS.REQ.*`

This is better than bolt-on admin APIs because the system describes itself in the native coordination medium.

### 4. Consumers are mini scheduling kernels

`server/consumer.go` goes well beyond "cursor + ack":

- push and pull
- flow control
- heartbeats
- max waiting
- max ack pending
- pause and unpause
- pull-consumer priority groups
- pull-consumer pinned-client delivery
- pull-consumer overflow and prioritized policies

NATS consumers are really programmable delivery policies sitting on top of stream state.

### 5. Stream storage is active, not passive

`server/stream.go`, `server/memstore.go`, and `server/filestore.go` show that JetStream storage is not a dumb append sink:

- stream ingest happens through the same internal subscription machinery
- stream and consumer metadata are explicit artifacts
- snapshotting can package stream metadata, message blocks, and consumer state together when requested
- snapshotting allows ongoing append while constraining destructive mutation
- control metadata is separated enough from the hot data path to support restoration and coordination

That is a strong systems pattern: persistence participates in the runtime contract.

## What Asupersync Can Add More Naturally Than NATS

NATS gives a very good operational model. Asupersync can give a stronger semantic model.

### 1. Region ownership instead of daemon folklore

Every Asupersync-hosted fabric task, consumer, mirror, gateway handler, and repair lane can be owned by a region that must close to quiescence.

### 2. Cancel-correct publish, delivery, and teardown

NATS is robust, but its semantics still inherit the usual distributed-system ambiguity around cancellation and partial progress. Asupersync can make publish, reply, and ack transitions explicit reserve/commit or request/drain/finalize protocols.

### 3. Obligations as the semantic backbone

Consumer pending state, request/reply commitments, export budgets, and replication repair can all be represented as obligations rather than inferred counters.

### 4. Capability-checked namespace sharing

NATS accounts are already a trust graph. Asupersync can make those edges capability-checked through `Cx`, not just config strings and auth decisions.

### 5. Replayable distributed behavior

The real differentiator is replayable distributed behavior:

- replay gateway partitions
- replay import/export revocations
- replay consumer ack races
- replay mirror/source reorderings
- replay control-plane advisory storms
- verify, inside the modeled capability boundary, that no obligations leak and no tasks orphan under those schedules

### 6. Evidence-native messaging

FrankenSuite makes it possible to treat important routing, export, redelivery, and failover decisions as explicit decision records with evidence, not just logs.

## The Missing Layer: A Fabric IR And Compiler

The proposal needs an explicit compiler layer. Right now it sometimes jumps directly from ideas such as subjects, morphisms, obligations, consumers, capsules, and replay into runtime behavior. It reads much better once those high-level declarations first compile into a shared intermediate representation.

A `FabricIR` should include at least:

- `SubjectSchema`
- `MorphismPlan`
- `ServiceContract`
- `ProtocolContract`
- `SessionSchema`
- `DeliveryClass`
- `CapturePlan`
- `ConsumerPolicy`
- `CapabilityTokenSchema`
- `EvidencePolicy`
- `PrivacyPolicy`
- `CutPolicy`
- `BranchPolicy`
- `QuantitativeObligationContract`

The compiler should then emit:

- sharded subject-index layouts
- owned capability token types for in-process paths plus runtime capability checks for distributed paths
- transform and morphism certificates
- projected local session types from registered protocol contracts
- control-capsule schemas
- key-derivation contexts
- replay oracles, conformance co-monitors, and explain plans
- handler scaffolding and adapter skeletons where synthesis is enabled

This matters for five reasons:

- it gives the proposal one center of gravity instead of many loosely related subsystems
- it lets radical features lower into small, inspectable artifacts rather than folklore
- it makes service classes, mobility rules, privacy policy, and evidence policy explicit objects rather than hidden behavior
- it creates one place to validate cost, secrecy, replayability, and reversibility constraints before the runtime goes live
- it turns protocol-carrying subjects and contract-carrying services into compiler targets rather than documentation conventions

Without a `FabricIR`, the proposal risks sounding like a brilliant bag of parts. With it, the proposal starts to look like a new kind of systems compiler.

## The Radical Proposal

The correct ambition level is to build a messaging-native subsystem that turns NATS's best operational ideas into stronger runtime semantics.

I would frame it as one integrated plan: a native subject fabric that deepens all the way into subject cells, control capsules, delegated cursor partitions, and capability-scoped brokerless coordination as first-class parts of the design.

### 0. Three planes and a semantic fast path

Before the rest of the design, the proposal should explicitly freeze one non-negotiable architectural split:

- the **packet plane** handles hot ephemeral publish/subscribe/request/reply
- the **authority plane** handles obligations, leases, fencing, durability transitions, cutover, and cursor authority
- the **reasoning plane** handles evidence, explainability, certified cuts, replay, and counterfactual branches

The default path should be packet-plane only. Movement into the authority plane or reasoning plane should be visible, attributable, and caused by a declared `DeliveryClass` or `ServiceContract`, never by accidental implementation leakage.

This one split makes the entire document more believable. It protects the NATS-like ergonomics and latency profile of the common case while still giving Asupersync a place to put the deeper semantics.

### 1. Capability-Compiled Subject Fabric

NATS gives the subject space. Asupersync should turn it into a capability-compiled address fabric.

Core idea:

- subjects become a first-class runtime primitive, not a convenience API
- subject declarations compile into `SubjectSchema` artifacts with a small set of semantic families: `Command`, `Event`, `Reply`, `Control`, `ProtocolStep`, `CaptureSelector`, and `DerivedView`
- family choice constrains admissible transforms, default service class, reply-space law, evidence policy, and mobility permissions
- each subject prefix or transform space is granted through explicit capabilities in `Cx`
- that capability grant should lower to both an owned token type for in-process Rust paths and a runtime capability check for distributed paths
- wildcard routing still uses a `Sublist`-style core, but exports/imports compile into capability-checked routing programs
- interest state changes are explicit events with trace-visible invalidation epochs

This goes beyond ACLs. It makes the namespace itself part of the capability model.

Concrete synthesis:

- actor-side mutation semantics own the canonical subject-index contract, but the index itself should be physically sharded and read-optimized rather than funneled through one monolithic mutable authority
- literal-subject hot caches and per-link hot caches are generation-invalidated
- compiled export/import plans attach required capabilities and compact checked transform certificates
- interest registration is cancel-correct, so a cancelled subscriber cannot leave ghost interest behind
- the subject fabric should be the named and distributed coordination layer, not a mandate that every local hot-path interaction stop using direct channels, sessions, or GenServer calls

This makes the subject fabric more than a trie plus ACLs: it becomes the typed namespace kernel from which placement, policy, replay, and operator explanation all derive.

This would be the foundation for:

- distributed actor naming and rendezvous
- service addressing and cross-domain request/reply
- stream capture and consumer coordination
- control-plane advisories
- distributed federation

all sharing one primary address model where distributed naming and policy matter, without pretending every local hot-path interaction should stop using direct channels or local server calls.

### 2. Import/Export Morphisms Instead of Plain Routing Rules

This is where the deeper NATS read really matters.

NATS already has exports, imports, response policies, sharing controls, latency tracking, and cycle detection. Asupersync should go further and model these edges as **typed namespace morphisms**.

A morphism would define:

- source subject language
- destination subject language
- allowed transform algebra
- reversibility requirements
- capability requirements
- sharing policy for metadata and identity
- privacy and metadata disclosure policy
- optional attestation or private-compliance proof policy for especially hard cross-domain boundaries
- response policy
- quota and budget policy

The proposal would be materially stronger if every morphism were explicitly classified as one of:

- **authoritative**: reversible, reply-authoritative, capability-bearing
- **derived-view**: may redact, summarize, or reorder within declared law, but cannot originate authority
- **egress**: one-way export into weaker trust or replay domains
- **delegation**: temporary sub-language handoff with bounded time, budget, and revocation semantics

Each compiled morphism should carry at least five independently checkable facets:

- authority
- reversibility
- secrecy and metadata exposure
- cost and quota envelope
- observability and evidence obligations

This enables several genuinely new things:

- definition-time or plan-compile-time validation that an import/export edge is reversible where required
- cycle detection with semantic classes, not just string collision checks
- explicitly checkable policy plus runtime enforcement that a cross-domain request can only produce replies in permitted reply spaces
- auditable reasoning about what metadata crosses a boundary and why
- a later lane for selective private-compliance proofs at hard trust boundaries without forcing heavy cryptography onto the default path
- a transform language that stays finite, decidable, and explainable instead of turning into an embedded scripting problem
- a deterministic core transform algebra for authority-bearing edges, with any randomized or irreversible transforms isolated to one-way, non-authoritative fanout paths

Here, "proof" should be read narrowly: a compact policy or transform certificate emitted by planning or registration logic and checked by a deterministic verifier, not a claim that every edge carries a full theorem-prover artifact.

This is much stronger than "tenant A can talk to tenant B on `foo.>`."

Instead, it becomes:

**tenant A has a capability-bearing morphism into a specific sub-language of tenant B's subject space, with verified reply, sharing, transform, privacy, and evidence policy.**

That is a more powerful trust primitive than conventional service mesh policy.

### 2.5. A static capability layer beneath `Cx`

Asupersync can do something NATS cannot: make capability possession a compile-time property for in-process Rust code and a runtime property at process boundaries.

The core move is to treat Rust ownership and typestate as a zero-cost capability layer beneath `Cx`:

- `PublishPermit<S>` is an owned non-`Copy` token that must be consumed to publish to subject family `S`
- `SubscribeToken<S>` is an owned token for registering interest in `S`
- `SessionToken<P, State>` is a linear protocol-state token for typed conversations
- `CursorAuthorityLease`, `AppendCertificate`, and `FenceToken` can all be modeled as owned authority artifacts for in-process logic

This yields a two-layer capability architecture:

- the **static layer** prevents stale-token reuse, missing permit consumption, and illegal local protocol steps at compile time
- the **dynamic layer** uses `Cx`, capability checks, and the obligation ledger to govern runtime and cross-process behavior

Neither layer is sufficient alone. Together they produce the strongest practical guarantee:

- in-process misuse becomes a compile error
- distributed misuse becomes a capability error, stale-certificate reject, or explicit obligation violation

That is a materially stronger security and correctness posture than any messaging fabric whose authority model lives only in configuration and runtime checks.

### 2.6. Session-typed protocol contracts

The proposal's "protocol-carrying subjects" idea becomes much stronger if it is grounded in session types rather than left at the design-intent level.

The model should be:

- each protocol-carrying subject family registers a **global session type**
- the fabric **projects** that global type into each participant's local type
- duality and compatibility are checked when services are imported, exported, or versioned
- the obligation ledger can mechanically derive reply, timeout, compensation, and cutoff obligations from the protocol contract instead of relying on manual registration everywhere

This matters for request/reply, streaming reply, reservation handoff, cursor delegation, compensation workflows, and cutover protocols. It matters even more for multi-party cases such as consumer-group coordination, stewardship handoff, and split-brain arbitration.

The proposal should be explicit that this starts with two-party protocols and grows later into multiparty session types (MPST). The aim is practical: move a whole class of "wrong message order / missing reply / incompatible conversation shape" failures from runtime incidents toward compiler errors and registration-time rejects.

That turns protocol-carrying subjects into compiler targets rather than documentation conventions.

### 3. Certificate-Carrying Request/Reply

NATS request/reply is elegant because it is cheap. Asupersync can preserve much of that ergonomic cheapness on the default path while making stronger contracts available when callers opt into them.

Proposal:

- each request allocates at least one service obligation and, when the caller demands stronger semantics, a separate reply-delivery or receipt obligation
- the callee must commit the service obligation with a reply payload, abort it with a typed failure, or transfer it according to policy
- forwarded requests carry the service obligation through import/export morphisms, while reply-delivery obligations are resolved only when the configured delivery receipt boundary is crossed
- timeouts are not "absence of message"; they are explicit aborted obligations with traceable cause

This elevates request/reply from a pattern to a contract.

Operational consequences:

- silent lost replies become protocol violations only in domains that also durably track reply-delivery or receipt obligations; otherwise, the strong guarantee is limited to service completion and reply emission
- service export latency can be measured separately for service completion and reply-delivery lifecycle, not just transport timing
- streamed or chunked replies can become obligation families with bounded cleanup semantics

This is a strong fit with `src/gen_server.rs`, which already has disciplined reply behavior, and with the obligation ledger.

### 4. Quiescent Streams With Active Storage Semantics

JetStream shows that a stream is capture policy plus storage plus consumer coordination. Asupersync should preserve that, but make storage and shutdown semantically stronger.

Proposal:

- a captured stream is hosted as a region-owned durable state machine
- stream capture stays opt-in on selected subject sets; ordinary uncaptured subject traffic should remain on a lighter Core-NATS-like path rather than silently paying durable-stream costs
- publish is two-phase: reserve persistence budget, then durably commit append
- the publisher-visible ack is emitted only when the corresponding append obligation commits at the requested durability boundary
- storage backends participate explicitly in cancel/drain/finalize
- mirror and source are child regions, not detached background loops
- metadata and placement control for streams should remain separated from the per-stream append and consumer hot path, so the system does not centralize every durability decision behind one global coordination bottleneck

This supports the usual useful features:

- limits retention
- work-queue retention
- interest retention
- dedupe windows
- filtered capture
- replay and catch-up
- mirror and source pipelines

But it also unlocks more novel semantics:

- no half-acknowledged append under cancellation
- no orphan mirror/source worker on shutdown
- replay and repair behavior that can be exercised under the lab runtime
- snapshot as a first-class runtime operation instead of just a storage utility

NATS already snapshots stream metadata, blocks, and consumer state together. Asupersync should build on that and introduce **forkable snapshots**:

- capture a stream plus consumer state at a logical cut inside the Asupersync capability boundary
- only permit a cheap fork at quiescent or cut-certified points, or else include the in-flight obligation and import/export frontier explicitly in the snapshot artifact
- restore it into a lab runtime or staging region
- on restore, rebind epochs, strip or replace live reply spaces, leases, subject-cell keys, and import/export credentials before the restored instance is allowed to talk to real peers
- replay counterfactual delivery policies or failover strategies against the frozen in-boundary state, with external peers and side effects modeled explicitly rather than hand-waved away

That starts to look like "git branches for live event systems," but under deterministic runtime semantics.

### 5. Consumers As Policy-Driven Delivery Engines

NATS consumer policy is richer than most people realize. Asupersync should not reduce it back down to simple cursors.

Proposal:

- fabric-hosted consumers become region-owned delivery engines
- ack state is backed by obligations, not only counters
- delivery attempts carry explicit attempt identity and stale-ack idempotence rules even in the base fabric; later subject-cell phases extend that identity with cell epoch and cursor-lease fields
- pull requests, flow control, pause windows, heartbeats, and pull-consumer scheduling policies such as priority groups become explicit policy objects
- delivery selection can incorporate budgets, backlog, ack debt, and fairness policy

The deepest NATS-inspired move here is to treat consumers as scheduling entities. Asupersync can go further and make them **decision-contract-driven schedulers**.

Example directions:

- pull-consumer priority groups become typed demand classes
- pull-consumer pinned-client policy becomes temporary capability leasing
- pull-consumer overflow policy becomes a bounded fallback rule with evidence
- redelivery policy becomes a decision contract that records why a retry, delay, or dead-letter action was selected

This creates the possibility of an "adaptive consumer kernel":

- stable, deterministic default policies
- optional advanced policies that remain audit-backed and replayable
- no hand-wavy exactly-once claims
- very strong reasoning about pending work and retry causality

That has more upside than simply reimplementing `AckWait`.

### Service classes and semantic SLOs

The proposal should stop sounding as if every message path pays for every semantic upgrade. The right move is to make the upgrade surface explicit and named.

Every subject family, stream, consumer, or service contract should compile to a semantic SLO tuple such as:

- latency envelope
- durability or recoverability class
- obligation scope
- ack meaning
- replay retention
- evidence sampling rate
- mobility allowance
- degradation priority
- privacy policy
- quantitative obligation contract where applicable

A small default class set would make the system operable:

- `EphemeralInteractive`
- `DurableOrdered`
- `ObligationBacked`
- `MobilitySafe`
- `ForensicReplayable`

Providers declare admissible classes; callers can only request a bounded subset within provider policy. That keeps the document from sounding as if any caller can unilaterally demand expensive guarantees by fiat.

The proposal should also define a small ack taxonomy instead of overloading the word "ack":

- `Accepted`: the packet plane accepted custody for forwarding; no durability or service completion implied
- `Committed`: the authority plane committed the control entry or obligation
- `Recoverable`: the declared durability class has been met
- `Served`: the service obligation was completed by the callee
- `Received`: the configured delivery or receipt boundary was crossed

This naming is not cosmetic. It bridges deep semantics to operator language.

The proposal also gets stronger if obligations can optionally carry a quantitative contract in addition to a binary one:

- binary: this obligation must resolve, abort, or transfer
- quantitative: this class of obligation should resolve within budget `b` with probability at least `p` under the declared service class

That turns tail-latency, retry law, and overload policy into auditable contracts rather than folklore.

### 6. Control Plane As Ordinary Subjects

This is an underexploited NATS idea.

Rather than expose admin state through a separate imperative control API, Asupersync should model the control plane as first-class subjects in the same fabric:

- fabric health
- import/export changes
- route and gateway advisories
- lameduck and drain state
- auth and capability failures
- consumer pause and unpin events
- stream snapshot creation and restore
- repair, replay, and rebalance advisories

But this should be logical unification, not operational naivete:

- system and control subjects should live in a dedicated capability domain
- control handlers should run with reserved budget and priority, not compete blindly with user traffic
- a minimal bootstrap and break-glass recovery path should remain available even if the ordinary subject fabric is degraded
- advisory subjects should not automatically feed policy loops without explicit damping, stratification, or operator intent, or the control plane will amplify its own observations

But Asupersync can add two twists NATS does not have:

- control-plane handlers and generated advisories are region-owned and replayable once external inputs are modeled explicitly
- material decisions on those subjects can emit FrankenSuite evidence and decision records

That means an operator would see more than "gateway detached." They could also see:

- which capability graph edges were affected
- which obligations were transferred, aborted, or replay-scheduled
- which policy decided the failover path
- what evidence justified it

This is the beginning of a system that can explain itself at runtime in its own native coordination language.

### 7. Federation As Capability-Scoped Region Bridges

NATS is right that different topologies deserve distinct roles. Asupersync should keep that and sharpen it.

I would define at least four role types:

- `LeafFabric`
- `GatewayFabric`
- `ReplicationLink`
- `EdgeReplayLink`

Each role would have distinct semantics.

`LeafFabric`:

- constrained export/import morphisms
- intermittent connectivity tolerated
- optimized for tenant enclaves, browsers, edge workers, and offline-capable agents

`GatewayFabric`:

- interest propagation across fabrics
- control-plane advisories
- low-amplification routing
- bounded convergence and replay guarantees

`ReplicationLink`:

- stream and consumer-state transfer
- snapshot and catch-up
- stronger ordering and durability policy

`EdgeReplayLink`:

- ships trace/snapshot/evidence artifacts
- supports lab replay of edge failures and delayed reconnection histories

These roles are more precise than a generic "cluster peer" abstraction and fit Asupersync's bridge/snapshot surfaces better.

## The Most Disruptive New Possibilities

If the above is built well, Asupersync could offer product surfaces that NATS only partially points toward.

### 1. Certificate-Carrying Pub/Sub

Every important delivery transition can become auditable:

- why this subscriber received the message
- why this import edge was authorized
- why a redelivery happened
- why a dead-letter decision was chosen
- why a failover route became active

Not for every hot-path packet by default, but for the transitions that matter operationally.

### 2. A Fabric-Native Service Plane

Most service meshes are bolt-on policy layers. Here, service boundaries that are intentionally routed through the subject fabric would be expressed as subject morphisms plus request/reply obligations plus control-plane subjects, while direct channels and local GenServer calls still remain the right answer for some hot-path local interactions.

That gives:

- better mental model
- fewer duplicated planes
- stronger cancellation semantics
- much richer replay and debugging

### 3. Deterministic Incident Rehearsal

Because the Asupersync-hosted implementations of streams, consumers, gateway handlers, and advisories can live inside replayable runtime semantics, operators could do:

- replay this outage with a different consumer policy
- replay this partition with a stricter export policy
- replay this drain event with a shorter budget
- replay this leaf reconnect storm against a candidate scheduler

That is much closer to "chaos engineering with proof obligations" than ordinary messaging infrastructure.

### 4. Subject-Native Multi-Tenant Namespace Kernel

Accounts/imports/exports in NATS already smell like an operating system namespace model. Asupersync can lean into that as a namespace-kernel analogy without pretending the proposal already solves full CPU, memory, and storage isolation.

Subjects become:

- process mailboxes
- service names
- control channels
- durable stream capture rules
- trust boundaries
- observability feeds

The runtime starts to look like a secure, replayable, distributed namespace kernel.

### 5. Evidence-Native Data Plane

FrankenSuite opens a non-obvious door: important messaging and routing choices can be attached to evidence entries and decision contracts without making the hot path absurd.

That means the system can answer not only "what happened?" but "what policy decided it, with what evidence?"

That is especially valuable for:

- security-sensitive routing
- adaptive delivery policy
- multi-tenant governance
- distributed failover
- operator trust

### 6. Cut-Certified Mobility Instead Of Restart-Based Operations

Most distributed systems still move state by some variation of "stop it here, start it there, and hope the handoff was clean."

Asupersync can plausibly do something more structural inside its hosted boundary because region close, obligation ledgers, and snapshot validity already have semantic meaning.

That opens the door to:

- hot-cell or hot-actor evacuation with proof that no reply, ack, or lease obligations were orphaned
- service and consumer handoff with explicit cut certificates instead of vague drain heuristics
- browser and edge warm restore from RaptorQ capsules rather than mandatory full resync
- deploys and failovers expressed as lawful mobility operations rather than crash-and-recover rituals

The key move is to make mobility a first-class semantic operation rather than an operational pattern layered on top.

### 7. Subject-Native Workflow And Saga Kernel

Most real distributed workflows today are assembled from separate queues, outbox tables, retry timers, compensators, and hand-written audit logic.

Asupersync can collapse that stack.

A durable workflow step can be modeled as a subject transition plus obligations for reply, lease, timeout, compensation, or deadline. Unresolved work is not inferred indirectly from counters; it is represented directly in the ledger.

That gives:

- one substrate for request/reply, retries, outbox, sagas, and compensation
- replayable partial progress with precise answers to "what is still owed?"
- recovery logic that inherits the same no-orphan and no-silent-drop rules as the runtime
- a path to turning messaging into a distributed work-accounting kernel rather than a transport plus conventions

For a narrow high-value subset of cross-cell workflows, later lanes can explore adaptor-signature or threshold-commit coupling of selected obligation families to reduce blocking coordination cost without promising generic coordination-free atomicity. That belongs in the research lane, not the V1 core claim.

If this lands, whole classes of "workflow infrastructure" start looking redundant.

### 8. Continuous Counterfactual Control, Not Just Incident Replay

Deterministic incident rehearsal is already a major step up from conventional messaging operations.

The more radical move is to make shadow branches normal.

From any cut-certified snapshot, the fabric can fork multiple candidate worlds that replay the same in-boundary history under different retry laws, morphisms, placement rules, coding budgets, or supervision policies. The decision layer can compare those branches and promote only policies that beat the current one inside explicit safety envelopes.

That turns:

- operations into an always-on policy laboratory
- adaptive control into evidence-backed promotion rather than heuristic toggles
- incidents into reusable evaluation data for future routing and recovery policy
- high-stakes changes into branch, score, and promote workflows instead of intuition-driven rollouts

Unlike ordinary simulation, the branch starts from semantically meaningful state rather than an approximate test fixture.

### 9. Distributed Supervision Compiler

Once subjects, streams, and consumers are region-owned and obligation-tracked, Spork and GenServer-style structure no longer has to stop at a single process boundary.

A distributed application could eventually compile into:

- supervision graphs
- subject morphisms
- failure domains
- restart envelopes
- drain and handoff contracts
- evidence hooks for every material control-plane decision

This is much closer to a distributed OTP than to "service mesh plus pub/sub." Remote mailboxes, monitors, links, registry leases, and failover behavior inherit structural guarantees instead of living in conventions and sidecars.

### 10. Bounded-Regret Reliability Control

Most messaging systems ask operators to choose fixed replication, retry, and backpressure settings up front and then live with the consequences.

Asupersync could expose safe envelopes and let the fabric tune within them.

Evidence, replay, and subject-cell telemetry can drive adaptive choice of:

- steward set size
- RaptorQ repair depth
- relay placement
- durable versus ephemeral service class
- redelivery law
- replay buffer depth

Done carefully, the fabric becomes self-improving without becoming inscrutable: every policy shift carries evidence, confidence, and a rollback path.

This is disruptive because it changes reliability from a static configuration surface into an audited control system.

### 11. Local-To-Global Consistency Certificates

Distributed systems often fail not because any single local component is obviously wrong, but because the pieces do not glue together globally.

Asupersync's existing sheaf and obstruction direction suggests a far more unusual capability.

Cells, morphisms, delegated cursor partitions, federation edges, and supervisor domains should emit explicit local consistency facts. The fabric can then attempt to glue those into global sections or emit obstruction certificates when they fail to compose:

- import/export policies line up with reply-space restrictions
- cursor delegations and read tickets do not overlap illegally
- cutover plans cover all outstanding obligations
- witness placement satisfies durability and confidentiality constraints simultaneously
- adaptive control policies stay inside the certified safety envelope across fabrics

That is more than observability. It turns the sheaf and obstruction direction into a concrete topology-checking pipeline that can detect global incoherence before it becomes an outage.

### 12. Recoverable Service Capsules

The brokerless data-capsule idea should not stop at raw message segments.

If a quiescent cut can capture stream windows, consumer cursors, supervisor state, read models, caches, and the local evidence frontier, then the fabric can package not just data but partially live distributed subsystems into recoverable capsules.

Restore still has to obey the same authority-scrubbing and epoch-rebinding rules described elsewhere in this proposal. The point is portable hosted state, not smuggling live leases, reply spaces, or credentials across cuts.

That creates a path to:

- bursty tenant services that hibernate and resume cheaply
- edge-ready warm state pre-positioned near demand
- realistic branchable sandboxes derived from production cuts
- disaster recovery where the unit of movement is already recoverable
- deploy and state-transfer machinery that converges on one object model

The radical shift is that persistence, transport, and service mobility stop being separate stacks and start sharing one recoverable substrate.

### 13. Protocol-Carrying Subjects

NATS gives subjects and request/reply. Asupersync can push further and make distributed conversations first-class.

A protocol definition can compile into:

- subject families and reply-space rules
- obligation transitions and timeout law
- compensation and cutoff paths
- admissible state transitions for the conversation
- evidence checkpoints for material control moves

That means request/reply, streaming reply, reservation handoff, compensation, cutover, and multi-step coordination stop being ad hoc handler logic and become checked protocol kernels.

The payoff is bigger than API cleanliness:

- explicit "what is still owed?" semantics at every step
- rejection of illegal conversation shapes before they become production drift
- replayable protocol traces instead of endpoint-local folklore
- one compiler surface for service APIs, workflow, and control-plane operations

This is where messaging starts to look like a practical distributed process calculus rather than a bag of topics and handlers.

### 14. Intent-Compiled Operations

Most operators still express intent indirectly by tuning a pile of knobs and then discovering the actual system behavior from incidents.

Asupersync can plausibly move toward a better model: let operators specify a narrow, auditable intent surface and lower that into service class, mobility budget, repair spread, federation constraints, evidence thresholds, and control-capsule policy.

Examples:

- keep this tenant below a tail-latency envelope while preserving sovereignty
- prefer quiescent mobility over restart-style failover for these services
- minimize egress unless recoverability drops below a stated threshold
- require certificate-carrying edges for all cross-tenant traffic
- widen repair spread before widening steward quorum for this namespace

This is a path toward operations as compiled policy with explicit artifacts, bounded authority, replay, and rollback. It is not an "autopilot ops" pitch.

### 15. Commutativity-Aware Sharding And Scheduling

Most messaging systems shard by subject string, hash bucket, or manually chosen stream partition. That scales, but it also creates avoidable false contention because the system does not know which operations actually interfere.

Asupersync can eventually do something stronger. If protocol-carrying subjects, declared interference classes, and obligation footprints make it explicit which transitions commute, then the fabric can introduce secondary execution-lane partitioning and scheduling by semantic independence above canonical subject-cell ownership rather than by name alone.

That means:

- non-interfering conversation families can be routed to separate execution lanes or secondary subpartitions without unnecessary coordination
- high-contention namespaces can be decomposed by declared or certified shared-state footprint instead of crude subject prefixes
- protocol kernels can advertise when reordering or parallel issuance is lawful
- hot paths can get more throughput by proving independence instead of relying on hand-tuned partitioning

This changes the scale-out story. The fabric stops asking only "where should this subject go?" and starts asking "what has to serialize, and what merely happens to share a textual prefix?" It keeps canonical, hash-stable `SubjectCell` ownership, but treats that layer as the base ownership boundary rather than the only concurrency boundary.

### 16. Branch-Addressable Reality

If cut-certified snapshots, replay, and recoverable service capsules are first-class, then "the live system" stops being the only addressable reality inside the hosted boundary.

This only works where external side effects are either fenced off or modeled explicitly. It provides addressable branch semantics for the parts of the runtime Asupersync actually owns; it is not a claim of magical time travel for arbitrary unmanaged systems.

Selected operator, audit, or carefully capability-scoped client workflows could eventually attach to:

- the live branch
- a lagged certified cut
- a replayed branch with different control policy
- a canary branch derived from production state but fenced from production side effects
- a forensic branch used to explain why a past result happened

For non-operator client workflows, these views should default to read-only observation or explicitly sandboxed mutation lanes. The proposal should not imply that arbitrary clients can write into replayed or forensic branches just because they can attach to them.

That would make the messaging substrate useful in a way ordinary brokers are not:

- safer rollouts because canaries can start from realistic state
- better support tooling because a user-visible outcome can be reproduced against a real semantic cut
- branch-based policy evaluation without synthetic fixtures
- a path to "explain this response" workflows grounded in actual protocol and evidence history

The important shift is that time and hypothetical policy stop being only external test concerns and become addressable dimensions of the hosted runtime.

### 17. Contract-Carrying Services

Service interfaces today usually say what messages look like, but not the deeper behavioral contract that matters under failure, overload, mobility, or compensation.

Asupersync can turn service contracts into much richer artifacts.

Those contracts also need an explicit authority split. Some terms are provider-declared invariants or guarantees, while others are caller-selectable request classes bounded by provider policy. Without that distinction, the document risks sounding as if every caller can demand its own mobility, durability, or overload semantics by fiat.

A service definition could eventually carry:

- request and reply shape
- cancellation and cleanup obligations
- budget and cleanup urgency semantics
- durability class and capture rules
- compensation semantics
- mobility or sovereignty constraints
- evidence and audit requirements

That lets clients and operators reason about more than schemas:

- whether a call is replayable or must remain single-shot
- whether a reply is best-effort, durable, or obligation-backed
- whether the service may be deprioritized, shed, or protected under overload
- whether the service may migrate across regions or must stay pinned
- whether failed work compensates, retries, or dead-letters

This would make subject-native services look less like thin RPC over pub/sub and more like distributed behavioral interfaces that can be checked, compiled, and audited.

### 18. Causality-Native Streams And Views

Most messaging systems quietly force a stronger ordering model than the workload actually needs.

They expose one linear stream because it is operationally convenient, even when the underlying work is only partially ordered. That simplicity carries a hidden cost: extra coordination, avoidable false serialization, and much weaker explanations of what really depended on what.

Asupersync can eventually expose a more honest model. For selected workloads, the fabric can preserve causal structure and let consumers or services choose from a bounded supported family of linearization policies instead of pretending one merged total order is always correct.

This should not be read as replacing per-cell append sequencing or control-capsule linearity. The stronger claim is narrower: selected higher-level views can be derived from explicitly dependency-tracked events and bounded frontier summaries without collapsing everything into one merged total order. That, in turn, only becomes operationally valuable when paired with the interference-aware scheduling and partitioning machinery described above; the view alone does not buy throughput.

That would allow:

- consumers that subscribe to a causally complete cut or dependency-certified frontier rather than an arbitrary merged total order
- multi-source workflows that merge by dependency rather than arrival order
- higher throughput when independent transitions no longer compete for the same serialized lane
- much better explanation of incidents because concurrency ambiguity is explicit instead of collapsed into one log order

In that model, selected messaging views start to look like a practical partial-order runtime built above linear control kernels rather than an append-only log with extra features.

### 19. Budget-Carrying Traffic And Obligation-Aware Degradation

Most overload control still works at the level of bytes, queue depth, and coarse priority.

Asupersync has the ingredients for something stronger because deadlines, cleanup budgets, reply obligations, lease obligations, and service contracts are already explicit.

This only becomes safe if degradation policy runs across declared service classes with explicit reserved capacity for control and recovery lanes. Otherwise the system will starve the very flows that preserve cutover, replay, and repair safety.

That means traffic and control decisions can eventually be driven by semantic damage, not just load:

- preserve cutover, cleanup, and reply-critical work before lower-value traffic
- prefer degradation paths that minimize orphaned obligations
- widen repair or routing effort for work whose failure would create the largest semantic debt
- degrade read models, low-value fanout, or expensive replay lanes before violating stronger service contracts
- keep operator-intent and recovery channels alive under pressure by design rather than by convention

This goes beyond QoS. It is a path toward overload behavior that is optimized against what the system is actually trying to protect, not a vague excuse for opaque priority inversion.

### 20. Certified Cut Lattice And Reality Index

Branch-addressable reality becomes much more powerful if the runtime does not treat certified cuts as ad hoc artifacts.

Asupersync can move toward a policy-scoped, retained, and compacted index of semantically meaningful cuts, branches, and lineage inside the hosted boundary.

That index could track:

- which service, stream, or subject-cell state is represented
- what obligations were still live or already resolved at the cut
- what policy regime and evidence frontier were in force
- what access policy or secrecy class governs visibility of the cut or branch
- which descendant branches were derived from that cut
- which cuts are materialized versus reconstructible on demand
- what restore, replay, or operator actions are valid from that point

That opens a more radical operational model:

- "attach me to the latest cut that is causally before incident X"
- "fork a canary from the last certified cut under policy Y"
- "show the smallest cut that explains this user-visible outcome"
- "restore only the subtree whose obligations can still be lawfully resumed"

The result is better than rollback tooling alone; it is a new object model for time, explanation, and recovery in distributed systems.

### 21. Session-typed distributed conversations

Most distributed protocol bugs are discovered at runtime or during incident review: wrong message order, missing reply, incompatible expectations across trust boundaries, or mismatched compensation semantics. Session-typed protocol contracts create a better failure mode.

This is more than "better API design." It creates a new class of protocol compatibility tooling:

- import/export registration can reject incompatible conversation shapes before any message is sent
- protocol evolution becomes a type-level change that forces adapters or updates instead of silently drifting
- trace-level conformance checking can run a session automaton alongside execution in the lab runtime
- obligation derivation becomes mechanical for large classes of protocols instead of hand-wired everywhere

That is the missing bridge between the formal semantics substrate and the operational reality of independently evolving services.

### 22. CRDT-augmented mergeable control plane

The proposal gets materially stronger if it says exactly where strong sequencing is required and where convergent mergeable state is enough.

Authoritative state still belongs in fenced, leadered control capsules:

- appends
- authority transfer
- reply rights
- cursor authority
- epoch changes

But high-churn non-authoritative surfaces can converge as delta-CRDTs:

- interest summaries
- coarse cursor checkpoints
- membership views
- lag and load sketches
- selected advisory aggregates

This is the right sweet spot:

- strong consistency where ambiguity would be dangerous
- convergent merge where centralization would become the bottleneck

It is a concrete answer to one of the hardest practical questions in the whole document: how to keep the control plane from secretly becoming a global metadata bottleneck.

### 23. Reactive protocol synthesis

Once protocols are typed and the fabric already compiles declarations into runtime artifacts, the next step is natural: synthesize the correct scaffolding from the protocol contract.

Reactive synthesis from a protocol contract can produce:

- handler skeletons for each role
- obligation registration and completion at the correct protocol points
- error and timeout branches
- compensation hooks for saga-style workflows
- adapters for compatible protocol evolution cases

The "fabric compiler" framing pays off clearly here. The developer still supplies business logic. The fabric supplies the conversation skeleton, obligation wiring, and compatibility checks.

It will not eliminate bugs, but it moves a large class of distributed plumbing bugs out of artisanal handler code.

### 24. Privacy-budgeted metadata surfaces

Even if payloads are encrypted and namespace access is capability-checked, metadata still leaks a great deal:

- who is active
- which subject families are hot
- how large a consumer set is
- how fast a tenant is changing state

The practical move is not to promise hot-path anonymity. It is to make exported metadata summaries privacy-budgeted and auditable:

- telemetry aggregates shared across trust boundaries can carry calibrated differential-privacy noise
- cross-domain advisory and observability summaries can publish an explicit privacy budget
- witness pools and weakly trusted observers see only blinded or wrapped metadata, not raw payloads or full activity traces

That is especially valuable in sovereignty-sensitive, financial, healthcare, and multi-tenant environments where metadata itself is sensitive.

### 25. Quantitative obligation contracts

The current obligation model is binary and that is the right foundation. But operators also need to reason about:

- how fast obligations resolve
- with what reliability under the declared class
- what retry or degradation law is required to stay inside the promised envelope

Extending obligations with optional quantitative contracts gives the system a language for those claims:

- "resolve within 50ms with probability ≥ 0.999 under class `EphemeralInteractive`"
- "resolve within 5s with probability ≥ 0.9999 under class `ObligationBacked`"

That enables:

- quantitative service-class SLOs
- algebraic retry and redelivery synthesis
- evidence records that explain why a policy change was justified
- e-process or conformal monitors that watch for drift from the promised envelope

Binary obligations remain the semantic floor. Quantitative obligations become the operator-facing contract above that floor.

## A More Radical Move: Brokerless Peer-Cooperative Fabric

NATS assumes a broker tier, even when that tier is clustered. Asupersync does not have to.

Because Asupersync already has region ownership, leases, obligations, quorums, deterministic replay, and RaptorQ-backed distributed state movement, it can pursue a much more unusual architecture:

**steward-eligible participants can act as either clients or temporary stewards, and subject space can be governed by rotating peer quorums instead of fixed servers.**

The right abstraction is not "a decentralized broker." It is a fabric of **quorum-owned subject cells**.

### 1. Subject Cells Instead Of Brokers

A `SubjectCell` is the smallest sovereign unit of the messaging fabric.

Each cell owns:

- a canonical, non-overlapping subject partition slice such as `tenant_a.orders.eu.<partition>`
- a current steward set chosen from steward-eligible nodes by placement policy
- a control capsule containing epoch, leases, obligation frontier, consumer-cursor ownership and fencing state, and policy state
- a data capsule containing recent message blocks, stream segments, or inbox fragments
- a repair policy describing how the cell reconstitutes itself under churn or packet loss

There is no permanent external broker role. A node may be:

- an origin for a publish
- a subscriber or consumer
- a temporary steward for a hot subject cell
- a repair witness holding symbols for future recovery
- a bridge for leaf or gateway-style propagation

The same physical node can play several of those roles at once, but on Asupersync-native nodes every hosted role still remains explicit and region-owned.

Not every participant should be steward-eligible. Browsers, constrained edge agents, or policy-limited clients may be publish/consume-only by design.
Ephemeral reply subjects and other high-cardinality transient namespaces should not each become their own `SubjectCell`; they should remain uncapsuled or be aggregated under explicit compaction policy, or the control plane will explode.

### 2. Discovery And Negotiation

Nodes either self-discover or begin from a seed list. The bootstrap handshake should exchange:

- node identity and capability set
- signed membership or admission credentials for the relevant trust domain
- supported messaging and RaptorQ policy versions
- available storage, uplink, and repair budget
- capability-scoped or blinded interest summaries
- current cell stewardship leases
- recent control-capsule epochs for cells the node already knows about

This should not be treated as ad hoc gossip. It should be a typed session with explicit lease obligations and replayable transitions.

Peer-advertised health, interest, and placement hints should remain advisory. Authority still comes from authenticated membership plus the current control-capsule epoch and capability policy.
Namespace visibility should be narrower than generic membership. Multi-tenant fabrics should assume that raw subject prefixes, hot keys, and traffic shape are sensitive metadata and should only disclose the minimum summaries required for placement and routing.

The ambitious move is to make placement **subject-relative**, not cluster-global:

- each subject cell is mapped through consistent hashing or related placement policy into a candidate steward pool derived from an explicit membership epoch or roster snapshot
- the active steward set is then negotiated from that pool subject to capability, health, storage class, latency envelope, and failure-domain diversity
- hot cells can temporarily widen their steward set or enlist repair witnesses
- cold cells can collapse back toward a minimal footprint without a centralized rebalance daemon
- stewardship changes should be damped by hysteresis and explicit rebalance budgets, or the system will thrash under noisy demand

Brokerless placement has to run on authoritative normalized subject space, not on whatever textual subject spelling a publisher happened to use first. Import/export morphisms, wildcard normalization, and reply-space aggregation need to happen before placement, and the resulting `SubjectCell` slices must be canonical, non-overlapping, and hash-stable for a given membership epoch.

This only works once subject space has a canonical non-overlapping partitioning scheme and an explicit cell cardinality policy. Without that, wildcard overlap, transform-dependent aliases, and reply-space churn would make ownership ambiguous and control-capsule count unbounded.

This creates a system where the network continuously self-organizes around the actual subject workload rather than around a static broker fleet.

### 3. Split The Problem Into Control Capsules And Data Capsules

Many peer-to-peer messaging designs stumble by treating agreement on metadata and storage of bytes as the same problem.

Asupersync should separate them aggressively.

### 3.5 Delta-CRDT augmented control surfaces

`ControlCapsuleV1` should remain leadered and fenced for authoritative state. But all non-authoritative metadata should not be forced through the same path.

That means:

- interest summaries
- coarse cursor checkpoints
- delegated-partition aggregates
- selected membership and load views

can converge as delta-CRDT join-semilattices rather than as fully sequenced log entries.

This gives the brokerless design a concrete scaling story:

- optimistic propagation across stewards and relays
- leaderless convergence on cold paths and during transient partitions
- dramatically cheaper high-fanout consumer churn
- much lower pressure on the authoritative sequencer lease

CRDTs are the complement to RaptorQ data capsules:

- authoritative control stays fenced
- bulk payloads stay recoverable
- mergeable non-authoritative summaries stop central metadata from becoming the real bottleneck

### 3.6 Speculative subject-cell execution with tentative obligations

The proposal can also afford a more practical form of "counterfactual" fast path than full branch-per-policy magic.

For low-conflict subject cells and service classes that permit it:

1. the origin issues a **tentative** publish backed by a tentative obligation
2. the control capsule sequences it in the background
3. if confirmed, the obligation commits and the tentative path becomes final
4. if sequencing reveals a conflict, the tentative obligation aborts deterministically and the corrected outcome is surfaced without ever exposing an illegal intermediate state to consumers

This is the grounded version of speculative execution that actually fits the rest of the proposal:

- bounded by service class
- bounded by cell-local conflict histograms
- bounded by explicit kill switches
- verified under the same replay and oracle machinery that already exists for cancellation and redelivery races

It is not generic "superposed execution." It is a narrowly justified latency optimization with explicit rollback semantics.

Each subject cell should maintain:

- a **control capsule**: small, strongly replicated state for epoch, append ordering and fencing, leases, idempotency windows, capability policy, and ownership/fencing state plus coarse batched summaries for delegated consumer cursor partitions
- a **data capsule**: bulk payload blocks encoded into systematic RaptorQ source symbols plus repair symbols

This matters because the control capsule needs crisp quorum semantics, while the data capsule primarily needs recoverability and mobility.

So a publish should look like this:

1. The origin node computes the target cell and opens a publish obligation.
2. The steward quorum accepts a control-capsule append record containing subject, idempotency key, payload digest, an epoch-fenced append sequence or certificate, and the required durability class.
3. The payload is either appended directly on a tiny-message fast path or rolled into a sealed segment window that is then chunked into source blocks and encoded into RaptorQ symbols.
4. Symbols are sprayed across stewards, repair witnesses, and optionally interested peers according to authorization, confidentiality, retention, and symbol-authentication policy.
5. The publish ack is emitted only after the control capsule commits and the durability target for that class is met: a steward replication quorum on the hot replicated-segment path, or the configured capsule recoverability target on the sealed coded path.

`ControlCapsuleV1` should be scoped honestly. Before delegated cursor partitions and batched checkpointing exist, it is a bounded-fanout, bounded-ack-rate design for cells whose consumer churn can still fit comfortably inside one replicated control stream. It should not be sold as the universal control path for arbitrarily hot cells.

This design is **agreement on meaning plus fountain-coded recoverability for bulk state**, not consensus on every byte.

Ordinary ephemeral pub/sub should not automatically pay this contract. The strong durable publish path should be explicit and opt-in, with batching or asynchronous sealing where possible, or the fabric will give up the latency profile that makes Core NATS compelling.

If symbols are stored outside the active steward quorum, they should generally be wrapped under subject-cell or policy-derived keys; otherwise, repair witnesses become an accidental data disclosure surface.
Symbols should also be bound to object identity, epoch, and payload digest so witnesses can withhold or lose data, but cannot silently forge a valid alternate capsule.

### 4. RaptorQ Should Be A First-Class Data-Plane Primitive, Not Just A Snapshot Feature

Asupersync already uses RaptorQ to distribute recoverable region snapshots. The messaging substrate should push that idea much further.

RaptorQ can give the fabric several unusual powers:

- **brokerless durability**: a subject cell does not need a full replica of every byte on every steward; it only needs enough symbol spread to meet a chosen recoverability target and decode-failure bound under the desired failure budget
- **mobility without full re-copy**: when stewardship changes, the new set can reconstruct the data capsule from any sufficient symbol quorum instead of waiting for a designated leader to stream the whole log
- **edge-tolerant fanout**: mobile or intermittent nodes can collect authorized symbols from current stewards or explicitly delegated relay peers without requiring one permanent broker replica to stream the whole history
- **progressive reliability classes**: low-value traffic can use mostly systematic symbols and shallow repair budgets, while high-value traffic can demand deeper repair symbol spread before ack
- **stream-window elasticity**: hot windows can attract more repair symbols and wider witness placement, then contract again when demand falls

A less obvious but important shift is to make the unit of durability a **recoverable capsule**, not a replica.

The coding granularity matters. In most cases, coding should happen at the segment-window or large-payload level, not by synchronously fountain-coding every tiny publish, or the CPU and latency budget will collapse under hot-subject traffic.

That is a far better fit for a peer-cooperative system than pretending every participant must keep a perfectly mirrored broker log.

### 5. Consumers Become Negotiated Cursor Leases Over Recoverable Capsules

In this model, a consumer is not "connected to a server." A consumer holds leases against subject-cell state.

Concretely:

- the consumer cursor authority lives in the control capsule or in delegated cursor partitions governed by it
- delivery rights are represented as obligations and temporary leases
- in `ControlCapsuleV1`, the data should be served only by current stewards or explicitly leased relay peers carrying a read-delegation ticket bound to the current cell epoch, cursor lease, and segment window; broader opportunistic serving should wait until its delegation and revocation model is proven
- pull consumers can ask for specific sequence windows or demand classes
- push consumers can be pinned temporarily to a steward or delegated to a nearby relay peer
- every ack, nack, or redelivery decision should carry an attempt-scoped certificate, at minimum `(cell_id, epoch, cursor_authority_lease, sequence_or_window, delivery_attempt, obligation_id)`, where later scaled variants can refine `cursor_authority_lease` into a delegated `cursor_partition_lease`

This makes consumer failover radically cheaper:

- if one serving node disappears, another current steward or still-valid leased relay with enough symbols and the current control capsule can continue
- if no single peer has all bytes locally, reconstruction is still possible from distributed symbols
- if a cursor transfer is contested, the control capsule resolves it as a lease and obligation question rather than as a hidden per-connection side effect
- if an ack arrives after failover, replay, or cursor transfer, the attempt certificate makes it either a valid commit against the current lease holder or a deterministic stale no-op

That is much closer to "distributed inboxes with algebraic cursor semantics" than to ordinary broker subscriptions.

### 6. Subject Cells Can Self-Rebalance Without A Dedicated Control Cluster

Because control capsules are small and data capsules are fountain-coded, rebalance no longer needs to mean "copy the entire shard, then move the leader."

Instead:

- a cell can issue a stewardship-change proposal under the current epoch
- new stewards collect enough symbols to meet the target recoverability class
- consumer and reply obligations are transferred or reissued explicitly
- once the cut is certified, the epoch advances, stale stewards are fenced from authoritative appends, and the old stewardship lease drains

This is where Asupersync's quiescence and obligation machinery matter. A cell handoff can be defined as a real semantic cut:

- no unresolved publish obligations below the cut
- no ambiguous consumer lease owners
- no dangling reply rights
- enough symbol spread to reconstitute the data capsule after the move

That is stronger and cleaner than ordinary shard migration.

### 7. The Algebraic Opportunity

This design gets more interesting when stated in Asupersync's native algebra.

Roughly:

- control-capsule state is a bounded, lease-aware coordination object with explicit epoch transitions
- obligation state wants convergent merge structure, likely a join-semilattice over resolved and unresolved facts
- interest summaries are compressible, mergeable approximations
- data-capsule placement becomes a constrained coding-and-cover problem rather than a plain replication problem
- stewardship selection becomes a policy-optimized quorum choice over latency, durability, and failure-domain constraints

That means the fabric can eventually do things that are much harder in a broker-centric design:

- certify that a handoff preserved the required recoverability class
- search for lower-cost steward sets without breaking consumer or reply invariants
- replay the same churn event under different coding budgets or quorum rules
- detect global inconsistency as a gluing failure instead of waiting for user-visible corruption

This is exactly the kind of design space where Asupersync's semantic kernel and RaptorQ substrate compound rather than merely coexist.

### 8. What This Could Feel Like In Practice

From the application's point of view, the API can still look simple:

- connect to any known node
- publish to a subject
- subscribe or create a consumer
- optionally request a durability or latency class

But under the hood, there is no fixed broker/server boundary.

The client is attaching to a living subject fabric where:

- ownership is cell-relative and lease-based
- durability is recoverability-based
- delivery is obligation-tracked
- failover is a cut-and-capsule transition
- recovery is fountain-coded rather than leader-streamed

That is a more genuinely new architecture than "NATS without a central cluster."

It is closer to:

**a distributed operating fabric in which subject-local quorums continuously form, dissolve, and re-form around demand, while RaptorQ-coded capsules make state portable enough that no permanent broker tier is required.**

### 9. Research-Informed Recommendation: Start With A Sharded Leadered Control Capsule

The brokerless section now needs an explicit algorithm choice, not just the phrase "epoch-fenced append sequence or certificate".

My current recommendation is:

- `ControlCapsuleV1` should be a per-cell, leadered, replicated control log with a single sequencer lease per cell epoch
- `ControlCapsuleV1` should be framed explicitly as an authenticated crash-fault design; Byzantine quorum semantics, equivocation-proofing, and hostile-steward tolerance are later lanes, not accidental implications of V1 language
- that should be understood as a logical per-cell control stream, not necessarily a dedicated physical consensus group per raw subject; multiple cold or low-rate cells should pack onto shared control shards under explicit cardinality limits
- the baseline replication model should be Raft-like, because joint consensus keeps membership change in-band with the control log and allows the system to keep serving requests during reconfiguration
- per-cell sequencing authority should be explicit: one steward owns the append lease for the current epoch, and every authoritative append, cursor-fence change, or reply-right transfer is either emitted by that sequencer or rejected as stale
- reconfiguration should be represented as an explicit joint old/new stewardship entry plus a new fenced sequencer lease, not as ad hoc ownership gossip

The research-informed reason for starting there is straightforward:

- Raft's joint consensus keeps reconfiguration understandable and overlap-safe
- Flexible Paxos shows that quorum geometry can be tuned without requiring all quorums to be simple majorities, which matters later for WAN deployment
- WPaxos shows that object- or cell-level ownership can move toward access locality without abandoning per-object sequencing discipline
- EPaxos Revisited is a warning that leaderless dependency tracking looks attractive on paper but can produce much worse tail latency and strong workload sensitivity under conflict

So the design choice should be:

- **default path**: leadered per-cell sequencing with fenced epochs and joint-consensus reconfiguration
- **optimization path**: introduce flexible quorum geometry or WPaxos-style ownership relocation only after the basic capsule semantics are proven and measured
- **specialized path**: consider a lighter lease-quorum protocol only for restricted cell classes that have one-writer or commutative semantics, low reconfiguration frequency, and no complex consumer-fence or reply-authority transfer rules

That gives the proposal an honest control story:

- the broker tier disappears
- the control plane does not disappear
- instead, control becomes sharded, explicit, and cell-local

Compiled runtime artifacts for this choice:

- `ControlEpoch`
- `SequencerLease`
- `AppendCertificate`
- `JointConfigEntry`
- `FenceToken`
- `CursorAuthorityLease` with `CursorPartitionLease` as the delegated-cursor specialization

Proof obligations for `ControlCapsuleV1`:

- at most one live sequencer lease per cell epoch
- no authoritative append from a stale steward after fencing
- no configuration transition in which old and new stewardship sets can each decide independently
- every committed append has a unique `(cell_id, epoch, sequence)` identity
- consumer-control authority transfers must be fenced before the old holder can issue more ack or cursor decisions
- every ack, nack, or redelivery decision must reference an attempt-scoped certificate bound to the current cell epoch and the current cursor-authority lease, with delegated-cursor variants specializing that to a cursor-partition lease
- late delivery responses from pre-failover or pre-transfer attempts must reduce to deterministic stale reject or idempotent no-op, never ambiguous dual resolution

### 10. Research-Informed Recommendation: Use A Two-Level Key Hierarchy

The document now names witness-safe envelope keying, but it still needs a concrete design for derivation, rotation, and revocation.

The research-informed recommendation is:

- do **not** run a full concurrent CGKA independently for every hot subject cell
- use a small-group, steward-pool control key layer with MLS/TreeKEM-style forward secrecy, post-compromise security, and authenticated group-state discipline
- derive per-cell and per-segment keys from that steward-pool epoch state instead of treating each subject cell as a fresh end-to-end messaging group

The reason is that MLS/TreeKEM and TreeSync give a strong foundation for authenticated group state, forward secrecy, and post-compromise security, but more recent CGKA work such as DeCAF and fork-resilient CGKA results shows that decentralized concurrent rekey remains subtle and expensive. That makes per-cell full CGKA a poor default for a high-churn infrastructure control plane.

Concretely:

- maintain a steward-pool epoch secret `K_pool_epoch` for the steward-eligible roster in a trust domain or placement pool
- derive an intermediate placement-subgroup epoch secret `K_subgroup_epoch = HKDF(K_pool_epoch, "subgroup-epoch" || placement_pool_id || subgroup_epoch || subgroup_roster_hash)`
- derive each cell root as `K_cell_root = HKDF(K_subgroup_epoch, "cell-root" || cell_id || cell_epoch || roster_hash || config_epoch_hash || cell_rekey_generation)`
- derive capability-separated subkeys from `K_cell_root`, for example:
  - `K_segment`
  - `K_symbol_wrap`
  - `K_symbol_auth`
  - `K_reply_space`
  - `K_metadata_blind`
  - `K_witness_wrap`
- witnesses never receive `K_cell_root`; they receive only ciphertext symbols, HPKE-wrapped segment material, or narrowly scoped witness tokens
- non-steward read serving should likewise require bounded read-delegation tickets or wrapped segment keys with explicit epoch scope, cacheability rules, and revocation semantics; "any authorized peer can serve" is not a safe V1 default

Rotation and revocation semantics should be explicit:

- **epoch rotation**: triggered by steward membership change, compromise suspicion, planned PCS refresh, or control-capsule rebind
- **subgroup rotation**: steward-pool churn should first rotate only the affected placement subgroup, not every unrelated cell in the trust domain
- **segment rotation**: use key-regression or generation-tagged derivation so future segments become inaccessible after revocation without requiring immediate rewrite of the whole history
- **witness revocation**: revoke by advancing the cell epoch and witness-wrap context; live or hot segments are rewrapped eagerly, while cold sealed segments can be lazily rewrapped or rewritten on touch, migration, or expiry
- **retroactive revocation honesty**: if old ciphertext and old keys were already exposed, revocation protects future epochs and future generations immediately, but it does not magically unread old ciphertext without rewrite or expiry
- **restore scrubbing**: any lab or staging restore must mint fresh cell IDs, epoch bindings, leases, reply spaces, and key derivation context before it can communicate with real peers

There is also a useful cold-path extension here:

- for long-lived witnesses or archival repair lanes, the system can optionally use proof-of-retrievability or succinct erasure-coding proofs so a witness can prove it still stores fragments consistent with a committed capsule without replaying the whole object

That should stay off the hot publish path, but it is a strong fit for:

- cold durability audits
- migration safety checks
- delayed rebalance verification
- hostile or weakly trusted witness pools

In practical terms, the scheme looks like:

- MLS-like machinery for steward-group secrecy and authenticated roster state
- HKDF-separated per-cell and per-segment derived keys for operational efficiency
- HPKE-wrapped witness access for narrow disclosure
- optional retrievability proofs for cold-path audit, not steady-state publish latency

## Design Guardrails

This proposal only works if Asupersync avoids importing NATS's implementation constraints.

Do not copy:

- goroutine-per-connection as the core mental model
- ambient authority over time, storage, or network
- protocol-first internals
- lock-heavy shared mutability as the organizing principle
- casual semantics around cancellation and partial progress

Do preserve:

- disciplined bring-up order
- subject-first API design
- layered routing caches
- explicit topology roles
- stream capture through the same substrate as ordinary messaging
- system advisories as native fabric messages
- the operational simplicity of NATS's public mental model

Stay honest about the soundness frontier:

- guarantees hold inside Asupersync's capability boundary, not for arbitrary unmanaged external side effects
- convergence-to-quiescence arguments assume the runtime's usual cooperative conditions: checkpoints, bounded masking, and fair progress
- local region quiescence does not automatically imply a globally consistent distributed cut; cross-node quiescence still needs an explicit cut, lease, or snapshot protocol
- replayable snapshots and counterfactual runs must model remote peers, clocks, and external effects explicitly rather than pretending they are free
- branch-addressable or replayed views must keep unmanaged external side effects fenced or explicitly modeled; do not imply free time travel across the whole world
- branch and cut indexes must stay retention- and access-policy scoped; do not imply that every execution becomes a permanent universally visible artifact
- distributed execution should continue to use idempotency plus leases at the boundary; do not promise magical global exactly-once semantics
- evidence and decision recording should be policy-driven and selective on hot paths, not sprayed everywhere by default
- do not let reasoning-plane evidence, branch, or query machinery leak into the default packet path; any elevation into the authority or reasoning planes must be explicit and attributable
- keep the service-class vocabulary small, named, and inspectable; do not let every team invent one-off semantics that fragment the model
- subject routing and fanout need explicit admission control and backpressure budgets; do not assume the fabric can stay simple if amplification is left implicit
- do not make in-band control subjects the only recovery path; preserve a minimal recovery channel even when the main fabric is unhealthy
- causality-native views do not eliminate linear control streams; they sit above explicit dependency metadata and bounded frontier summaries
- do not force every peer to decode or store everything; the whole point of the data capsule split is to let recoverability replace naive full replication
- keep control capsules small enough that stewardship changes remain cheap; if they accrete too much policy or telemetry, the system will secretly reinvent a central metadata plane
- certified cut and branch indexes need explicit retention, compaction, and materialization policy; do not imply infinite persisted reality history
- do not let high-fanout consumer state collapse into one monolithic control capsule; shard or hierarchy is required once cursor cardinality gets large
- do not pretend `ControlCapsuleV1` handles arbitrary hot-cell fanout before delegated cursor partitions and checkpointing exist; bounded scope first, then scale claims
- keep the publish ack contract honest: it should certify a chosen recoverability class, not imply impossible guarantees about arbitrary downstream consumer side effects
- bind repair symbols to epoch and retention generation so witnesses cannot resurrect expired or superseded data after a cutover
- require authenticated membership and capability enforcement for discovery and stewardship negotiation; otherwise the brokerless design degenerates into an easy Sybil and data-poisoning target
- do not assume all participants can or should steward; steward eligibility is a capability and policy question, not a universal right
- do not synchronously RaptorQ-encode every tiny publish on the hot path; use direct or batched segment-window fast paths where appropriate, then seal into coded capsules
- do not run a full concurrent CGKA per hot subject cell by default; put strong group key agreement at the steward-pool layer and derive cell-local keys underneath it
- do not let CRDTs absorb authoritative state; they belong only on explicitly non-authoritative, mergeable control surfaces
- do not claim Byzantine fault tolerance from the Raft-based `ControlCapsuleV1`; BFT is a named future direction, not a V1 property
- do not claim differential privacy eliminates traffic analysis; it bounds information leakage per disclosure, not against unlimited observations
- do not claim session type checking covers arbitrary cross-language or unmanaged participants; the static layer covers in-process Rust; the dynamic layer covers the rest
- do not claim reactive synthesis produces correct business logic; it produces correct protocol scaffolding; the business logic filling is still the developer's responsibility
- do not claim speculative subject-cell execution is universally beneficial; it is for low-conflict classes with explicit rollback semantics and kill switches
- keep heavy cryptographic proof systems off the default path; if later used, they should live only on selected hard-boundary compliance lanes
- do not promise hot-path homomorphic transforms; encrypted payloads plus blinded metadata are already enough for the practical near-term plan
- the progressive-disclosure model fails if Layer 0 or Layer 1 become footguns that silently require Layer 3 or Layer 4 to be safe
- keep randomized or irreversible transforms out of authority-bearing import/export edges; they do not mix with replay, reversibility, or reply-space proofs

## Threat Model, Fault Model, And Economic Envelope

To make the proposal sounder and more actionable, it should explicitly state the fault and trust assumptions for each layer.

### In scope and designed to resist

- **crash-fault participants**: stewards or relays that fail silently without Byzantine behavior
- **honest-but-curious stewards and witnesses**: participants that follow protocol but attempt to infer tenant or traffic information
- **stale or slow participants**: entities issuing appends, acks, or cursor decisions from past epochs
- **unauthorized namespace access**: clients attempting to use subjects or reply spaces without the right capabilities
- **replay attacks**: old messages, tokens, or certificates replayed across epochs
- **Sybil pressure on brokerless admission**: unauthorized or weakly trusted nodes attempting to bias placement or stewardship

### Partially addressed but not eliminated

- **network-level traffic analysis**: bounded with privacy-budgeted summaries and blinded metadata, but not eliminated
- **colluding protocol-compliant stewards**: bounded by key narrowing and trust scoping, but not eliminated if a full cell quorum colludes

### Explicitly out of scope for V1

- **Byzantine-fault stewards**: `ControlCapsuleV1` is not a BFT design
- **microarchitectural side channels on cryptographic operations**
- **legal coercion of steward operators**
- **full physical resource isolation between tenants on shared hardware**

Every major feature should also publish a cost vector:

- steady-state latency
- tail latency
- storage amplification
- control-plane amplification
- CPU and crypto cost
- evidence bytes
- restore and handoff time

Implementation risks worth naming now:

- hot-path latency explosion -> keep authority-plane coordination narrow and class-gated
- hidden global metadata plane -> use CRDT summaries, delegated cursor partitions, and strict control-capsule budgets
- developer overwhelm -> progressive disclosure with no-footgun guarantees between layers
- class proliferation -> small named service-class vocabulary
- privacy/reporting distortion -> differential privacy only on exported summaries, never on authoritative internal control state
- speculative fast-path misfire -> make it opt-in, low-conflict only, and kill-switchable per class or per cell

## Suggested Asupersync Module Shape

I would treat this as a flagship subsystem and give it a coherent home.

This should coexist with the current `src/messaging/nats.rs` and `src/messaging/jetstream.rs` surfaces rather than pretending they do not exist. The native subject-fabric work is a new internal lane and possible future default, while the existing NATS/JetStream adapters remain edge integrations and compatibility surfaces.

Suggested lane:

- `src/messaging/ir.rs`
- `src/messaging/compiler.rs`
- `src/messaging/class.rs`
- `src/messaging/subject.rs`
- `src/messaging/morphism.rs`
- `src/messaging/capability/`
- `src/messaging/session/`
- `src/messaging/fabric.rs`
- `src/messaging/service.rs`
- `src/messaging/stream.rs`
- `src/messaging/consumer.rs`
- `src/messaging/control.rs`
- `src/messaging/policy.rs`
- `src/messaging/privacy.rs`
- `src/messaging/cut.rs`
- `src/messaging/explain.rs`
- `src/messaging/federation.rs`
- `src/messaging/snapshot.rs`
- `src/messaging/protocol/` only if compatibility adapters are later pursued

Likely reuse points:

- actors and GenServers for region-owned loops
- `src/channel/session.rs` for tracked reserve/commit behavior
- `src/obligation/ledger.rs` for reply and ack obligations
- `src/distributed/*` for bridge, snapshot, assignment, and recovery
- `src/lab/*` plus oracles for deterministic multi-node hardening
- FrankenSuite crates for decision and evidence surfaces
- Rust ownership, `#[must_use]`, and typestate patterns as the zero-cost static capability and session layers for in-process paths

## Developer Ergonomics And Progressive Disclosure

The proposal only becomes strategically strong if a developer can start at a NATS-like surface and climb toward stronger semantics without rewriting their whole mental model.

The right disclosure ladder is:

**Layer 0: NATS-small**

At-most-once publish/subscribe/request/reply with packet-plane semantics and no hidden durable tax.

```rust
let client = FabricClient::connect("fabric://localhost").await?;
client.publish("orders.us.new", payload).await?;
let mut sub = client.subscribe("orders.us.*").await?;
```

**Layer 1: Durable and obligation-aware**

```rust
let ack = client
    .publish_durable("orders.us.new", payload, DeliveryClass::DurableOrdered)
    .await?;
// ack now has a declared semantic meaning, not just "something happened"
```

**Layer 2: Capability-checked subjects**

```rust
let permit = cx.acquire_publish_permit::<OrderSubject>().await?;
client.publish_with_permit(permit, payload).await?;
```

**Layer 3: Session-typed conversations**

```rust
let session = client.open_session::<OrderProtocol>("orders.service.v1").await?;
let (reply, session) = session.request(cx, OrderRequest { /* ... */ }).await?;
```

**Layer 4: Full fabric control**

Platform engineers and operators work here:

- morphism registration
- cut and branch policy
- evidence and replay policy
- control-capsule and mobility tuning
- protocol synthesis
- privacy and export policy

The key ergonomic rule is that every stronger layer must be opt-in by calling a stronger API, not by silently repairing a footgun in a weaker one. Teams should be able to stay at Layer 0 or Layer 1 indefinitely when those semantics are actually the right fit.

## Success Criteria And Kill Criteria

A proposal this ambitious should be falsifiable.

Success criteria:

- ordinary uncaptured `EphemeralInteractive` publish and request/reply stay on the packet plane with no reasoning-plane tax
- any `Accepted`, `Committed`, `Recoverable`, `Served`, or `Received` ack can be rendered as an exact statement of what crossed which semantic boundary
- bounded exhaustive or DPOR-guided lab runs show no leaked obligations, no dual live sequencer leases, no illegal session transitions, and no ambiguous stale-ack outcomes
- mobility cutovers and cursor transfers always produce a human-readable cut certificate describing what was preserved, transferred, aborted, or fenced
- developers can remain productive at Layer 0 or Layer 1 without secretly needing Layer 3 or Layer 4 to stay safe for those chosen semantics
- privacy-budgeted exports and quantitative obligation contracts can be explained and audited rather than waved away as heuristics

Kill criteria:

- if common-case publish requires authority-plane or reasoning-plane coordination
- if control capsules accrete into a hidden global metadata plane
- if service classes proliferate until no one can reason about them
- if evidence hooks cannot be sampled, budgeted, or disabled cleanly
- if the system cannot answer "what is still owed?" or "what did this ack actually certify?" deterministically
- if the progressive-disclosure ladder collapses because lower layers are only safe when higher layers are adopted
- if privacy or proof features force hot-path cost onto workloads that did not opt into them

## Phased Delivery Plan

The phases below are one continuous plan. The compiler layer, service classes, and plane separation are first-class from the start; subject cells, control capsules, delegated cursor partitions, and cell-scoped keying are later consequences, not unrelated side tracks.

### Phase 0: Fabric IR, service classes, and the semantic fast path

Deliver:

- `FabricIR` and compiler pipeline
- explicit packet-plane / authority-plane / reasoning-plane split
- named service classes and semantic SLO tuples
- ack taxonomy and explain-plan rendering
- initial capability-token schema for in-process subject permits
- a cost model for when work is allowed to escalate out of the packet plane

Exit criteria:

- every publish, reply, and delivery path can explain which planes it touched and why
- uncaptured pub/sub and request/reply remain packet-plane only
- compiled artifacts can be inspected, diffed, and replay-audited before deployment
- operators can query "what is this service class buying me?" without reading implementation code

### Phase 1: Subject Kernel

Deliver:

- wildcard subject fabric with layered caches
- basic mergeable interest summaries with visible invalidation epochs
- canonical subject normalization, transform-before-placement rules, overlap rejection, reply-space compaction, and bounded cell-cardinality policy so `SubjectCell` ownership is deterministic from the start
- capability-scoped subject registration
- authenticated membership and admission handshake for the fabric trust domain
- interest events with visible invalidation epochs
- basic request/reply over subjects
- control-plane subjects for local fabric state
- first mechanized models for subject registration and interest propagation, backed by replay oracles

### Phase 2: Morphisms And Service Contracts

Deliver:

- import/export morphisms
- reversibility validation where required
- cycle detection across trust graph edges
- certificate-carrying request/reply
- initial protocol-carrying subject definitions for request/reply, streaming reply, and cutover or compensation workflows
- initial global session-type registry with projection to local two-party types
- duality checking at import/export registration time for typed protocols
- owned subject capability token types such as `PublishPermit<S>` and `SubscribeToken<S>` for in-process paths
- service latency and sharing policy as first-class metadata
- contract-carrying service definitions that separate provider-declared guarantees from bounded caller-selectable classes for cancellation, durability, compensation, mobility, budget or cleanup urgency semantics, and evidence or audit requirements
- deterministic-core transform algebra for authority-bearing edges, with randomized transforms isolated to one-way non-authoritative fanout
- schema support for later privacy and hard-boundary proof policies, even if the proof systems themselves come later

### Phase 3: Quiescent Streams And Consumers

Deliver:

- explicit service-class split between ordinary ephemeral pub/sub and durable stream or capsule publish
- subject-captured durable streams
- uncaptured subject traffic remains on a lighter ephemeral path rather than silently inheriting durable-stream costs
- dependency metadata and bounded frontier summaries for selected workloads that opt into causality-preserving derived views
- initial ordering modes so selected workloads can expose causality-preserving derived views over explicitly dependency-tracked events instead of always forcing one merged total order
- obligation-backed ack and redelivery
- explicit delivery-attempt identity and stale-ack handling for consumers, even before the brokerless cell-specific certificate extensions
- pull and push consumers
- pause, heartbeat, flow control, and pull-consumer priority-group policy
- snapshot and restore of stream plus consumer state
- explicit authority-scrubbing and epoch-rebinding on restore

### Phase 4: Federation Roles

Deliver:

- leaf, gateway, and replication roles
- interest propagation and bounded catch-up
- control-plane advisories over subjects
- deterministic failure and drain modeling in lab runtime
- exported observability and privacy-policy plumbing for cross-domain summaries

### Phase 5: Subject Cells And Control Capsules

Deliver:

- `ControlCapsuleV1` with explicit append sequencing, fencing, reconfiguration proofs, and concrete artifacts such as sequencer lease, append certificate, joint-config entry, and fence token
- logical per-cell control streams packed onto shared control shards under explicit cardinality limits
- subject-cell coded data plane for steward-owned rebalance and cold catch-up
- delta-CRDT non-authoritative control surfaces for interest summaries, coarse cursor checkpoints, delegated-partition aggregates, and selected membership or load views
- attempt-scoped ack certificates and deterministic stale-ack handling across failover and cursor transfer, with relay-change extensions added once leased relay serving exists
- initial bounded-fanout / bounded-ack-rate operating envelope for subject-cell coordination
- first mechanized models for fencing, cursor transfer, and reconfiguration safety

### Phase 6: Cursor Scaling And Recoverable Mobility

Deliver:

- delegated cursor partitions and batched checkpoint protocol so high-fanout consumer churn stays off the main control capsule
- rebalance and stewardship handoff over recoverable capsules
- sealed-segment mobility and coded repair flows without leader-streaming the whole history
- speculative subject-cell execution with tentative obligations for low-conflict classes, plus rollback-race coverage in replay harnesses
- quiescent mobility and recoverable service capsules for selected fabric-hosted services, read models, and actor regions, with authority scrubbing and epoch rebinding before restored instances rejoin live peers

### Phase 7: Keying, Evidence, And Counterfactual Replay

Deliver:

- subject-cell envelope keying and two-level key hierarchy
- leased relay and read-delegation tickets with revocation semantics
- witness key lifecycle, revocation, and optional retrievability-audit pipeline
- read-delegation and leased relay serving for subject-cell consumers
- witness lanes and wider repair placement once key wrapping and revocation semantics exist
- decision/evidence hooks for important routing and retry choices
- protocol interference classes and commutativity certificates so selected workloads can shard execution lanes by semantic independence above canonical subject-cell ownership, not just by textual subject partition
- budget-carrying routing and obligation-aware degradation policy so overload and failover protect the most semantically expensive work first
- replay-constrained adaptive control loops for retry law, repair depth, and routing preference, each recorded through the decision/evidence lane
- first distributed-supervision compilation path for selected fabric-hosted topologies, lowering remote monitors, leases, and cutover contracts into subject or control artifacts
- initial intent-to-policy compilation for a narrow operator surface such as latency, sovereignty, and recoverability envelopes
- forkable stream snapshots
- branch-addressable stream and service views for selected capability-gated canary, audit, operator, and client workflows derived from certified cuts, with read-only or explicitly sandboxed mutation as the default for client-facing lanes
- policy-scoped, retention-governed, capability-gated certified cut lattice and compacted reality index for selected replay, restore, and explanation workflows
- replay harnesses for topology and delivery incidents
- dedicated oracles for:
  - no lost committed publish
  - no leaked reply obligations
  - no leaked ack obligations
  - quiescent shutdown
  - bounded redelivery
  - control-plane convergence
  - CRDT convergence on non-authoritative control surfaces

### Phase 8: Session types, synthesis, privacy, and quantitative contracts

Deliver:

- multiparty session types (MPST) for selected multi-party workflows, with projection to local role types
- a session-automaton co-monitor in the lab runtime that checks runtime traces against registered protocol contracts
- reactive synthesis of handler skeletons, obligation wiring, timeout branches, compensation hooks, and compatible adapters from selected protocol contracts
- cross-version protocol compatibility checking for registered services
- privacy-budgeted metadata summaries for exported telemetry and cross-domain observability
- optional hard-boundary attestation or private-compliance proof lanes for selected morphisms where the trust boundary justifies the cost
- quantitative obligation contracts `(p, b)` and e-process or conformal monitors for drift from the promised envelope
- progressive-disclosure regression tests proving that Layer 0 through Layer 3 remain usable without hidden footguns
- threat-model review against the implemented capability, protocol, and privacy surfaces

### Phase 9: NATS Edge Compatibility

Deliver:

- optional NATS text-protocol ingress and egress
- protocol adapters at the edge only
- no degradation of internal semantics to match legacy wire expectations

## Beachhead Product Surface

The first winning product should not be "general-purpose broker replacement." The strongest wedge is environments that simultaneously need:

- cross-tenant namespace policy
- durable partial progress
- intermittent connectivity or mobility-heavy topology
- post-incident explanation or replay

That points to especially strong early surfaces:

- sovereignty-sensitive multi-tenant control planes
- edge and field fabrics that sync opportunistically and need warm restore
- workflow and saga heavy systems whose hardest question is "what is still owed?"
- high-trust internal platforms that want incident replay and cut-certified canaries
- browser, edge, and autonomous worker systems that need first-class participation rather than second-class gateway semantics

That wedge makes the weirdest parts of the proposal pay rent early.

## Why This Is Hard To Copy

The moat is the composition:

- subject-first APIs
- static capability tokens
- dynamic `Cx` and obligation semantics
- typed protocol contracts
- replay and DPOR exploration
- evidence-native control decisions
- recoverable mobility and certified cuts

Many competitors can imitate one layer:

- ACLs
- durable streams
- replay harnesses
- typed client libraries

What is difficult to copy is the compounding effect of building all of those on the same semantic kernel. That is what turns the proposal from "better broker features" into a new systems substrate.

## Why This Could Be More Important Than NATS Itself

NATS proved that messaging can be operationally simple without becoming toy infrastructure.

Asupersync can plausibly prove a stronger claim:

**distributed messaging can be operationally simple, semantically explicit, capability-safe, and replayable.**

Most event systems still force ugly tradeoffs:

- speed or correctness
- flexibility or legibility
- distributed power or debuggability
- multi-tenant control or ergonomic APIs

This proposal tries to break those tradeoffs by using NATS's best simplifications and rebuilding them on top of Asupersync's stronger core invariants.

If executed well, the end state is not "Asupersync plus JetStream features."

It is:

**a distributed subject runtime where the Asupersync-hosted portions of routing, trust policy, delivery, persistence, and control-plane behavior compose around one semantic kernel and can be interrogated after the fact with actual evidence.**

## The Inversion: What Asupersync Enables More Naturally Than NATS

The analysis above mostly asks: what should Asupersync steal from NATS?

The deeper inversion is: what becomes possible only because Asupersync starts from richer semantic primitives than NATS has available at all?

NATS starts from goroutines, locks, subscriptions, protocol handlers, and operational discipline. That is enough to build an excellent system, but it is not enough to make concurrency itself algebraically structured and globally checkable.

Asupersync starts from a different substrate:

- region-owned task trees
- cancel/drain/finalize as an actual protocol
- linear obligations for permits, acks, replies, leases, and names
- explicit capability flow through `Cx`
- deterministic lab scheduling, DPOR, and replay
- spec-level formal operational semantics and mechanization scaffolding
- algebraic law sheets for combinators and rewrite policies

That changes the ceiling of the design space.

### 1. Quiescence Can Become A Theorem-Like Property

NATS can drain. Asupersync has a clearer path to theorem-like guarantees about stronger properties.

Inside Asupersync's capability boundary, and under the runtime's standard cooperative assumptions, every task is region-owned and every region closes to quiescence. That lets us define and enforce system cuts with semantic meaning:

- "all descendants have completed"
- "all finalizers have run"
- "all reply/ack/lease/name obligations have resolved"
- "this subtree is safe to snapshot, migrate, restart, or retire"

This supports much more than better shutdown behavior. It is the foundation for:

- semantically valid hot cutovers
- region-safe stream handoff
- replayable failover boundaries
- deterministic partial-system restart
- auditable repair protocols

NATS can approximate these with careful implementation. Asupersync can make them much more structural because its runtime starts from stronger ownership and cancellation semantics.

### 2. Messaging Plans Can Be Algebraically Rewritten

Asupersync's combinators come with explicit laws. That means a messaging workflow can be treated as a plan that is optimized subject to semantic side conditions.

Examples:

- rewrite nested timeouts into tighter canonical forms
- deduplicate shared work across race branches
- normalize join/race/quorum structures
- optimize drain and retry plans while preserving loser-drain and quiescence invariants

This matters because many message fabrics are really execution planners in disguise.

NATS can implement clever fast paths, but Asupersync has a much clearer path to certified whole-plan rewrites because it exposes a more explicit concurrency algebra over the system.

### 3. Delivery Can Be Obligation-Tracked Instead Of Only Counter-Based

NATS consumer state is operationally strong, but it is still mostly counters and inferred protocol meaning.

Asupersync can do something stronger:

- a delivered item creates a live obligation
- ack commits it
- nack/timeout/failure aborts it
- redelivery is derived from unresolved obligation state
- reply channels, registry names, and leases fit the same semantic pattern

That yields a uniform notion of "work still morally in flight."

This is much more powerful than a messaging feature. It creates a runtime-wide linearity discipline for distributed work accounting. NATS can track many of these concepts separately, but Asupersync has a more natural path to unifying them at the substrate level.

### 4. Control Plane Decisions Can Carry Actual Evidence

NATS can emit advisories. Asupersync can turn material control-plane decisions into auditable decision records.

Examples:

- why a redelivery policy changed
- why a gateway path was preferred
- why a lease transfer was accepted
- why a failover plan beat a competing plan
- why a retry moved from backoff to dead-letter

Because Asupersync already has FrankenSuite evidence and decision machinery, these choices can be recorded with explicit assumptions, posterior/confidence state where relevant, and replay linkage.

That makes the fabric observable and, to a meaningful extent, self-explaining.

### 5. Distributed Messaging Can Be Studied By Trace Algebra, Not Just Logs

NATS can record what happened. Asupersync can quotient executions by independence and reason about equivalence classes of schedules.

That is a radically different capability.

It means we can:

- explore one representative per genuinely distinct concurrency behavior
- canonicalize equivalent executions
- compare failures modulo irrelevant interleaving noise
- prioritize topologically interesting schedules
- attach proofs and counterexamples to trace classes instead of raw logs

This moves debugging from "log archaeology" toward something closer to concurrency geometry.

NATS has a much harder incremental path there because its runtime does not own enough of the execution semantics to define those equivalence classes precisely.

### 6. Federation Can Be Capability Algebra, Not Just Routing Policy

NATS accounts, imports, and exports are already one of its deepest ideas.

Asupersync can push that further because authority is already explicit in the runtime.

That allows federation edges to be modeled as:

- capability-bearing namespace morphisms
- reversible or non-reversible transforms with proof obligations
- response-space restrictions with linear reply guarantees
- metadata-sharing policies that compose with authority boundaries
- resource budgets that compose algebraically across boundaries

This is qualitatively stronger than service-mesh policy or broker ACLs.

It is a form of programmable distributed authority that still admits precise reasoning.

### 7. Supervision Can Become A Compiler Target

Spork hints at this already: supervisors, registries, monitors, links, and GenServer-style loops are not built on "best effort plus conventions." They inherit structural guarantees from the kernel.

That opens a path that is much more natural in Asupersync:

- compile high-level distributed applications into supervision graphs
- derive restart and drainage obligations from topology
- validate ordering and tie-break rules up front
- synthesize control-plane subjects and failure contracts from the supervision structure

More concretely, the runtime can eventually compile distributed operational structure rather than just host it.

NATS is a platform you program on. Asupersync can become a platform that also compiles concurrency architecture.

### 8. Counterfactual Operations Become A First-Class Workflow

Once snapshots, obligations, and traces are semantically meaningful, we can ask questions that ordinary messaging systems struggle to answer rigorously:

- what would this outage have looked like under a different retry law?
- what if this region had drained under a tighter cleanup budget?
- what if this gateway policy had preferred lower fanout over lower latency?
- what if this consumer had used pinned-client handoff instead of overflow policy?

This is counterfactual execution over semantically faithful in-boundary state plus explicit models for the external world the runtime does not own. It is not loose simulation.

This could become one of the most differentiated capabilities in the whole system: operations as replayable, auditable decision science rather than reactive intuition.

### 9. The Strategic Shift

NATS simplifies messaging by hiding a lot of concurrency complexity behind disciplined engineering.

Asupersync can simplify messaging by making the concurrency structure itself lawful enough that large classes of mistakes become unrepresentable, algebraically checkable, or replayably diagnosable.

That is broader than "better broker semantics."

The longer-term outcome would be:

**a concurrency-native systems substrate where messaging, supervision, federation, storage, and control-plane logic can be built from and constrained by the same semantic kernel across the portions the runtime actually hosts.**

## Recommendation

The highest-value direction is a flagship internal subsystem, but it should be described more crisply:

**build a semantic subject fabric compiler with a NATS-small packet plane, an obligation-backed authority plane, and a replay/evidence reasoning plane.**

Concretely, the first internal target should be:

**a capability-compiled subject fabric that supports import/export morphisms, contract-carrying services, session-typed protocol contracts, semantic service classes, quiescent streams, policy-driven consumers, typed capabilities, and certified cuts. Only after the fast path and compiler layer are proven should it grow into subject cells, mergeable non-authoritative control surfaces, recoverable mobility, branchable replay, privacy-budgeted exports, quantitative obligation contracts, and intent-compiled operations.**

That is bold enough to matter, but still grounded in concrete mechanisms that NATS already proved are useful:

- subject-first APIs
- explicit trust graph edges
- transform-constrained routing
- advisory-native control plane
- stream plus consumer operational model
- simple, role-specific topology shapes

If this proposal is executed fully, the strategic win is broader than "better messaging." The same fabric starts to absorb distributed workflow, checked protocol kernels, behavioral service contracts, supervision, live mobility, semantic execution-lane sharding, capability-gated branch-selectable reality, causality-aware views, obligation-aware degradation, and fabric-wide consistency checking.

Asupersync's job is to take NATS's best ideas, finish the thought, compile them into inspectable runtime artifacts, and then feed that substrate back into the rest of the runtime until large classes of distributed systems machinery stop being ad hoc. The correctness argument for a distributed system should then be able to point simultaneously to the Rust type checker, the session contract, the obligation ledger, the control capsule, and the replay harness, rather than only to documentation, code review, and incident history.
