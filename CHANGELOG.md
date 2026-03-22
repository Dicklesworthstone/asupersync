# Changelog

All notable changes to [Asupersync](https://github.com/Dicklesworthstone/asupersync) are documented here.

Asupersync is a spec-first, cancel-correct, capability-secure async runtime for Rust.

**Format notes:**

- Versions with a **Release** badge have published GitHub Releases. Plain git tags are milestone markers without release artifacts.
- Commit links point to representative commits, not exhaustive lists.
- Organized by landed capabilities within each version, not by diff order.

---

## [Unreleased]

> 1 commit since v0.2.9

- Refresh RaptorQ wavefront pipeline benchmark results ([`0f3f7e4`](https://github.com/Dicklesworthstone/asupersync/commit/0f3f7e4f))

---

## [v0.2.9](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.2.9) -- 2026-03-21 (Release)

> 461 commits since v0.2.8 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.8...v0.2.9)

### FABRIC Messaging Engine

The largest area of post-v0.2.8 development: a brokerless subject-oriented messaging system with session typing, obligation-backed delivery, and evidence-native decision planes.

- **Session projection engine** with duality verification for two-party protocols ([`3614ffd`](https://github.com/Dicklesworthstone/asupersync/commit/3614ffdb))
- **Semantic execution lane planner** for SubjectCell conversation families ([`85cebd4`](https://github.com/Dicklesworthstone/asupersync/commit/85cebd4f))
- **Deterministic protocol-scaffolding synthesis** for FABRIC sessions ([`0ff5530`](https://github.com/Dicklesworthstone/asupersync/commit/0ff55307))
- **SafetyEnvelope** for adaptive reliability tuning with runtime health evaluator ([`daf9c57`](https://github.com/Dicklesworthstone/asupersync/commit/daf9c572))
- **Fabric discovery sessions**, operator intent compiler, recoverable service capsules, IR monotone normalization ([`8fe3bb2`](https://github.com/Dicklesworthstone/asupersync/commit/8fe3bb25))
- **Full FABRIC IR compilation** with artifact registry, service/morphism/protocol/consumer compilation ([`670d072`](https://github.com/Dicklesworthstone/asupersync/commit/670d0723))
- **Adaptive consumer kernel** with overflow policy, decision audit, and pinned-client delivery ([`9f1d79b`](https://github.com/Dicklesworthstone/asupersync/commit/9f1d79b0))
- **Delta-CRDT metadata layer** for non-authoritative control surfaces ([`2d4561a`](https://github.com/Dicklesworthstone/asupersync/commit/2d4561af))
- **Bounded control-plane artifacts** for brokerless subject fabric ([`31d828e`](https://github.com/Dicklesworthstone/asupersync/commit/31d828e7))
- **Evidence-native data-plane decisions** and operator explain-plan expansion ([`920b531`](https://github.com/Dicklesworthstone/asupersync/commit/920b5315))
- **Delegated cursor partitions**, federation bridge runtime, multi-tenant namespace kernel ([`b69c261`](https://github.com/Dicklesworthstone/asupersync/commit/b69c2613))
- Certificate-carrying request/reply protocol with chunked reply obligations ([`a0cd1ad`](https://github.com/Dicklesworthstone/asupersync/commit/a0cd1ad6))
- Branch-addressable reality framework for cut-certified mobility ([`45859b0`](https://github.com/Dicklesworthstone/asupersync/commit/45859b00))
- Privacy-preserving metadata export with blinding and differential-privacy noise ([`c5878b6`](https://github.com/Dicklesworthstone/asupersync/commit/c5878b63))
- Obligation-backed consumer delivery with redelivery, dead-letter, and stats ([`b93be30`](https://github.com/Dicklesworthstone/asupersync/commit/b93be307))
- Shared fabric state registry with HMAC-SHA256 cell key hierarchy ([`2112b1f`](https://github.com/Dicklesworthstone/asupersync/commit/2112b1f6))
- Saga/Workflow obligation types re-exported from service module ([`017ba9e`](https://github.com/Dicklesworthstone/asupersync/commit/017ba9ef))
- Repair symbol binding, rebalance cut certification, cell epoch rebind ([`566728a`](https://github.com/Dicklesworthstone/asupersync/commit/566728a5))
- Semantic degradation policy for FABRIC lane overload decisions ([`393698e`](https://github.com/Dicklesworthstone/asupersync/commit/393698e1))
- Consistency topology and admission surface for FABRIC explain-plan ([`81f77c6`](https://github.com/Dicklesworthstone/asupersync/commit/81f77c6b))
- FABRIC control plane with system subjects and FrankenSuite advisories ([`848be23`](https://github.com/Dicklesworthstone/asupersync/commit/848be230))
- FABRIC compiler, explain-plan, IR cost model, and ShardedSublist ([`3b2ef97`](https://github.com/Dicklesworthstone/asupersync/commit/3b2ef972))
- Deterministic incident rehearsal framework for cut-certified mobility ([`68df80a`](https://github.com/Dicklesworthstone/asupersync/commit/68df80af))
- SublistLinkCache for per-link subject resolution hot cache ([`c3a3aaa`](https://github.com/Dicklesworthstone/asupersync/commit/c3a3aaa1))
- Quantitative obligation contracts (SLO-style) ([`e9b1c22`](https://github.com/Dicklesworthstone/asupersync/commit/e9b1c22f))
- EvidenceRecord advisory, typed filter, and evidence_id tracing ([`47d7f10`](https://github.com/Dicklesworthstone/asupersync/commit/47d7f10b))

### Transport and Networking

- **Rollback record**, dedup drain, and expiry-driven eviction in symbol aggregator ([`297cc5c`](https://github.com/Dicklesworthstone/asupersync/commit/297cc5c3))
- **Weight-aware select_n** for WeightedRoundRobin load balancing ([`3575ccf`](https://github.com/Dicklesworthstone/asupersync/commit/3575ccf8))
- Weighted round-robin select_n advances by 1 slot per selection, not by weight span ([`f76fcab`](https://github.com/Dicklesworthstone/asupersync/commit/f76fcab1))
- Weighted load balancer tracks active_backend_count, bounds-checks backend operations ([`2634deb`](https://github.com/Dicklesworthstone/asupersync/commit/2634deb5))
- Suppress spurious control traffic from cancel-ack and drain-request after shutdown ([`54bcaba`](https://github.com/Dicklesworthstone/asupersync/commit/54bcaba2))
- Prune_expired now includes default route TTL enforcement ([`a9fe79a`](https://github.com/Dicklesworthstone/asupersync/commit/a9fe79ae))
- Replace single-slot pending_symbol with FIFO staged queue in BufferedSink ([`1eedab5`](https://github.com/Dicklesworthstone/asupersync/commit/1eedab5f))

### Lab and Differential Testing

- **Differential artifact schemas** for retained divergence bundles ([`c372def`](https://github.com/Dicklesworthstone/asupersync/commit/c372deff))
- **Fuzz-to-scenario promotion** for differential regressions ([`5e583c6`](https://github.com/Dicklesworthstone/asupersync/commit/5e583c6e))
- **Evidence normalization** for lab-vs-live comparison ([`d865974`](https://github.com/Dicklesworthstone/asupersync/commit/d8659745))
- CaptureManifest field provenance and LiveWitnessCollector manifest tracking ([`e912340`](https://github.com/Dicklesworthstone/asupersync/commit/e9123408))
- Expand dual-run observable comparison to cover all semantic fields ([`a6c4b90`](https://github.com/Dicklesworthstone/asupersync/commit/a6c4b907))
- Divergence classification pipeline, fuzz-to-dual-run promotion, and divergence corpus registry ([`8e8f4a8`](https://github.com/Dicklesworthstone/asupersync/commit/8e8f4a83))
- Expand differential runner with 3 new scenarios, optional final policy ([`934a034`](https://github.com/Dicklesworthstone/asupersync/commit/934a034a))
- Validate obligation region ownership in snapshot restore ([`0e5de5a`](https://github.com/Dicklesworthstone/asupersync/commit/0e5de5a8))

### WASM and Browser

- **Browser runtime selection**, scope selection, and lane-health demotion/recovery coverage ([`2409c4b`](https://github.com/Dicklesworthstone/asupersync/commit/2409c4bc))
- **Lane-health retry window** coverage proving bounded retry budget before demotion ([`bdc84b7`](https://github.com/Dicklesworthstone/asupersync/commit/bdc84b74))
- Dedicated-worker matrix and execution-ladder diagnostics ([`7fb0c49`](https://github.com/Dicklesworthstone/asupersync/commit/7fb0c490))
- Shared-worker coordinator scaffolding with bounded attach, version handshake ([`f97de80`](https://github.com/Dicklesworthstone/asupersync/commit/f97de80a))
- Prerequisite-loss simulation in dedicated worker consumer test fixture ([`19f1250`](https://github.com/Dicklesworthstone/asupersync/commit/19f12505))
- Bounded service-worker broker API surface ([`45f8ff1`](https://github.com/Dicklesworthstone/asupersync/commit/45f8ff1a))

### Filesystem and I/O

- **BufReader::capacity()** accessor and safety doc comments for get_mut/into_inner ([`44459fe`](https://github.com/Dicklesworthstone/asupersync/commit/44459fe1))
- Correct 0o777 mode for io-uring create_dir, preserve file permissions in write_atomic ([`510fe8e`](https://github.com/Dicklesworthstone/asupersync/commit/510fe8e8))
- copy_buf tracks read_done state to flush correctly after EOF ([`1277755`](https://github.com/Dicklesworthstone/asupersync/commit/12777557))
- Peekable::size_hint returns (0, Some(0)) after cached exhaustion ([`5443ae6`](https://github.com/Dicklesworthstone/asupersync/commit/5443ae63))

### TLS and Security

- Fail closed on missing close_notify per RFC 8446 ([`602571e`](https://github.com/Dicklesworthstone/asupersync/commit/602571e8))
- Malformed grpc-timeout header fails closed instead of falling back to server default ([`e38a3b1`](https://github.com/Dicklesworthstone/asupersync/commit/e38a3b11))
- Improve certificate directory scanning robustness ([`8780cbc`](https://github.com/Dicklesworthstone/asupersync/commit/8780cbc6))

### Runtime and Concurrency Fixes

- Supervised restart leaves actor in Stopping state (deadlock) -- fixed ([`7812876`](https://github.com/Dicklesworthstone/asupersync/commit/78128769))
- Pending counter leak in Buffer when poll_ready errors ([`192c361`](https://github.com/Dicklesworthstone/asupersync/commit/192c361c))
- Buffer pending slot leak on panic in call() ([`1fad761`](https://github.com/Dicklesworthstone/asupersync/commit/1fad7614))
- Correct notify baton-passing when broadcast follows notify_one ([`fdc7a60`](https://github.com/Dicklesworthstone/asupersync/commit/fdc7a60e))
- Remove spurious baton passing when a notified waiter is dropped before poll ([`c10ca2a`](https://github.com/Dicklesworthstone/asupersync/commit/c10ca2aa))
- Adaptive hedge warmup threshold respects small configured windows ([`f11b4f0`](https://github.com/Dicklesworthstone/asupersync/commit/f11b4f01))
- Clock skew evidence for all skew types, prevent jitter zero-collapse at 1ns boundary ([`78fd305`](https://github.com/Dicklesworthstone/asupersync/commit/78fd3054))
- Enforce max_concurrent_streams for incoming remote-initiated H2 streams ([`0e27de0`](https://github.com/Dicklesworthstone/asupersync/commit/0e27de09))
- Preserve handler Content-Length in HEAD response per RFC 9110 ([`c10f4f9`](https://github.com/Dicklesworthstone/asupersync/commit/c10f4f9d))
- JoinHandle::is_finished detects dropped executor side ([`4ac0e5a`](https://github.com/Dicklesworthstone/asupersync/commit/4ac0e5a7))
- Process: close piped stdin before wait to prevent child deadlock ([`af8541e`](https://github.com/Dicklesworthstone/asupersync/commit/af8541e5))
- Kill_on_drop background reaping prevents zombie processes ([`81be156`](https://github.com/Dicklesworthstone/asupersync/commit/81be156d))
- Saga Drop panicking guard + circuit breaker Acquire ordering ([`79d25ca`](https://github.com/Dicklesworthstone/asupersync/commit/79d25caf))
- Server trigger_immediate runs pre-phase hook before advancing to ForceClosing ([`d0079ee`](https://github.com/Dicklesworthstone/asupersync/commit/d0079eeb))

### RaptorQ Erasure Coding

- Profile-pack v5 schema with decision_evidence_status tracking ([`69916e1`](https://github.com/Dicklesworthstone/asupersync/commit/69916e19))
- Conservative tie-breaker in decision contract, DRY test fixtures in gf256 ([`26beb1b`](https://github.com/Dicklesworthstone/asupersync/commit/26beb1ba))
- E2E script validates decision-metadata and override truthfulness ([`5379f3f`](https://github.com/Dicklesworthstone/asupersync/commit/5379f3f4))
- c==1 addmul fast path and SIMD threshold fix ([`2e4e327`](https://github.com/Dicklesworthstone/asupersync/commit/2e4e3272))
- SparseRow bounds check before zero fast-path ([`62bb40c`](https://github.com/Dicklesworthstone/asupersync/commit/62bb40c2))
- Stricter test log schema validation catches whitespace-only fields ([`ed80616`](https://github.com/Dicklesworthstone/asupersync/commit/ed806169))

### Comprehensive Audit Campaign

- ~130,000 lines audited across batches 391--415, all SOUND
- Representative batch: batch 415 covering service/concurrency_limit + timeout + rate_limit ([`b0c7aa3`](https://github.com/Dicklesworthstone/asupersync/commit/b0c7aa3b))
- Machine-searchable audit history expanded with 576 entries across 472 files ([`04b9d2a`](https://github.com/Dicklesworthstone/asupersync/commit/04b9d2af))

---

## [v0.2.8](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.2.8) -- 2026-03-15 (Release)

> 958 commits since v0.2.7 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.7...v0.2.8)

The largest release to date: 410+ bug fixes, 222 features, and audit coverage across 500+ files.

### Runtime Correctness and Safety

- **Fail-closed completion guards** added to all Future implementations (streams, I/O, sync, service) -- prevents silent misuse when polling after terminal state ([`a9e737d`](https://github.com/Dicklesworthstone/asupersync/commit/a9e737d8), [`c917822`](https://github.com/Dicklesworthstone/asupersync/commit/c917822d), [`c9069cc`](https://github.com/Dicklesworthstone/asupersync/commit/c9069cc2))
- **ThreeLaneLocalWaker** default_priority prevents priority inversion for cancelled local tasks ([`12d261d`](https://github.com/Dicklesworthstone/asupersync/commit/12d261db))
- **Actual cancel masking** in commit_section ([`85b1ac0`](https://github.com/Dicklesworthstone/asupersync/commit/85b1ac07))
- Deterministic waker drain, early lock drops, keepalive builder, mask optimization ([`0f0fe0a`](https://github.com/Dicklesworthstone/asupersync/commit/0f0fe0a6))
- Stale-entry skipping extended to all scheduler pop methods ([`ac4d2e9`](https://github.com/Dicklesworthstone/asupersync/commit/ac4d2e96))
- Task completion coerced to Cancelled when cancel is in-flight ([`bebe6b9`](https://github.com/Dicklesworthstone/asupersync/commit/bebe6b9b))
- Double-panic guards on all Drop-based leak detectors ([`44708b1`](https://github.com/Dicklesworthstone/asupersync/commit/44708b12))
- yield_now panics on repoll; timeout reset unconditional ([`596f351`](https://github.com/Dicklesworthstone/asupersync/commit/596f3518))
- Soften repoll guards from panic to error return across time, runtime, net ([`4a40627`](https://github.com/Dicklesworthstone/asupersync/commit/4a40627a))
- Join semantics with proper close handling ([`34fbc58`](https://github.com/Dicklesworthstone/asupersync/commit/34fbc581))

### Service Layer

- **Discover-driven topology updates** in LoadBalancer ([`765f9f3`](https://github.com/Dicklesworthstone/asupersync/commit/765f9f34))
- **Weighted strategy** polish with PolledAfterCompletion on LoadShed ([`fdca8d9`](https://github.com/Dicklesworthstone/asupersync/commit/fdca8d97))
- Unified NotReady error variant across all service middlewares ([`fbf95a7`](https://github.com/Dicklesworthstone/asupersync/commit/fbf95a7f))
- Readiness contracts and expanded filter, hedge, and timeout coverage ([`2e97eee`](https://github.com/Dicklesworthstone/asupersync/commit/2e97eeea))
- Buffer NotReady enforcement, OneshotError wrapper, LoadBalancer sync_backend_count ([`1d0505b`](https://github.com/Dicklesworthstone/asupersync/commit/1d0505b3))
- Correct readiness tracking in Filter/Reconnect, add RetryError wrapper ([`32cb86a`](https://github.com/Dicklesworthstone/asupersync/commit/32cb86a5))
- Stale DNS resolution prevented from clobbering newer state ([`1cb7314`](https://github.com/Dicklesworthstone/asupersync/commit/1cb73149))

### HTTP and Protocol Compliance

- **RFC 9110** identity encoding negotiation and HEAD response handling ([`662b127`](https://github.com/Dicklesworthstone/asupersync/commit/662b1271))
- **RFC 7540** reserved streams counted toward max_concurrent_streams ([`02bb14b`](https://github.com/Dicklesworthstone/asupersync/commit/02bb14bb))
- H2-reserved H3 settings rejected ([`518b400`](https://github.com/Dicklesworthstone/asupersync/commit/518b4008))
- Stateful streaming decompression, quality validation, and Expect: 100-continue refactoring ([`65b6677`](https://github.com/Dicklesworthstone/asupersync/commit/65b66771))
- CRLF injection sanitization in response headers, redirect Location, gRPC-web trailers ([`c178930`](https://github.com/Dicklesworthstone/asupersync/commit/c1789300), [`bdfc321`](https://github.com/Dicklesworthstone/asupersync/commit/bdfc3213), [`931150f`](https://github.com/Dicklesworthstone/asupersync/commit/931150f2))
- Tri-state Limited body distinguishes clean EOF from failure ([`2ed0aab`](https://github.com/Dicklesworthstone/asupersync/commit/2ed0aab4))
- Reference-count HealthReporters to prevent premature status clear ([`b96d51c`](https://github.com/Dicklesworthstone/asupersync/commit/b96d51c4))
- SSE: reject null bytes in last_event_id per SSE spec ([`6ae5703`](https://github.com/Dicklesworthstone/asupersync/commit/6ae57034))

### WASM and Browser

- **Real MessagePort and BroadcastChannel** bindings for browser reactor ([`c29a4c9`](https://github.com/Dicklesworthstone/asupersync/commit/c29a4c9b))
- **StreamAccounting** for BrowserReadable/WritableStream ([`119f217`](https://github.com/Dicklesworthstone/asupersync/commit/119f2174))
- Non-clobbering addEventListener-based message and error listeners ([`41ff324`](https://github.com/Dicklesworthstone/asupersync/commit/41ff3240))
- Service-worker broker descriptor and handoff parser validation ([`ddcfad6`](https://github.com/Dicklesworthstone/asupersync/commit/ddcfad65))

### Distributed and CRDT

- **Multi-block encoding** with per-block repair distribution ([`39f38b4`](https://github.com/Dicklesworthstone/asupersync/commit/39f38b45))
- **Quorum-aware recovery** completion and replica mutation guards ([`6985c9c`](https://github.com/Dicklesworthstone/asupersync/commit/6985c9c6))
- Close idempotent, reconcile replica loss across all degraded states ([`ad46fb2`](https://github.com/Dicklesworthstone/asupersync/commit/ad46fb27))
- ORSet tombstone tracking prevents removed values from reappearing on merge ([`7516adf`](https://github.com/Dicklesworthstone/asupersync/commit/7516adf7))
- GCounter saturating add, PNCounter widened to i128, checked ORSet seq ([`0673257`](https://github.com/Dicklesworthstone/asupersync/commit/0673257e))
- Reject trailing bytes in snapshot deserialization ([`99640c5`](https://github.com/Dicklesworthstone/asupersync/commit/99640c56))

### Sync Primitives

- OnceCell::set made non-blocking to prevent async deadlocks ([`a4985e7`](https://github.com/Dicklesworthstone/asupersync/commit/a4985e7f))
- Zero semaphore permits on close and handle pool close-while-create race ([`047c88a`](https://github.com/Dicklesworthstone/asupersync/commit/047c88a7))
- Lost notify_one baton when broadcast supersedes original waiter set ([`95c7de7`](https://github.com/Dicklesworthstone/asupersync/commit/95c7de7e))
- RwLock waiter state cleanup on cancellation and poison ([`3ae13c1`](https://github.com/Dicklesworthstone/asupersync/commit/3ae13c15))
- Atomic record_event replaces split next_seq/push_event to prevent sequence interleaving ([`da4facc`](https://github.com/Dicklesworthstone/asupersync/commit/da4facc8))

### Observability and Lab

- **Sync reactor chaos statistics** into LabRuntime aggregated stats ([`da489aa`](https://github.com/Dicklesworthstone/asupersync/commit/da489aa7))
- **Deadlocked health classification** from explicit trapped wait-cycle evidence ([`bd4b6b1`](https://github.com/Dicklesworthstone/asupersync/commit/bd4b6b1a))
- Task inspector falls back to logical state clock ([`d3c7744`](https://github.com/Dicklesworthstone/asupersync/commit/d3c7744d))
- Timer wheel synchronization to current clock before register/update/query paths ([`16eba13`](https://github.com/Dicklesworthstone/asupersync/commit/16eba13a))
- Trace writer drop flush ([`c6c8114`](https://github.com/Dicklesworthstone/asupersync/commit/c6c81145))
- Evict oldest incomplete traces when complete-trace eviction is insufficient ([`22aa925`](https://github.com/Dicklesworthstone/asupersync/commit/22aa925a))

### Database

- Cancel-aware result set draining and overflow-safe packet reads ([`f5e188d`](https://github.com/Dicklesworthstone/asupersync/commit/f5e188d1))
- DbPool mutex locks survive poisoned state ([`ba43ecc`](https://github.com/Dicklesworthstone/asupersync/commit/ba43ecc4))
- Return_connection reports whether connection was requeued ([`83f31ac`](https://github.com/Dicklesworthstone/asupersync/commit/83f31ac5))
- MySQL IPv6/timeout, QPACK static table and header validation ([`467831d`](https://github.com/Dicklesworthstone/asupersync/commit/467831d6))

### Audit Campaign

- **Over 500 files audited**, all SOUND, across batches 199--379
- 65,307 lines in batches 199--208 alone; 0 bugs remaining after fixes
- Audit coverage includes all major subsystems: runtime, scheduler, channels, net, HTTP, service, distributed, messaging

### Drop_unwrap_finder Utility

- New static analysis utility for finding potential unwrap panics in Drop impls ([`0c45351`](https://github.com/Dicklesworthstone/asupersync/commit/0c453514))

---

## [v0.2.7](https://github.com/Dicklesworthstone/asupersync/tag/v0.2.7) -- 2026-03-03 (Tag)

> 412 commits since v0.2.6 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.6...v0.2.7)

### Web Framework

- **Session middleware** with pluggable backends ([`ff2c55b`](https://github.com/Dicklesworthstone/asupersync/commit/ff2c55be))
- **Static file serving** with ETag and caching ([`d6d012b`](https://github.com/Dicklesworthstone/asupersync/commit/d6d012bb))
- **Multipart form data** parser and RFC 7578 extractor ([`60e6c83`](https://github.com/Dicklesworthstone/asupersync/commit/60e6c83f), [`96292ef`](https://github.com/Dicklesworthstone/asupersync/commit/96292eff))
- **Health check endpoints** for Kubernetes-style probes ([`543587f`](https://github.com/Dicklesworthstone/asupersync/commit/543587f2))
- **Server-Sent Events (SSE)** support ([`5600b25`](https://github.com/Dicklesworthstone/asupersync/commit/5600b25d))
- **Cookie and CookieJar** extractors with header parsing ([`1e54bea`](https://github.com/Dicklesworthstone/asupersync/commit/1e54bea0))
- **CORS middleware** with configurable origin/method/header policies ([`4d9f63f`](https://github.com/Dicklesworthstone/asupersync/commit/4d9f63fa))
- **SecurityHeadersMiddleware** with configurable security policy ([`38bec9c`](https://github.com/Dicklesworthstone/asupersync/commit/38bec9cf))
- **Gzip/deflate compressors** and response compression middleware ([`79f746b`](https://github.com/Dicklesworthstone/asupersync/commit/79f746bf))
- 8 production middleware types for stack parity ([`13912ba`](https://github.com/Dicklesworthstone/asupersync/commit/13912ba8))
- RequestTraceMiddleware for request timing and trace propagation ([`beb1b0b`](https://github.com/Dicklesworthstone/asupersync/commit/beb1b0be))
- Full WebSocket implementation with module doc comment ([`7f0e222`](https://github.com/Dicklesworthstone/asupersync/commit/7f0e222f))
- WebSocket HTTP upgrade extractor ([`aa04fbd`](https://github.com/Dicklesworthstone/asupersync/commit/aa04fbd4))
- Form body size limit and comprehensive extractor tests ([`591d4fd`](https://github.com/Dicklesworthstone/asupersync/commit/591d4fd0))
- Content negotiation module ([`e806de9`](https://github.com/Dicklesworthstone/asupersync/commit/e806de91))
- TypeId-keyed typed state extraction in Extensions ([`d6d202a`](https://github.com/Dicklesworthstone/asupersync/commit/d6d202a4))

### Stream Combinators

- **Scan, peekable, throttle, debounce** combinators ([`2f7be8c`](https://github.com/Dicklesworthstone/asupersync/commit/2f7be8c4))

### Redis

- **Transaction (MULTI/EXEC)** and PubSub APIs ([`fad7cbb`](https://github.com/Dicklesworthstone/asupersync/commit/fad7cbb3))
- Pub/Sub types, PUBLISH, WATCH/UNWATCH, MULTI/EXEC, and PING ([`0d1383b`](https://github.com/Dicklesworthstone/asupersync/commit/0d1383b6))

### gRPC

- **Server reflection service** with descriptor registry ([`23f6f20`](https://github.com/Dicklesworthstone/asupersync/commit/23f6f207))
- **Compression encoding negotiation** on gRPC channel ([`7aedbe2`](https://github.com/Dicklesworthstone/asupersync/commit/7aedbe20))

### Tokio Compatibility Layer

- **Safe blocking bridge** with Cx context propagation ([`72557fa`](https://github.com/Dicklesworthstone/asupersync/commit/72557fae))
- Real I/O trait bridging and functional hyper executor/timer ([`6813e18`](https://github.com/Dicklesworthstone/asupersync/commit/6813e18f))
- Tokio-compat scaffolding, interop ranking, and migration framework ([`e23469a`](https://github.com/Dicklesworthstone/asupersync/commit/e23469a7))
- Replace thread-based sleep with native timer wheel delegation ([`6a58861`](https://github.com/Dicklesworthstone/asupersync/commit/6a58861a))
- Cancel-aware polling in Tower bridge replacing with_tokio_context ([`89e7c3c`](https://github.com/Dicklesworthstone/asupersync/commit/89e7c3c7))

### Database

- **MySQL client hardened** with result limits, URL parsing, abandoned tx drain ([`1a13be2`](https://github.com/Dicklesworthstone/asupersync/commit/1a13be2d))
- **SQLite connection defaults** and runtime configuration ([`6d1e2e1`](https://github.com/Dicklesworthstone/asupersync/commit/6d1e2e19))
- **PostgreSQL** type-safe parameter encoding, extended query protocol, prepared statements ([`3e2ad4f`](https://github.com/Dicklesworthstone/asupersync/commit/3e2ad4f4))

### I/O and Networking

- **RFC 8305 Happy Eyeballs v2** concurrent connection racing ([`60a8023`](https://github.com/Dicklesworthstone/asupersync/commit/60a80230))
- **AsyncSeekExt** trait ([`30993b6`](https://github.com/Dicklesworthstone/asupersync/commit/30993b6e))
- **ReaderStream and StreamReader** bridge adapters ([`e37a9d4`](https://github.com/Dicklesworthstone/asupersync/commit/e37a9d45))
- **Async Command/Child** methods for cooperative polling ([`4376aab`](https://github.com/Dicklesworthstone/asupersync/commit/4376aab5))
- Typed integer read/write methods on AsyncReadExt/AsyncWriteExt ([`40a6866`](https://github.com/Dicklesworthstone/asupersync/commit/40a68661), [`7b4ecdd`](https://github.com/Dicklesworthstone/asupersync/commit/7b4ecdd2))
- **Write_atomic** for durable file replacement via temp+rename ([`dd0573a`](https://github.com/Dicklesworthstone/asupersync/commit/dd0573ab))
- LinesCodec decode_eof, discard-and-recover for oversized lines ([`75b96ff`](https://github.com/Dicklesworthstone/asupersync/commit/75b96ffb))

### QUIC/HTTP3

- Native feature surfaces, deprecate compat wrappers ([`06df9b5`](https://github.com/Dicklesworthstone/asupersync/commit/06df9b52))
- QPACK field-section decode helpers with pseudo-header validation ([`a70436e`](https://github.com/Dicklesworthstone/asupersync/commit/a70436e5))
- 0-RTT/resumption and path migration lifecycle ([`556290c`](https://github.com/Dicklesworthstone/asupersync/commit/556290c9))
- Packet send-state guard and congestion recovery epoch fix ([`be7d9fb`](https://github.com/Dicklesworthstone/asupersync/commit/be7d9fb7))

### Kafka

- Deterministic producer/consumer lifecycle ([`e7a9204`](https://github.com/Dicklesworthstone/asupersync/commit/e7a92040))
- Messaging module gated behind kafka feature ([`c4705b7`](https://github.com/Dicklesworthstone/asupersync/commit/c4705b71))
- NATS graceful flush before shutdown, max_payload enforcement ([`16c4a88`](https://github.com/Dicklesworthstone/asupersync/commit/16c4a88f), [`1527fe9`](https://github.com/Dicklesworthstone/asupersync/commit/1527fe9b))

### WASM Supply Chain

- Supply-chain artifact bundle: SBOM, provenance, integrity manifest ([`37c0037`](https://github.com/Dicklesworthstone/asupersync/commit/37c00370))
- Flake governance framework with policy and checker ([`a48a751`](https://github.com/Dicklesworthstone/asupersync/commit/a48a751a))
- ABI compatibility policy and harness ([`335c905`](https://github.com/Dicklesworthstone/asupersync/commit/335c9051))
- Bundler/runtime compatibility matrix and test suite ([`7d54656`](https://github.com/Dicklesworthstone/asupersync/commit/7d54656d))
- DX error taxonomy, diagnostic enrichment, and IntelliSense quality contract ([`9b3c72b`](https://github.com/Dicklesworthstone/asupersync/commit/9b3c72b0))

### Semantic and Formal Verification

- TLA+ abstraction boundaries and runtime correspondence ([`28f7ca2`](https://github.com/Dicklesworthstone/asupersync/commit/28f7ca22))
- SEM-11 complete: enablement FAQ, maintainer playbook, audit cadence, retrospective ([`b4c57fa`](https://github.com/Dicklesworthstone/asupersync/commit/b4c57fa7))
- SEM-10.5 CI signal-quality gate with flake rate and runtime budget enforcement ([`fef0af4`](https://github.com/Dicklesworthstone/asupersync/commit/fef0af48))
- Residual risk register with bounded exceptions and GO/NO-GO rules ([`0f8d10e`](https://github.com/Dicklesworthstone/asupersync/commit/0f8d10ef))
- Failure-replay cookbook with triage tree and rerun shortcuts ([`c6beffb`](https://github.com/Dicklesworthstone/asupersync/commit/c6beffb6))

### Sync and Channel Fixes

- RwLock pre-grant drop safety extended to OwnedWriteFuture with cascading wakeup ([`94cc4ca`](https://github.com/Dicklesworthstone/asupersync/commit/94cc4cac))
- Watch channel Receiver::changed waker leak ([`5af621b`](https://github.com/Dicklesworthstone/asupersync/commit/5af621b6))
- Waiter ID overflow prevention, RwLock FIFO fairness ([`124a2c3`](https://github.com/Dicklesworthstone/asupersync/commit/124a2c3d))
- Receiver close returns Disconnected when channel empty instead of Empty ([`616d0b6`](https://github.com/Dicklesworthstone/asupersync/commit/616d0b6f))
- Broadcast receiver_count increment inside lock to prevent subscribe race ([`e9314df`](https://github.com/Dicklesworthstone/asupersync/commit/e9314df5))
- RwLock wake blocked readers when last queued writer is dropped ([`605e413`](https://github.com/Dicklesworthstone/asupersync/commit/605e413f))

### Lean Formal Proofs

- No-ambient-authority capability exclusion theorems ([`bd726ce`](https://github.com/Dicklesworthstone/asupersync/commit/bd726ce1))
- Global no-obligation-leak theorems ([`b60f38c`](https://github.com/Dicklesworthstone/asupersync/commit/b60f38c6))
- SingleOwner invariant proof ([`070ef00`](https://github.com/Dicklesworthstone/asupersync/commit/070ef003))
- Cancel-request idempotence theorems ([`447fcd8`](https://github.com/Dicklesworthstone/asupersync/commit/447fcd85))

### Performance

- Fused dual-slice GF(256) SIMD mul/addmul for AVX2 and NEON ([`58b27f4`](https://github.com/Dicklesworthstone/asupersync/commit/58b27f43))
- Always use dual-add fast path for c==1 in gf256_addmul_slices2 ([`b5b37fc`](https://github.com/Dicklesworthstone/asupersync/commit/b5b37fc3))
- AsyncReadVectored for TCP and Unix stream split halves ([`b3e8768`](https://github.com/Dicklesworthstone/asupersync/commit/b3e8768e))

### Doctor CLI

- Performance budget matrix and instrumentation gates ([`f638c35`](https://github.com/Dicklesworthstone/asupersync/commit/f638c35d))
- Visual regression harness and golden fixture suite ([`8367006`](https://github.com/Dicklesworthstone/asupersync/commit/8367006f))
- Guided remediation preview/apply pipeline with staged approval checkpoints ([`184fa87`](https://github.com/Dicklesworthstone/asupersync/commit/184fa87c))
- Post-remediation verification loop with trust scorecards ([`6ae61e4`](https://github.com/Dicklesworthstone/asupersync/commit/6ae61e4d))

---

## [v0.2.6](https://github.com/Dicklesworthstone/asupersync/tag/v0.2.6) -- 2026-02-22 (Tag)

> 260 commits since v0.2.5 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.5...v0.2.6)

### RaptorQ Erasure Coding

- **Wavefront decode pipeline** for bounded assembly+peeling ([`e613664`](https://github.com/Dicklesworthstone/asupersync/commit/e6136648))
- **F8 wavefront pipeline closed** -- all G3 blockers resolved ([`42e2b6f`](https://github.com/Dicklesworthstone/asupersync/commit/42e2b6f2))
- Per-lane floor threshold for dual-addmul auto policy ([`4cfaada`](https://github.com/Dicklesworthstone/asupersync/commit/4cfaadad))
- Arc-wrap dense factor cache artifacts, flatten signature memory layout ([`0c26349`](https://github.com/Dicklesworthstone/asupersync/commit/0c263497))
- Raise addmul floor to 12KiB and add XOR fast path for tiny slices ([`b37eed8`](https://github.com/Dicklesworthstone/asupersync/commit/b37eed89))
- Iterator-based propagation in peel_from_queue ([`8ee3c9c`](https://github.com/Dicklesworthstone/asupersync/commit/8ee3c9c5))
- Dense-column mapping with adaptive DenseColIndexMap ([`b607315`](https://github.com/Dicklesworthstone/asupersync/commit/b607315c))

### HTTP/2 and Security

- **CVE-2023-44487 Rapid Reset** mitigated with RST_STREAM rate limiting ([`b47a7a5`](https://github.com/Dicklesworthstone/asupersync/commit/b47a7a5f))
- Chunked trailer size limit check reordered to avoid premature rejection ([`8754e3d`](https://github.com/Dicklesworthstone/asupersync/commit/8754e3dc))

### Networking

- **TCP accept storm** detection with exponential backoff ([`b187985`](https://github.com/Dicklesworthstone/asupersync/commit/b187985c))
- Exponential backoff for transient accept errors and fallback IO rewakes ([`ab42cfa`](https://github.com/Dicklesworthstone/asupersync/commit/ab42cfad))
- Fallback accept backoff moved to background thread ([`f6e567b`](https://github.com/Dicklesworthstone/asupersync/commit/f6e567b1))
- Region close notification so scope awaits child completion ([`834172e`](https://github.com/Dicklesworthstone/asupersync/commit/834172e1))

### Sync Primitives

- Exception safety improved in barrier/notify primitives ([`de7d4bc`](https://github.com/Dicklesworthstone/asupersync/commit/de7d4bc1))
- RwLockWriteGuard Sync bound tightened to require T: Send + Sync ([`0e74544`](https://github.com/Dicklesworthstone/asupersync/commit/0e745445))
- Require &mut self for oneshot Receiver::recv ([`6a081e2`](https://github.com/Dicklesworthstone/asupersync/commit/6a081e25))
- BlockingOneshotReceiver waker cleared on drop to prevent stale wake ([`118e356`](https://github.com/Dicklesworthstone/asupersync/commit/118e3566))
- Saturating_duration_since in pool eviction to prevent panic ([`925628a`](https://github.com/Dicklesworthstone/asupersync/commit/925628a9))
- Active waiter count incremented when notify waker slot re-filled ([`c2a1ab6`](https://github.com/Dicklesworthstone/asupersync/commit/c2a1ab6d))
- Lost-wakeup chain resolved in mutex and rwlock drop paths ([`698c425`](https://github.com/Dicklesworthstone/asupersync/commit/698c425e))

### Runtime

- Try_lock I/O leader pattern replaced with atomic CAS polling ([`d5ba8a2`](https://github.com/Dicklesworthstone/asupersync/commit/d5ba8a26))
- Panic safety added to blocking pool, shutdown check before wait ([`2ed0ba7`](https://github.com/Dicklesworthstone/asupersync/commit/2ed0ba7a))
- WebSocket close handshake timeout ([`0b473bc`](https://github.com/Dicklesworthstone/asupersync/commit/0b473bc8))
- Finished thread handle reaping + pool timeout cleanup ([`1fba0f9`](https://github.com/Dicklesworthstone/asupersync/commit/1fba0f9c))

### Performance

- Cache max duration as u64 nanoseconds to avoid repeated u128-to-u64 conversions ([`611acf6`](https://github.com/Dicklesworthstone/asupersync/commit/611acf63))
- Compare_exchange in Parker park/unpark ([`e2caecc`](https://github.com/Dicklesworthstone/asupersync/commit/e2caecc3))
- Fast-path empty wheel + purge storage on last cancel ([`70bf97e`](https://github.com/Dicklesworthstone/asupersync/commit/70bf97e6))
- Single-pass reservoir sampling in random load balancer ([`9198d51`](https://github.com/Dicklesworthstone/asupersync/commit/9198d516))
- Fast-path work stealing when queue has no local tasks ([`8b0ee3e`](https://github.com/Dicklesworthstone/asupersync/commit/8b0ee3e7))
- Stack-pin futures in scope race/select patterns ([`9035b20`](https://github.com/Dicklesworthstone/asupersync/commit/9035b204))
- Bounded concurrent sends in distributed distribute() ([`b582ebd`](https://github.com/Dicklesworthstone/asupersync/commit/b582ebd0))
- Bitmap-scan next-deadline via next_occupied_circular() ([`7e2bc5f`](https://github.com/Dicklesworthstone/asupersync/commit/7e2bc5f8))
- Reduce mutex hold time in TcpListener::register_interest ([`c42e9af`](https://github.com/Dicklesworthstone/asupersync/commit/c42e9af9))
- Cap stealer skip-list to inline capacity + full-scan wheel levels ([`465d82f`](https://github.com/Dicklesworthstone/asupersync/commit/465d82f8))

### Oracle and Testing

- **Refinement firewall** and temporal oracle hydration ([`c7c4a21`](https://github.com/Dicklesworthstone/asupersync/commit/c7c4a21c))
- Deterministic fault injection and lab scenario testing ([`766c2fb`](https://github.com/Dicklesworthstone/asupersync/commit/766c2fb0))
- Cumulative event count tracking for ring buffer eviction detection ([`fbf82e6`](https://github.com/Dicklesworthstone/asupersync/commit/fbf82608))
- Edge-case tests for snapshot OOM and timer wraparound ([`025324e`](https://github.com/Dicklesworthstone/asupersync/commit/025324e7))

### QPACK/HTTP3

- QPACK field section encode/decode for static-only mode ([`abfe6ad`](https://github.com/Dicklesworthstone/asupersync/commit/abfe6ad8))
- QPACK wire validation and interop fixture corpus ([`12f3c10`](https://github.com/Dicklesworthstone/asupersync/commit/12f3c108))

### Database

- Synchronous rollback, OOM cap, wrapping IDs fixed ([`c433946`](https://github.com/Dicklesworthstone/asupersync/commit/c4339464))

---

## [v0.2.5](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.2.5) -- 2026-02-18 (Release)

> 13 commits since v0.2.4 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.4...v0.2.5)

Workspace crate versions aligned to 0.2.5 for crates.io publication with MIT + OpenAI/Anthropic rider license metadata.

- **Deterministic artifact manifests** with replay verification and jq-based contract validation ([`b0c0fd1`](https://github.com/Dicklesworthstone/asupersync/commit/b0c0fd1c))
- **Coverage ratchet**, no-mock waiver expiry, and Track-D CI gates ([`19cfb06`](https://github.com/Dicklesworthstone/asupersync/commit/19cfb068))
- Preserve custom WebSocket close codes, persist load-shed state, tighten HTTP/1 parsing ([`21fb7c8`](https://github.com/Dicklesworthstone/asupersync/commit/21fb7c80))
- Tighten cast failure semantics and cancellation cleanup invariants ([`c5b1d75`](https://github.com/Dicklesworthstone/asupersync/commit/c5b1d758))
- Dense-factor reuse cache and broader decode stress benchmarks ([`c90f59f`](https://github.com/Dicklesworthstone/asupersync/commit/c90f59f6))
- Use BTreeMap for expected_loss_by_action payloads (publish fix) ([`0c8fd60`](https://github.com/Dicklesworthstone/asupersync/commit/0c8fd602))

---

## [v0.2.4](https://github.com/Dicklesworthstone/asupersync/tag/v0.2.4) -- 2026-02-18 (Tag)

> 21 commits since v0.2.3 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.3...v0.2.4)

### Rust 2024 Edition Migration

- **Workspace migrated to Rust edition 2024** ([`db4ec3d`](https://github.com/Dicklesworthstone/asupersync/commit/db4ec3d8))
- Comprehensive rustfmt 2024 formatting applied across entire codebase ([`5cb48b4`](https://github.com/Dicklesworthstone/asupersync/commit/5cb48b40))
- Windows IOCP poller migrated from RawSocket to BorrowedSocket ([`29edc8f`](https://github.com/Dicklesworthstone/asupersync/commit/29edc8fe))

### Bug Fixes

- gRPC CallContext deadline expiry made boundary-inclusive and testable ([`0e36edd`](https://github.com/Dicklesworthstone/asupersync/commit/0e36edd3))
- TraceMonoid PartialEq guarded against fingerprint hash collisions ([`44072cb`](https://github.com/Dicklesworthstone/asupersync/commit/44072cb8))
- EndpointState made atomic; update_endpoint_state no-op fixed ([`fdc9cd1`](https://github.com/Dicklesworthstone/asupersync/commit/fdc9cd1a))
- Bridge sync pending accounting and CRDT obligation acquire idempotency ([`1f678ba`](https://github.com/Dicklesworthstone/asupersync/commit/1f678ba9))
- RFC 6455 close code validation on parse, tighten wire-sendable set ([`591bf57`](https://github.com/Dicklesworthstone/asupersync/commit/591bf574))
- Integer overflow prevention in Duration-to-u64 conversions and HPACK bitmask shifts ([`5b80ba6`](https://github.com/Dicklesworthstone/asupersync/commit/5b80ba69))
- Circuit breaker half_open_max_probes clamped to minimum of 1 ([`70c19da`](https://github.com/Dicklesworthstone/asupersync/commit/70c19dac))
- DummyCx stub in scope compile-fail test ([`b824e69`](https://github.com/Dicklesworthstone/asupersync/commit/b824e692))

### Performance

- Decoder scratch buffer reuse, HPACK prealloc, WatchStream mark_seen ([`9f0522e`](https://github.com/Dicklesworthstone/asupersync/commit/9f0522e0))
- Single-pass HTTP/1 header parsing and raptorq decoder retry snapshot/restore ([`33ce0f0`](https://github.com/Dicklesworthstone/asupersync/commit/33ce0f06))

---

## [v0.2.3](https://github.com/Dicklesworthstone/asupersync/tag/v0.2.3) -- 2026-02-17 (Tag)

> 2 commits since v0.2.2 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.2...v0.2.3)

- Version bump release for tagged milestone
- Fix Windows reactor modify/delete socket source typing ([`63880c2`](https://github.com/Dicklesworthstone/asupersync/commit/63880c24))

---

## [v0.2.2](https://github.com/Dicklesworthstone/asupersync/tag/v0.2.2) -- 2026-02-17 (Tag)

> 380 commits since v0.2.0 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.2.0...v0.2.2)

### Performance Overhaul: parking_lot Migration

- **Complete migration from std::sync to parking_lot** across the entire codebase -- channels, runtime, scheduler, sync primitives, actor, service, net, transport ([`3c1b335`](https://github.com/Dicklesworthstone/asupersync/commit/3c1b3356), [`067e030`](https://github.com/Dicklesworthstone/asupersync/commit/067e0306))
- Lock-free atomic counters replacing Mutex-guarded stats in channels, bulkhead, DNS, shutdown ([`c9d2ddb`](https://github.com/Dicklesworthstone/asupersync/commit/c9d2ddb3), [`e826391`](https://github.com/Dicklesworthstone/asupersync/commit/e8263919))
- BTreeMap/BTreeSet to HashMap/HashSet migration for hot paths ([`d421836`](https://github.com/Dicklesworthstone/asupersync/commit/d4218361), [`e25acf4`](https://github.com/Dicklesworthstone/asupersync/commit/e25acf4d))
- Then later reversed: HashMap/HashSet back to BTreeMap/BTreeSet for deterministic iteration in tests ([`ae922e6`](https://github.com/Dicklesworthstone/asupersync/commit/ae922e6d), [`e15df42`](https://github.com/Dicklesworthstone/asupersync/commit/e15df427))

### Performance: Hot-Path Optimizations

- Waker cloning eliminated via will_wake() guards across async subsystems ([`da99eb3`](https://github.com/Dicklesworthstone/asupersync/commit/da99eb32))
- CAS loops refined to compare_exchange_weak with match-arm retry ([`2056653`](https://github.com/Dicklesworthstone/asupersync/commit/2056653a))
- Pre-size collections and reduce heap churn across core subsystems ([`b4b053b`](https://github.com/Dicklesworthstone/asupersync/commit/b4b053be))
- Scheduler task dispatch reordering, metrics provider caching, inline waker hot paths ([`8a9330c`](https://github.com/Dicklesworthstone/asupersync/commit/8a9330c6))
- SmallVec in HTTP connection pool cleanup ([`97a1506`](https://github.com/Dicklesworthstone/asupersync/commit/97a1506d))
- Pre-allocate in-flight VecDeque with front-ready fast path in streams ([`aa571c0`](https://github.com/Dicklesworthstone/asupersync/commit/aa571c0f))
- Per-waiter Arc+Mutex eliminated in MPSC channel ([`5df3dad`](https://github.com/Dicklesworthstone/asupersync/commit/5df3dad3))
- Zero-copy response encoding and byte-level header parsing ([`9c4adfe`](https://github.com/Dicklesworthstone/asupersync/commit/9c4adfec))
- Lock-free timed_count, SmallVec steal, and 3-phase next_task ([`58ed379`](https://github.com/Dicklesworthstone/asupersync/commit/58ed3790))
- Stack pinning via std::pin::pin! replacing Box::pin in scopes ([`3967aa7`](https://github.com/Dicklesworthstone/asupersync/commit/3967aa7a))

### RaptorQ Erasure Coding

- **Block-Schur low-rank hard-regime branch** and dense column index acceleration ([`5aaaf82`](https://github.com/Dicklesworthstone/asupersync/commit/5aaaf82c))
- **Runtime decoder policy framework** with sparse elimination refinement ([`178824e`](https://github.com/Dicklesworthstone/asupersync/commit/178824ee))
- Sparse-first column ordering, hybrid elimination, chunked GF256 scalar kernels ([`1104918`](https://github.com/Dicklesworthstone/asupersync/commit/1104918a))
- Precompute GF(256) nibble multiplication tables as compile-time statics ([`8a5fd02`](https://github.com/Dicklesworthstone/asupersync/commit/8a5fd02b))
- Queue-based peeling, hard-regime elimination, input validation, output verification ([`62d79c4`](https://github.com/Dicklesworthstone/asupersync/commit/62d79c40))
- Detect inconsistent overdetermined systems in Gaussian elimination ([`04700e7`](https://github.com/Dicklesworthstone/asupersync/commit/04700e74))
- Binary search peeling removal ([`b015331`](https://github.com/Dicklesworthstone/asupersync/commit/b0153319))
- Cap symbol pool initial allocation to per-object demand ([`040006e`](https://github.com/Dicklesworthstone/asupersync/commit/040006e2))

### Reactor and I/O

- **Edge-triggered, priority, and HUP support** added to epoll reactor ([`65a47d7`](https://github.com/Dicklesworthstone/asupersync/commit/65a47d70))
- io_uring ETIME handling, Windows modify stale socket cleanup ([`c93cc6b`](https://github.com/Dicklesworthstone/asupersync/commit/c93cc6ba))
- io_uring modify() rollback semantics and stale-registration pruning ([`77ae6aa`](https://github.com/Dicklesworthstone/asupersync/commit/77ae6aa9))
- fd registration hardened against reuse and stale deregistration ([`66eff16`](https://github.com/Dicklesworthstone/asupersync/commit/66eff16a))
- Windows: duplicate socket guard, best-effort deregister, stale handle helper ([`2399d00`](https://github.com/Dicklesworthstone/asupersync/commit/2399d007))
- Colocate token and fd maps in EpollReactor, eliminate O(n) fd scan ([`363b898`](https://github.com/Dicklesworthstone/asupersync/commit/363b8982))

### Scheduler

- **Harden intrusive heap** against stale or corrupted heap indices ([`790bc44`](https://github.com/Dicklesworthstone/asupersync/commit/790bc44e))
- Harden local task safety, deadline dispatch, panic recovery, counter underflow protection ([`b07d13f`](https://github.com/Dicklesworthstone/asupersync/commit/b07d13fd))
- CAS for counter saturation, validate queue tags, recover from foreign-pinned waiters ([`aae1b2f`](https://github.com/Dicklesworthstone/asupersync/commit/aae1b2f9))
- Three liveness bugs resolved in work-stealing and shutdown paths ([`9fe7960`](https://github.com/Dicklesworthstone/asupersync/commit/9fe79606))
- Try_local_any_lane for single-lock multi-lane local dispatch ([`9125605`](https://github.com/Dicklesworthstone/asupersync/commit/91256053))
- Pop_any_lane_with_hint for single-call multi-lane dispatch ([`975763d`](https://github.com/Dicklesworthstone/asupersync/commit/975763df))
- Cancel_streak accounting corrected, Parker made poison-tolerant ([`9b2a812`](https://github.com/Dicklesworthstone/asupersync/commit/9b2a812b))
- No-progress detection for tasks that never checkpoint via logical time ([`cfbc3d3`](https://github.com/Dicklesworthstone/asupersync/commit/cfbc3d3c))
- ABBA deadlock prevented in Stealer::steal() lock ordering ([`9f00fae`](https://github.com/Dicklesworthstone/asupersync/commit/9f00faed))

### Formal Verification (Lean)

- **Close/cancel protocol totality proofs** with CI manifest schema validation ([`4b4d7c0`](https://github.com/Dicklesworthstone/asupersync/commit/4b4d7c0d))
- **10 canonical-form decomposition theorems** for state ladder types ([`ad10ca4`](https://github.com/Dicklesworthstone/asupersync/commit/ad10ca4c))
- Cross-entity liveness contract with composition validation tests ([`cd1f7e9`](https://github.com/Dicklesworthstone/asupersync/commit/cd1f7e97))
- Reliability hardening contract and closed-loop impact report ([`017d4ee`](https://github.com/Dicklesworthstone/asupersync/commit/017d4eef))
- Preservation helper prelude with canonical reusable theorems ([`31e7ee4`](https://github.com/Dicklesworthstone/asupersync/commit/31e7ee41))

### Distributed

- **DistributorTransport trait** for replica symbol dispatch ([`781acac`](https://github.com/Dicklesworthstone/asupersync/commit/781acac1))
- Full snapshot application in RegionBridge ([`42365b1`](https://github.com/Dicklesworthstone/asupersync/commit/42365b16))
- Region apply_distributed_snapshot and set_budget for bridge recovery ([`46986e1`](https://github.com/Dicklesworthstone/asupersync/commit/46986e13))
- Verified symbols can replace unverified; tolerate rejected symbols ([`18481eb`](https://github.com/Dicklesworthstone/asupersync/commit/18481ebd))
- ESI acceptance range widened for high-loss recovery scenarios ([`38c4e37`](https://github.com/Dicklesworthstone/asupersync/commit/38c4e37d))
- Recovery collector verified flag not trusted when verify_integrity is enabled ([`1472e42`](https://github.com/Dicklesworthstone/asupersync/commit/1472e425))

### Combinator and Service Layer

- **Async barrier rewrite** from synchronous Condvar to Future-based ([`1079a50`](https://github.com/Dicklesworthstone/asupersync/commit/1079a501))
- ConcurrencyLimit rewritten as async state machine ([`4282f82`](https://github.com/Dicklesworthstone/asupersync/commit/4282f82d))
- Circuit breaker CallGuard prevents probe permit leak on panic ([`21fb6d1`](https://github.com/Dicklesworthstone/asupersync/commit/21fb6d12))
- BulkheadPermit converted to RAII guard with Drop, fixes zombie queue capacity leak ([`81e80be`](https://github.com/Dicklesworthstone/asupersync/commit/81e80bea))
- Bulkhead cancel releases granted-but-unclaimed permits ([`08721816`](https://github.com/Dicklesworthstone/asupersync/commit/08721816))
- Lock ordering fixed in bulkhead, circuit breaker, and rate limiter ([`0dde97d`](https://github.com/Dicklesworthstone/asupersync/commit/0dde97db))
- RwLock metrics replaced with atomic counters on hot paths ([`335a6c8`](https://github.com/Dicklesworthstone/asupersync/commit/335a6c8a))
- RAII guards for connection slots and dispatch counters in transport ([`8feb047`](https://github.com/Dicklesworthstone/asupersync/commit/8feb0477))
- Drain pending queue after cancel returns a permit ([`698c425`](https://github.com/Dicklesworthstone/asupersync/commit/698c425e))

### Channel Correctness

- Broadcast channel recv protected from u64->usize truncation on 32-bit ([`3e6cb7d`](https://github.com/Dicklesworthstone/asupersync/commit/3e6cb7de))
- Cancellation-aware partition sends and fault buffer ownership safety ([`f889405`](https://github.com/Dicklesworthstone/asupersync/commit/f8894057))
- Flush errors propagated and undelivered messages requeued in fault channel ([`e2ce5dc`](https://github.com/Dicklesworthstone/asupersync/commit/e2ce5dca))
- Reorder buffer pre-allocation preserved across flushes ([`7ee583a`](https://github.com/Dicklesworthstone/asupersync/commit/7ee583a2))

### Supervision

- Configurable tolerance added to RestartStormMonitor ([`9225331`](https://github.com/Dicklesworthstone/asupersync/commit/92253312))

### Database

- MySQL auth nonce parsing and PostgreSQL error handling robustness ([`752e164`](https://github.com/Dicklesworthstone/asupersync/commit/752e164e))
- MySQL: disambiguate 0x00 data rows from OK terminators in DEPRECATE_EOF mode ([`cfd1792`](https://github.com/Dicklesworthstone/asupersync/commit/cfd17929))
- MySQL: use negotiated capabilities for result-set parsing ([`4197df9`](https://github.com/Dicklesworthstone/asupersync/commit/4197df9f))
- PostgreSQL: return Ok after successful SCRAM authentication ([`173ed90`](https://github.com/Dicklesworthstone/asupersync/commit/173ed903))
- PostgreSQL: drain to ReadyForQuery on ErrorResponse ([`a0b8a5f`](https://github.com/Dicklesworthstone/asupersync/commit/a0b8a5f2))

### HTTP/2 Protocol

- Skipped queued outbound DATA for reset/closed streams ([`e736975`](https://github.com/Dicklesworthstone/asupersync/commit/e7369754))
- Reject PUSH_PROMISE with promised stream ID 0 per RFC 7540 ([`b8546e4`](https://github.com/Dicklesworthstone/asupersync/commit/b8546e45))
- Wire role-aware settings into connection, reject server ENABLE_PUSH ([`9111259`](https://github.com/Dicklesworthstone/asupersync/commit/91112595))
- Enforce RFC 7540 idle stream connection errors ([`b434c29`](https://github.com/Dicklesworthstone/asupersync/commit/b434c291))
- RFC 7540/7541 conformance hardening and HPACK security fixes ([`995196e`](https://github.com/Dicklesworthstone/asupersync/commit/995196e2))
- CONTINUATION on closed streams and headers_complete corruption prevented ([`fa79c39`](https://github.com/Dicklesworthstone/asupersync/commit/fa79c392))

### Sync Primitives

- Cancellation-safe barrier, lost-wakeup prevention in Notify, wake-under-lock elimination in Semaphore ([`f4ed526`](https://github.com/Dicklesworthstone/asupersync/commit/f4ed5264))
- Broadcast-cancelled Notify waiter prevented from leaking stored token ([`686716c`](https://github.com/Dicklesworthstone/asupersync/commit/686716c6))
- Mutex baton-passing coverage and OnceCell::set() retry on cancelled initializer ([`b2406c6`](https://github.com/Dicklesworthstone/asupersync/commit/b2406c6b))
- OnceCell queued waker refreshed on re-poll in get_or_init ([`c5a2dd0`](https://github.com/Dicklesworthstone/asupersync/commit/c5a2dd0a))
- Pool return-waker notification, contended_mutex poison discrimination ([`ca438a3`](https://github.com/Dicklesworthstone/asupersync/commit/ca438a34))
- BarrierWaitFuture Drop impl and type-erased ConcurrencyLimit acquire future ([`d5b0b95`](https://github.com/Dicklesworthstone/asupersync/commit/d5b0b950))

### Determinism

- HashMap migrated to DetHashMap across determinism-sensitive paths ([`bf17982`](https://github.com/Dicklesworthstone/asupersync/commit/bf179823))
- DetHasher hardened for portable hashing with little-endian encoding ([`556b5d3`](https://github.com/Dicklesworthstone/asupersync/commit/556b5d33))

### Net

- Bind/reuseaddr/reuseport configuration before TcpSocket::connect ([`50fd1f2`](https://github.com/Dicklesworthstone/asupersync/commit/50fd1f27))
- UnixDatagram::bind prevented from deleting non-socket files ([`61bdbdd`](https://github.com/Dicklesworthstone/asupersync/commit/61bddbda))
- UnixListener::bind only removes stale socket files, refuses non-socket paths ([`8fd90c5`](https://github.com/Dicklesworthstone/asupersync/commit/8fd90c55))
- TCP and Unix split locks held across driver.register() to prevent EEXIST race ([`41de223`](https://github.com/Dicklesworthstone/asupersync/commit/41de2239))

### WebSocket

- Cancel-safety and pong encoding fixed in split halves ([`27ee9ce`](https://github.com/Dicklesworthstone/asupersync/commit/27ee9cea))
- Reserved close codes rejected and 1-byte close payloads per RFC 6455 ([`0eb5467`](https://github.com/Dicklesworthstone/asupersync/commit/0eb5467b))
- Frame codec hardened for RFC 6455: minimal encoding, MSB, close reason ([`178ecaf`](https://github.com/Dicklesworthstone/asupersync/commit/178ecafc))
- Server-selected subprotocol validated against client request per RFC 6455 ([`717ed35`](https://github.com/Dicklesworthstone/asupersync/commit/717ed35c))

### Test Coverage Expansion

- **Massive B10 test wave campaign** (waves 1--87): ~2,000+ new tests covering pure data-type invariants across every module
- Comprehensive E2E test suite for QUIC/H3 (72 scenarios) ([`d317506`](https://github.com/Dicklesworthstone/asupersync/commit/d3175068))
- Database: 109 unit tests for postgres, sqlite, and migration modules ([`fa7fab2`](https://github.com/Dicklesworthstone/asupersync/commit/fa7fab29))
- Cancellation protocol and race-drain conformance tests ([`99ee740`](https://github.com/Dicklesworthstone/asupersync/commit/99ee7409))

---

## [v0.2.0](https://github.com/Dicklesworthstone/asupersync/tag/v0.2.0) -- 2026-02-15 (Tag)

> 396 commits since v0.1.1 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.1.1...v0.2.0)

Major version bump covering formal verification, deep audit, and RaptorQ decoder rewrite.

### Formal Verification (Lean 4)

- **Track-2 declaration-order stabilization** closed ([`ecc2921`](https://github.com/Dicklesworthstone/asupersync/commit/ecc29215))
- Obligation stability theorems registered and frontier tests hardened ([`96caeba`](https://github.com/Dicklesworthstone/asupersync/commit/96caeba8))
- Refinement map enriched with ownership, routing metadata, conformance tests ([`3c47575`](https://github.com/Dicklesworthstone/asupersync/commit/3c47575a))
- Lean proof-guided performance opportunity map ([`7cbb175`](https://github.com/Dicklesworthstone/asupersync/commit/7cbb1755), [`4cd59ec`](https://github.com/Dicklesworthstone/asupersync/commit/4cd59ec5))
- Track 2 burndown dashboard and CI verification profiles ([`cacb264`](https://github.com/Dicklesworthstone/asupersync/commit/cacb2648))
- Lean smoke gate job for pull requests ([`8800e82`](https://github.com/Dicklesworthstone/asupersync/commit/8800e82f))
- Proof-aware review workflow, artifact contract tests ([`68d09cc`](https://github.com/Dicklesworthstone/asupersync/commit/68d09cc1))

### RaptorQ Decoder

- **RFC 6330 tuple semantics** and repair equation generation ([`d8c37ad`](https://github.com/Dicklesworthstone/asupersync/commit/d8c37ad4))
- **RFC 6330 Table 2 lookup** replacing ad-hoc parameter derivation ([`5bf62fb`](https://github.com/Dicklesworthstone/asupersync/commit/5bf62fb7))
- **RFC 6330 golden vector conformance suite** ([`666d705`](https://github.com/Dicklesworthstone/asupersync/commit/666d705a))
- **Metamorphic property erasure-recovery** test battery ([`fe0d7de`](https://github.com/Dicklesworthstone/asupersync/commit/fe0d7dee))
- GF256 AVX2 and NEON SIMD intrinsics with feature-gated unsafe ([`4c51ee6`](https://github.com/Dicklesworthstone/asupersync/commit/4c51ee64))
- SIMD kernel dispatch infrastructure with AVX2/NEON scaffolds ([`47ed283`](https://github.com/Dicklesworthstone/asupersync/commit/47ed283a))
- Legacy soliton-based repair path removed, unified on RFC 6330 tuples ([`1c062a5`](https://github.com/Dicklesworthstone/asupersync/commit/1c062a50))
- Full pivoting in systematic constraint solver ([`a720f11`](https://github.com/Dicklesworthstone/asupersync/commit/a720f115))
- Minimum-degree row selection for constraint matrix pivoting ([`957c50b`](https://github.com/Dicklesworthstone/asupersync/commit/957c50b4))
- Deterministic D6 E2E scenario runner with profile support ([`da10a1a`](https://github.com/Dicklesworthstone/asupersync/commit/da10a1a0))
- Deterministic pivot tie-breaking tests and GF256 replay catalog ([`96dc92d`](https://github.com/Dicklesworthstone/asupersync/commit/96dc92d5))
- Canonical test log schema (D7) with failure context migration ([`49965c2`](https://github.com/Dicklesworthstone/asupersync/commit/49965c2e))
- SIMD intrinsics made opt-in for stable Rust compatibility ([`5a6a753`](https://github.com/Dicklesworthstone/asupersync/commit/5a6a753c))

### Runtime Correctness

- Macaroon discharge first-party caveats evaluated during verification ([`79fc52a`](https://github.com/Dicklesworthstone/asupersync/commit/79fc52af))
- Spurious cancel prevented when dropping ready JoinFuture ([`8834c12`](https://github.com/Dicklesworthstone/asupersync/commit/8834c12e))
- Scheduler collision slots collapsed when task generations drain ([`b202312`](https://github.com/Dicklesworthstone/asupersync/commit/b202312b))
- Blocking pool idle-thread retirement uses atomic CAS to prevent undershoot ([`441c7f5`](https://github.com/Dicklesworthstone/asupersync/commit/441c7f5c))
- Atomic saturating_decrement and polls_remaining consumption ([`467fcd3`](https://github.com/Dicklesworthstone/asupersync/commit/467fcd3b))
- Governor_interval=0 normalization and env config coverage expanded ([`38bd7e1`](https://github.com/Dicklesworthstone/asupersync/commit/38bd7e10))
- LeakEscalation threshold=0 clamped to 1 ([`a9442b5`](https://github.com/Dicklesworthstone/asupersync/commit/a9442b53))
- Region heap alloc made transactional w.r.t. stats ([`91f002b`](https://github.com/Dicklesworthstone/asupersync/commit/91f002b7))

### Channel and Sync

- Wake outside lock in broadcast and oneshot channels ([`a821183`](https://github.com/Dicklesworthstone/asupersync/commit/a8211831))
- Wake-under-lock deadlock prevented in mpsc sender cascade ([`c90c4ad`](https://github.com/Dicklesworthstone/asupersync/commit/c90c4ade))
- Integer-precision drift calculation and exhaustive waker cleanup on terminal paths ([`f0a7ce7`](https://github.com/Dicklesworthstone/asupersync/commit/f0a7ce7c))
- Double-panic abort prevented in mpsc and watch channel Drop impls ([`47d2c03`](https://github.com/Dicklesworthstone/asupersync/commit/47d2c03d), [`add13a3`](https://github.com/Dicklesworthstone/asupersync/commit/add13a3d))
- Waker lifecycle, permit semantics, and evidence emission fixes ([`5136714`](https://github.com/Dicklesworthstone/asupersync/commit/51367145))
- Waker-while-locked hazards eliminated in TCP and WebSocket split halves ([`6004fc3`](https://github.com/Dicklesworthstone/asupersync/commit/6004fc3f))

### Reactor

- events.len() corrected for kqueue, macOS kqueue, and Windows IOCP poll ([`775ffdf`](https://github.com/Dicklesworthstone/asupersync/commit/775ffdfb))
- epoll poll returns count of actually stored events ([`5d74e64`](https://github.com/Dicklesworthstone/asupersync/commit/5d74e642))
- Adapted to polling 3.11 Events API ([`b01c40c`](https://github.com/Dicklesworthstone/asupersync/commit/b01c40c4))
- io_uring fcntl pre-flight check for modify() early stale-fd pruning ([`4b87067`](https://github.com/Dicklesworthstone/asupersync/commit/4b870679))
- Poll_events mutex guard dropped before returning from EpollReactor::poll ([`5da8d49`](https://github.com/Dicklesworthstone/asupersync/commit/5da8d49d))

### Networking

- TCP split test guard drops and CombinedWaker for owned split halves ([`7a8d7cf`](https://github.com/Dicklesworthstone/asupersync/commit/7a8d7cf7))
- MX records sorted by RFC-priority order on construction ([`98b4ec2`](https://github.com/Dicklesworthstone/asupersync/commit/98b4ec24))
- Non-UTF8 Unix paths supported in io-uring path_to_cstring helpers ([`bc4cb65`](https://github.com/Dicklesworthstone/asupersync/commit/bc4cb65e))
- TCP/Unix split combined waiter interest on re-registration ([`b035ae6`](https://github.com/Dicklesworthstone/asupersync/commit/b035ae68), [`c841b9d`](https://github.com/Dicklesworthstone/asupersync/commit/c841b9da))

### H2 Protocol

- last_stream_id tracked for GOAWAY, CONTINUATION interleaving prevented ([`b94f07b`](https://github.com/Dicklesworthstone/asupersync/commit/b94f07bd))
- last_stream_id pollution on rejected HEADERS prevented ([`ed85b9b`](https://github.com/Dicklesworthstone/asupersync/commit/ed85b9bd))
- Zero-increment WINDOW_UPDATE on stream is stream error, not connection ([`1f65a18`](https://github.com/Dicklesworthstone/asupersync/commit/1f65a187))
- RFC 7540 error classification corrected for PRIORITY and WINDOW_UPDATE ([`2965fab`](https://github.com/Dicklesworthstone/asupersync/commit/2965fabf))

### Combinator

- Select polls both futures each tick so loser gets initialized ([`63525618`](https://github.com/Dicklesworthstone/asupersync/commit/63525618))
- join2 dual-cancellation strengthening and SelectAllDrain simultaneous-ready safety ([`520c561`](https://github.com/Dicklesworthstone/asupersync/commit/520c561e))
- Bracket catch panics from release future during Drop to prevent abort ([`49d6ac7`](https://github.com/Dicklesworthstone/asupersync/commit/49d6ac7c))
- Bracket drives release future to completion when dropped during Releasing phase ([`41c0e45`](https://github.com/Dicklesworthstone/asupersync/commit/41c0e45b))
- Saturating arithmetic strengthened in circuit breaker, scheduler, transport ([`357bebd`](https://github.com/Dicklesworthstone/asupersync/commit/357bebd3))
- Map_reduce edge cases hardened ([`2cb3dba`](https://github.com/Dicklesworthstone/asupersync/commit/2cb3dba2))

### Choreography

- Loop label scoping and Continue projection bugs fixed ([`3621d7a`](https://github.com/Dicklesworthstone/asupersync/commit/3621d7a6))
- first_active_participant traverses inert Seq/Par prefixes ([`271b6da`](https://github.com/Dicklesworthstone/asupersync/commit/271b6da0))
- Loop codegen break, duplicate participant detection ([`7d6a2d1`](https://github.com/Dicklesworthstone/asupersync/commit/7d6a2d17))
- Parallel knowledge-of-choice validation, compensation stubs, LabRuntime tests ([`a9d7e13`](https://github.com/Dicklesworthstone/asupersync/commit/a9d7e13f))

### Deep Audit Campaign

- Extensive deep audit of major subsystems, all confirmed SOUND
- Scheduler (worker, local_queue, global_injector), gen_server, blocking_pool, io_driver, bulkhead, channel subsystem, transport/aggregator, fs/uring, tcp/split, sharded_state, resource_accounting, time/driver, kafka ([`82a9d3f`](https://github.com/Dicklesworthstone/asupersync/commit/82a9d3f3), [`85cc3a1`](https://github.com/Dicklesworthstone/asupersync/commit/85cc3a15), [`f0133e3`](https://github.com/Dicklesworthstone/asupersync/commit/f0133e32))

### Performance Tuning

- #[inline] on hot-path cancel check, Cx clone, DetRng PRNG methods ([`0451e25`](https://github.com/Dicklesworthstone/asupersync/commit/0451e256), [`9e0f2e8`](https://github.com/Dicklesworthstone/asupersync/commit/9e0f2e8d))
- Atomic orderings relaxed, scheduler allocations eliminated, Cx clone consolidated ([`027821f`](https://github.com/Dicklesworthstone/asupersync/commit/027821f4))
- Scheduler skip cancel-lane rebuild when re-promotion priority is same or lower ([`316e7f7`](https://github.com/Dicklesworthstone/asupersync/commit/316e7f73))
- SmallVec for hot-path waker collections ([`aa3b61a`](https://github.com/Dicklesworthstone/asupersync/commit/aa3b61a4))

### CI

- Tag-triggered builds and owner-routing in Lean failure payloads ([`bf8a3c4`](https://github.com/Dicklesworthstone/asupersync/commit/bf8a3c44))
- Lean smoke gate, full gate, and bundle config in CI profiles ([`cb9cd9a`](https://github.com/Dicklesworthstone/asupersync/commit/cb9cd9aa))
- Nightly toolchain pinned to 2026-02-05 for reproducible builds ([`ef2540c`](https://github.com/Dicklesworthstone/asupersync/commit/ef2540c0))

### Dependencies

- polling 2.8 to 3.11, opentelemetry{,_sdk} 0.28 to 0.31 ([`0cef3b6`](https://github.com/Dicklesworthstone/asupersync/commit/0cef3b6b))
- rusqlite 0.33 to 0.38, rcgen 0.13 to 0.14, lz4_flex 0.11 to 0.12, toml 0.8 to 1.0, webpki-roots 0.26 to 1.0 ([`1f5733f`](https://github.com/Dicklesworthstone/asupersync/commit/1f5733f3), [`f2e5164`](https://github.com/Dicklesworthstone/asupersync/commit/f2e51646), [`d7ea4cf`](https://github.com/Dicklesworthstone/asupersync/commit/d7ea4cfe))

### Observability

- Lock-free resource accounting ([`4c68494`](https://github.com/Dicklesworthstone/asupersync/commit/4c68494b))
- Conformance test runner (cancellation protocol and race-drain) ([`99ee740`](https://github.com/Dicklesworthstone/asupersync/commit/99ee7409))
- 88 new trace event tests, 31 trace integrity tests, 24 trace recorder tests ([`6cdab62`](https://github.com/Dicklesworthstone/asupersync/commit/6cdab62a), [`aa8f0a4`](https://github.com/Dicklesworthstone/asupersync/commit/aa8f0a44), [`d0fe05d`](https://github.com/Dicklesworthstone/asupersync/commit/d0fe05db))

---

## [v0.1.1](https://github.com/Dicklesworthstone/asupersync/tag/v0.1.1) -- 2026-02-07 (Tag)

> 3 commits since v0.1.0 | [compare](https://github.com/Dicklesworthstone/asupersync/compare/v0.1.0...v0.1.1)

- Exclude `.out` files from crate package and fix match arm syntax ([`67f660c`](https://github.com/Dicklesworthstone/asupersync/commit/67f660cc))
- Add `.tmp/` to `.gitignore` ([`e8f03f1`](https://github.com/Dicklesworthstone/asupersync/commit/e8f03f18))

---

## [v0.1.0](https://github.com/Dicklesworthstone/asupersync/tag/v0.1.0) -- 2026-02-06 (Tag)

> ~1,650 commits | Initial public milestone

The initial tagged milestone establishing the core async runtime with structured concurrency, cancel-correctness, and capability security.

### Core Runtime

- **Structured concurrency** with region-based task ownership -- every spawned task belongs to a region that closes to quiescence ([`33335ea`](https://github.com/Dicklesworthstone/asupersync/commit/33335ea3))
- **Cancel-correct protocol**: cancellation is request, drain, finalize -- never silent data loss
- **Capability-secure effects**: all effects flow through explicit `Cx` context; no ambient authority
- **Four-valued Outcome**: `Ok`, `Err`, `Cancelled(reason)`, `Panicked(payload)` with severity lattice
- **Lab runtime**: deterministic testing with virtual time, deterministic scheduling, and trace replay
- **Test oracle module** for runtime invariant verification ([`dc03abd`](https://github.com/Dicklesworthstone/asupersync/commit/dc03abd8))

### Channels (Two-Phase Send)

- **MPSC channel** with reserve/commit pattern ([`73dab81`](https://github.com/Dicklesworthstone/asupersync/commit/73dab815))
- **Oneshot channel** with reserve/commit pattern ([`0f478cd`](https://github.com/Dicklesworthstone/asupersync/commit/0f478cd9))
- **Broadcast channel** with two-phase send and lagging receiver detection
- **Watch channel** with borrow-and-clone semantics

### Sync Primitives

- Two-phase sync primitives with guard obligations ([`cb7b1f1`](https://github.com/Dicklesworthstone/asupersync/commit/cb7b1f1c))
- Mutex, RwLock, Semaphore, Barrier, Notify, OnceCell -- all cancel-aware with `&Cx`

### Combinators

- **join_all**, **race_all** (N-way), **select** (2-way), **first_ok**, **pipeline**, **map_reduce** ([`945414a`](https://github.com/Dicklesworthstone/asupersync/commit/945414a6), [`d04745b`](https://github.com/Dicklesworthstone/asupersync/commit/d04745bc), [`34fe222`](https://github.com/Dicklesworthstone/asupersync/commit/34fe2220), [`d457794`](https://github.com/Dicklesworthstone/asupersync/commit/d457794c))
- **Bulkhead** combinator with queue timeout ([`180dc9e`](https://github.com/Dicklesworthstone/asupersync/commit/180dc9ea))
- **Circuit breaker** with half-open probing
- **Bracket** combinator: cancel-safe resource acquisition with Drop-based release ([`fdb20e7`](https://github.com/Dicklesworthstone/asupersync/commit/fdb20e76))

### Time

- Sleep and Timeout primitives with explicit time sources ([`1a58619`](https://github.com/Dicklesworthstone/asupersync/commit/1a586194))
- Timer wheel for efficient timeout management
- Works with virtual time in lab runtime for deterministic testing

### Scheduler

- EDF (Earliest Deadline First) scheduling with bug fixes ([`3787abb`](https://github.com/Dicklesworthstone/asupersync/commit/3787abbf))
- Three-lane priority scheduler
- Work-stealing with local queues and global injector

### I/O and Networking

- TCP, UDP, Unix stream/datagram support
- I/O conformance test suite (IO-001 through IO-007) ([`6a9a876`](https://github.com/Dicklesworthstone/asupersync/commit/6a9a876f))
- HTTP/1 and HTTP/2 codec and connection management
- TLS with ALPN negotiation

### Supervision (Spork/OTP Model)

- **GenServer** with init/terminate lifecycle and trace schema ([`c6a9068`](https://github.com/Dicklesworthstone/asupersync/commit/c6a90682))
- **Restart storm detection** via anytime-valid e-processes ([`500ac33`](https://github.com/Dicklesworthstone/asupersync/commit/500ac33c))
- **Conformal calibration** for health thresholds ([`b0ed01f`](https://github.com/Dicklesworthstone/asupersync/commit/b0ed01f9))
- **CrashPack**: golden snapshots, replay tests, artifact writer capability, versioned manifest ([`267153c`](https://github.com/Dicklesworthstone/asupersync/commit/267153cd), [`3ba14c7`](https://github.com/Dicklesworthstone/asupersync/commit/3ba14c75))
- **Link/Monitor system** with LinkedExit cancel kind and trap-exit policy ([`756d65d`](https://github.com/Dicklesworthstone/asupersync/commit/756d65db))
- NamePermit reserve/commit with linear obligations ([`13cbc6a`](https://github.com/Dicklesworthstone/asupersync/commit/13cbc6ae))
- Deterministic collision resolution for NameRegistry ([`77cd887`](https://github.com/Dicklesworthstone/asupersync/commit/77cd887e))
- AppSpec compiled to SupervisorSpec + Regions ([`50e566c`](https://github.com/Dicklesworthstone/asupersync/commit/50e566c9))

### RaptorQ (FEC)

- Core symbol types and encoding/decoding pipeline
- Benchmark baselines ([`74784392`](https://github.com/Dicklesworthstone/asupersync/commit/74784392))

### Formal Verification

- Determinism oracle ([`1b33dad`](https://github.com/Dicklesworthstone/asupersync/commit/1b33dad4))
- Divergent prefix minimizer ([`3d38c21`](https://github.com/Dicklesworthstone/asupersync/commit/3d38c21a))

### Documentation

- Comprehensive README with architecture diagrams, tokio mapping table, and quick examples
- Spork OTP mental model section ([`f26f319`](https://github.com/Dicklesworthstone/asupersync/commit/f26f319f))
- Networking, database, channels, and observability architecture sections ([`c367fd5`](https://github.com/Dicklesworthstone/asupersync/commit/c367fd54))

---

[Unreleased]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.9...HEAD
[v0.2.9]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.8...v0.2.9
[v0.2.8]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.7...v0.2.8
[v0.2.7]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.6...v0.2.7
[v0.2.6]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.5...v0.2.6
[v0.2.5]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.4...v0.2.5
[v0.2.4]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.3...v0.2.4
[v0.2.3]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.2...v0.2.3
[v0.2.2]: https://github.com/Dicklesworthstone/asupersync/compare/v0.2.0...v0.2.2
[v0.2.0]: https://github.com/Dicklesworthstone/asupersync/compare/v0.1.1...v0.2.0
[v0.1.1]: https://github.com/Dicklesworthstone/asupersync/compare/v0.1.0...v0.1.1
[v0.1.0]: https://github.com/Dicklesworthstone/asupersync/commits/v0.1.0
