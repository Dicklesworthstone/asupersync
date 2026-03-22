# Changelog

All notable changes to [Asupersync](https://github.com/Dicklesworthstone/asupersync) are documented here.

Asupersync is a spec-first, cancel-correct, capability-secure async runtime for Rust.

**Format notes:**

- Versions with a GitHub Release link are published releases with downloadable binaries. Plain git tags are milestone markers without release artifacts.
- Commit links point to representative commits, not exhaustive lists.
- Organized by landed capabilities within each version.

---

## [Unreleased]

---

## [v0.2.9](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.2.9) -- 2026-03-21

> 460 commits since v0.2.8 | 2026-03-15 to 2026-03-21

### FABRIC Messaging Engine

Major expansion of the brokerless subject-oriented messaging system (FABRIC). This is the most active area of post-v0.2.8 development.

- **Session projection engine** with duality verification for two-party protocols ([`3614ffd`](https://github.com/Dicklesworthstone/asupersync/commit/3614ffdb24d1c28847993237feb2f3f5d240913d))
- **Semantic execution lane planner** for SubjectCell conversation families ([`85cebd4`](https://github.com/Dicklesworthstone/asupersync/commit/85cebd4f8228da96246347c830d6d3159bd681be))
- **Deterministic protocol-scaffolding synthesis** for FABRIC sessions ([`0ff5530`](https://github.com/Dicklesworthstone/asupersync/commit/0ff553075928db2249f969f409367a09f39ffc57))
- **SafetyEnvelope** for adaptive reliability tuning with runtime health evaluator ([`daf9c57`](https://github.com/Dicklesworthstone/asupersync/commit/daf9c572c98c4d637ca94d68362c84a835e3ebd2))
- **Fabric discovery sessions**, operator intent compiler, recoverable service capsules, IR monotone normalization ([`8fe3bb2`](https://github.com/Dicklesworthstone/asupersync/commit/8fe3bb25bb3511343df799d60c6471fa9824f566))
- **Delegated cursor partitions**, federation bridge runtime, multi-tenant namespace kernel ([`b69c261`](https://github.com/Dicklesworthstone/asupersync/commit/b69c2613920a2fdb9f5ad02e49dd702d3a003d00))
- Shared fabric state registry with HMAC-SHA256 cell key hierarchy ([`2112b1f`](https://github.com/Dicklesworthstone/asupersync/commit/2112b1f))
- Certificate-carrying request/reply protocol with chunked reply obligations ([`a0cd1ad`](https://github.com/Dicklesworthstone/asupersync/commit/a0cd1ad))
- Branch-addressable reality framework for cut-certified mobility ([`45859b0`](https://github.com/Dicklesworthstone/asupersync/commit/45859b0))
- Full FABRIC IR compilation with artifact registry ([`670d072`](https://github.com/Dicklesworthstone/asupersync/commit/670d072))
- Delta-CRDT metadata layer for non-authoritative control surfaces ([`2d4561a`](https://github.com/Dicklesworthstone/asupersync/commit/2d4561a))
- Adaptive consumer kernel with overflow policy and decision audit ([`9f1d79b`](https://github.com/Dicklesworthstone/asupersync/commit/9f1d79b))
- Privacy-preserving metadata export with blinding and differential-privacy noise ([`c5878b6`](https://github.com/Dicklesworthstone/asupersync/commit/c5878b6))
- Obligation-backed consumer delivery with redelivery, dead-letter, and stats ([`b93be30`](https://github.com/Dicklesworthstone/asupersync/commit/b93be30))
- Saga/Workflow obligation types re-exported from service module ([`017ba9e`](https://github.com/Dicklesworthstone/asupersync/commit/017ba9efd33c9b7662887a353736a5f47bdcea5f))
- Repair symbol binding, rebalance cut certification, cell epoch rebind ([`566728a`](https://github.com/Dicklesworthstone/asupersync/commit/566728a5399320520cd62290c81da7672b65db39))

### Bug Fixes (Messaging)

- Gate e-process reset on Alert state to prevent spurious resets at confidence cap ([`f54dd73`](https://github.com/Dicklesworthstone/asupersync/commit/f54dd73d1382319fc2b227e926787e425ab8bd78))
- Enforce max_deliver in Stable kernel mode, normalize unique-key validation ([`fc0741d`](https://github.com/Dicklesworthstone/asupersync/commit/fc0741d))
- Consumer ack_floor cannot advance past pending windows ([`3a8752f`](https://github.com/Dicklesworthstone/asupersync/commit/3a8752f))
- Cap decision_log to prevent unbounded memory growth ([`1387df3`](https://github.com/Dicklesworthstone/asupersync/commit/1387df3))
- Prune expired revocation entries to prevent unbounded growth ([`3126295`](https://github.com/Dicklesworthstone/asupersync/commit/3126295))
- Redis PubSub ping preserves interleaved subscription messages ([`ce038cc`](https://github.com/Dicklesworthstone/asupersync/commit/ce038cc))
- Cap pending_events buffer during PubSub ping ([`c4b6e99`](https://github.com/Dicklesworthstone/asupersync/commit/c4b6e99))
- Certify_self_rebalance mut binding, JetStream JSON unicode unescaping ([`f6466ee`](https://github.com/Dicklesworthstone/asupersync/commit/f6466ee))

### Runtime & Sync

- Correct notify baton-passing when broadcast follows notify_one ([`fdc7a60`](https://github.com/Dicklesworthstone/asupersync/commit/fdc7a60ea08d657e569f589217c8617c3c97b0fb))
- Remove spurious baton passing when a notified waiter is dropped before poll ([`c10ca2a`](https://github.com/Dicklesworthstone/asupersync/commit/c10ca2a))
- Supervised actor restart no longer leaves actor in Stopping state (deadlock fix) ([`7812876`](https://github.com/Dicklesworthstone/asupersync/commit/781287694420e7084b98aba22f56e2932d934c65))
- Saga Drop panicking guard + circuit breaker Acquire ordering ([`79d25ca`](https://github.com/Dicklesworthstone/asupersync/commit/79d25ca))

### Networking, HTTP & gRPC

- Malformed grpc-timeout header fails closed instead of falling back to server default ([`e38a3b1`](https://github.com/Dicklesworthstone/asupersync/commit/e38a3b11dcad8203f1795c06218a221f15086dfd))
- Preserve handler Content-Length in HEAD responses per RFC 9110 section 9.3.2 ([`c10f4f9`](https://github.com/Dicklesworthstone/asupersync/commit/c10f4f9d7fb57812056ef26faa1d773107a7656c))
- Enforce max_concurrent_streams for incoming remote-initiated H2 streams ([`0e27de0`](https://github.com/Dicklesworthstone/asupersync/commit/0e27de0))
- Suppress spurious control traffic from cancel-ack and drain-request after shutdown ([`54bcaba`](https://github.com/Dicklesworthstone/asupersync/commit/54bcaba22e8b02b7c647454ba35a6e75bb5450ae))
- WebSocket: accept RFC-reserved close codes on receive, enforce 125-byte close payload limit ([`39cc2bf`](https://github.com/Dicklesworthstone/asupersync/commit/39cc2bf))
- FramedCodec::with_frame_hooks for gRPC compression hooks ([`d771979`](https://github.com/Dicklesworthstone/asupersync/commit/d771979162b168a65ba7795d177ef8159a62f89f))

### TLS & Security

- Fail closed on missing close_notify per RFC 8446 ([`602571e`](https://github.com/Dicklesworthstone/asupersync/commit/602571e8f747f7253f4aaa335f0272146fe5e2a4))
- Improve certificate directory scanning robustness ([`8780cbc`](https://github.com/Dicklesworthstone/asupersync/commit/8780cbc))
- Expand TLS connector with additional protocol negotiation and certificate handling ([`7127afc`](https://github.com/Dicklesworthstone/asupersync/commit/7127afc))

### Filesystem & I/O

- Correct 0o777 mode for io-uring create_dir, preserve file permissions in write_atomic ([`510fe8e`](https://github.com/Dicklesworthstone/asupersync/commit/510fe8e809fb66771d2271b06d6905cd967252d5))
- copy_buf tracks read_done state to flush correctly after EOF ([`1277755`](https://github.com/Dicklesworthstone/asupersync/commit/1277755))
- BufReader::capacity() accessor and safety doc comments ([`44459fe`](https://github.com/Dicklesworthstone/asupersync/commit/44459fe1111121e0e677703a484f732a1d2f9d8f))

### Service & Transport Layer

- Buffer pending counter leak on poll_ready errors ([`192c361`](https://github.com/Dicklesworthstone/asupersync/commit/192c361cdee02d0f2dfd0da40dfe8b732c9b2aad))
- Release pending slot before buffer transitions to Error state ([`f1789b0`](https://github.com/Dicklesworthstone/asupersync/commit/f1789b04d5a2a0397731321b13a4e26d3c3979f4))
- Prevent buffer pending slot leak on panic in call() ([`1fad761`](https://github.com/Dicklesworthstone/asupersync/commit/1fad761))
- Weighted load balancer tracks active_backend_count ([`2634deb`](https://github.com/Dicklesworthstone/asupersync/commit/2634deb))
- Weight-aware select_n for WeightedRoundRobin load balancing ([`3575ccf`](https://github.com/Dicklesworthstone/asupersync/commit/3575ccf82126484de00d48fb61f90b184859e265))
- Rollback_record, dedup drain, and expiry-driven eviction to symbol aggregator ([`297cc5c`](https://github.com/Dicklesworthstone/asupersync/commit/297cc5c3f695643d32471514c644c1cf4bced25b))
- Transport prune_expired includes default route TTL enforcement ([`a9fe79a`](https://github.com/Dicklesworthstone/asupersync/commit/a9fe79a))

### WASM / Browser

- Shared-worker coordinator scaffolding with bounded attach and version handshake ([`f97de80`](https://github.com/Dicklesworthstone/asupersync/commit/f97de80a3a35b8a442158f9fb491e3f8988a1411))
- Dedicated-worker matrix and execution-ladder diagnostics ([`7fb0c49`](https://github.com/Dicklesworthstone/asupersync/commit/7fb0c490220f0fb44b3d441bdc2aa6a350b1f16e))
- Lane-health retry window coverage, browser runtime selection and scope selection ([`bdc84b7`](https://github.com/Dicklesworthstone/asupersync/commit/bdc84b7), [`2409c4b`](https://github.com/Dicklesworthstone/asupersync/commit/2409c4b))

### RaptorQ (RFC 6330)

- Profile-pack v5 schema with decision_evidence_status tracking ([`69916e1`](https://github.com/Dicklesworthstone/asupersync/commit/69916e19cb01e6585d2091dfc556f730da0d5a4f))
- c==1 addmul scope boundary and DUAL-008 scenario ([`ed86413`](https://github.com/Dicklesworthstone/asupersync/commit/ed8641332cbb078994f3ada2e16e1cb25ed48d1a))
- Override truthfulness -- manual env overrides scrub canonical selection metadata ([`a75d63f`](https://github.com/Dicklesworthstone/asupersync/commit/a75d63f))
- Stricter test log schema validation ([`ed80616`](https://github.com/Dicklesworthstone/asupersync/commit/ed806169b20e67e03d7ae37eb326b78dcf9b634c))

### Lab & Testing

- Expand differential runner with 3 new scenarios, optional final policy, and executable anchor inventory ([`934a034`](https://github.com/Dicklesworthstone/asupersync/commit/934a034a5931bbbda14703c8cf83556a653a0a30))
- Deadlocked health classification from explicit trapped wait-cycle evidence ([`bd4b6b1`](https://github.com/Dicklesworthstone/asupersync/commit/bd4b6b1ac7a121ad368c30e416e7181eab3126a6))
- DPOR queue dedup, topology frontier score upgrades, fuzz multi-category minimization ([`637f777`](https://github.com/Dicklesworthstone/asupersync/commit/637f777))

### Audit

- Comprehensive soundness audit batches 401--415, covering messaging, service, scheduler, HPACK, intrusive queue, distributed/recovery, and more (approximately 60,000+ lines reviewed, all SOUND)

### Integer Safety

- Replace silent u128-to-u64 truncation across 24 files with saturating arithmetic ([`5c1e971`](https://github.com/Dicklesworthstone/asupersync/commit/5c1e971))
- Prevent u32 overflow in scheduler depth sum and obligation balance ([`a8fc634`](https://github.com/Dicklesworthstone/asupersync/commit/a8fc634), [`3058a3b`](https://github.com/Dicklesworthstone/asupersync/commit/3058a3b))

---

## [v0.2.8](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.2.8) -- 2026-03-15

> **GitHub Release** | 958 commits since v0.2.7 | Tag: [`e848752`](https://github.com/Dicklesworthstone/asupersync/commit/e848752be3699cfbda1c211b6ca42cf6282b67cc)
>
> Binaries: Linux x86_64, macOS arm64, Windows x86_64

The largest release to date. 228 features, 445 bug fixes, and a comprehensive multi-hundred-file soundness audit.

### Injectable Time Sources (Ambient Authority Removal)

A systematic sweep replaced all ambient `Instant::now()` and `SystemTime::now()` calls with injectable `Time` sources, a key step toward full capability security. This unlocks deterministic testing across the entire crate.

- DNS resolver, Happy Eyeballs, TcpListener accept storm detection ([`d9ca428`](https://github.com/Dicklesworthstone/asupersync/commit/d9ca42809d552645c8897ad40d757a703f91b0d8), [`5c7ff7c`](https://github.com/Dicklesworthstone/asupersync/commit/5c7ff7cd026d786c5910937e3a2ba9d3da0855d7))
- HttpClient, Http1Listener, DbPool, GracePeriodGuard, BlockingPool ([`64f96b4`](https://github.com/Dicklesworthstone/asupersync/commit/64f96b41c72f1595b1c33c5bbbd3c4263a2bef1f), [`29eecc6`](https://github.com/Dicklesworthstone/asupersync/commit/29eecc6e3f19f92189eaa565316ce4f2c4b963cd), [`48a8c55`](https://github.com/Dicklesworthstone/asupersync/commit/48a8c55a72ed4cfe7211008ad28881f2b393e0b6), [`345112f`](https://github.com/Dicklesworthstone/asupersync/commit/345112f33109a219bcf4b2d12cb8e1c63bf473c4))
- Debounce, Throttle stream combinators ([`b09b95c`](https://github.com/Dicklesworthstone/asupersync/commit/b09b95c795c6c33a8b234af3cb542cb77d1e9756))
- WebSocket: replace ambient entropy with capability-plumbed EntropySource ([`3037a6e`](https://github.com/Dicklesworthstone/asupersync/commit/3037a6e64f9db3ae8d970eb162a3d9c8646ec409))
- Server and service layers ([`54ad209`](https://github.com/Dicklesworthstone/asupersync/commit/54ad209a3f3b1b90dba2ad7665a0b532cace7103))

### Cooperative Yielding Budgets

Prevents executor monopolization by enforcing yield budgets across stream consumers, codec readers, and transport operators.

- Streams: Buffered, BufferUnordered, Merge, chunks, forward, try_stream ([`8d1e1c4`](https://github.com/Dicklesworthstone/asupersync/commit/8d1e1c4), [`fe1a840`](https://github.com/Dicklesworthstone/asupersync/commit/fe1a84051aab37aeef6049917a5320d201f76645), [`859c9c5`](https://github.com/Dicklesworthstone/asupersync/commit/859c9c504bdaa969e61d50ec8a94423680758a02))
- Transport sink and stream ([`95f8222`](https://github.com/Dicklesworthstone/asupersync/commit/95f82220539817ff87f55948fa5c75acabdd83bd))
- Codec: Framed and FramedRead ([`7c92a36`](https://github.com/Dicklesworthstone/asupersync/commit/7c92a365d02b51e1ee2f494a8725fd556d65ee4f))
- Service retry and collect_to_set ([`52a5137`](https://github.com/Dicklesworthstone/asupersync/commit/52a51376f74cf01a886a9d6217a58b9c0e671b65))

### Service Layer

Feature-complete middleware stack modeled after Tower, with cancel-correctness built in.

- **Load balancer** with round-robin, P2C, and weighted strategies ([`de61c62`](https://github.com/Dicklesworthstone/asupersync/commit/de61c626049ce2219078be5744330e0358379313))
- **Service discovery** trait with DNS implementation ([`ee7b879`](https://github.com/Dicklesworthstone/asupersync/commit/ee7b879f83323cd12e7a5c1e9ac5f448060a4bf3))
- **Buffer** service layer with bounded request queuing ([`15ced24`](https://github.com/Dicklesworthstone/asupersync/commit/15ced248040e031ff27e77a953a0826297587492))
- **Reconnect and hedge** middleware layers ([`77e8d0d`](https://github.com/Dicklesworthstone/asupersync/commit/77e8d0df4144be9e45ace5b9af9978a14f6fd252))
- **Steer and filter** service combinators ([`7933276`](https://github.com/Dicklesworthstone/asupersync/commit/793327611b904d713d7bfe68869e4aa09f6e3523))
- Discover-driven topology updates to LoadBalancer ([`765f9f3`](https://github.com/Dicklesworthstone/asupersync/commit/765f9f34a181ec4ced3a8f61f8e1f327c7e875f9))
- Unified NotReady error variant across all service middlewares ([`fbf95a7`](https://github.com/Dicklesworthstone/asupersync/commit/fbf95a7f14e58e0494df51d4f50be0b71b6d8535))
- Readiness contracts and test coverage for filter, hedge, and timeout ([`2e97eee`](https://github.com/Dicklesworthstone/asupersync/commit/2e97eeea37d91bc732e389d6eebcbadb4d2b6481))
- Weighted strategy state sync on topology changes ([`06229d0`](https://github.com/Dicklesworthstone/asupersync/commit/06229d031492cd22fefdfa1cc5c6138bd0849736))

### HTTP Client & Server

- HTTP/1.1 keep-alive connection reuse ([`24f93dc`](https://github.com/Dicklesworthstone/asupersync/commit/24f93dca7a838dbc9f5d76301cde4ee987bd1bf4))
- Request/Response builder API with fluent method chaining ([`3f91079`](https://github.com/Dicklesworthstone/asupersync/commit/3f91079be46bd53b9a8d26511fd4b181c4f20c55))
- HTTP CONNECT tunnel and Expect: 100-continue handling ([`b735cd1`](https://github.com/Dicklesworthstone/asupersync/commit/b735cd1ead6ab329c60cbd72c5b349f8625bed5f))
- Proxy, cookie, multipart, pool reuse ([`a7a3699`](https://github.com/Dicklesworthstone/asupersync/commit/a7a3699036c298ab803bcac4381a6c47422fc11c))
- StatusCode type and request/response ergonomics ([`5f3cb3f`](https://github.com/Dicklesworthstone/asupersync/commit/5f3cb3f16d581070507f393b3261469a7298d998))
- Stale connection retry, idle cleanup, and reactor self-wake on registration ([`35498cd`](https://github.com/Dicklesworthstone/asupersync/commit/35498cd1a4810702873bcc4246e5cd1dd2db9d74))
- Http1ListenerStats diagnostic counters ([`c6b8668`](https://github.com/Dicklesworthstone/asupersync/commit/c6b8668a17d0078432967b119babbeb308c9d4b7))
- Cx parameter to HttpClient for cancel-correctness ([`115d796`](https://github.com/Dicklesworthstone/asupersync/commit/115d796))

### gRPC

- gRPC-web protocol support module ([`6c253b9`](https://github.com/Dicklesworthstone/asupersync/commit/6c253b972e32b067ae95bebf98f9015a86d21bf7))
- gzip frame compression/decompression with flate2 ([`cd6c692`](https://github.com/Dicklesworthstone/asupersync/commit/cd6c69273b8971a6a625bc297096416844b72a89))
- HealthWatcher, grpc-timeout parsing, default server timeout ([`7ab7386`](https://github.com/Dicklesworthstone/asupersync/commit/7ab7386bca1e8a4670cc3cac7e70d3f80c42cb76))
- Reference-counted HealthReporters to prevent premature status clear ([`b96d51c`](https://github.com/Dicklesworthstone/asupersync/commit/b96d51c))

### WASM / Browser Edition

- Real MessagePort and BroadcastChannel bindings for browser reactor ([`c29a4c9`](https://github.com/Dicklesworthstone/asupersync/commit/c29a4c9baa7e0871991760c691fdaf45ae8cd292))
- asupersync-wasm and asupersync-browser-core crates ([`a2964c8`](https://github.com/Dicklesworthstone/asupersync/commit/a2964c8))
- Browser host I/O wiring for storage and streams ([`4696bd4`](https://github.com/Dicklesworthstone/asupersync/commit/4696bd4))
- Parent-child handle ownership and descendant traversal in WASM ABI ([`3be3c28`](https://github.com/Dicklesworthstone/asupersync/commit/3be3c28))
- Browser-core release artifacts and wasm-opt bulk-memory validation ([`6202db2`](https://github.com/Dicklesworthstone/asupersync/commit/6202db2))
- Next.js maintained example with client/bridge split ([`94121ef`](https://github.com/Dicklesworthstone/asupersync/commit/94121ef))
- Packaged bootstrap/cancellation harnesses, framework consumer validators ([`6ee872c`](https://github.com/Dicklesworthstone/asupersync/commit/6ee872c))

### Networking

- AsyncReadVectored for TCP and Unix stream split halves ([`b3e8768`](https://github.com/Dicklesworthstone/asupersync/commit/b3e8768e4513aba0693919501b0513daaa251169))
- Windows named-pipe client ([`eba0443`](https://github.com/Dicklesworthstone/asupersync/commit/eba0443b19b67bb239c01a97d688af3c9eb76712))
- DNS resolver fail-closed on custom nameservers ([`c084e13`](https://github.com/Dicklesworthstone/asupersync/commit/c084e13))
- Generation-based stale DNS resolution protection ([`1cb7314`](https://github.com/Dicklesworthstone/asupersync/commit/1cb73149))
- QUIC/H3 unit protocol matrix ([`9563b33`](https://github.com/Dicklesworthstone/asupersync/commit/9563b339761fe6114a65696b9019657595f33399))

### RaptorQ (RFC 6330)

- G7 expected-loss decision contract with structured logging ([`4428379`](https://github.com/Dicklesworthstone/asupersync/commit/44283798891409a9c35bb532053b78cc7633a158))
- G7 governance decision contract integrated into decoder ([`a05e493`](https://github.com/Dicklesworthstone/asupersync/commit/a05e493d08b0f37cc6a9be205b1e5faad69dada6))
- Policy_snapshot_id and selected_path traceability ([`404a081`](https://github.com/Dicklesworthstone/asupersync/commit/404a081))
- GF(256) c=1 addmul fast path and SIMD threshold fix ([`2e4e327`](https://github.com/Dicklesworthstone/asupersync/commit/2e4e327))
- SparseRow canonicalization, type-aware schema validation, multi-block decode threshold ([`bfc12a7`](https://github.com/Dicklesworthstone/asupersync/commit/bfc12a7))
- ESI multiset hash in decode proof for replay verification ([`2b71728`](https://github.com/Dicklesworthstone/asupersync/commit/2b71728))
- E-process evidence dilution protection before calibration ([`8941121`](https://github.com/Dicklesworthstone/asupersync/commit/8941121))
- Infinity-safe decode threshold calculations ([`6460d30`](https://github.com/Dicklesworthstone/asupersync/commit/6460d30))
- Multi-block encoding with per-block repair distribution ([`39f38b4`](https://github.com/Dicklesworthstone/asupersync/commit/39f38b455804d1bd0cfa7975fb5b4158fad9cbd7))

### Database

- Generic connection pool with health checks ([`e893176`](https://github.com/Dicklesworthstone/asupersync/commit/e893176a91d407a4b1f19e5f3f29f6625f703003))
- Transaction management helpers, savepoints, PgError code methods ([`23547e7`](https://github.com/Dicklesworthstone/asupersync/commit/23547e7c9cdcb0730aad34c9a588691380b76f41))
- MySQL/SQLite transaction retry wrappers ([`deb3232`](https://github.com/Dicklesworthstone/asupersync/commit/deb3232))
- Error classification methods across all backends ([`0c22eae`](https://github.com/Dicklesworthstone/asupersync/commit/0c22eae))
- SleepFn hook to DbPool for deterministic testing ([`0fc9561`](https://github.com/Dicklesworthstone/asupersync/commit/0fc95611aa8b790012d731786512f74f540dabf6))

### Messaging

- KafkaProducer close lifecycle and KafkaConsumer rebalance API ([`c8442bb`](https://github.com/Dicklesworthstone/asupersync/commit/c8442bb))
- C-ERR-05 error classification across all messaging backends ([`d5eb1d2`](https://github.com/Dicklesworthstone/asupersync/commit/d5eb1d2))
- NATS deadline-based request timeouts and cleanup helpers ([`a73577c`](https://github.com/Dicklesworthstone/asupersync/commit/a73577c6680e6c82f4421116b5fc1825c5511463))
- Kafka TOCTOU race between rebalance and close fixed via double-checked locking ([`108f44e`](https://github.com/Dicklesworthstone/asupersync/commit/108f44e))
- Kafka consumer partition validation and duplicate detection ([`5dbc2a6`](https://github.com/Dicklesworthstone/asupersync/commit/5dbc2a6))

### Distributed Systems

- Quorum-aware recovery completion and replica mutation guards ([`6985c9c`](https://github.com/Dicklesworthstone/asupersync/commit/6985c9c))
- Close made idempotent; reconcile replica loss across all degraded states ([`ad46fb2`](https://github.com/Dicklesworthstone/asupersync/commit/ad46fb2))
- Reject trailing bytes in snapshot deserialization ([`99640c5`](https://github.com/Dicklesworthstone/asupersync/commit/99640c5))
- Weighted symbol assignment strategy ([`37f2d78`](https://github.com/Dicklesworthstone/asupersync/commit/37f2d78))

### Signals & Graceful Shutdown

- Windows cross-platform support for ctrl_c and signal module ([`37f60e4`](https://github.com/Dicklesworthstone/asupersync/commit/37f60e4bdb65e4e44bc09072b2309e70c1cd7570))
- GracefulBuilder::run rewritten with grace period timeout ([`6968d19`](https://github.com/Dicklesworthstone/asupersync/commit/6968d190180dfe927545bb9d7355ce73d8e8452e))
- Custom time source support to graceful shutdown ([`621226f`](https://github.com/Dicklesworthstone/asupersync/commit/621226fc1116ee530b7c70cae73d3943d923ef61))

### Channels & Sync

- FlushGuard RAII prevents message loss in FaultSender ([`d30ba66`](https://github.com/Dicklesworthstone/asupersync/commit/d30ba66))
- Watch channel `borrow_and_update` atomic TOCTOU fix ([`b6fead6`](https://github.com/Dicklesworthstone/asupersync/commit/b6fead6))
- Broadcast receiver_count increment inside lock to prevent subscribe race ([`e9314df`](https://github.com/Dicklesworthstone/asupersync/commit/e9314df))
- RwLock waiter state cleanup on cancellation and poison ([`3ae13c1`](https://github.com/Dicklesworthstone/asupersync/commit/3ae13c1))
- Prevent waiter ID overflow panic and add RwLock FIFO fairness ([`124a2c3`](https://github.com/Dicklesworthstone/asupersync/commit/124a2c3))

### Scheduler & Runtime

- ThreeLaneLocalWaker default_priority prevents priority inversion for cancelled local tasks ([`12d261d`](https://github.com/Dicklesworthstone/asupersync/commit/12d261d))
- Actual cancel masking in `commit_section` (was previously a no-op) ([`85b1ac0`](https://github.com/Dicklesworthstone/asupersync/commit/85b1ac0))
- Skip stale entries in all scheduler pop methods ([`ac4d2e9`](https://github.com/Dicklesworthstone/asupersync/commit/ac4d2e9))
- Runaway CPU usage fix in budget-exhausted future polling via exponential backoff ([`9db005b`](https://github.com/Dicklesworthstone/asupersync/commit/9db005b))
- Spurious wake injection with per-task deduplication (reactor chaos stats aggregation)

### Correctness & Safety

- Double-panic guards across all Drop-based leak detectors ([`44708b1`](https://github.com/Dicklesworthstone/asupersync/commit/44708b1))
- Obligation ledger abort_by_id for drain paths and reset safety ([`fc1b928`](https://github.com/Dicklesworthstone/asupersync/commit/fc1b928))
- OOM/DoS prevention: unbounded length-prefix allocations eliminated ([`ef8438c`](https://github.com/Dicklesworthstone/asupersync/commit/ef8438c))
- Obligation kind conflict detection in CRDT merge and acquire paths ([`5dd9f97`](https://github.com/Dicklesworthstone/asupersync/commit/5dd9f97))
- Prevent silent length truncation in trace writer and H2 frame encoding

### Tokio Compatibility Layer

- Tower Service bridge adapters ([`dbd1b90`](https://github.com/Dicklesworthstone/asupersync/commit/dbd1b905e05b835a3c81cee9f19c87e96b5fd7f4))
- enter(), with_tokio_context, and with_tokio_context_sync APIs ([`9c18c83`](https://github.com/Dicklesworthstone/asupersync/commit/9c18c83))
- Real I/O trait bridging and functional hyper executor/timer ([`6813e18`](https://github.com/Dicklesworthstone/asupersync/commit/6813e18))
- Safe blocking bridge with Cx context propagation ([`72557fa`](https://github.com/Dicklesworthstone/asupersync/commit/72557fa))

### Observability

- Task-console wire snapshot format and CLI viewer ([`3d9c0b9`](https://github.com/Dicklesworthstone/asupersync/commit/3d9c0b9))
- Machine-searchable audit_index.jsonl with 576 entries across 472 files ([`04b9d2a`](https://github.com/Dicklesworthstone/asupersync/commit/04b9d2a))
- Atomic record_event replaces split next_seq/push_event to prevent sequence interleaving ([`da4facc`](https://github.com/Dicklesworthstone/asupersync/commit/da4facc))

### Lab Runtime

- Reactor chaos statistics synced into LabRuntime aggregated stats ([`da489aa`](https://github.com/Dicklesworthstone/asupersync/commit/da489aa747516a4cf4406e8925a808e744d223bf))
- Validate obligation region ownership in snapshot restore ([`0e5de5a`](https://github.com/Dicklesworthstone/asupersync/commit/0e5de5a895f6ba893205b4062eef1e8f1537bb5b))
- Per-test fd namespace isolation and post-rearm cleanup assertion ([`f154d6a`](https://github.com/Dicklesworthstone/asupersync/commit/f154d6a))
- RAII FdRestoreGuard for poller fd manipulation in tests ([`dc30de6`](https://github.com/Dicklesworthstone/asupersync/commit/dc30de6))

### CI & Tooling

- Nightly stress/soak automation with flake burndown ([`7b16c4f`](https://github.com/Dicklesworthstone/asupersync/commit/7b16c4fdd3793808038208964936d9a924eb0c5d))
- Structured release traceability artifacts in publish workflow ([`9d0bf08`](https://github.com/Dicklesworthstone/asupersync/commit/9d0bf08))
- drop_unwrap_finder static analysis utility ([`0c45351`](https://github.com/Dicklesworthstone/asupersync/commit/0c45351444b846d6b15d431cce516f653a896b84))

---

## [v0.2.7](https://github.com/Dicklesworthstone/asupersync/commit/ff2c55bedab7056120adc2e6c10bc080ae6d7aea) -- 2026-03-03

> **Git tag only** (no GitHub Release) | 412 commits | Tag: [`ff2c55b`](https://github.com/Dicklesworthstone/asupersync/commit/ff2c55bedab7056120adc2e6c10bc080ae6d7aea)

The initial public milestone. Represents the accumulation of the foundational runtime, networking stack, web framework, and correctness infrastructure built from 2026-02-25 through 2026-03-03.

### Core Runtime & Structured Concurrency

The foundation: region-based task ownership, cancel-correct lifecycle, and capability-secured effects.

- Waker registration on WriteZero retry fallback ([`ed72c23`](https://github.com/Dicklesworthstone/asupersync/commit/ed72c238796d42a6a6693f8aabd0655ed155d535))
- Race combinator surfaces loser panics even when the winner succeeds ([`c5f5055`](https://github.com/Dicklesworthstone/asupersync/commit/c5f5055c5ade29eb8b792a87237828c8ac80dbb9))
- Recover from mutex poisoning instead of cascading panics ([`e12b357`](https://github.com/Dicklesworthstone/asupersync/commit/e12b357731d0a2dbc4224143a85286c0ea922e00))
- Yield counters prevent fast readers/writers from starving executor ([`432763e`](https://github.com/Dicklesworthstone/asupersync/commit/432763e0324203fa95ce21fc87b6f5788f8144ce))
- Service returns error instead of panicking when call() precedes poll_ready() ([`f5272f8`](https://github.com/Dicklesworthstone/asupersync/commit/f5272f8972e479d76b528e65124a0b62421d00b8))
- Orphaned pending symbols prevented via completed-object tracking ([`fe00638`](https://github.com/Dicklesworthstone/asupersync/commit/fe0063807defa281258d82f8606392622b8404bc))
- Region leak on spawn failure + drop bomb on stop/join error path ([`8fac088`](https://github.com/Dicklesworthstone/asupersync/commit/8fac088))
- Notify lost-notification bug and pool cancellation leak ([`15cdc12`](https://github.com/Dicklesworthstone/asupersync/commit/15cdc12))

### Sync Primitives

- Notify baton-passing on cancelled futures ([`dbda2fc`](https://github.com/Dicklesworthstone/asupersync/commit/dbda2fc))
- OnceCell set retries on cancelled initializer ([`71292e9`](https://github.com/Dicklesworthstone/asupersync/commit/71292e9))
- mpsc cancellation baton loss, pool FIFO after health check ([`905c50e`](https://github.com/Dicklesworthstone/asupersync/commit/905c50e))
- Waiter queue positional removal instead of retain ([`ecf6f1f`](https://github.com/Dicklesworthstone/asupersync/commit/ecf6f1f))

### Observability

- Thread-local context stack for DiagnosticContext ([`62a344f`](https://github.com/Dicklesworthstone/asupersync/commit/62a344f55f0625c01f71abc41bd3c97db0c320e5))
- Deterministic hasher for stable trace fingerprints ([`46877f8`](https://github.com/Dicklesworthstone/asupersync/commit/46877f8cd12485c722bf2931839a467f1c037fa7))
- Advanced observability taxonomy with deterministic event classifier ([`d03ceaf`](https://github.com/Dicklesworthstone/asupersync/commit/d03ceaf))

### Web Framework

- Session middleware with pluggable backends ([`ff2c55b`](https://github.com/Dicklesworthstone/asupersync/commit/ff2c55bedab7056120adc2e6c10bc080ae6d7aea))
- Static file serving with ETag and caching ([`d6d012b`](https://github.com/Dicklesworthstone/asupersync/commit/d6d012b))
- Multipart form data parser (RFC 7578) ([`60e6c83`](https://github.com/Dicklesworthstone/asupersync/commit/60e6c83))
- Health check endpoints for Kubernetes-style probes ([`543587f`](https://github.com/Dicklesworthstone/asupersync/commit/543587f))
- Server-Sent Events (SSE) support ([`5600b25`](https://github.com/Dicklesworthstone/asupersync/commit/5600b25))
- WebSocket implementation ([`7f0e222`](https://github.com/Dicklesworthstone/asupersync/commit/7f0e222))
- 8 production middleware types for stack parity ([`13912ba`](https://github.com/Dicklesworthstone/asupersync/commit/13912ba))
- Cookie and CookieJar extractors ([`1e54bea`](https://github.com/Dicklesworthstone/asupersync/commit/1e54bea))
- CORS middleware ([`4d9f63f`](https://github.com/Dicklesworthstone/asupersync/commit/4d9f63f))
- SecurityHeadersMiddleware ([`38bec9c`](https://github.com/Dicklesworthstone/asupersync/commit/38bec9c))
- Compression middleware (gzip/deflate) ([`79f746b`](https://github.com/Dicklesworthstone/asupersync/commit/79f746b))
- Content negotiation module ([`e806de9`](https://github.com/Dicklesworthstone/asupersync/commit/e806de9))

### gRPC

- Loopback transport for client and server ([`7d7a190`](https://github.com/Dicklesworthstone/asupersync/commit/7d7a190868c3e815c2327e88bd420e912dd35e41))
- Server reflection service with descriptor registry ([`23f6f20`](https://github.com/Dicklesworthstone/asupersync/commit/23f6f20))
- Compression encoding negotiation ([`7aedbe2`](https://github.com/Dicklesworthstone/asupersync/commit/7aedbe2))

### HTTP

- Content-Length handling and idle timeout for HTTP/1.1 ([`703411f`](https://github.com/Dicklesworthstone/asupersync/commit/703411f))
- H2 connection window leak on closed-stream DATA fixed ([`5f61374`](https://github.com/Dicklesworthstone/asupersync/commit/5f61374))
- Graceful transport shutdown for HTTP/1.1 client and server ([`5c29289`](https://github.com/Dicklesworthstone/asupersync/commit/5c29289))
- H2 settings emission and Connection header overwrite correction ([`1c27e33`](https://github.com/Dicklesworthstone/asupersync/commit/1c27e33))

### Networking

- WebSocket close handshake, fallible mask generation, IPv6 handling, accept storm backoff ([`4146b09`](https://github.com/Dicklesworthstone/asupersync/commit/4146b09))
- IPv6 brackets for WebSocket TCP connect ([`5365c63`](https://github.com/Dicklesworthstone/asupersync/commit/5365c63))
- Happy Eyeballs: sort_socket_addrs preserves per-address ports ([`a0899cb`](https://github.com/Dicklesworthstone/asupersync/commit/a0899cb))

### Stream Combinators

- Scan, peekable, throttle, debounce combinators ([`2f7be8c`](https://github.com/Dicklesworthstone/asupersync/commit/2f7be8c))
- Select combinator: poll both branches for cancel-correctness ([`98be3fd`](https://github.com/Dicklesworthstone/asupersync/commit/98be3fd))
- Stop eagerly polling loser branches in select ([`165af82`](https://github.com/Dicklesworthstone/asupersync/commit/165af82))

### Database

- Redis MULTI/EXEC transactions and Pub/Sub connection ([`d6cd5dc`](https://github.com/Dicklesworthstone/asupersync/commit/d6cd5dc))
- SQLite transaction drop safety and connection defaults ([`133fdee`](https://github.com/Dicklesworthstone/asupersync/commit/133fdee), [`6d1e2e1`](https://github.com/Dicklesworthstone/asupersync/commit/6d1e2e1))
- MySQL client hardening with result limits, URL parsing, abandoned tx drain ([`1a13be2`](https://github.com/Dicklesworthstone/asupersync/commit/1a13be2))
- PostgreSQL: fallible build_parse_msg and parameter overflow guard ([`680b93e`](https://github.com/Dicklesworthstone/asupersync/commit/680b93e))

### Signals

- SIGPIPE and SIGALRM support in signal dispatcher ([`6c698d9`](https://github.com/Dicklesworthstone/asupersync/commit/6c698d9))

### I/O & Filesystem

- write_atomic for durable file replacement via temp+rename ([`dd0573a`](https://github.com/Dicklesworthstone/asupersync/commit/dd0573a))
- LinesCodec decode_eof, discard-and-recover for oversized lines ([`75b96ff`](https://github.com/Dicklesworthstone/asupersync/commit/75b96ff))
- AsyncSeekExt trait ([`30993b6`](https://github.com/Dicklesworthstone/asupersync/commit/30993b6))
- io_uring reactor spurious ERROR event fix ([`38c1524`](https://github.com/Dicklesworthstone/asupersync/commit/38c1524))

### QUIC / HTTP/3

- RFC 9002 loss_delay_micros and congestion recovery epoch ([`14f9289`](https://github.com/Dicklesworthstone/asupersync/commit/14f9289))
- QPACK field-section decode helpers with pseudo-header validation ([`a70436e`](https://github.com/Dicklesworthstone/asupersync/commit/a70436e))
- Packet send-state guard and congestion recovery epoch fix ([`be7d9fb`](https://github.com/Dicklesworthstone/asupersync/commit/be7d9fb))

### Tokio Parity Planning

- Cancellation fuzz campaigns, CI quality gates, replay artifact policies ([`ccf0953`](https://github.com/Dicklesworthstone/asupersync/commit/ccf0953))
- Performance regression budgets and alarm policy ([`7b8bb76`](https://github.com/Dicklesworthstone/asupersync/commit/7b8bb76))
- Parity dashboard generator and contract tests ([`d9ee366`](https://github.com/Dicklesworthstone/asupersync/commit/d9ee366))

### Doctor Subsystem (CLI Diagnostics)

- scan-workspace command for deterministic workspace diagnostics ([`74ec549`](https://github.com/Dicklesworthstone/asupersync/commit/74ec549))
- Operator-model contract and enhanced workspace scanner ([`81df51c`](https://github.com/Dicklesworthstone/asupersync/commit/81df51c))
- Scenario composer and run-queue manager contract ([`1ce2389`](https://github.com/Dicklesworthstone/asupersync/commit/1ce2389))
- Navigation topology, screen engine, evidence ingestion ([`2e3440e`](https://github.com/Dicklesworthstone/asupersync/commit/2e3440e))

### Correctness

- Harden snapshot restore validation and fix depth computation cycle safety ([`b75e7b4`](https://github.com/Dicklesworthstone/asupersync/commit/b75e7b4))
- Integer overflow prevention in RESP parser and RaptorQ symbol params ([`dd4b8bb`](https://github.com/Dicklesworthstone/asupersync/commit/dd4b8bb))
- Timer overflow safety, parking_lot migration ([`ce0a9a1`](https://github.com/Dicklesworthstone/asupersync/commit/ce0a9a1))
- H2 stream ID overflow prevention, cooperative yielding in ReadExact ([`8580bab`](https://github.com/Dicklesworthstone/asupersync/commit/8580bab))

---

## [v0.2.5](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.2.5) -- 2026-02-19

> **GitHub Release** (no local tag) | Published: 2026-02-19

Workspace alignment release. Prepared the crate for crates.io publication.

- All workspace crate versions aligned to 0.2.5
- Release train prepared for crates.io publication with license-file metadata (MIT + OpenAI/Anthropic rider)

---

## Links

- **Repository:** <https://github.com/Dicklesworthstone/asupersync>
- **v0.2.9 Release:** <https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.2.9>
- **v0.2.8 Release:** <https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.2.8>
- **v0.2.5 Release:** <https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.2.5>
- **Live Demo:** <https://dicklesworthstone.github.io/asupersync/asupersync_web_demo.html>
