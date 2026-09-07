# Comprehensive Dependency Replacement Plan — Asupersync

> **Goal:** systematically shrink asupersync's external dependency surface, optimizing for **eliminated trust relationships and eliminated native/unsafe surface — not the raw count of crate names** — replacing dependencies with home-grown strict-memory-safe Rust (per the safety taxonomy in §3), or with FrankenSuite projects we control, with performance tuned for Apple Silicon and high-core-count x86.
>
> Audit date: 2026-07-23 (SapphireHill). **Rev 3 (2026-07-24):** execution-ready revision incorporating Sol Max's external review of Rev 2. Major changes: an explicit safety taxonomy that prohibits algorithmic unsafe in replacements by default (§3); prioritization by *marginal* dependency cost via a generated ledger (§4); a public-API-decision phase inserted before all codec work (§7 Phase 3); the parking_lot replacement redesigned for stable-lane compatibility; the X.509 work re-scoped as a security epic that delegates to rustls/webpki first; Kafka native rewrite descoped to an independent future campaign; and a set of verdicts flipped to KEEP where marginal ROI was poor (semver, thiserror, pin-project, crossbeam-queue, smallvec, memchr, socket2, polling, unicode-normalization). Rev-2 factual errors fixed: rdkafka builds bundled C via configure/make (cmake declared but inactive); `parking_lot::Condvar` *is* used in production; the x509 surface includes validity/EKU/KU/BasicConstraints checks, not just SPKI+SAN.
>
> Governing scope, reconciled 2026-09-07: the accepted DEP-ADR decisions and current `AGENTS.md` override the original Rev-3 removal proposals. Preserve every shipped 0.4.x public signature, exhaustive type, foreign trait/error identity, accepted input, default and wire format. Better ergonomics or private implementation parity does not authorize a public break. Additive implementations and compatible adapters remain allowed under their existing task gates. Consult live beads for status; the old blanket pause is historical.

---

## 1. Philosophy

External library dependencies are an anti-pattern for this project, for four reasons:

1. **Supply chain.** Every one of the ~376 crates in our full workspace graph is a person or CI pipeline that can be compromised. The default *consumer* graph alone is 121 external crates (130 counting duplicate versions).
2. **Memory safety.** We `deny(unsafe_code)` and ledger every exception — then link in `ring` (C + assembly), bundled SQLite (250k lines of C), and bundled `librdkafka` (C). The safety story is only as strong as the weakest native blob.
3. **The generality tax.** One-size-fits-all crates carry code, features, and compile time we never use. Purpose-built code is smaller, faster, and fully understood.
4. **Performance ownership.** Our continuous optimization campaigns stop at crate boundaries. Code we own keeps getting faster; code we import doesn't.

**The Rev-3 discipline:** a dependency is removed when doing so eliminates *trust* (an upstream maintainer/repo/build script), *native or unsafe surface*, or *real marginal graph weight* — measured by the §4 ledger — at acceptable implementation and soundness cost. Moving unsafe from a mature, widely-fuzzed dependency into fresh first-party code does **not** inherently reduce risk; that trade needs measured evidence and owner sign-off. Dev-dependencies used as differential-testing references are an asset for proving replacements correct, but they run on our build/release machines, so Phase 9 keeps them inside the audit perimeter.

---

## 2. Audit Snapshot (2026-07-23, Rev-3-corrected)

### 2.1 Graph size

Unit note: "names" = unique external crate names; "crate-versions" counts duplicate major versions separately. Per-feature rows are **name** counts.

| Graph | Pre-Phase-0 baseline | Post-Phase-0 (landed `a86bfb3a6`) |
|---|---|---|
| Default consumer graph | 124 names / 132 crate-versions | **121 names / 130 crate-versions** |
| `+tls` | 150 | 147 |
| `+sqlite` | 134 | 131 |
| `+kafka` | 137 | 134 |
| `+metrics` | 137 | 134 |
| `+cli` | 167 | 164 |
| Workspace, all features, incl. dev/build deps | ~376 external / 390 packages | ~374 |

Verified: a synthesized out-of-workspace consumer resolves the same 130 crate-versions as in-workspace measurement — today. The Phase-9 budget contract measures from a synthesized consumer (methodology in Appendix C, now package-ID-based and per-platform).

### 2.2 Native code (C/C++/asm) in the graph

| Crate | Native payload | Pulled by | When |
|---|---|---|---|
| `ring` | C + hand-written assembly | `rustls/ring` provider | `tls` |
| `libsqlite3-sys` | bundled SQLite C amalgamation | `rusqlite` | `sqlite` |
| `rdkafka-sys` | **bundled `librdkafka` C via `./configure` + `make`** (the `cmake-build` feature exists but is not enabled — lockfile-verified, no `cmake` crate resolves) | `rdkafka` | `kafka` |
| `psm`/`stacker` | C/asm stack-probing | `sqlparser` (via `recursive`) | `sqlite` |
| `generator` | C context-switching | `loom` | `loom-tests` (feature-gated **normal** dep) |
| `alloca` | C | `criterion` (Windows) | dev-only |

`signal-hook` compiles no C in our feature set (its `cc` edge is behind `extended-siginfo-raw`). Standing rule: native-code attribution must be **lockfile-verified**, because `cargo metadata` reports declared build-deps regardless of feature activation (this trap produced two Rev-1/2 errors: signal-hook "cc shim" and rdkafka "via cmake").

### 2.3 Version-duplication bloat in the default graph

Two RustCrypto generations remain linked after Phase 0: `sha2`/`digest`/`block-buffer`/`crypto-common`/`const-oid`/`cpufeatures`/`getrandom` ×2 each, plus `rand_core` 0.6+0.10 (new with aead 0.6). Sole driver: `nkeys → ed25519-dalek 2.2` pins the old generation. **Because ed25519-dalek stays (as a direct dep) after the nkeys replacement, this dedup ultimately waits on an upstream dalek release on digest-0.11 — outside our control.** `syn` 2+3 are both present (serde_derive moved; our macros and most of the ecosystem have not).

### 2.4 Dead and misplaced dependencies found

| Finding | Status |
|---|---|
| `crossbeam-deque` — zero references (work-stealing is home-grown) | **removed in Phase 0** (+ transitive crossbeam-epoch) |
| `hkdf` — zero references (HKDF hand-rolled on `hmac`) | **removed in Phase 0** |
| `tempfile` normal-dep forced by two feature-gated non-test modules (`atp/benchmark/suite.rs` under `benchmark-adapters`; `test_logging.rs` under `test-internals`) | optionalize (Phase 2) |
| Three orphaned never-compiled files (`src/real_{fs_dir_fs_vfs_integration,integration_scenarios,distributed}_e2e_tests.rs`) — not declared as modules anywhere | wire-or-remove decision needs owner sign-off (no-deletion rule) |
| `env_logger` enabled by all of `cli`, consumed by 2 lines in `offline_tuner` | remove (Phase 2) |
| `time` + `chrono` both in CLI; `time` has one call site | **superseded by DEP-ADR-011** — the observation is accurate but "consolidate (Phase 2)" conflicts with the Phase-5 chrono row below. What *is* Phase-2-sized: consolidating the **two already-owned** chrono-free RFC 3339 formatters (`atp/logging`, `messaging/jetstream`) into one type. Replacing chrono is not |
| `num_cpus` + `whoami`: one call site each; std covers it | remove (Phase 2) |
| `src/net/atp/chunk/artifact.rs` local `mod regex` **mock** in production | replace (Phase 2, no-mock policy) |
| Stale crc32fast manifest comment | **fixed in Phase 0** |

### 2.5 Usage-map corrections carried into Rev 3

The Rev-1/2 usage tables remain substantially correct (spot-verified to the line) with these corrections:

- **`parking_lot`:** the "no Condvar" claim was **wrong** — `parking_lot::Condvar` is production-load-bearing in `runtime/blocking_pool.rs` and `service/discover.rs`, and parking-lot guard types leak into crate-visible/public method signatures. Any replacement must cover `Mutex`/`RwLock`/`Condvar` and the exposed guard types.
- **`x509-parser`:** the "SPKI + SAN only" scope was **wrong**. Active checks also include certificate validity windows and server EKU (`bin/atp.rs`), validity+EKU+KeyUsage+SAN in the native-QUIC verifier (`net/quic_native/handshake_driver.rs`), per-chain-certificate validity (`tls/acceptor.rs`), and BasicConstraints CA:TRUE (`tls/connector.rs`), plus SPKI extraction (`tls/types.rs`). See §9.4.
- **`memchr`:** replacing it removes **zero** packages — `serde_json` (KEEP) depends on memchr independently.
- **`smallvec`:** remains in the graph through `parking_lot_core` until/unless the parking_lot work lands.
- **CLI scale:** the six clap-consuming files total ~33.8k lines with hundreds of derive/attribute sites — an owned parser is XL, not L.
- **`typed_symbol.rs` / `grpc/protobuf.rs` / `otel.rs` are public generic surfaces** (arbitrary-`Serialize` `SerdeCodec` with public Bincode/MessagePack format variants; public `ProstCodec` over arbitrary `prost::Message`; public consumption of OpenTelemetry's `Meter`). Replacing the backing crates is therefore a **public API redesign**, not an internal swap — hence the new Phase 3.
- Home-grown infrastructure inventory unchanged (`TokenSlab`, `DetHashMap`, `Arena`, `CachePadded` [64-byte today], intrusive queues, hand-rolled HKDF, `tracing_compat` shim, GF(256) SIMD kernels). The `grpc/protobuf.rs` varint helpers are `#[cfg(test)]`-only — differential oracle, not reusable production code.

---

## 3. Safety taxonomy (new in Rev 3 — the policy that resolves "strict memory-safe")

Every replacement is classified before it is approved:

| Class | Definition | Policy |
|---|---|---|
| **SAFE-OWN** | `#![forbid(unsafe_code)]`-clean first-party code | Default. Always eligible. |
| **BOUNDARY-UNSAFE** | Narrow, ledgered unsafe at OS/FFI or CPU-dispatch boundaries: syscall wrappers, `#[target_feature]` dispatch shims, env-var setters — the categories the unsafe-boundary ledger already governs | Eligible with fn-scoped `#[allow]`, ledger row, proof note, and Miri/UBS coverage. This is the same standard the epoll reactor and GF(256) kernels already meet. |
| **ALGORITHMIC-UNSAFE** | Unsafe that *encodes an ownership/liveness/initialization argument*: lock-free queues with pointer tagging, `MaybeUninit` inline storage, futex parking protocols, generated pin-projection | **Prohibited for replacements by default.** Loom does not prove liveness/linearizability, Miri does not model weak memory, and a 48-h soak is not a proof. Moving this class of unsafe from a mature, widely-fuzzed crate into fresh first-party code increases risk. Exceptions require: a measured performance defect in the incumbent, a SAFE alternative benchmarked and rejected, and explicit owner sign-off. |

**Immediate verdict consequences:** `crossbeam-queue`, `smallvec`, and `pin-project` flip to **KEEP** (their entire value *is* well-audited algorithmic unsafe). The parking_lot replacement is redesigned as a SAFE-OWN wrapper over `std::sync` (§9.2). SIMD replacements are honest about which strength class they land in per ISA (§6).

---

## 4. Marginal-cost ledger (new in Rev 3 — the prioritization metric)

Raw closure size overstates wins because shared subtrees don't leave when one parent does. Prioritization now uses **marginal cost**: the packages that actually exit the graph when a root is removed, plus qualitative risk columns.

**Ledger spec** — `artifacts/dependency_marginal_ledger_v1.json`, generated by a script from `cargo metadata` (package IDs, not name text), recomputed after every phase, one row per direct dependency:

`{ crate, marginal_package_versions (per platform: linux/macos/windows/wasm), unique_upstream_repos, build_scripts, proc_macros, native_code, unsafe_exposure_class, runtime_hotness, api_blast_radius, est_impl_cost, security_risk, verdict, phase }`

**Key marginals measured today (default graph, Linux):**

| Root | Closure (Rev-2 framing) | **Marginal (what actually leaves)** |
|---|---|---|
| `nkeys` | 36 packages | **~16** (ed25519-dalek chain stays as a direct dep) |
| `prost` | 13 | **6** (prost, prost-derive, bytes, anyhow, itertools, either) |
| `bincode-next` | 14 | ~5 (bincode, derive, pastey, virtue, unty) |
| `futures-lite` | 6 | ~3–4 |
| `hashbrown` | 4 | ~4 (foldhash/rapidhash/allocator-api2) |
| `semver`, `socket2`, `polling`, `base64`, `hex`, `crc32fast` | — | **~1 each** |
| `memchr` | — | **0** (serde_json keeps it) |
| `smallvec` | — | 0 until parking_lot also lands |
| `rusqlite`+`sqlparser` | — | ~10 + **bundled C + psm/stacker** |
| `rdkafka` | — | ~13 + **bundled C** |
| `x509-parser` | — | ~9 (tls graph) |
| `opentelemetry`+`_sdk` | — | ~13 (metrics graph) |
| `clap` (+time/chrono/env_logger/serde_yaml) | — | ~40+ (cli graph) |

These July measurements identify potential graph costs, not authorized exits.
The accepted ADRs retain SQLite, Kafka, nkeys, prost, CLI and OpenTelemetry
capabilities and their incumbents until the respective gates are met. Rank
implementation work using a fresh marginal ledger and the cost of achieving
complete compatible behavior; a large historical closure alone is not a win.

---

## 5. Classification: every dependency, one verdict (Rev 3)

**Legend:** `REMOVE` · `STD` · `OWN` (with safety class) · `FRANKEN` · `KEEP` · `DEV-KEEP`. Phases per §7.

| Crate | Verdict | Phase | Note |
|---|---|---|---|
| `crossbeam-deque`, `hkdf` | REMOVE | 0 ✅ | dead; done |
| `hashbrown` | STD | 2 | 2 sites → std/`DetHashMap`; marginal ~4 |
| `num_cpus`, `whoami` | STD | 2 | one call site each |
| `env_logger` | REMOVE | 2 | 2 lines → tracing shim |
| `time` | **gated by DEP-ADR-011** | — | The 1-call-site measurement is **correct** (private CLI helper, no type leak). But removal is gated *with* chrono, not ahead of it: the registry binds both to one capability whose no-claim boundary says a nanos→RFC3339 helper cannot justify removing either. Removing `time` alone would leave a **third** RFC 3339 implementation beside the two the repo already owns (`atp/logging`, `messaging/jetstream`) |
| `tempfile` | OPTIONALIZE→DEV-KEEP | 2 | optional on `benchmark-adapters`/`test-internals`; no rewrite |
| `bincode-next` + `rmp-serde` | **KEEP_UNTIL_PARITY** (generic) / **PRESERVE_AND_REPLACE_IF_PARITY, blocked** (persisted) | — | **DEP-ADR-001 resolved: KEEP.** Not an API trim — these are the actual on-disk encodings: rmp-serde writes every trace file and replay trace, bincode (legacy config) writes distributed-snapshot vector clocks. Hand-coding schemas removes neither dependency while the existing corpus must still load. Replacement additionally blocked until byte-level goldens exist for Bincode and MessagePack — today **none do**, so nothing would detect a divergence. Marginal ~5 + 2 stands as a measurement, not a licence |
| `futures-lite` | **PRESERVE_AND_REPLACE_IF_PARITY, blocked** | — | **DEP-ADR-008 resolved: KEEP.** Not a Phase-2 leaf. Production coupling is 6 sites in 5 files, but one is a **public trait impl** (`AtpWriter`/`AtpReader` implement `futures_lite::Stream`, downstream-visible, semver-relevant) and three are the executor itself — `block_on` inside the public *synchronous* `Router::handle` and ×2 driving signal-listener threads outside any runtime. Total churn is ~272 files incl. tests, not disjoint. The `util/future.rs` shim list is also incomplete: it omits `poll_once`, `join_all`, `pending`, `FutureExt::catch_unwind` and `Stream`, and the last two are not free functions a helper module can supply |
| `visibility` | OWN (SAFE) | 2 | 12 uses → `asupersync-macros` attr |
| `slab` | STD/OWN (SAFE) | 2 | unify on in-tree `TokenSlab` family |
| `hex`, `base64` | OWN (SAFE) | 2 | scalar-safe engines; marginal ~1 each — justified by triviality, not weight |
| `semver` | **KEEP** | — | flipped in Rev 3: one safe marginal package with subtle precedence rules; poor risk-adjusted value to replace |
| `thiserror` | **KEEP** (defer) | — | flipped: nets −2 packages for 112-file churn; revisit only in a suite-wide macro consolidation |
| `pin-project` | **KEEP** (defer) | — | flipped: nets −2; replacement macro is soundness-critical (ALGORITHMIC-UNSAFE class) |
| `smallvec` | **KEEP** | — | flipped: ALGORITHMIC-UNSAFE class; marginal 0 while parking_lot remains |
| `crossbeam-queue` | **KEEP** | — | flipped: ALGORITHMIC-UNSAFE class. A SAFE mutex-backed queue may be *prototyped and benchmarked*; the incumbent leaves only if the safe variant wins or ties (§3 exception process otherwise) |
| `memchr` | **KEEP** | — | flipped: marginal 0 (serde_json). Revisit only if serde_json ever goes |
| `socket2` | **KEEP** | — | flipped: marginal ~1; real scope (socket creation, SockAddr conversion, abstract-Unix, SockRef, keepalive, cross-platform options) was understated. Evidence-gated revisit in Phase 8 |
| `polling` | **KEEP** | — | flipped: marginal ~1; replacement must own EINTR, fd reuse, generation tokens, wakeups, fork behavior, registration races, oneshot/edge, kqueue, IOCP. Evidence-gated revisit in Phase 8 |
| `signal-hook`, `sysinfo`, `xattr` | OWN (BOUNDARY) — deferred | 8 | consolidation candidates with small marginals; each needs a measured or maintenance-driven justification before build |
| `parking_lot` | Additive SAFE wrapper experiment; KEEP public incumbent | 8 | `sync/oslock.rs` may provide owned guards on new/private surfaces while preserving existing public parking-lot types and non-poisoning behavior. Require audited stable-lane compilation and §6.6 metrics. The historical −3-package marginal applies only if every required edge can compatibly exit; it is not a guaranteed result. |
| `prost` | **KEEP_UNTIL_PARITY** | — | **DEP-ADR-002 resolved: KEEP.** `ProstCodec<T, U>` is an unrestricted public generic over arbitrary downstream `prost::Message` types and `prost` is a non-optional dependency, so protobuf ships at default features. The finite sets a replacement would hand-write are already prost-free, so replacement removes capability and gains nothing. Marginal 6 stands as a measurement, not a licence. **Not** a prerequisite for native OTLP — an owned OTLP message set can use prost derives as `otlp_logs_proto` already does |
| `toml` | **KEEP_UNTIL_PARITY / KEEP_INCUMBENT** | 3/5 | DEP-ADR-004 preserves accepted TOML configuration, precedence and diagnostics. JSON is additive. A subset parser or corpus conversion does not authorize dropping TOML acceptance or its incumbent. |
| `serde_yaml` | **KEEP_UNTIL_PARITY / KEEP_INCUMBENT** | 5 | DEP-ADR-004 preserves accepted YAML scenarios and replay semantics. Additive JSON needs lossless round-trip evidence; no format migration or file deletion is authorized by this plan. |
| `clap` | **KEEP_UNTIL_PARITY** | — | **DEP-ADR-005 resolved: KEEP.** The XL re-scope below stands and is adopted verbatim as the replacement precondition — ~33.8k CLI lines, hundreds of attr sites; an owned parser must cover OsString/invalid-UTF-8, `--`, short clusters, negative values, global/flattened args, counts, custom parsers, defaults, value delimiters/enums, help text, exit codes, error goldens. Only the disposition label changes, so this row cannot be read as authorizing implementation. **Parity is currently unmeasurable: there is NO `--help` golden for any of the four binaries**, the help/OsString/accessibility contract is prose guarded by one substring assertion, and no test asserts a nonzero semantic exit code from a real binary run. Goldens first. Also frozen: `wrap_help` is OFF (help wraps at clap's fixed width, not the terminal's) and `env` is OFF (zero clap `env=` attrs; all env reads are hand-rolled) |
| `chrono` | **PRESERVE_AND_REPLACE_IF_PARITY, blocked** | — | **DEP-ADR-011 resolved.** Owned `UtcTimestamp` authorized as **additive** work. Scope is bigger than formatting: **10 public serde-derived `DateTime<Utc>` fields** feed **3 JSON index stores that are read as well as written**, so a swap must *parse* an existing on-disk corpus and is semver-breaking under `cli`/`benchmark-adapters`. Nothing owned parses RFC 3339 today, and `types::Time` is process-epoch relative + calendar-free so it is **not** a rename target. **No round-trip test and no byte golden exist** for any of it. Keep the chrono **dev-dep** as the PostgreSQL temporal oracle |
| `regex` | KEEP_UNTIL_PARITY (DEP-ADR-012) | — | **superseded.** The accepted pattern language may not narrow — downstream supplies arbitrary patterns via `pii_patterns` / `try_with_pii_pattern`, and a fail-closed *subset* matcher would reject patterns that work today. There is also nothing to promote: all four built-in detectors are themselves regex-backed. Separately, `mod regex` in `net/atp/chunk/artifact.rs` is a **mock** that ignores its pattern and is compiled unconditionally — a no-mock violation, not a consumer |
| `opentelemetry`/`_sdk` | **KEEP_UNTIL_PARITY** | — | **DEP-ADR-003 resolved: KEEP.** The Phase-3 decision did *not* approve dropping external-SDK interop. The external `Meter`/SDK bridge is the **only** production export path for the metrics and traces signals (the owned OTLP request builders are gated to test/fuzz because they need the tokio-carrying `opentelemetry-proto`), so removing these crates leaves the runtime unable to export metrics or traces at all. Does **not** depend on a prost replacement — DEP-ADR-002 keeps prost, and an owned OTLP message set can use prost derives directly |
| `rusqlite` + `sqlparser` | KEEP_UNTIL_PARITY (DEP-ADR-010) | — | **superseded.** KEEP is the default terminal result: Cargo cannot make the root feature depend on the downstream adapter without a cycle, so removal would strand the one-stop path. fsqlite's dependency is **unconditional** (the bead's "optionally" is wrong), so it may not enter this workspace in any form. Adds two gates to §9.1: **data compatibility** (WAL + unclean shutdown) and an **equivalent `ToSql` trait** for the one public leak |
| `rdkafka` | KEEP_UNTIL_PARITY (DEP-ADR-009) | — | **superseded.** The registry's no-claim boundary governs: a wire codec or simple producer is not a Kafka client. The gating downstream inventory has never been run, and removal would also delete the owned fail-closed no-feature lane. Native client remains an independent campaign (§9.3) |
| `nkeys` | **KEEP_UNTIL_PARITY** | — | **DEP-ADR-007 resolved: KEEP.** §9.5 sizes this at ~200 lines and frames it as NATS work, but `nkeys` is load-bearing in **four subsystems** (NATS, ATP identity + capability-token verification, agent-swarm admission, runtime signed-profile bundles) across 6 production files, and the registry demands every prefix form, Curve keys, JWT signer policy and zeroization. Also note the trade direction: `ed25519-dalek` is **not** a direct dep today (transitive via nkeys), so the swap *adds* a direct crypto dep plus hand-rolled base32/CRC-16. Blocking: the differential oracle **does not exist** (harness dir absent; nkeys is not a dev-dep) and the declared security review has not happened |
| `x509-parser` | OWN (BOUNDARY) — **security epic** | 8 | re-scoped (§9.4): delegate maximally to rustls/webpki; own only extraction that cannot be delegated; full checklist (canonicality, full-input consumption, ASN.1 time, KU/EKU/BasicConstraints, SAN, SPKI, duplicate/critical-extension policy, error-mapping parity) |
| `flate2` | OWN (stretch) | 8 | pure-Rust miniz_oxide meanwhile |
| `brotli` | **KEEP_UNTIL_PARITY / KEEP_INCUMBENT** | 3/8 | DEP-ADR-006 resolved the decision: preserve RFC 7932 compression/decompression, negotiation and bounds. Any owned implementation belongs to its separate complete parity campaign; DEFLATE evidence does not establish Brotli parity. |
| `lz4_flex` | OWN (SAFE) | 8 | ~1–1.5k lines realistic |
| `unicode-normalization` | **KEEP** | — | flipped: hand-maintaining Unicode tables/versioning/security semantics is a poor target. The dependency-free alternative — rejecting non-ASCII paths — is an owner-level product decision, offered but not assumed |
| `serde` + `serde_json` | KEEP | — | keystone; suite-level decision later |
| `sha1/sha2/hmac/subtle/zeroize/getrandom`, `aes-gcm`, `chacha20poly1305`, `ed25519-dalek` | KEEP | — | audited crypto; not a place for NIH |
| `rustls` + pki-types + pemfile + roots | KEEP | — | §8.2 for ring/Graviola |
| `libc`, `nix`, `windows-sys`, `io-uring`, wasm-bindgen family | KEEP | — | FFI/ABI bedrock |
| `tracing`/`tracing-subscriber`, `backtrace`/`rustc-demangle`, `loom` (feature-gated normal), `tower`, `tokio`+`async-trait` (benchmark lane), `arbitrary`, `opentelemetry-proto` (fuzz) | KEEP | — | isolated, feature-gated, or verification lanes. Note: `cli` currently enables `tracing-integration`, so retained tracing crates remain a marginal cost of `cli` unless that feature edge is dropped — recorded in Appendix B |
| `syn`/`quote`/`proc-macro2` | KEEP | — | permanent residents (our macros + serde_derive) |

Satellites: `asupersync-tokio-compat` = KEEP-by-design (it *is* the Tokio boundary); `conformance` + `fuzz/` = DEV-KEEP verification lanes; `asupersync-browser-core`'s `serde-wasm-bindgen` = browser ABI KEEP; `frankenlab` follows the CLI/YAML decisions; `drop_unwrap_finder` = internal tool. npm `packages/` handled in Phase 9. Dev-dependencies: all DEV-KEEP; replaced crates stay as differential oracles for two release cycles.

---

## 6. Performance doctrine (Rev-3-corrected)

1. **Safe portable baseline first; ledgered dispatch second, only where measured** (the GF(256) pattern).
2. **`std::simd` honesty:** it is a nightly experimental API; codegen may split wide ops into multiple instructions or scalarize — it is *not* guaranteed "full-strength NEON/AVX2". Treat portable-SIMD results as an empirical question per kernel: benchmark, inspect codegen where it matters, and fall back to ledgered `#[target_feature]` intrinsics (BOUNDARY-UNSAFE) when the numbers demand.
3. **x86-64 baseline is SSE2** without target-feature dispatch; AVX2/AVX-512 need runtime dispatch through ledgered shims. AVX-512 notes: Zen 4 executes 512-bit ops over two 256-bit paths; **Zen 5 has a native 512-bit datapath** — do not group them; Intel pre-Ice-Lake downclocking still argues for runtime gating.
4. **Apple Silicon:** prefer branchless scalar below ~64 B; `std::hint::spin_loop` lowers to `isb` on aarch64 (a pipeline-flush hint — *not* a WFE wait protocol; do not design spin loops assuming event-wait semantics).
5. **Cache-line padding is measured, not global:** aarch64 ≠ Apple Silicon. Do not blanket-change `CachePadded` to 128 B; scope 128-byte padding to *specific measured structures* on target families where the benchmark shows contention wins (Apple M-series 128-B lines; x86 adjacent-line prefetcher), keeping 64 B elsewhere to avoid wasting cache.
6. **Lock/primitive gate metrics (replaces the Rev-2 "2% p50" gate):** throughput, p50/p95/p99/p999, fairness (max starvation), cancellation latency, allocations + RSS, compile time, binary size, and 1/8/32/64-core scaling curves on the tracked bench set. A replacement ships only if it is within threshold on *all* tracked axes or the regression is explicitly accepted by the owner.
7. **Determinism trumps micro-wins:** bit-exact outputs across ISAs remain part of every kernel's contract.

**Verification stack per replacement:** differential property tests vs the replaced crate (dev-dep oracle) · golden vectors · fuzz target · Miri on unsafe modules (with the §3 caveat that Miri does not prove concurrent liveness or weak-memory correctness) · criterion ratchet · UBS.

---

## 7. Execution plan (Rev 3 — DAG, not "embarrassingly parallel")

Rev 2's "Phases 1–3 are embarrassingly parallel" was false: bincode and MessagePack both touch `typed_symbol.rs`; ~~prost is a prerequisite for native OTLP~~ (**withdrawn** — DEP-ADR-002/003: prost is KEEP, and an owned OTLP message set can use prost derives as `otlp_logs_proto` already does, so no such ordering edge exists); TOML/YAML/chrono/clap overlap heavily in the CLI files and manifests; parking_lot gates smallvec's marginal. The plan is now an ordered DAG; within each phase, listed items are independent **only if their file sets are disjoint — every bead carries exact file reservations**.

**Phase 0 — Hygiene. LANDED** (`a86bfb3a6`; net −2 crate-versions / −3 names; UPGRADE_LOG.md pass 4).

**Phase 1 — Foundations (blocks everything).**
1.1 Safety-taxonomy artifact (§3) as `artifacts/dependency_safety_taxonomy_v1.json` + contract test.
1.2 Marginal-ledger generator (§4) from `cargo metadata` package IDs, per-platform, synthesized-consumer root excluded; committed artifact + contract test.

**Phase 2 — Low-risk leaf removals (SAFE-OWN/STD only; genuinely parallel, disjoint files).**
hashbrown→std/DetHashMap · num_cpus/whoami→std · env_logger removal · `time` consolidation · tempfile optionalization · ~~futures-lite→`util/future.rs`~~ (**withdrawn** — DEP-ADR-008: public-api exposed via the ATP SDK `Stream` impls, cutover BLOCKED_PENDING_EVIDENCE, ~272 files, not a low-risk disjoint leaf) · visibility→own attr · slab→TokenSlab · hex/base64 own engines · delete the `mod regex` mock (plain digit-run parser stopgap) · file the orphaned-e2e-files wire-or-remove bead (owner sign-off).

**Phase 3 — Public API decisions (blocks all codec/CLI/otel work; produces ADRs + api_surface_map updates, no implementation).**
3.1 `SerdeCodec` (`typed_symbol.rs`): **RESOLVED — see `docs/adr/dep_plan_adr_001_serde_generic_formats.md` (DEP-ADR-001).** The Rev-3 framing above is superseded. It reads as an API narrowing but is really a **persisted-format break**: `rmp-serde` is the on-disk encoding of every trace file and replay trace, and `bincode` (legacy config) encodes distributed-snapshot vector clocks — dropping either strands the existing corpus. All four `SerializationFormat` discriminants stay (including `Custom`, whose header byte 255 is the downstream extension point via `with_serializer`/`with_deserializer`). Canonical JSON and owned schemas are **additive**, permitted for new writes only once a reader for the existing corpus exists. Terminal: `KEEP_UNTIL_PARITY`/`KEEP_INCUMBENT` for the generic formats; `PRESERVE_AND_REPLACE_IF_PARITY`/`BLOCKED_PENDING_EVIDENCE` for the persisted artifacts.
3.2 `ProstCodec` (`grpc/protobuf.rs`): **RESOLVED — see `docs/adr/dep_plan_adr_002_protobuf_generic.md` (DEP-ADR-002).** The Rev-3 framing above ("owned `ProtoMessage` trait over a finite message set; drop the public arbitrary-`prost::Message` surface") is superseded and rejected by the Rev-5 no-loss gate. Source re-read established that the trade does not work: the finite sets §9.6 proposes to hand-write — gRPC health and reflection — are **already prost-free today**, and the only closed prost message set (`otlp_logs_proto`) is module-private. prost therefore buys exactly one thing, the arbitrary downstream generic surface, so dropping it surrenders the whole capability in exchange for work already done. Terminal decision: `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`.
3.3 OTLP/metrics: **RESOLVED — see `docs/adr/dep_plan_adr_003_otlp_ecosystem.md` (DEP-ADR-003).** The Rev-3 framing above ("remove external OpenTelemetry `Meter`/SDK interoperability, or abandon the replacement") is superseded: the Rev-5 no-loss gate rejects both branches. Source re-read established that the owned OTLP request builders for metrics and traces are gated to test/fuzz builds (they depend on the tokio-carrying `opentelemetry-proto`), so the external SDK bridge is the *only* production export path for those two signals; only logs have a complete owned production path. The terminal decision is additive coexistence with `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`, and a dependency exit additionally requires an owned tokio-free wire encoder for metrics and traces.
3.4 Config formats: **RESOLVED — see `docs/adr/dep_plan_adr_004_config_scenario_formats.md` (DEP-ADR-004).** Not a migration. TOML configuration and YAML scenarios stay accepted indefinitely; canonical JSON is **additive** only, with lossless round-trip and rollback. `toml` and `serde_yaml` are `KEEP_UNTIL_PARITY`. Note two source facts the Rev-3 wording obscured: `src/lab/scenario.rs` contains no YAML code at all (serde derives only, parsed at call sites), and JSON *config* loading plus any canonical-JSON encoder do not exist yet and would be new work.
3.5 CLI surface: **RESOLVED — see `docs/adr/dep_plan_adr_005_cli_contract.md` (DEP-ADR-005).** Terminal decision `KEEP_UNTIL_PARITY`/`KEEP_INCUMBENT` for all four binaries. The golden strategy is the decision: **goldens gate everything else**, because none exist today — byte-exact `--help`/subcommand-help/`--version`/error text for all four binaries, then non-UTF-8 argv coverage, then real-binary nonzero exit assertions, *then* a measured owned parser. Two findings recorded: only `asupersync` consumes the shared `ExitCode` registry (`atp` returns std 0/1, `atpd` exits 1 via default `Termination`, `offline_tuner` calls `process::exit(1)`), and `src/cli/atp_command_tree.rs` defines 22 clap commands reachable from **no** binary. The `cli` → `tracing-integration` edge is NOT dropped here: subscriber initialization must be specified first so removing `env_logger` or `clap` cannot silence diagnostics.
3.6 Brotli: **RESOLVED — see `docs/adr/dep_plan_adr_006_brotli_compression.md` (DEP-ADR-006).** Terminal decision `KEEP_UNTIL_PARITY`/`KEEP_INCUMBENT`; the removal branch is closed. HTTP and ATP impact is documented in the ADR. An owned RFC 7932 codec may only proceed as a **separate security-sensitive codec epic** — a DEFLATE parity result confers nothing about Brotli. Two corrections recorded: the real codec is `src/http/compress.rs` (the registry names `src/web/compress.rs`, whose only Brotli refs are in its test module), and `src/net/atp/compress/` is **orphaned and has never compiled** (its gzip path imports `flate2` with no feature gate), so it must not be counted as partial work.
Each ADR updates `artifacts/api_surface_map_v1.json` and docs in the same commit.

**Phase 4 — nkeys parity campaign under DEP-ADR-007 (KEEP incumbent).**
The original base32/CRC-16/NATS-only proposal is insufficient. The existing
campaign must cover all four consumers, every accepted key/prefix form,
signer policy, zeroization, differential vectors and security review before
an incumbent transition can be considered. See the governing §5 row and
`docs/adr/dep_plan_adr_007_nkey_auth.md`; the historical marginal is not exit
evidence.

**Phase 5 — Codec/CLI implementation in dependency order (after Phase 3).**
5.1 Owned protobuf types and wire codec are additive under DEP-ADR-002: use the
existing `Codec` seam alongside `ProstCodec`; the test-only varint helpers remain
an oracle. 5.2 Native OTLP export is additive under DEP-ADR-003 and does not
depend on 5.1. Typed-symbol/snapshot/trace work preserves the generic formats
and existing persisted corpus under DEP-ADR-001; bincode and rmp-serde do not
exit. JSON remains additive alongside TOML/YAML under DEP-ADR-004. The chrono
and clap campaigns preserve public types, accepted inputs and diagnostics under
DEP-ADR-011/005. Fixed privacy scanners may provide a fast path under
DEP-ADR-012, but the full accepted regex language and public `regex::Error`
identity remain supported. Each campaign retains its implementation and
behavioral evidence obligations; KEEP is not completion of that work.

**Phase 6 — FrankenSQLite integration (independent campaign; §9.1 gates).**

**Phase 7 — Kafka capability preservation and native parity campaign.**
DEP-ADR-009 keeps the existing feature and no-feature typed refusal. The native
client remains a separate implementation campaign (§9.3); downstream inventory
alone does not authorize removal. K10's public/configuration contract is
`asupersync-dep-p7-kafka-removal-sarszu.2.10`, whose governing scope preserves
the shipped 0.4.x facade and requires real broker/user-journey evidence.

**Phase 8 — Evidence-gated deferrals (each needs a measured/maintenance justification + owner sign-off before build).**
parking_lot→SAFE `sync/oslock.rs` wrapper (stable-lane-compatible; §9.2) · signal-hook/sysinfo/xattr consolidation (BOUNDARY) · x509 security epic (§9.4) · polling/socket2 revisit (only with measured defect or a suite-wide platform-boundary project) · flate2/lz4/DEFLATE work · crossbeam-queue SAFE prototype benchmark.

**Phase 9 — Continuous enforcement.**
Dependency budget contract from the marginal ledger (synthesized consumer, per-platform, ratchet-down) · `cargo deny`/`cargo audit` over the full workspace incl. dev/build graphs · GitHub Actions pinned by commit SHA · npm `packages/` + pnpm lockfile audit · `fuzz/` graph in the sweep · consumer guidance (library lockfiles don't protect consumers; minimal-versions lane; `cargo vendor` posture) · AGENTS.md dep table generated from the contract.

**Historical bead mapping (consult current tracker status and governing scope):** `d24mms` = Phases 1–2 · `5z2scg` = Phases 3+5 · `ym2wtv` = Phases 4, 6, 7 · `3u3tej` + `0h6myr` = Phase 8 (evidence-gated; do not start without gate evidence) · `mnotoo` = Phase 9. Epic `ir2uf0` owns the dependency program; the old `bm3tty` reference is not a current whole-HEAD test result.

**End-state projection:** replaced by generated forecasts. The ledger (Phase 1.2) emits per-phase projected graphs with confidence ranges; the static "~40–50 names" figure from Rev 2 is retired. Direction, not destination, is the commitment: every phase must reduce trusted upstreams, native/unsafe surface, or marginal weight — and prove it with the recomputed ledger.

---

## 8. What we deliberately keep

### 8.1 Cryptography is not a place for NIH
`sha1/sha2/hmac/subtle/zeroize/getrandom/aes-gcm/chacha20poly1305/ed25519-dalek`: audited, pure-Rust, security-load-bearing. Non-negotiable keep. We remove crypto-adjacent *packaging* (nkeys' text codec; x509 extraction where webpki can't help), never the primitives.

### 8.2 rustls and the ring problem
Keep rustls. For the ring provider: **Graviola is a provider *experiment*, not a default switch** — it is very new, incorporates (formally verified) assembly, supports only x86_64/aarch64, and requires substantial CPU features; it does not satisfy a literal no-unsafe/no-assembly rule and needs runtime/fleet eligibility handling. Trial it on the encrypted ATP matrix; adopt only with owner sign-off on the assembly trade. FrankenTLS remains out of scope.

### 8.3 serde / serde_json
Keystone (~4,600 derives, ~1,450 `json!` in the historical census). Keep; any `franken-serde` is a suite-level decision after this plan completes. JSON is an additive machine-output/input option under DEP-ADR-004; it does not replace accepted TOML/YAML. Recompute shared dependency marginals from the selected current graph.

### 8.4 FFI bedrock and the mature-unsafe principle
`libc`/`nix`/`windows-sys`/`io-uring`/wasm-bindgen family: the platform boundary. The same reasoning now explicitly protects `crossbeam-queue`/`smallvec`/`pin-project` (§3): mature, widely-fuzzed algorithmic unsafe beats fresh first-party algorithmic unsafe until measurement says otherwise.

### 8.5 FrankenSuite non-candidates (for the record)
**FrankenFS** is not a host-xattr substitute (its xattr work is filesystem/on-disk semantics, not portable syscalls). **FrankenLibC** is Linux/interposer-oriented prior art with intentional unsafe ABI boundaries — its syscall/signal//proc logic can inform Phase-8 implementations but cannot replace the cross-platform layer.

---

## 9. Flagship designs (Rev-3-scoped)

### 9.1 FrankenSQLite (downstream integration; KEEP incumbent SQLite feature)
**Superseded by DEP-ADR-010 on the terminal outcome: KEEP.** The deprecate/remove-and-invert direction below is *not* authorized. Cargo cannot make the root `sqlite` feature depend on the downstream adapter without a cycle, so removing it would strand the one-stop supported path and force users to reconstruct the integration themselves — the bead makes KEEP the default terminal result absent explicit owner approval after user-journey trials. Two gates are **added** to the three below: (d) **data compatibility** — files written by the incumbent must be readable, including WAL and unclean-shutdown state; and (e) an **equivalent `ToSql` trait**, because `impl rusqlite::ToSql for SqliteValue` is a public foreign-trait impl and the only engine leak in the API (no signature names the engine, so a signature-grep audit misses it). Note also that the parity matrix in (b) **cannot run in this workspace** — fsqlite may not be added back in any form, not even as a dev-dependency oracle.

Direction as originally written: fsqlite-core's asupersync dependency is unconditional, so integration would have to be inverted — asupersync's `sqlite` feature deprecated/removed; fsqlite's existing `async-api` grows the `Cx`-threaded glue. This is **capability relocation, not zero dependency cost**: fsqlite's async graph carries its own external crates and currently resolves the published asupersync 0.3.9 graph. Gates before the swap: (a) a **combined fsqlite + asupersync consumer budget** measured with the §4 ledger; (b) a **semantic parity matrix** — transactions, prepared statements + cache, interruption, budget-derived timeouts, typed rows, cancellation behavior — proven against the existing sqlite e2e suite running on both engines during overlap; (c) honest maturity framing: fsqlite's native mode is partial per its own README — the claim is *owned, safe, concurrent-writer SQLite on our runtime*, not "MVCC and RaptorQ durability for free."

### 9.2 Additive `sync/oslock.rs` experiment (SAFE-OWN, stable-compatible)

The original wrapper design below may introduce owned guards on new/private
surfaces. It must preserve existing public parking-lot guard identities and
behavior throughout 0.4.x; changing those signatures to owned guards is not
authorized. KEEP the incumbent wherever that public contract requires it.
An owned wrapper over `std::sync::{Mutex, RwLock, Condvar}` must recover poisoned
guards internally (`PoisonError::into_inner`), cover the load-bearing Condvar
behavior, and compile on the audited stable lane
(`--no-default-features --features proc-macros`). An optional nightly
`nonpoison` backend may serve contributor lanes. Owned guards belong on
additive/private APIs; compatible adapters preserve shipped public types.
The experiment must pass the §6.6 multi-axis gate on 1/8/32/64 cores. Recompute
the marginal only after accounting for every retained compatibility edge.

### 9.3 Kafka: keep now, campaign later
**Superseded by DEP-ADR-009 on "remove now": the feature stays.** The registry's no-claim boundary governs — a wire codec or simple producer is not a Kafka client — and the gating downstream inventory has never been run. Removal would also delete the *owned*, rdkafka-free fail-closed lane: the modules are not feature-gated, so the types compile on every build and a no-feature production call returns a typed feature-disabled error plus a diagnostic. Worth recording for whoever picks up the campaign: the public API is **already completely rdkafka-free** (the upstream error is aliased and mapped, never re-exported; the context type is private), so this is a backend swap behind a facade we own — but the surface to match also has two holes that bound what "parity" means, namely **no transactional consumer offsets** (so no read-process-write EOS) and **no admin surface at all**. Any native client remains an **independent protocol campaign** with its own epic: API-version negotiation matrix, flexible/tagged fields, coordinator protocols (groups/heartbeats/rebalance), idempotence epochs/sequences, transactions, isolation levels, offset management, compression codecs, TLS/SASL, metadata refresh + retry semantics, fuzzing, and real-broker conformance. The current surface it would have to match is ~7k lines of wrapper API including transactional producers and consumer groups — no line estimate is retained here by design.

### 9.4 X.509: a security epic, not a parser swap
Current x509-parser usage is **active validation**, not just extraction (§2.5): validity windows, server EKU, KeyUsage, BasicConstraints CA:TRUE, per-chain validity, SAN matching, SPKI pinning, plus error-mapping consumers. Strategy, in order: (1) **delegate every check rustls/webpki can perform to rustls/webpki** — chain validity, EKU, name checking on the standard path; (2) inventory what genuinely cannot be delegated (SPKI-bytes extraction for pinning; SAN access inside the custom native-QUIC verifier); (3) only then scope `tls/der_min.rs` for that residue, with the full checklist: DER canonicality, full-input consumption, ASN.1 time parsing, duplicate/critical-extension policy (hard error), depth caps, fail-closed ambiguity handling, and byte-for-byte error-mapping parity with today's diagnostics. Differential fuzzing vs x509-parser over an openssl-generated + BetterTLS/limbo-style mutated corpus (to-be-built). Own epic + security-review bead; not schedulable from this plan alone.

### 9.5 nkeys → `security/nkey.rs` — **SUPERSEDED by DEP-ADR-007 (KEEP); `security/nkey.rs` does not exist**
Unchanged from Rev 2 except honest accounting: ~200 lines SAFE-OWN codec (base32 no-pad + CRC-16/XMODEM + prefixes) on a direct ed25519-dalek dep; **marginal ~16 packages**; NATS-fixture differential vectors; the digest-generation dedup additionally waits on upstream dalek (§2.3).

### 9.6 `codec/proto.rs` — **SUPERSEDED by DEP-ADR-002; does NOT replace prost**
~~Owned `ProtoMessage` trait + hand-written finite message set replaces prost.~~ The premise was wrong. `src/grpc/health.rs` and `src/grpc/reflection.rs` contain **zero** prost references today — the finite gRPC message sets are already hand-written and prost-free — and the OTLP export subset (`otlp_logs_proto`) is a module-private prost-derive set owned by DEP-ADR-003. Building any of these removes nothing, because `prost` is required **only** for the arbitrary downstream generic `ProstCodec<T, U>` surface. An owned protobuf implementation is still permitted as *additive* work, but it must plug into the existing `Codec` seam alongside `ProstCodec` and clears no dependency until it matches prost's derive ergonomics for arbitrary downstream schemas. The `#[cfg(test)]` varint helpers in `grpc/protobuf.rs` remain differential-oracle code, not a partial implementation. Not a prerequisite for 5.2: an owned OTLP message set can use prost derives exactly as `otlp_logs_proto` already does.

---

## 10. Risk register (Rev 3)

| Risk | Mitigation |
|---|---|
| Fresh algorithmic unsafe introduces liveness/UB bugs mature crates don't have | §3 prohibits the class by default; exceptions need measured defect + safe-alternative benchmark + owner sign-off |
| Public API redesigns (SerdeCodec/ProstCodec/Meter/CLI/config) ship half-decided | Phase 3 ADR gate blocks implementation; api_surface_map + docs updated per ADR |
| X.509 replacement drops an active security check | §9.4 delegate-first strategy; residue checklist; differential fuzz; security-review bead; error-mapping parity requirement |
| Stable lane breaks (parking_lot replacement, nightly-only APIs) | §9.2 stable-first design; `run_stable_lane_e2e.sh` added to the gate set for every Phase-8 primitive |
| PII-redaction subset silently weakens operator configs | DEP-ADR-012 retains the full accepted pattern language and public error identity; fixed scanners are an additive fast path, not a replacement gate |
| Additive JSON changes accepted TOML/YAML semantics | DEP-ADR-004 preserves both input formats, precedence and replay behavior; use round-trip/corpus evidence without deleting existing files |
| Brotli replacement degrades HTTP/ATP interop | DEP-ADR-006 resolves KEEP; require the independent complete codec parity campaign |
| Native Kafka transition strands an existing consumer | DEP-ADR-009 retains the feature and typed refusal; require complete public/configuration and real-broker parity, not inventory alone |
| FrankenSQLite swap regresses semantics or inflates the combined graph | §9.1 parity matrix + combined-graph budget + overlap period |
| Trace/snapshot format churn breaks replay tooling | format-version bumps + `trace/compat.rs`; registry-consumer exposure checked (frankensqlite pins 0.3.9) |
| Marginal-ledger drift makes priorities stale | ledger regenerated and committed after every phase; budget contract fails closed on drift |
| Agent-swarm conflicts on shared files (typed_symbol, CLI cluster) | DAG ordering + exact per-bead file reservations (§7) |

---

## Appendix A — Graph snapshots
Pre-Phase-0: 132 crate-versions / 124 names. Post-Phase-0 (`a86bfb3a6`): 130 / 121. Duplicate-version driver: nkeys→dalek old-gen chain. Full lists regenerate via Appendix C.

## Appendix B — Feature-cost table (names, post-Phase-0)
| Feature | Adds today | End-state |
|---|---|---|
| (default) | 121 | generated forecast (Phase 1.2 ledger) |
| `tls` | +26 | the measured rustls/provider/webpki closure (~12–15; forecast-generated) |
| `sqlite` | +10 + bundled C | KEEP incumbent feature under DEP-ADR-010. A downstream/neutral adapter must avoid a reverse dependency edge and preserve the old public `rusqlite::ToSql` path; no zero-external outcome is authorized. |
| `kafka` | +13 + bundled C | KEEP incumbent feature and no-feature refusal under DEP-ADR-009. Native implementation and complete compatible cutover evidence remain separate work. |
| `metrics` | +13 | **+13 retained.** DEP-ADR-003 did not approve dropping external-SDK interop; the zero-external end-state is not an authorized outcome. Any future reduction is gated behind an owned tokio-free OTLP wire encoder for metrics and traces plus proven provider-bridge parity. |
| `cli` | +43 | KEEP accepted parser/configuration/diagnostic behavior under DEP-ADR-004/005/011. Additive work does not authorize removing clap, TOML/YAML, chrono or the tracing feature edge. |
| `compression` | +8 | KEEP Brotli and flate2 under DEP-ADR-006 until complete codec-specific parity; no capability removal. |

## Appendix C — Measurement methodology (Rev 3)
```bash
# Canonical counting: cargo metadata PACKAGE IDS, not crate-name text parsing.
# 1. Synthesize a consumer crate depending on asupersync (path dep, chosen features).
# 2. cargo metadata --format-version 1 --filter-platform <triple> on that consumer.
# 3. Count resolve-graph package IDs reachable via normal+build edges from the
#    consumer root, EXCLUDING the synthetic root itself and workspace-path members.
# 4. Report Linux, macOS, Windows, and wasm32 graphs separately; report both
#    unique-name and crate-version counts.
# 5. Marginal cost of root R = |graph| - |graph with R's edge removed|.
# The ledger generator (Phase 1.2) implements this; ad-hoc `cargo tree | awk`
# pipelines are for exploration only.
# Native-code attribution must be lockfile-verified (declared build-deps can be
# feature-gated off — see rdkafka/signal-hook corrections in §2.2).
```
