# TLS / Send downstream consumer (GH #86)

This independent workspace depends on the real runtime without its dev graph.
Its library checks `SpawnRequest: Send`, `Cx: Send + Sync`, and `Send + 'static`
for futures retaining either type across an await and for a capturing closure.
That default-limit compile surface does not import or use the HTTP client. It
has no `recursion_limit` override and does not box away the obligation under test.

From the repository checkout, on an available RCH worker:

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- bash scripts/validate_tls_send.sh
```

The default matrix uses exact stable 1.99.0 and 1.99.1, each with nine profiles:
`proc-macros,native-runtime` with and without TLS; the reporter's additional
`nightly-outcome-try` with and without TLS; runtime defaults with and without
TLS; provider-free `tls-core`; native roots; and WebPKI roots. On stable the
runtime's existing build probe leaves the nightly-only Try implementation
inactive. The runner does not enable `RUSTC_BOOTSTRAP` to change that behavior.
It explicitly sets `RUSTFLAGS='-C debuginfo=0'` so the repository's nightly-only
`-Z threads=4` Cargo configuration cannot contaminate a stable qualification.

## Detecting type-graph growth, not only default-limit compilation

A plain `SpawnRequest: Send` assertion can pass at the default recursion limit
even before the fix; a downstream application's surrounding future contributes
additional depth. Therefore the native TLS/off rows additionally compile the
separate opt-in `depth_probe` binary at a **lower** limit of 60. The fix commit's
stable 1.99.1 measurements put this obligation at 53-54 after erasure and 63-64
with the concrete TLS slot, so this sentinel targets that measured regression.
The ordinary library surface still compiles at the unmodified default limit.

This is a pinned-compiler sentinel, not a portable minimum-depth API guarantee.
Do not move it to a floating stable/nightly lane or raise its ceiling merely to
make a failure green. On a toolchain or type-graph change, remeasure the erased
and concrete-slot graphs and investigate the additional path. The recorded
measurements explain the chosen ceiling; they are not a fresh execution receipt.

## Runtime behavior is a separate graph

The `behavior` feature enables test-internals only for `tests/http_slot.rs`.
It is never selected by the production-only compiler matrix. Four tests cover:

- Lazy initialization, including a context cloned before first access.
- Concurrent first access on four OS threads, followed by real HTTP requests
  that must all reuse one accepted TCP connection; a separate root stays empty.
- Slot inheritance through both the spawn closure's Cx and Cx::current(), with
  the child initializing first, on current-thread and two-worker runtimes.
- Cancellation published through a Cx clone before sending: a cancellation
  result, no created connection, and no connection accepted by the listener.

All server threads are finite and reaped, including during assertion unwinding.
The runner executes these tests with TLS disabled and enabled on each compiler.
It separately runs the existing root default-client and pool-wait conformance
suites, plus `http_client_https_e2e` for TLS. Those existing targets cover the
normal HTTP/TLS path, local-root verification/refusal, and pool-wait cancellation;
they are not substituted by the type assertions or the Debug-based lazy check.

## Evidence and release boundary

Run separately on available Linux and macOS hosts. The runner records the
compiler, host, source revision, working-tree status, dependency feature graph,
consumer lockfile, and every stage's exit code. It rejects test-internals
unification in compile rows, missing/unexpected rustls, unavailable compilers,
and a zero-test behavioral result. It never publishes, creates a tag, or
silently substitutes local compilation. An existing consumer lockfile is reused
with `--locked`; the first invocation resolves one and retains it with its
receipt. It is not the workspace lockfile; root integration tests use root's.

A pass covers only these named checks. Broad pinned-nightly test/Clippy gates,
package/dry-run validation, signing, and post-publication source/artifact
verification remain separate requirements. Missing evidence is not a pass.
