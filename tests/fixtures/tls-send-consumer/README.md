# TLS / Send downstream consumer (GH #86)

This independent workspace depends on the real runtime without its dev graph.
It proves `SpawnRequest: Send`, `Cx: Send + Sync`, and `Send + 'static` for
futures retaining either type across an await and for a capturing closure.
The compile surface does not import or use the HTTP client. It has no
`recursion_limit` override and does not box away the obligation under test.

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

Run separately on available Linux and macOS hosts. The runner records the
compiler, host, source revision, working-tree status, dependency feature graph,
consumer lockfile, and every stage's exit code. It rejects test-internals
unification, a missing/unexpected rustls dependency, and unavailable compilers.
It never publishes, creates a tag, or silently substitutes local compilation.
An existing consumer lockfile is reused with `--locked`; the first invocation
resolves one and retains it with its receipt. It is not the workspace lockfile.

These are default-limit compatibility checks, not a claim that a fixed numeric
trait-solver depth is stable across compiler versions. The original 53–54 vs
63–64 measurements remain diagnostic evidence from the fix commit, not a
portable pass threshold. Passing this matrix does not establish runtime HTTP
behavior, package correctness, or release readiness. Those require their own
executed qualifications; missing evidence must not be represented as a pass.
