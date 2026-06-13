# Cx Authority Flow Graph

<!-- CX-AUTHORITY-FLOW:SOURCE -->

This document renders `artifacts/cx_authority_flow_graph_v1.json` for
`asupersync-idea-wizard-fifth-wave-3gaiun.6`.

The graph describes how capability authority is routed through `Cx` and the
framework wrapper contexts. It is a checked map for operators and agents, not a
static whole-program security proof.

## Source Surface

| source | role |
|---|---|
| `src/cx/cap.rs` | Type-level capability bits, subset relation, sealed marker traits, and runtime `CapMask`. |
| `src/cx/cx.rs` | `Cx::current`, restriction stack, runtime-mask checks, effect accessors, spawning, budget, and tracing surfaces. |
| `src/cx/wrappers.rs` | Least-privilege wrapper contexts for web, gRPC, background, pure, and entropy-only code. |
| `src/cx/mod.rs` | Public exports for capability rows and wrappers. |
| `README.md` and `AGENTS.md` | User-facing invariant statements for explicit `Cx` authority and no ambient authority. |

<!-- CX-AUTHORITY-FLOW:GRAPH -->

## Graph Rows

| context | capabilities | use |
|---|---|---|
| `Cx<AllCaps>` | spawn, time, random, I/O, remote | Runtime-owned task contexts and trusted test constructors. |
| `Cx<NoCaps>` | none | Ambient-denial and pure computation boundaries. |
| `WebContext` | time, I/O | Request handlers without spawn, random, or remote authority. |
| `GrpcContext` | spawn, time, I/O | Streaming RPC handlers that need structured child work. |
| `BackgroundContext` | spawn, time | Background tasks without I/O, entropy, or remote effects. |
| `Cx<PureCaps>` | none | Pure computation examples and effect-denial tests. |
| `EntropyCaps` | random | Entropy-only boundaries. |

The important edges are monotone: full contexts may be narrowed to wrapper
contexts, but wrapper contexts do not widen back to full authority. Runtime-mask
restriction applies to ambient lookups too: `Cx::current()` observes the
innermost installed mask, so a restricted scope cannot recover full authority
through the thread-local current-context stack.

<!-- CX-AUTHORITY-FLOW:DENIED-EXAMPLES -->

## Denied Examples

| example | expected denial |
|---|---|
| `web-denies-spawn` | `WebContext::cx()` lacks the `HasSpawn` bound required by spawn APIs. |
| `pure-denies-io` | `PureCaps` lacks I/O authority, and restricted runtime accessors return `None`. |
| `restricted-current-denies-remote` | `Cx::current()` inside a restricted scope carries the narrowed mask, so `remote()` returns `None`. |
| `background-denies-io` | `BackgroundContext` can spawn and use time, but lacks the `HasIo` bound. |

## Validation

Use the remote-only focused lane declared in the artifact:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_cx_authority_flow_graph" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test cx_authority_flow_graph_contract -- --nocapture
```

Local Cargo fallback is not evidence for this contract.

<!-- CX-AUTHORITY-FLOW:NO-CLAIMS -->

## No-Claim Boundaries

This graph does not prove static whole-program security, broad workspace health,
release readiness, or runtime correctness outside the cited `Cx` capability
surfaces. It does not replace the authority-flow adversarial audit corpus,
capability-token model, security threat model, or per-feature proof lanes.
