# Structured Concurrency Macro DSL

This document describes the Asupersync macro DSL for structured concurrency:
`#[main]`, `#[test]`, `scope!`, `spawn!`, `join!`, `join_all!`, and `race!`.

The macros are designed to reduce boilerplate while preserving Asupersync
invariants: structured concurrency, cancellation correctness, and deterministic
testing.

## Enable Macros

The macro DSL ships in the default feature set, so a standard dependency is
enough. If you disable default features, re-enable `proc-macros` explicitly.

```toml
[dependencies]
asupersync = { path = "." }
```

```toml
[dependencies]
asupersync = { path = ".", default-features = false, features = ["proc-macros"] }
```

```rust
use asupersync::proc_macros::{join, join_all, main, race, scope, spawn, test};
```

## Supported Contract

| Macro | `proc-macros` build | No-`proc-macros` build | Current semantics |
|------|----------------------|------------------------|-------------------|
| `scope!` | Supported and re-exported by `asupersync` | Unavailable | Binds a `Scope` for the current region; does not create a fresh child-region boundary |
| `spawn!` | Supported and re-exported by `asupersync` | Unavailable | Expands to `Scope::spawn_registered`; requires ambient `__state` and `__cx` |
| `join!` | Supported and re-exported by `asupersync` | Contract-enforcement `compile_error!` fallback | Awaits branches sequentially today |
| `join_all!` | Supported and re-exported by `asupersync` | Unavailable | Awaits branches sequentially today |
| `race!` | Supported and re-exported by `asupersync` | Contract-enforcement `compile_error!` fallback | Expands to `Cx::race_drained*`; losers are protocol-cancelled **and drained** |
| `#[main]` / `#[test]` | Supported and re-exported by `asupersync` | Unavailable | Runs async entry functions on the production runtime and optionally injects the installed root `Cx` |
| `#[lab_test]` | Supported and re-exported by `asupersync` | Unavailable | Runs deterministic lab tests under one seed or a seed matrix and fails with seed/rerun details |

`session_protocol!` and `#[conformance]` exist in `asupersync-macros`, but they
are not part of the root `asupersync` macro contract.

`#[main]` and `#[test]` are production-runtime entry attributes. They build an
`asupersync::runtime::Runtime`, call `block_on`, and allow an optional
`cx: &Cx` parameter that is bound from the root context installed by `block_on`.
They accept `flavor`, `workers`, and `budget` arguments and reject unsupported
signatures at macro expansion time.

```rust
use asupersync::{Cx, main};

#[main(flavor = "current_thread", workers = 1, budget = 128)]
async fn main(cx: &Cx) -> Result<(), asupersync::Error> {
    cx.checkpoint()?;
    Ok(())
}
```

`#[test]` uses the same production runtime path under the Rust test harness:

```rust
use asupersync::{Cx, test};

#[test(flavor = "multi_thread", workers = 2)]
async fn production_runtime_smoke(cx: &Cx) {
    cx.checkpoint().expect("checkpoint");
}
```

`#[lab_test]` wraps deterministic lab tests in a fixed seed or seed matrix,
initializes test logging, drives the lab to quiescence, and fails with the exact
seed plus a rerun command when the body, oracle report, or invariant report
fails.

```rust
use asupersync::{lab::LabRuntime, lab_test};

#[lab_test(seeds = 0..16)]
fn invariant_matrix(lab: &mut LabRuntime) {
    assert!(lab.config().seed < 16);
}
```

Async root-task form receives a `&Cx` and is run through
`lab::run_async_under_lab_with_config`:

```rust
use asupersync::{cx::Cx, lab_test};

#[lab_test(seeds = 7..9, chaos)]
async fn cancel_path(cx: &Cx) {
    cx.checkpoint().expect("checkpoint");
}
```

Initial porting evidence for `asupersync-lab-dx-v2-n2v2fi.1`: six
representative `src/lab/runtime.rs` tests now use
`#[asupersync::lab_test(seeds = 42..43)]`:
`empty_runtime_is_quiescent`, `advance_time`, `advance_to_next_timer_empty`,
`clock_pause_resume`, `inject_clock_skew`, and
`auto_advance_quiescent_termination`. Their repeated raw setup/completion
boilerplate moved from 18 lines (`init_test`, `LabRuntime::{with_seed,new}`,
and `test_complete!`) to 6 attribute lines, a 67% reduction for that setup
block.

## Quick Start (Runnable)

This snippet is runnable as an example binary through the production runtime
entry macro:

```rust
use asupersync::{Cx, main};

#[main]
async fn main(cx: &Cx) {
    cx.checkpoint().expect("checkpoint");
}
```

## Phase 0 Status Notes

The macro DSL is usable today, but its semantics are narrower than the long-term
design target. Keep the following in mind:

- `scope!` currently calls `Cx::scope()` and binds the existing region. If you
  need a fresh child-region boundary with quiescence on exit, use
  `Scope::region(...)` explicitly.
- `spawn!` requires a `__state: &mut RuntimeState` variable to exist in scope.
  The supported path is `scope!(cx, state: ..., { ... })`.
- `race!` expands to the drain-correct `Cx::race_drained*` methods: each branch
  is spawned as a region task and resolved through `Scope::race_all`, so every
  loser is protocol-cancelled **and drained** (awaited to termination) before
  the macro returns. Branches and their outputs must therefore be `Send +
  'static`, and `cx` must carry spawn authority. The lower-level drop-on-cancel
  `Cx::race*` methods remain as an escape hatch for non-`'static` inline races.
- `join!` and `join_all!` are sequential today. Parallel polling is future work.

These are *phase limitations*, not permanent API choices.

## Macro Reference

### scope!

Create a `Scope` binding for the current region. The macro binds a `scope`
variable inside the body.

**Syntax**

```rust
scope!(cx, { ... })
scope!(cx, "name", { ... })
scope!(cx, budget: Budget::INFINITE, { ... })
scope!(cx, "name", budget: Budget::INFINITE, { ... })
```

**Expansion (conceptual)**

```rust
{
    let __cx = &cx;
    let __scope = __cx.scope();
    async move {
        let scope = __scope;
        /* body */
    }.await
}
```

**Notes**

- `scope!` always inserts `.await`, so it must be invoked inside an async context.
- `scope!` does not create a fresh child region today.
- `return` is rejected inside the body. Use early-return patterns instead.

### spawn!

Spawn work inside the current `scope`.

**Syntax**

```rust
spawn!(future)
spawn!("name", future)
spawn!(scope, future)
spawn!(scope, "name", future)
```

**Expansion (conceptual)**

```rust
scope.spawn_registered(__state, __cx, |cx| async move { future.await })
```

**Notes**

- `spawn!` expects `__state: &mut RuntimeState` and `__cx: &Cx` to be in scope.
- `scope!(..., state: ..., { ... })` is the supported way to introduce `__state`.
- The handle is returned immediately; scheduling is handled by the runtime.

### join!

Join multiple futures and return a tuple of results.

**Syntax**

```rust
join!(f1, f2, f3)
join!(cx; f1, f2, f3)
```

**Notes**

- Current implementation: sequential awaits (still correct, just not parallel).
- `cx;` is reserved for future cancellation propagation.

### join_all!

Join multiple futures and return an array.

**Syntax**

```rust
join_all!(f1, f2, f3)
```

**Notes**

- All futures must return the same type.
- Useful when you want to iterate results.
- Current implementation: sequential awaits (still correct, just not parallel).

### race!

Race inline futures and return the first completion. Losers are
protocol-cancelled **and drained** — awaited to termination — before the macro
returns, so obligations and finalizers a loser holds are resolved, not
abandoned. This drain guarantee is the differentiator versus a plain
drop-the-losers select (e.g. `tokio::select!`).

**Syntax**

```rust
race!(cx, { f1, f2 })
race!(cx, { "fast" => f1, "slow" => f2 })
race!(cx, timeout: Duration::from_secs(5), { f1, f2 })
```

**Notes**

- Expands to the drain-correct `Cx::race_drained*` methods: each branch is
  spawned as a region task and resolved through `Scope::race_all`.
- Branches and their outputs must be `Send + 'static`, and `cx` must carry spawn
  authority (a runtime-wired context).
- Semantics: the winner returns first; every loser is cancelled and drained.
  On the `timeout:` path an elapsed deadline abandons the whole race by drop.
- For a lower-level drop-on-cancel select over non-`'static` inline futures,
  call `Cx::race*` directly.

## Patterns

### Fan-out / fan-in

```rust,ignore
scope!(cx, state: &mut state, {
    let h1 = spawn!(async { fetch_a().await });
    let h2 = spawn!(async { fetch_b().await });
    let (a, b) = join!(h1, h2);
    (a, b)
})
```

### Timeout wrapper

```rust,ignore
let value = race!(cx, timeout: Duration::from_secs(2), {
    long_operation(),
    async { Err(TimeoutError) },
});
```

### Nested scopes with tighter budgets

```rust,ignore
scope!(cx, state: &mut state, {
    scope!(cx, budget: Budget::with_deadline_secs(5), {
        // inner work with tighter budget
    });
})
```

## Migration Guide

Manual API usage (today):

```rust,ignore
let scope = cx.scope();
let handle = scope.spawn_registered(&mut state, &cx, |cx| async move { work(cx).await })?;
let result = handle.join(&cx).await?;
```

Macro DSL (current supported surface):

```rust,ignore
scope!(cx, state: &mut state, {
    let handle = spawn!(async { work(cx).await });
    let result = handle.await;
    result
})
```

## Examples

Example binaries live in `examples/`:

- `examples/macros_basic.rs`
- `examples/macros_race.rs`
- `examples/macros_nested.rs`
- `examples/macros_error_handling.rs`

Run with:

```bash
rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_macro_dsl_docs cargo run --example macros_basic --features proc-macros
```
