# Structured Concurrency Macro DSL

This document describes the Asupersync macro DSL for structured concurrency:
`scope!`, `spawn!`, `join!`, `join_all!`, and `race!`.

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
use asupersync::proc_macros::{scope, spawn, join, join_all, race};
```

## Supported Contract

| Macro | `proc-macros` build | No-`proc-macros` build | Current semantics |
|------|----------------------|------------------------|-------------------|
| `scope!` | Supported and re-exported by `asupersync` | Unavailable | Binds a `Scope` for the current region; does not create a fresh child-region boundary |
| `spawn!` | Supported and re-exported by `asupersync` | Unavailable | Expands to `Scope::spawn_registered`; requires ambient `__state` and `__cx` |
| `join!` | Supported and re-exported by `asupersync` | Present only as an intentional `compile_error!` placeholder | Awaits branches sequentially today |
| `join_all!` | Supported and re-exported by `asupersync` | Unavailable | Awaits branches sequentially today |
| `race!` | Supported and re-exported by `asupersync` | Present only as an intentional `compile_error!` placeholder | Expands to `Cx::race*`; losers are dropped, not drained |

`session_protocol!` and `#[conformance]` exist in `asupersync-macros`, but they
are not part of the root `asupersync` macro contract.

## Quick Start (Runnable)

This snippet is fully runnable today because it only uses `join!`.

```rust
use asupersync::proc_macros::join;
use asupersync::runtime::RuntimeBuilder;

fn main() {
    let rt = RuntimeBuilder::current_thread()
        .build()
        .expect("runtime");

    let (a, b) = rt.block_on(async {
        join!(async { 1 }, async { 2 })
    });

    assert_eq!(a + b, 3);
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
- `race!` expands to implemented `Cx::race*` methods, but those methods cancel
  losers by dropping them. They do not await loser drain. Use `Scope::race`
  when drain guarantees matter.
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

Race inline futures and return the first completion. Losers are cancelled by
drop; they are not drained.

**Syntax**

```rust
race!(cx, { f1, f2 })
race!(cx, { "fast" => f1, "slow" => f2 })
race!(cx, timeout: Duration::from_secs(5), { f1, f2 })
```

**Notes**

- Requires `Cx::race*` methods (implemented today).
- Semantics: winners return first, losers are cancelled by drop.
- Use `Scope::race` when loser-drain semantics matter.

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
    scope!(cx, budget: Budget::deadline(Duration::from_secs(5)), {
        // inner work with tighter budget
    });
})
```

## Migration Guide

Manual API usage (today):

```rust,ignore
let scope = cx.scope();
let (handle, stored) = scope.spawn(&mut state, &cx, |cx| async move { work(cx).await })?;
state.store_spawned_task(handle.task_id(), stored);
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
cargo run --example macros_basic --features proc-macros
```
