# Refactor Ledger: `ConnectionTasks` Derived Default

## Scope

- Source: `src/http/h1/listener.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0811Z-connection-tasks-default/`

## Line Delta

- Source lines before: 1084
- Source lines after: 1078
- Source reduction: 6

## Proof Summary

`ConnectionTasks` manually initialized an empty `Vec` and zero counter. Derived
`Default` constructs the same initial state for this private helper, and the
single callsite can use that default directly.

## Verification

- Passed: `rustfmt --edition 2024 --check src/http/h1/listener.rs`
- Passed:
  `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-connection-tasks-0817-check -p asupersync --lib`
- Passed:
  `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-connection-tasks-0821-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- `ConnectionTasks` remains private to `src/http/h1/listener.rs`.
- The only callsite is still at listener run-loop startup, before accepted
  connection handles can exist.
- Derived `Default` initializes `handles` to an empty `Vec` and `push_count` to
  zero, matching the removed constructor exactly.
- `push`, periodic finished-handle cleanup, and `join_all` behavior are
  unchanged.
