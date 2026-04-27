# Isomorphic Simplification Pass 028

## Candidate

- File: `src/net/happy_eyeballs.rs`
- Lever: extract the repeated two-family interleaving loop used by address sorting.
- Score: `(LOC_saved 3 * confidence 5) / risk 1 = 15.0`

## Isomorphism Proof

- `sort_addresses` still supplies IPv6 as the leading iterator and IPv4 as the trailing iterator, preserving RFC 8305 IPv6-first interleaving.
- `sort_socket_addrs` still chooses the leading iterator from the first input address family, preserving prior resolver ordering and per-address ports.
- The helper executes the same four cases as each old loop: both families present, only lead remains, only trailing remains, and both exhausted.
- The first item from a one-sided case is still pushed before extending the remainder of that same iterator.
- Result vector capacity, iteration laziness, tie-breaking, public APIs, and error semantics are unchanged.

## Metrics

- Source LOC before: 1350
- Source LOC after: 1320
- Source LOC delta: -30
- Source diff numstat: `26 insertions, 56 deletions`

## Validation

- `rustfmt --edition 2024 --check src/net/happy_eyeballs.rs`: passed
- `git diff --check -- src/net/happy_eyeballs.rs refactor/artifacts/2026-04-26-isomorphic-pass-028/ledger.md`: passed
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-happy-eyeballs-pass028-test -p asupersync --lib net::happy_eyeballs`: pending
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass028-check -p asupersync --lib`: pending
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass028-clippy-lib -p asupersync --lib -- -D warnings`: pending
