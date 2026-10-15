# Isomorphic Simplification Pass 017

## Change

Replaced `NetworkSection`'s manual `Default` implementation and private serde
default function with derived defaults on `NetworkSection` and `NetworkPreset`.

## Equivalence Contract

- Inputs covered: direct `NetworkSection::default()` construction and serde
  deserialization when the `preset` or `links` fields are absent.
- Ordering preserved: unchanged; `links` remains an empty `BTreeMap`.
- Error semantics: unchanged; derive-based serde defaults do not introduce new
  fallible operations.
- Laziness/materialization: unchanged; defaults allocate the same empty map.
- Observable side effects: none.
- Default values: `NetworkPreset::default()` is marked as `Ideal`, matching the
  removed private `default_network_preset` function and the previous manual
  `NetworkSection::default()` implementation.

## Verification

- `rustfmt --edition 2024 --check src/lab/scenario.rs`: pass.
- `git diff --check -- src/lab/scenario.rs refactor/artifacts/2026-04-25-isomorphic-pass-017/ledger.md`: pass.
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-lab-scenario-pass017-test -p asupersync --lib lab::scenario`: pass, 55 passed.
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass017-check -p asupersync --lib`: pass.
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass017-clippy-tests -p asupersync --lib --tests -- -D warnings`: pass.

## Delta

- `src/lab/scenario.rs`: 4 insertions, 16 deletions.
