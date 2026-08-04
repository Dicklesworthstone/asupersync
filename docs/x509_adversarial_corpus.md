# X.509 adversarial corpus and bounded fuzz runbook

This is **A5 evidence only** for `asupersync-0h6myr.3.5`. The canonical
machine packet is
`artifacts/x509_adversarial_corpus_v1.json`. It records provenance, expected
security outcomes, differential dispositions, source pins, execution receipts,
rollback triggers, and no-claim boundaries.

## Evidence surfaces

The corpus has three deliberately separate oracle domains:

1. `src/tls/der_min.rs` owns strict, complete, bounded DER residue extraction.
   Its inline builders generate canonical and malformed certificates with
   fixed bytes and exact expected error classes.
2. `x509-parser` is used only as a structural differential oracle where both
   contracts overlap. An oracle acceptance requires one complete certificate
   and an empty remainder.
3. rustls/WebPKI remains the owner for chain signatures, roots, validity,
   hostname and wildcard matching, name constraints, and standard certificate
   purpose policy. The contract drives this through the existing
   `QuicServerIdentityVerifier`.

The repository `tests/fixtures/tls/server.crt` supplies the existing valid
localhost certificate. Four independently generated OpenSSL fixtures under
`tests/fixtures/x509_adversarial/` add:

- a CA with a critical permitted DNS subtree `.allowed.example`;
- a permitted leaf for `api.allowed.example`;
- a leaf outside that subtree for `blocked.example`; and
- a self-signed `*.example.com` leaf for one-label wildcard evidence.

The artifact pins OpenSSL version, fixed serials, fixed validity dates,
generation recipes, SHA-256 certificate fingerprints, file hashes, and the
test-only key-reuse boundary. These fixtures are test evidence, never
production key-management guidance.

## Intentional differential divergence

Every observed divergence must be one of these approved cases:

- `der_min` rejects duplicate extension OIDs even when `x509-parser` can
  structurally decode them.
- The pinned-leaf residue profile rejects critical extensions outside its
  KeyUsage, SubjectAltName, and ExtendedKeyUsage allow-set.
- `der_min` returns validity, EKU, KU, SAN, and BasicConstraints facts without
  applying caller-owned admission policy.
- rustls/WebPKI rejects standard-policy failures that are intentionally outside
  the residue reader: time, trust, signatures, names, wildcard depth, and name
  constraints.

Any other accept/reject mismatch inside the normalized complete-DER overlap is
an unexplained divergence and a rollback trigger.

## Bounded fuzz contract

`fuzz/fuzz_targets/x509_der_residue.rs` includes the exact A4 source module
directly. That lets the separate cargo-fuzz package exercise the implementation
without widening the production API.

The target:

- applies all four fact-only profiles twice and requires identical results;
- requires every error offset to be at most input length;
- bounds numeric error detail by the 1 MiB certificate cap;
- bounds PEM extraction by input size and at most four certificates; and
- contains no `x509-parser`, rustls/WebPKI accept/reject oracle, network,
  filesystem, clock, or ambient-policy input.

Use the durable `fuzz/seeds/tls` and
`tests/fixtures/x509_adversarial` seed paths. The admitted run must set
`-max_len=1048577`, a finite `-max_total_time`, and capture elapsed time,
executions, peak RSS, exit status, toolchain, target/source hashes, and the
explicit sanitizer/coverage instrumentation state. This is a bounded
no-panic/no-hang receipt for that run, not an exhaustive proof or throughput
claim.

## Verification

All Cargo commands are remote-only and use an exact clean overlay:

```text
cargo test -p asupersync --lib --features tls der_min
cargo test -p asupersync --test x509_adversarial_corpus_contract --features tls
cargo check --manifest-path fuzz/Cargo.toml --bin x509_der_residue
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
```

The cargo-fuzz run is executed remotely against the two recorded seed paths
with capped terminal output. UBS scans the changed Rust sources and must report
zero critical findings. Standalone `rustfmt --check`, JSON parsing, PEM
verification, and `git diff --check` complete the local non-Cargo checks.

## Handoff and rollback

A6 owns reservation-serialized migration of the approved reader into call
sites. A5 grants **No call-site migration** and **No dependency cutover**.
It also makes no release-readiness, broad workspace-health, exhaustive
security, performance-improvement, live-fleet, or local-Cargo-fallback claim.

Roll back the A5 evidence claim if a pin drifts, an unexplained differential
appears, a fixture stops producing its expected delegated result, the fuzz
target gains an oracle, or any admitted fuzz run crashes, panics, hangs, emits
an out-of-bounds offset, or exceeds a recorded bound.
