# Regex semantic terminal receipt

<!-- BEGIN REGEX SEMANTIC TERMINAL RECEIPT -->

This is the sole R3.2 terminal consumed by regex compiler work. The terminal
decision is `KEEP_INCUMBENT_DEFER`: the independently replayed syntax, Unicode
class, UTF-8 byte, simple-fold, and boundary rows are `SAME` except for the
explicitly deferred dotted Age value spelling. The candidate still consumes the
pinned `regex-syntax` 0.8.11 Unicode 16.0.0 tables. Isolated release-artifact
deltas and terminal ARM/WASM execution are also incomplete.

R3.3 compiler experimentation is authorized against
`ASUP-REGEX-SEMANTICS-TERMINAL-V1` only while all predecessor digests and
retained semantics remain exact. This does not authorize production wiring,
matcher execution, an owned table cutover, or removal of `regex` or
`regex-syntax`.

## Frozen authority

The receipt pins UCD 16.0.0 and the authoritative archive, `CaseFolding.txt`,
`PropList.txt`, `DerivedCoreProperties.txt`, and `UnicodeData.txt` checksums.
Default simple folding admits `C` and `S` rows. Full (`F`) and Turkic (`T`) rows
are excluded; no full multi-scalar folding, locale-sensitive folding, or
normalization is claimed.

The minimized `\p{Age:16.0}` case is `KEEP_DEFER`: the staged lexer rejects the
dot in the incumbent value spelling with `RGX-LEX-E004`. The equivalent
dot-free canonical alias `\p{Age:V16_0}` reaches the pinned table and is `SAME`.
This is an explicit syntax-surface deferral, not silent property loss.

The conformance corpus includes all retained table families, official edge
vectors, UTF-8-safe byte scopes, invalid bytes, every supported boundary
variant, five repository-shaped privacy patterns, 1,024 deterministic generated
patterns from seed `0x5A2C_0324_D15C_A11E`, and 121 generated word-status
pairs. Unknown properties, zero resource budgets, invalid byte scopes, and
invalid UTF-8 offsets fail closed. The diagnostic redaction canary
`PRIVATE_TERMINAL_PROPERTY_CANARY` must never be rendered.

## Size and target interpretation

The three staged sources total 212,640 bytes. That is 26.97% of the incumbent
module-plus-enabled-table source budget of 788,324 bytes, but it is not a source
reduction: the staged implementation imports those retained tables. The pinned
regex stack archives total 1,327,744 bytes. One cold same-worker release probe
measured the proc-macros base at 328,640,544 rlib bytes and 309.8 compile
seconds, and the aggregate proc-macros-plus-metrics profile at 331,072,512 bytes
and 308.5 seconds. The one-run deltas are +2,431,968 bytes (+0.740009%) and
-1.3 seconds (-0.4196%). This is a feature-profile delta, not candidate-only
linker attribution. A valid cutover still requires five cold same-worker runs
per profile, no artifact growth, at most 5% compile regression, no new build
scripts/proc macros/native code, and terminal target evidence. The one-run
artifact growth and incomplete sample count resolve to `KEEP_INCUMBENT_DEFER`.

Native x86_64 focused proof is required below. AArch64 and wasm32 remain
unexecuted and therefore `KEEP_DEFER`; deterministic source behavior is not
presented as cross-target execution evidence.

## Replay

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --features metrics --test regex_semantic_terminal_receipt_contract -- --nocapture
```

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo clippy -p asupersync --features metrics --test regex_semantic_terminal_receipt_contract -- -D warnings
```

No local Cargo fallback is approved. A green focused receipt proves only the
frozen R3.2 semantics and terminal decision. It does not prove broad workspace
health, release readiness, a production matcher, performance improvement,
isolated binary equivalence, full cross-target behavior, owned Unicode tables,
normalization, full/Turkic folding, or permission to remove dependencies.

<!-- END REGEX SEMANTIC TERMINAL RECEIPT -->
