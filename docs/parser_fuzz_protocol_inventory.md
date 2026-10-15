# Parser Fuzz Protocol Inventory

`artifacts/parser_fuzz_protocol_inventory_v1.json` is the scoped receipt for
`asupersync-idea-wizard-fifth-wave-3gaiun.10`. It maps high-risk wire/parser
protocol families to the fuzz targets currently registered in `fuzz/Cargo.toml`.

The receipt is deliberately narrow:

- `covered` means the family has at least one current registered target and the
  target file exists under `fuzz/fuzz_targets/`.
- It does not claim complete semantic-oracle coverage, corpus quality, cargo-fuzz
  execution, production security assurance, or broad workspace health.
- Missing, stale, duplicate, and exemption behavior remains owned by
  `scripts/parser_fuzz_coverage_registry.py` and
  `tests/parser_fuzz_coverage_registry_contract.rs`.

The inventory covers the families requested by the fifth-wave parser-fuzz bead:
HTTP/1, HTTP/2 plus HPACK, HTTP/3 plus QPACK, WebSocket, TLS helper parsing, DNS,
database protocols, Kafka, QUIC, codecs, and RaptorQ metadata. It also records
adjacent Redis, NATS, and JetStream wire parsing so the Kafka/messaging boundary
does not hide nearby parser debt.

Use the inventory as an admission checklist before claiming a protocol parser is
fuzz-accounted-for:

1. Check the family row in the artifact.
2. Confirm every `target_refs` entry is still registered in `fuzz/Cargo.toml`.
3. Run the existing parser registry helper on any explicit parser-surface input
   when stale, missing, duplicate, or exemption behavior matters.
4. Create or assign an owner bead before marking a required family accounted-for
   without registered fuzz target evidence.

Focused proof lane:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_parser_fuzz_protocol_inventory" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test parser_fuzz_protocol_inventory_contract --no-default-features -- --nocapture
```

This lane validates the artifact shape, target registration, fixture references,
non-claim boundaries, and remote-only validation command. It does not run cargo-fuzz.
