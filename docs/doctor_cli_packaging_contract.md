# doctor_asupersync CLI Packaging Contract

This document defines the deterministic packaging workflow for bead
`asupersync-2b4jj.6.3`.

## Command

```bash
asupersync --format json doctor package-cli \
  --source-binary target/release/asupersync \
  --out-dir target/e2e-results/doctor_cli_package/artifacts \
  --binary-name doctor_asupersync \
  --default-profile ci \
  --smoke
```

`--source-binary` is optional. When omitted, the running executable is used.

## Output Schema (`doctor-cli-package-v1`)

Required top-level fields:

- `schema_version` (`doctor-cli-package-v1`)
- `package_version`
- `binary_name`
- `source_binary`
- `packaged_binary`
- `packaged_binary_size_bytes`
- `packaged_binary_sha256`
- `release_manifest`
- `default_profile` (`local` or `ci`)
- `config_templates` (non-empty deterministic array)
- `install_smoke` (present when `--smoke` is set)
- `rerun_commands`
- `structured_logs`

Required `config_templates[*]` fields:

- `profile`
- `path`
- `command_preview`

Required `install_smoke` fields:

- `install_root`
- `installed_binary`
- `startup_status` (`ok`)
- `command_status` (`ok`)
- `command_output_sha256`
- `observed_contract_version` (`doctor-core-report-v1`)

## Config Template Contract (`doctor-cli-package-config-v1`)

Two templates are materialized per package run:

- `<binary>.local.json`
- `<binary>.ci.json`

Each template is validated after serialization and must include:

- `schema_version` (`doctor-cli-package-config-v1`)
- `profile` (`local` or `ci`)
- `binary_name`
- `output_format`
- `color`
- `doctor_command` (`report-contract`)
- `workspace_root`
- `report_out_dir`
- `strict_mode`
- `rch_binary`

Validation fails closed on unsupported profile, unsupported output format, or
missing/invalid required fields.

## Release Manifest (`doctor-cli-package-manifest-v1`)

The manifest records:

- package identity + source/packaged binary metadata
- SHA-256 digest and deterministic config template references
- supported platform matrix
- compatibility expectations
- required upgrade path steps

## Structured Log Expectations

`structured_logs` includes deterministic event records for:

- package start metadata
- template materialization
- manifest write completion
- install smoke completion (with remediation guidance)
- package completion

When validation or smoke steps fail, errors include remediation guidance in CLI
error context for operator triage.

## Supported Platforms

- `linux-x86_64`
- `linux-aarch64`
- `macos-x86_64`
- `macos-aarch64`

## Upgrade Path

1. Build a new CLI binary via `rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_tokio_conformance_docs cargo build --release --features cli --bin asupersync`.
2. Re-run `doctor package-cli` and compare `packaged_binary_sha256` in release manifests.
3. Promote only when package smoke and e2e checks are deterministic and green.

## Compatibility Expectations

1. Config schema evolution is additive within `doctor-cli-package-config-v1`.
2. Packaged smoke requires `doctor report-contract` to emit `doctor-core-report-v1`.
3. CI and operator workflows must route cargo-heavy checks through `rch exec -- ...`.

## E2E Coverage

Deterministic end-to-end validation:

```bash
bash scripts/test_doctor_cli_packaging_e2e.sh
```

The suite validates:

- package payload contract conformance
- template profile/command compatibility metadata
- packaged install/startup/command smoke behavior
- cross-run deterministic metadata and command-output digests
- structured log + remediation guidance coverage
