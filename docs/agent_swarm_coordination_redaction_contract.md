# Agent Swarm Coordination Redaction Contract

Bead: `asupersync-qn8i0p.6`

## Purpose

This contract defines the privacy and trust boundary for coordination workload
evidence. It extends the bundle schema in
`docs/agent_swarm_coordination_workload_contract.md` with redaction classes,
synthetic detector fixtures, trust levels, deterministic pseudonymization rules,
and operator-readable privacy reports.

The bridge must preserve coordination pressure while refusing raw secrets and
high-risk local metadata. It must never capture live credentials, raw message
bodies, raw command environments, raw home-directory paths, raw hostnames, raw
`rch` worker names, or arbitrary attachment contents.

## Contract Artifact

The canonical artifact is:

- `artifacts/agent_swarm_coordination_redaction_contract_v1.json`

The artifact declares:

- redaction classes and actions
- source trust levels
- synthetic detector fixtures
- deterministic pseudonymization expectations
- refusal rules
- required privacy report fields
- sample accepted and refused fixture reports
- escape-hatch constraints

## Redaction Classes

The v1 classes are:

- `secret_like`
- `bearer_token`
- `github_token`
- `api_key`
- `ssh_path`
- `absolute_local_path`
- `email_identifier`
- `agent_identity`
- `hostname`
- `command_env_var`
- `attachment_reference`
- `message_body`
- `git_remote_url`
- `worker_metadata`
- `malformed_redaction_metadata`

Classes that could carry secrets are refused unless the collector can prove they
were replaced by `<redacted>` or a stable pseudonym before bundle emission.

## Trust Levels

The contract permits:

- `fixture_checked`
- `explicit_export`
- `live_command_output`
- `metadata_only`
- `unknown`

`unknown` input can only produce refused events. `live_command_output` is trusted
only after redaction succeeds and no raw environment values, hostnames, worker
names, or message bodies remain.

## Pseudonymization

Stable pseudonyms are scoped by:

1. contract version
2. project-scoped salt identifier
3. redaction class
4. normalized input value

The test suite pins deterministic fixture outputs instead of requiring a
specific cryptographic implementation in this bead. Later collector work can use
a stronger hash while preserving the same external contract.

## Privacy Report

Every redaction run must emit:

- `schema_version`
- `run_id`
- `source_bundle_hash`
- `redacted_field_count`
- `pseudonymized_field_count`
- `metadata_only_field_count`
- `refused_event_count`
- `retained_field_summary`
- `source_hashes`
- `refusal_reasons`
- `privacy_verdict`

The final verdict is `pass` only when every high-risk field is either redacted,
pseudonymized, metadata-only, or absent. Malformed metadata, unknown sources,
unredacted secrets, raw command environments, raw bodies, raw local paths, raw
hostnames, raw worker metadata, and arbitrary attachment contents must fail
closed.

## Validation

The invariant suite for this contract lives in:

- `tests/agent_swarm_coordination_redaction_contract.rs`

Focused reproduction:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_agent_swarm_coordination_redaction cargo test -p asupersync --test agent_swarm_coordination_redaction_contract -- --nocapture
```

The validation checks:

1. Required redaction classes and trust levels are present.
2. Synthetic fixtures cover secret-like strings, bearer tokens, GitHub token
   sentinels, API key sentinels, SSH paths, absolute local paths, email-like
   identifiers, agent names, hostnames, command environment values, attachment
   references, malformed metadata, and deterministic pseudonymization.
3. High-risk fixture actions are fail-closed or redacted.
4. Pseudonymization fixtures are stable and class-scoped.
5. Sample privacy reports include counts, source hashes, retained-field
   summaries, refusal reasons, and final privacy verdicts.
6. Escape hatches are explicit, disabled by default, and test-covered.

## Cross-References

- `artifacts/agent_swarm_coordination_redaction_contract_v1.json`
- `tests/agent_swarm_coordination_redaction_contract.rs`
- `docs/agent_swarm_coordination_workload_contract.md`
- `artifacts/agent_swarm_coordination_workload_contract_v1.json`
