# Mock-Code-Finder Proof Runbook

This runbook is the operating guide for the mock-code-finder closure stack. It
uses the aggregate proof runner added for `asupersync-oelvq2` and the shared
evidence schema from `asupersync-qlvtin`; it is intentionally grounded in
commands and artifacts that exist in the repository.

## Command Matrix

Run these commands from the repository root.

| Purpose | Command | Expected result |
| --- | --- | --- |
| List default child proof lanes without running them | `python3 scripts/run_mock_code_finder_evidence.py --list --mode rch --run-id smoke-list` | JSON plan with six child lanes and rch-mode commands. |
| CI dry run | `python3 scripts/run_mock_code_finder_evidence.py --dry-run --ci --run-id ci-smoke` | JSON plan with `mode: "ci"` and CI environment behavior. |
| Runner fixture self-test | `python3 scripts/run_mock_code_finder_evidence.py --self-test` | Prints `mock-code-finder aggregate self-test: pass`. |
| Local aggregate proof | `python3 scripts/run_mock_code_finder_evidence.py --mode local --artifact-root artifacts/mock-code-finder/asupersync-oelvq2 --run-id local-proof` | Runs all child lanes locally, using local-mode child flags where supported. |
| rch-backed aggregate proof | `rch exec -- python3 scripts/run_mock_code_finder_evidence.py --mode rch --artifact-root artifacts/mock-code-finder/asupersync-oelvq2 --run-id rch-proof` | Runs the aggregate from an rch worker without forcing child `--local` mode. |
| Rerun one subsystem | `python3 scripts/run_mock_code_finder_evidence.py --child asupersync-a45 --mode local --run-id no-mock-rerun` | Runs only the no-mock policy lane. Use any child bead id or subsystem name. |

Default child lanes:

| Child bead | Subsystem | Script |
| --- | --- | --- |
| `asupersync-uw9zg9` | `observability-otel-w3c` | `scripts/run_observability_evidence.sh` |
| `asupersync-hxi1ga` | `http2-conformance` | `scripts/run_h2_conformance_evidence.sh` |
| `asupersync-kokw3m` | `raptorq-rfc6330` | `scripts/run_rfc6330_conformance_evidence.sh` |
| `asupersync-zftrj9` | `database-postgres-copy-from` | `scripts/run_postgres_copy_from_evidence.sh` |
| `asupersync-a5d34a` | `runtime-sync` | `scripts/run_runtime_sync_invariant_evidence.sh` |
| `asupersync-a45` | `mock-code-finder-policy` | `scripts/run_no_mock_policy_evidence.sh` |

## Environment

| Variable | Required by | Meaning |
| --- | --- | --- |
| `ARTIFACT_ROOT` | Child proof scripts except no-mock policy | Child-specific artifact root supplied by the aggregate runner. |
| `STUB_SCAN_ARTIFACT_ROOT` | `asupersync-a45` no-mock policy lane | Artifact root for no-mock policy and stub scan outputs. |
| `STUB_SCAN_ARTIFACT_PATH_ROOT` | `asupersync-a45` no-mock policy lane | Path root used by `scripts/scan_stubs.sh` when emitting scan artifacts. |
| `RUN_ID` | All aggregate children | Stable run identifier for a proof attempt. |
| `CI` | CI mode | Set to `true` by `--ci` mode. |
| `ASUPERSYNC_POSTGRES_TEST_URL` | PostgreSQL real-server lane | Optional live PostgreSQL connection string for real-server COPY FROM proof. |

Evidence artifacts may name required environment keys, but must never capture
secret values. The validator rejects secret-looking strings such as
`password=...`, `token=...`, `authorization: ...`, and database URLs containing
embedded credentials unless they are redacted. Use `<redacted>` in any artifact
or log excerpt that needs to mention a sensitive value.

## Artifact Layout

The aggregate runner writes under:

```text
artifacts/mock-code-finder/asupersync-oelvq2/<run-id>/
```

Each child receives a subdirectory named by child bead id, for example:

```text
artifacts/mock-code-finder/asupersync-oelvq2/local-proof/asupersync-a45/
```

Important files:

| File | Meaning |
| --- | --- |
| `mock-code-finder-aggregate.json` | Machine-readable aggregate report. |
| `mock-code-finder-aggregate.summary.md` | Human summary with scenario counts, verdict counts, evidence-quality counts, and first failure. |
| `<child>/child.stdout.log` | Captured child stdout. |
| `<child>/child.stderr.log` | Captured child stderr. |
| `<child>/**/*.jsonl` | Scenario evidence records validated against `artifacts/mock_code_finder_verification_contract_v1.json`. |
| `<child>/**/*.validation.json` | Validator summaries for each child JSONL file. |

## Verdict Semantics

The aggregate runner returns exit code `0` only when every child command exits
successfully and every child JSONL artifact validates. It returns exit code `1`
when a child command fails, a JSONL artifact is malformed, a child emits zero
scenario records, a required field such as `evidence_quality` is missing, or a
blocked/unsupported record lacks context.

`verdict`, `evidence_quality`, and `support_class` are related but not
interchangeable:

| Verdict | Required evidence quality | User-ready meaning |
| --- | --- | --- |
| `pass` | `live` | Counts as live proof only when support is not `audit_only` or `fixture_reference`. |
| `fail` | `live` | A live check found a real regression or policy violation. |
| `blocked` | `blocked` | The proof could not run because of a named blocker; it must include `blocker_bead_id` and context. |
| `unsupported` | `unsupported` | The project deliberately lacks this surface; do not count it as conformance. |
| `expected_fail` | `expected_fail` | A known failing boundary is recorded honestly; do not count it as a pass. |
| `fixture_only` | `fixture_only` | Useful for audit context only; never sufficient for production or conformance readiness. |

Support classes:

| Support class | Meaning |
| --- | --- |
| `production_live` | The real implementation path was exercised. |
| `wire_level` | A real wire/protocol boundary was exercised without a higher-level service. |
| `fixture_reference` | Fixture or reference data only. |
| `explicitly_unsupported` | The surface is intentionally unsupported. |
| `blocked_external` | External service, environment, or unrelated compile state blocked proof. |
| `audit_only` | Historical/audit context only. |

Do not declare `asupersync-u7y` ready from `fixture_only`, `audit_only`, or
`expected_fail` evidence. A successful aggregate exit proves the evidence is
well-formed; final signoff must still inspect the counts and support classes.

## PostgreSQL COPY FROM Lane

The PostgreSQL proof lane is `asupersync-zftrj9` and the child script is
`scripts/run_postgres_copy_from_evidence.sh`.

Use a live server when possible:

```bash
ASUPERSYNC_POSTGRES_TEST_URL=<redacted> \
  python3 scripts/run_mock_code_finder_evidence.py \
  --child asupersync-zftrj9 \
  --mode local \
  --run-id postgres-live
```

If no live server is available, the lane may emit wire-level fallback evidence.
Wire-level fallback can prove parser/state-machine behavior, but it is weaker
than a real-server run. Treat `wire_level` as acceptable protocol evidence only
when the record names the inspected source files, command, output artifact, and
why a real service was unavailable. Treat `blocked_external` as a blocker to
link, not as a pass.

## No-Mock Policy Lane

The no-mock lane is `asupersync-a45` and runs:

```bash
python3 scripts/run_mock_code_finder_evidence.py --child asupersync-a45 --mode local --run-id no-mock-rerun
```

It delegates to `scripts/run_no_mock_policy_evidence.sh`, which runs:

| Check | Purpose |
| --- | --- |
| `python3 scripts/check_no_mock_policy.py --report-json ...` | Categorized policy scan. |
| `python3 scripts/check_no_mock_policy.py --self-test-negative-fixture` | Proves new fake conformance is rejected. |
| `python3 scripts/check_no_mock_policy.py --self-test-policy-fixtures` | Proves policy parser/classifier fixtures. |
| `bash scripts/scan_stubs.sh` | Legacy stub scan ratchet. |

Policy categories currently used by `.github/no_mock_policy.json`:

| Category | Meaning |
| --- | --- |
| `production_stub` | Source files under `src/**` that contain mock/stub/fake terminology and need explicit justification. |
| `conformance_placeholder` | Conformance surfaces where fake behavior would undermine spec claims. |
| `intentional_test_double` | Test-only doubles and fixtures. |
| `fixture_reference_implementation` | Fixture/reference data, generated snapshots, or scripts that are not production behavior. |
| `stale_audit_prose` | Historical audit files whose claims must be normalized when implementation proof lands. |

Allowlist entries for production, conformance, and stale-audit categories must
include a replacement issue or revisit metadata. New production or conformance
mock terminology should fail the gate until classified or fixed.

## Troubleshooting Decision Tree

1. If the aggregate process exits `1`, open `mock-code-finder-aggregate.json`
   and read `first_failure_line`.
2. If `first_failure_line` starts with `child command exited`, open the child
   `child.stderr.log` and `child.stdout.log`; the child command failed before
   producing clean evidence.
3. If `first_failure_line` names malformed JSONL, missing `evidence_quality`,
   or zero scenario records, open the listed child JSONL and its
   `.validation.json` file.
4. If a record has `verdict: "blocked"`, follow `blocker_bead_id`. If it lacks
   a blocker id, source line, or actual-behavior context, fix the evidence
   record before treating the run as useful.
5. If a record has `verdict: "unsupported"`, confirm the unsupported boundary is
   deliberate and documented; do not count it as implementation proof.
6. If a record has `verdict: "expected_fail"` or `verdict: "fixture_only"`,
   keep it in the closeout counts but do not use it as a pass.
7. If the no-mock lane fails, open `no-mock-policy-report.json` first; it
   contains `scan_counts`, `category_counts`, `coverage_counts`, and remaining
   allowlist rows.

## Final Operator Checklist

Proceed to `asupersync-u7y` only after all of this is true:

- `python3 scripts/run_mock_code_finder_evidence.py --self-test` passes.
- `python3 scripts/run_mock_code_finder_evidence.py --list --mode rch --run-id smoke-list` lists all six default child lanes.
- `python3 scripts/run_mock_code_finder_evidence.py --dry-run --ci --run-id ci-smoke` emits CI-mode plan output.
- The aggregate run has a recorded `mock-code-finder-aggregate.json` and `mock-code-finder-aggregate.summary.md`.
- Every child JSONL validates against `artifacts/mock_code_finder_verification_contract_v1.json`.
- The closeout records per-subsystem scenario counts, verdict counts, evidence-quality counts, support-class counts, artifact paths, and first failure lines.
- Any `blocked`, `unsupported`, `expected_fail`, `fixture_only`, or `audit_only` evidence is called out with a linked blocker or explicit rationale.
- `scripts/run_no_mock_policy_evidence.sh` and `scripts/scan_stubs.sh` remain green, or their exact blocker is linked.
- `br dep tree asupersync-yex`, `bv --robot-plan --label mock-code-finder`, and `bv --robot-insights --label mock-code-finder` are captured in the signoff notes.

## Schema-Valid Example Records

The following JSONL block is validated by
`tests/mock_code_finder_runbook_contract.rs` with
`scripts/validate_mock_code_finder_evidence.py`.

<!-- mock-code-finder-sample-jsonl:start -->
```jsonl
{"schema_version":"mock-code-finder-evidence-jsonl-schema-v1","bead_id":"asupersync-n9laev","scenario_id":"runbook-live-pass","subsystem":"mock-code-finder-runbook","support_class":"production_live","source_files_inspected":["scripts/run_mock_code_finder_evidence.py","docs/mock_code_finder_proof_runbook.md"],"command":"python3 scripts/run_mock_code_finder_evidence.py --self-test","rch_command_if_used":"","cargo_features":[],"test_filter":"aggregate-self-test","env_keys_required":[],"deterministic_seed_or_fixture_id":"runbook-sample-v1","input_artifact":"docs/mock_code_finder_proof_runbook.md","output_artifact":"target/mock-code-finder/asupersync-n9laev/runbook-self-test.log","expected_behavior":"The aggregate runner fixture self-test passes without external services.","actual_behavior":"The command prints mock-code-finder aggregate self-test: pass.","verdict":"pass","first_failure_line":"","duration_ms":1,"git_sha_or_tree_state":"main@runbook-sample","blocker_bead_id":"","evidence_quality":"live"}
{"schema_version":"mock-code-finder-evidence-jsonl-schema-v1","bead_id":"asupersync-n9laev","scenario_id":"runbook-live-fail","subsystem":"mock-code-finder-runbook","support_class":"production_live","source_files_inspected":["scripts/run_mock_code_finder_evidence.py"],"command":"python3 scripts/run_mock_code_finder_evidence.py --config-json target/bad-config.json","rch_command_if_used":"","cargo_features":[],"test_filter":"aggregate-malformed-fixture","env_keys_required":["ARTIFACT_ROOT"],"deterministic_seed_or_fixture_id":"runbook-sample-v1","input_artifact":"target/bad-config.json","output_artifact":"target/mock-code-finder/asupersync-n9laev/bad-aggregate.json","expected_behavior":"Malformed child JSONL fails the aggregate.","actual_behavior":"The aggregate runner reports malformed JSONL and exits 1.","verdict":"fail","first_failure_line":"target/bad.jsonl:1","duration_ms":1,"git_sha_or_tree_state":"main@runbook-sample","blocker_bead_id":"","evidence_quality":"live"}
{"schema_version":"mock-code-finder-evidence-jsonl-schema-v1","bead_id":"asupersync-n9laev","scenario_id":"runbook-blocked","subsystem":"database-postgres-copy-from","support_class":"blocked_external","source_files_inspected":["scripts/run_postgres_copy_from_evidence.sh"],"command":"python3 scripts/run_mock_code_finder_evidence.py --child asupersync-zftrj9 --mode local --run-id postgres-live","rch_command_if_used":"rch exec -- python3 scripts/run_mock_code_finder_evidence.py --child asupersync-zftrj9 --mode rch --run-id postgres-live","cargo_features":["postgres","test-internals"],"test_filter":"postgres-copy-from-live","env_keys_required":["ASUPERSYNC_POSTGRES_TEST_URL"],"deterministic_seed_or_fixture_id":"runbook-sample-v1","input_artifact":"","output_artifact":"artifacts/mock-code-finder/asupersync-oelvq2/postgres-live/asupersync-zftrj9/postgres-copy.summary.json","expected_behavior":"A live PostgreSQL COPY FROM proof runs when a server URL is available.","actual_behavior":"The live server was unavailable; the record names this external blocker without exposing credentials.","verdict":"blocked","first_failure_line":"ASUPERSYNC_POSTGRES_TEST_URL unavailable","duration_ms":1,"git_sha_or_tree_state":"main@runbook-sample","blocker_bead_id":"asupersync-postgres-live-env","evidence_quality":"blocked"}
{"schema_version":"mock-code-finder-evidence-jsonl-schema-v1","bead_id":"asupersync-n9laev","scenario_id":"runbook-unsupported","subsystem":"mock-code-finder-runbook","support_class":"explicitly_unsupported","source_files_inspected":["docs/mock_code_finder_proof_runbook.md"],"command":"python3 scripts/validate_mock_code_finder_evidence.py --validate-contract-only","rch_command_if_used":"","cargo_features":[],"test_filter":"unsupported-boundary-doc","env_keys_required":[],"deterministic_seed_or_fixture_id":"runbook-sample-v1","input_artifact":"docs/mock_code_finder_proof_runbook.md","output_artifact":"","expected_behavior":"Unsupported boundaries are documented but not counted as live proof.","actual_behavior":"The runbook states unsupported evidence is explicit context, not conformance success.","verdict":"unsupported","first_failure_line":"","duration_ms":1,"git_sha_or_tree_state":"main@runbook-sample","blocker_bead_id":"","evidence_quality":"unsupported"}
{"schema_version":"mock-code-finder-evidence-jsonl-schema-v1","bead_id":"asupersync-n9laev","scenario_id":"runbook-expected-fail","subsystem":"mock-code-finder-policy","support_class":"production_live","source_files_inspected":["scripts/check_no_mock_policy.py"],"command":"python3 scripts/check_no_mock_policy.py --self-test-negative-fixture","rch_command_if_used":"","cargo_features":[],"test_filter":"negative-fixture","env_keys_required":[],"deterministic_seed_or_fixture_id":"runbook-sample-v1","input_artifact":"scripts/check_no_mock_policy.py","output_artifact":"","expected_behavior":"The negative fixture remains rejected by the no-mock policy.","actual_behavior":"The scanner rejects the fixture as expected; this is useful signal but not a production pass.","verdict":"expected_fail","first_failure_line":"negative_fixture.py:1","duration_ms":1,"git_sha_or_tree_state":"main@runbook-sample","blocker_bead_id":"asupersync-a45","evidence_quality":"expected_fail"}
{"schema_version":"mock-code-finder-evidence-jsonl-schema-v1","bead_id":"asupersync-n9laev","scenario_id":"runbook-fixture-only","subsystem":"raptorq-rfc6330","support_class":"fixture_reference","source_files_inspected":["docs/mock_code_finder_proof_runbook.md"],"command":"python3 scripts/validate_mock_code_finder_evidence.py --self-test","rch_command_if_used":"","cargo_features":[],"test_filter":"fixture-only-example","env_keys_required":[],"deterministic_seed_or_fixture_id":"runbook-sample-v1","input_artifact":"docs/mock_code_finder_proof_runbook.md","output_artifact":"","expected_behavior":"Fixture-only records remain visible for audit history.","actual_behavior":"The runbook states fixture-only records never count as live conformance proof.","verdict":"fixture_only","first_failure_line":"","duration_ms":1,"git_sha_or_tree_state":"main@runbook-sample","blocker_bead_id":"","evidence_quality":"fixture_only"}
```
<!-- mock-code-finder-sample-jsonl:end -->
