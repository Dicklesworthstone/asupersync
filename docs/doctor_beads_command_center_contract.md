# doctor_asupersync Beads/BV Command-Center Contract

## Scope

This contract defines deterministic command-center behavior for
`asupersync-2b4jj.5.1`:

- normalize `br ready --json` and `br blocked --json` outputs
- normalize `bv --robot-triage` quick picks
- apply deterministic filter semantics for operator workflows
- detect stale data and parse-failure error states with structured events
- emit deterministic refresh fingerprints for UI refresh/change detection

The schema is represented by `BeadsCommandCenterContract` in
`src/cli/doctor/mod.rs`.

## Contract Version

- `doctor-beads-command-center-v1`

## Canonical Commands

- `br ready --json`
- `br blocked --json`
- `bv --robot-triage`

## Required Fields

`ready` rows:

- `id`
- `priority`
- `status`
- `title`

`blocked` rows:

- `blocked_by`
- `id`
- `priority`
- `status`
- `title`

`triage` rows (`triage.quick_ref.top_picks[*]`):

- `id`
- `reasons`
- `score`
- `title`
- `unblocks`

## Filter Modes

- `all`
- `in_progress`
- `open`
- `priority_le_2`
- `unblocked_only`

`unblocked_only` removes ready items whose IDs appear in blocked rows and
clears blocked rows in the rendered snapshot.

## Event Taxonomy

- `command_invoked`
- `parse_failure`
- `snapshot_built`
- `stale_data_detected`

## Determinism and Safety Invariants

1. Contract field lists are lexical and duplicate-free.
2. Ready rows are sorted by `priority` ascending, then `id` ascending.
3. Blocked rows are sorted by blocker count descending, then `id` ascending.
4. Triage rows are sorted by `score` descending, then `id` ascending.
5. Parse failures never panic; they populate `parse_errors` and emit
   `parse_failure` events.
6. Snapshot stale flag is computed strictly by `snapshot_age_secs >
   stale_after_secs`.
7. Refresh fingerprint is deterministic and fully derived from filter + ordered
   item IDs.

## Error-State Semantics

- Invalid JSON or malformed fields in any source stream must not crash snapshot
  assembly.
- The failing stream is replaced by an empty list for that build.
- A parse-failure message is appended to `parse_errors`.
- A `parse_failure` event records source and failure reason.

## Operator Workflow Mapping

- Use `all` for global triage.
- Use `open`/`in_progress` for status-focused operational slices.
- Use `priority_le_2` for incident-driven urgency views.
- Use `unblocked_only` when selecting immediately executable work.
