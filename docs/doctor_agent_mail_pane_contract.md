# doctor_asupersync Agent Mail Pane Contract

## Scope

This contract defines deterministic Agent Mail pane behavior for
`asupersync-2b4jj.5.2`:

- normalize inbox/outbox message streams into stable pane rows
- normalize contact status rows for contact-awareness and coordination safety
- model acknowledgement transitions (`ack_required` -> acknowledged)
- provide active-thread continuity views for in-thread workflows
- emit replay-ready command traces and structured pane events

The schema is represented by `AgentMailPaneContract` in
`src/cli/doctor/mod.rs`.

## Contract Version

- `doctor-agent-mail-pane-v1`

## Canonical Command Surfaces

- `mcp_agent_mail.fetch_inbox(project_key, agent_name, include_bodies=true, limit=50)`
- `mcp_agent_mail.search_messages(project_key, query="from:<agent_name>", limit=50)`
- `mcp_agent_mail.list_contacts(project_key, agent_name)`
- `mcp_agent_mail.acknowledge_message(project_key, agent_name, message_id)`
- `mcp_agent_mail.reply_message(project_key, message_id, sender_name, body_md)`

## Required Fields

Message rows:

- `ack_required`
- `created_ts`
- `from`
- `id`
- `importance`
- `subject`

Contact rows:

- `reason`
- `status`
- `to`
- `updated_ts`

## Thread Filter Modes

- `ack_required`
- `all`
- `thread_only`
- `unacked_only`

`thread_only` requires an explicit active thread id and fails closed when
`active_thread` is not provided.

## Event Taxonomy

- `ack_transition`
- `command_invoked`
- `contact_attention_required`
- `delivery_failure`
- `parse_failure`
- `snapshot_built`
- `thread_continuity_gap`
- `thread_view_updated`

## Determinism and Safety Invariants

1. Contract field lists are lexical and duplicate-free.
2. Inbox/outbox rows are sorted by `(created_ts, id, direction)`.
3. Contact rows are sorted lexically by peer agent name.
4. `ack_required` supports deterministic bool coercion from `true|false|1|0`.
5. Parse failures never panic; they produce `parse_errors` and `parse_failure`
   events with source attribution.
6. Thread view generation is deterministic for a fixed active thread and
   message set.
7. Snapshot refresh fingerprint is fully derived from filter mode, active
   thread, and normalized row identities/states.

## Error-State Semantics

- Invalid inbox/outbox/contacts payloads do not crash snapshot assembly.
- The failing stream is replaced by an empty list for that build.
- Parse failures are appended to `parse_errors` and surfaced as events.
- `thread_continuity_gap` is emitted when an explicitly selected thread has no
  visible rows after filtering.

## E2E Smoke Workflow Coverage

`run_agent_mail_pane_smoke` executes deterministic workflow stages:

1. `fetch`: build baseline inbox/outbox/thread/contact snapshot.
2. `ack`: acknowledge an `ack_required` inbox message and verify transition.
3. `reply`: add outbox reply in-thread and verify thread continuity view.

The transcript (`AgentMailPaneWorkflowTranscript`) is deterministic across runs
and encodes step-level snapshots for regression assertions.

## Integration Notes (Coordination Safety)

1. Claim work in beads before sending task-start messages.
2. Use thread ids equal to bead ids for continuity (`asupersync-*`).
3. Acknowledge `ack_required` messages promptly to avoid hidden coordination debt.
4. Treat non-`approved` contacts as explicit attention items before sending.
5. Reserve edit surfaces before implementation and release immediately on bead
   completion.
