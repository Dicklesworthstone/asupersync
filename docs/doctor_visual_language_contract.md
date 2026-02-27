# doctor_asupersync Visual Language Contract

This document defines the deterministic visual language contract for `doctor_asupersync` terminal surfaces.

## Versioning

- Contract ID: `doctor-visual-language-v1`
- Source showcase baseline: `frankentui-demo-showcase-v1`
- Default profile: `showcase_ansi256`

## Design Direction

The contract intentionally targets a bold operator-console style:

- Typography: monospace hierarchy with explicit heading/body/code tokens.
- Palette: semantic roles (`critical`, `warning`, `panel`, etc.), not decorative colors.
- Motion: deterministic cues tied to explicit triggers (`screen_enter`, `focus_change`, `list_render`).
- Layout motifs: canonical motifs plus deterministic degraded motifs for weaker terminals.

## Terminal Capability Profiles

Profiles are sorted lexically and include fallback chains:

1. `showcase_truecolor` (fallback -> `showcase_ansi256`)
2. `showcase_ansi256` (fallback -> `showcase_ansi16`)
3. `showcase_ansi16` (no fallback)

Fallbacks may only reduce capability requirements; they must never increase them.

## Screen Style Mapping

Each screen binds to a preferred profile and required semantic roles.

- `bead_command_center` -> `showcase_truecolor`
- `gate_status_board` -> `showcase_truecolor`
- `incident_console` -> `showcase_truecolor`
- `replay_inspector` -> `showcase_ansi256`

Every mapping includes:

- `canonical_layout_motif`
- `degraded_layout_motif`
- lexically sorted `required_color_roles`

## Accessibility and Readability Constraints

The contract enforces sorted, deterministic constraints:

- `all_alert_roles_must_remain_distinguishable_in_ansi16`
- `avoid_motion_only_state_signals`
- `preserve_text_readability_under_small_terminal_widths`

## Explicit Non-Goals

To prevent generic visual drift, these are contract-level non-goals:

- `do_not_recreate_generic_dashboard_defaults`
- `do_not_use_ambient_rainbow_palette_without_semantic_meaning`
- `do_not_use_typography_that_breaks_monospace_alignment`

## Structured Visual Event Logging

`simulate_visual_token_application()` and
`simulate_visual_token_application_for_viewport()` emit deterministic structured events:

- `theme_selected`
- `theme_fallback`
- `token_resolution_failure`
- `layout_degradation`

Each event includes:

- `correlation_id`
- `screen_id`
- `profile_id`
- `capability_class`
- human-readable `message`
- actionable `remediation_hint`

## Deterministic Transcript Semantics

For a given `(contract, screen_id, correlation_id, capability_class, viewport)`,
token application is deterministic:

- same selected profile id
- same fallback decision
- same applied layout motif
- same missing role set
- same ordered event stream

`simulate_visual_token_application_for_viewport()` enforces readability thresholds for compact terminals:

- minimum readable viewport is `110x32`
- viewports below threshold emit `layout_degradation`
- degraded motif is applied even when color capability is sufficient

## Validation Invariants

`validate_visual_language_contract()` enforces:

- non-empty required top-level fields
- lexically sorted and unique profile IDs
- lexically sorted and unique screen IDs
- lexically sorted and unique token lists (typography, spacing, motifs, notes)
- lexically sorted and unique palette role keys
- lexically sorted and unique motion cue IDs
- fallback profile existence and non-self-reference
- fallback capability monotonicity (never capability-increasing)
- screen required roles must exist in preferred profile palette

## Test Coverage

`src/cli/doctor/mod.rs` includes tests for:

- contract validation and JSON round-trip stability
- deterministic contract construction
- invalid contract rejection (ordering/fallback monotonicity)
- fallback behavior under ANSI-16 terminals
- structured token-resolution failure logging
- viewport matrix snapshots across representative terminal sizes
- zero-dimension viewport rejection
