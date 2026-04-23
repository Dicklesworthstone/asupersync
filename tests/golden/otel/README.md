# OpenTelemetry Span Serialization Golden Artifacts

This directory contains golden artifact tests for OpenTelemetry span serialization in asupersync.

## Purpose

Golden artifact tests ensure that OTEL span serialization output remains stable across code changes. They capture regressions in:

- Span JSON structure and field ordering
- Attribute and baggage serialization
- Event serialization with timestamps
- Status code formatting
- Parent-child relationship representation
- Attribute limit enforcement
- Baggage propagation across service boundaries

## Test Coverage

| Test | Scenario | Coverage |
|------|----------|-----------|
| `basic_server_span` | Simple HTTP request span | Basic span structure, attributes, status |
| `client_with_events` | Database query with events | Client spans, events, timestamps |
| `error_status_span` | Payment error scenario | Error status, error events |
| `span_hierarchy` | Parent-child relationships | Trace propagation, baggage inheritance |
| `attribute_limits` | Attribute constraints | Limit enforcement, truncation |
| `baggage_propagation` | Cross-service context | Remote parent, baggage merging |
| `unended_span` | Active long-running span | Serialization of active spans |
| `empty_minimal_span` | Minimal span data | Edge case with no attributes/events |

## Data Scrubbing

All golden artifacts use Pattern 2 (Scrubbed Golden) from the testing methodology:

- **Trace IDs and Span IDs** → `[ID]`
- **Timestamps** → `[TIMESTAMP]`
- **Request IDs** → `[REQUEST_ID]`
- **Memory addresses** → `[ADDR]`

This ensures deterministic output across test runs while preserving the structural integrity of span data.

## Running Tests

```bash
# Run all OTEL span golden tests
cargo test span_golden --features tracing-integration

# Update golden artifacts when intentional changes are made
UPDATE_GOLDENS=1 cargo test span_golden --features tracing-integration

# Review changes before committing
git diff tests/golden/otel/
```

## Updating Goldens

When span serialization intentionally changes:

1. Run tests normally → they will fail with diffs
2. Set `UPDATE_GOLDENS=1` and re-run tests
3. Review all changes in `git diff tests/golden/otel/`
4. Commit the updated golden files with clear commit message

**⚠️ Never blindly accept golden changes without review!**