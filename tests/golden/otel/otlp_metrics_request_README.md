# OTLP Metrics Request Golden Artifacts

This directory contains golden snapshot tests for OpenTelemetry Protocol (OTLP) metrics export request wire format validation.

## Purpose

These golden artifacts ensure that OTLP metrics export requests maintain stable wire format across code changes. They capture the complete request structure from metrics collection to protobuf serialization, preventing regressions in:

- Counter, gauge, and histogram metric serialization
- Resource attributes encoding (service.name, service.version, etc.)
- Instrumentation scope metadata
- Temporal data point formatting
- Label/attribute handling
- Metric aggregation and temporality
- Unicode and edge case handling

## Test Coverage

| Golden Artifact | Scenario | Coverage |
|-----------------|----------|-----------|
| `otlp_baseline_metrics_request` | Standard metrics export | Counter/gauge/histogram, resource attributes, instrumentation scope |
| `otlp_edge_case_metrics_request` | Boundary conditions | Zero values, negative numbers, empty fields, Unicode characters |
| `otlp_high_cardinality_metrics_request` | Multiple label combinations | High cardinality labels, timestamp variations |
| `otlp_multiple_scopes_metrics_request` | Multiple instrumentation scopes | Runtime vs HTTP metrics separation |
| `otlp_empty_metrics_request` | Empty export | No metrics case, minimal resource attributes |

## Data Scrubbing

All golden artifacts use consistent scrubbing for deterministic snapshots:

- **Timestamps** → `[TIMESTAMP]`
- **Process IDs** → `[PID]`
- **Host names** → `[HOSTNAME]`

This ensures golden snapshots are deterministic across test runs while preserving structural integrity.

## Wire Format Validation

The golden artifacts validate the following OTLP specification compliance:

### Resource Attributes
- Required fields: `service.name`, `service.version`
- Optional fields: `deployment.environment`, `host.name`, `process.pid`
- Unicode handling: UTF-8 strings including emoji and non-ASCII characters
- Empty value handling: Empty strings preserved correctly

### Instrumentation Scope
- Scope name and version metadata
- Multiple scopes in single request
- Empty version strings

### Metric Data Types
- **Counter**: Monotonic increasing values with cumulative temporality
- **Gauge**: Point-in-time values with unspecified temporality  
- **Histogram**: Distribution with count, sum, and explicit bucket bounds

### Data Points
- Label/attribute key-value pairs
- Timestamp formatting (nanoseconds since Unix epoch)
- Value types (int64, double)
- Bucket counts and explicit bounds for histograms

### Edge Cases Tested
- Zero values and negative numbers
- Empty attribute sets
- Empty histogram buckets (count=0, sum=0.0)
- Unicode in metric names and labels
- Missing optional fields (empty descriptions, units)

## Running Tests

```bash
# Run all OTLP golden snapshot tests
cargo test otlp_metrics_request_golden

# Update golden artifacts when intentional changes are made
UPDATE_GOLDENS=1 cargo test otlp_metrics_request_golden

# Review changes before committing
git diff tests/snapshots/otlp_metrics_request_golden*
```

## Protocol Compatibility

The golden artifacts ensure compatibility with:

- OpenTelemetry Collector (all versions)
- Prometheus remote write receivers
- Grafana Agent OTLP ingestion
- Jaeger OTLP endpoint
- Custom OTLP metric processors

Changes to the wire format that break compatibility with these systems will be caught by golden snapshot mismatches.

## OTLP Specification References

- [OTLP Protocol Specification](https://opentelemetry.io/docs/specs/otlp/)
- [OpenTelemetry Metrics Data Model](https://opentelemetry.io/docs/specs/otel/metrics/)
- [Metrics SDK Export Pipeline](https://opentelemetry.io/docs/specs/otel/metrics/sdk/)

**⚠️ Always review golden snapshot changes carefully!** Wire format changes can break downstream consumers.