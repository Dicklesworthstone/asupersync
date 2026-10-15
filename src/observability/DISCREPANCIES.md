# Prometheus Exposition Format Conformance Discrepancies

This document tracks known differences between our Prometheus exposition format implementation and the `prometheus_client` crate reference implementation.

## Conformance Testing Approach

- **Pattern:** Differential Testing (Pattern 1)
- **Reference Implementation:** `prometheus_client` crate v0.23
- **Test Coverage:** Counters, Gauges, Histograms, Edge cases
- **Comparison Method:** Byte-for-byte comparison of exposition format output

## Known Discrepancies

### DISC-001: Metric Description Format
- **Reference:** prometheus_client includes `# HELP` lines with metric descriptions
- **Our implementation:** Currently omits `# HELP` lines to minimize output size
- **Impact:** Exposition format is valid but less self-documenting
- **Resolution:** INVESTIGATING - consider adding optional description support
- **Tests affected:** All differential tests
- **Review date:** 2026-04-29

### DISC-002: Metric Ordering
- **Reference:** prometheus_client may order metrics differently within types
- **Our implementation:** Orders metrics by name within each type (counter, gauge, histogram)
- **Impact:** Functionally identical but different byte representation
- **Resolution:** ACCEPTED - deterministic ordering is beneficial for debugging
- **Tests affected:** All comprehensive tests
- **Review date:** 2026-04-29

### DISC-003: Floating Point Precision
- **Reference:** prometheus_client may use different precision for floating-point values
- **Our implementation:** Uses Rust's default `f64::to_string()` formatting
- **Impact:** Values may differ in trailing digits or scientific notation
- **Resolution:** INVESTIGATING - may need consistent precision formatting
- **Tests affected:** Histogram and summary tests
- **Review date:** 2026-04-29

### DISC-004: Label Escaping Extensions
- **Reference:** Standard Prometheus label escaping (\\, \n, \")
- **Our implementation:** Extended escaping for \r, \t, \x00, Unicode separators (br-asupersync-pdu7wg)
- **Impact:** More secure but produces different escaped output for edge cases
- **Resolution:** ACCEPTED - enhanced security is worth the format difference
- **Tests affected:** Edge case tests with control characters
- **Review date:** 2026-04-29

### DISC-005: Metric Name Sanitization
- **Reference:** prometheus_client may reject invalid metric names
- **Our implementation:** Sanitizes invalid characters to underscores (br-asupersync-aog3fz)
- **Impact:** Accepts broader input but produces different names
- **Resolution:** ACCEPTED - sanitization prevents injection attacks
- **Tests affected:** Edge case tests with special characters
- **Review date:** 2026-04-29

## Coverage Matrix

| Prometheus Feature | MUST Test | SHOULD Test | Our Implementation | Status |
|-------------------|-----------|-------------|-------------------|--------|
| Counter format | ✓ | ✓ | ✓ | TESTED |
| Gauge format | ✓ | ✓ | ✓ | TESTED |
| Histogram format | ✓ | ✓ | ✓ | TESTED |
| Histogram buckets | ✓ | ✓ | ✓ | TESTED |
| Metric naming | ✓ | ✓ | ✓ (sanitized) | TESTED |
| Label escaping | ✓ | ✓ | ✓ (extended) | TESTED |
| Help lines | - | ✓ | ✗ | INVESTIGATING |
| Zero values | ✓ | ✓ | ✓ | TESTED |
| Extreme values | ✓ | ✓ | ✓ | TESTED |

**Score: 8/9 MUST clauses = 89% - Target: ≥95%**

## Action Items

1. **HIGH**: Investigate HELP line format compatibility
2. **MEDIUM**: Standardize floating-point precision formatting
3. **LOW**: Document accepted security-driven differences (DISC-004, DISC-005)

## Testing Commands

```bash
# Run all conformance tests
cargo test conformance_prometheus_client

# Run specific differential tests
cargo test conformance_counter_basic_differential
cargo test conformance_comprehensive_5c_3h_1g_differential

# Generate compliance report
cargo test conformance_generate_compliance_report -- --nocapture
```

## References

- [Prometheus Exposition Format Specification](https://prometheus.io/docs/instrumenting/exposition_formats/)
- [prometheus_client crate documentation](https://docs.rs/prometheus-client)
- [br-asupersync-aog3fz]: Metric name injection prevention
- [br-asupersync-pdu7wg]: Extended label value escaping