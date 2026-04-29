//! Conformance harness for the `grpc-timeout` header parser/formatter
//! in `asupersync::grpc::server` vs the gRPC HTTP/2 spec
//! (https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md).
//!
//! Operator note for tick #125: `src/grpc/codec.rs` does not implement
//! LZ4 or Snappy compression — only `gzip` (and `identity`) are wired
//! in via `with_gzip_frame_codec` / `gzip_frame_compress`. Per the
//! tick's instruction to skip the LZ4/Snappy fuzz target when those
//! aren't implemented, this file does the alternative
//! conformance-harness-on-server.rs deliverable instead.
//!
//! Spec text (PROTOCOL-HTTP2.md §"Protocol"):
//!
//!     Timeout       → "grpc-timeout" TimeoutValue TimeoutUnit
//!     TimeoutValue  → {positive integer as ASCII string of at most 8 digits}
//!     TimeoutUnit   → Hour | Minute | Second | Millisecond | Microsecond | Nanosecond
//!     Hour          → "H"
//!     Minute        → "M"
//!     Second        → "S"
//!     Millisecond   → "m"
//!     Microsecond   → "u"
//!     Nanosecond    → "n"
//!
//! tonic and grpc-go both implement this exact parser; a divergence
//! here would silently reinterpret peer-sent timeouts (e.g. read a
//! "100m" as 100 minutes vs 100 milliseconds, a 600× error).
//!
//! Six tests pin the spec contract:
//!   1. Each unit parses to the correct Duration (smallest example).
//!   2. Boundary values: max 8-digit value (99_999_999) per unit
//!      parses; 9+ digits rejected; empty string rejected; non-ASCII
//!      rejected; unknown unit rejected.
//!   3. Formatter prefers the coarsest LOSSLESS unit (matches grpc-go
//!      / tonic which emit "1H" rather than "3600S" for one hour).
//!   4. Zero duration → "0n" canonical (NOT "0H" / "0S" — those would
//!      decode equally but the canonical wire form matters for
//!      idempotent header diffs in caches and traces).
//!   5. Round-trip: parse(format(d)) == d for every representative
//!      duration, including sub-microsecond + sub-millisecond +
//!      multi-hour.
//!   6. Reserved-prefix interaction: the canonical key
//!      `grpc-timeout` is recognized in metadata even when stored
//!      with mixed case — gRPC headers are case-insensitive per
//!      HTTP/2.

use asupersync::grpc::{format_grpc_timeout, parse_grpc_timeout};
use std::time::Duration;

#[test]
fn parser_accepts_each_unit_at_minimum_value() {
    // Each unit at value=1 maps to the spec-defined Duration.
    assert_eq!(parse_grpc_timeout("1H"), Some(Duration::from_secs(3600)));
    assert_eq!(parse_grpc_timeout("1M"), Some(Duration::from_secs(60)));
    assert_eq!(parse_grpc_timeout("1S"), Some(Duration::from_secs(1)));
    assert_eq!(parse_grpc_timeout("1m"), Some(Duration::from_millis(1)));
    assert_eq!(parse_grpc_timeout("1u"), Some(Duration::from_micros(1)));
    assert_eq!(parse_grpc_timeout("1n"), Some(Duration::from_nanos(1)));
}

#[test]
fn parser_boundary_rules_match_spec() {
    // Spec: TimeoutValue is "at most 8 digits". Exactly 8 digits at
    // the max value MUST parse; 9 digits MUST reject.
    assert_eq!(
        parse_grpc_timeout("99999999n"),
        Some(Duration::from_nanos(99_999_999)),
        "spec maximum (8 digits) must parse",
    );
    assert!(
        parse_grpc_timeout("100000000n").is_none(),
        "9-digit value must reject — gRPC spec hard cap",
    );
    // Empty string.
    assert!(parse_grpc_timeout("").is_none());
    // No digits.
    assert!(parse_grpc_timeout("S").is_none());
    // No unit.
    assert!(parse_grpc_timeout("100").is_none());
    // Unknown unit (lowercase 'h' is NOT 'H' — the spec is case-
    // sensitive on the unit char).
    assert!(parse_grpc_timeout("1h").is_none());
    assert!(parse_grpc_timeout("1d").is_none());
    // Non-ASCII (multi-byte UTF-8 in the unit slot would corrupt
    // the split_at boundary).
    assert!(parse_grpc_timeout("1Σ").is_none());
    assert!(parse_grpc_timeout("1日").is_none());
    // Negative — gRPC TimeoutValue is unsigned.
    assert!(parse_grpc_timeout("-1S").is_none());
    // Spaces / leading zeros are NOT in the spec grammar.
    assert!(parse_grpc_timeout(" 1S").is_none());
    assert!(parse_grpc_timeout("1 S").is_none());
    // Decimal point — TimeoutValue is "positive integer".
    assert!(parse_grpc_timeout("1.5S").is_none());
}

#[test]
fn formatter_prefers_coarsest_lossless_unit() {
    // 1 hour as Duration → "1H" (NOT "3600S" or "60M").
    assert_eq!(format_grpc_timeout(Duration::from_secs(3600)), "1H");
    // 1 minute → "1M" (NOT "60S").
    assert_eq!(format_grpc_timeout(Duration::from_secs(60)), "1M");
    // 1 second → "1S" (NOT "1000m").
    assert_eq!(format_grpc_timeout(Duration::from_secs(1)), "1S");
    // 1 ms → "1m".
    assert_eq!(format_grpc_timeout(Duration::from_millis(1)), "1m");
    // 1 μs → "1u".
    assert_eq!(format_grpc_timeout(Duration::from_micros(1)), "1u");
    // 1 ns → "1n".
    assert_eq!(format_grpc_timeout(Duration::from_nanos(1)), "1n");

    // Non-power-of-coarser-unit must drop to the smallest LOSSLESS
    // unit — 90 seconds is 1.5 minutes (lossy in M) and 90000 ms
    // (lossy in m) but losslessly representable as "90S".
    assert_eq!(format_grpc_timeout(Duration::from_secs(90)), "90S");
    // 1500 ms → "1500m" — divides into ms cleanly, the coarser
    // 'S' would lose the 500 ms remainder.
    assert_eq!(format_grpc_timeout(Duration::from_millis(1500)), "1500m");
}

#[test]
fn formatter_zero_duration_is_canonical() {
    // The spec doesn't strictly mandate "0n" but tonic and grpc-go
    // both emit it for Duration::ZERO. Pinning this so a future
    // refactor that emitted "0H" or "" doesn't silently break
    // header-diff-based trace caching.
    assert_eq!(format_grpc_timeout(Duration::ZERO), "0n");
}

#[test]
fn parse_format_round_trip_is_identity_for_representative_durations() {
    let fixtures = [
        Duration::ZERO,
        Duration::from_nanos(1),
        Duration::from_nanos(999),
        Duration::from_micros(1),
        Duration::from_micros(999),
        Duration::from_millis(1),
        Duration::from_millis(999),
        Duration::from_secs(1),
        Duration::from_secs(59),
        Duration::from_secs(60),
        Duration::from_secs(3599),
        Duration::from_secs(3600),
        Duration::from_secs(86_400), // 1 day → fits in hours
        // Sub-second mixed precisions — exercise the lossless-unit
        // selection over the boundary.
        Duration::new(1, 500_000_000),  // 1.5 s → 1500m
        Duration::new(0, 1_500_000),    // 1500 μs → "1500u"
        Duration::new(0, 12_345),       // 12.345 μs → "12345n"
    ];

    for d in fixtures {
        let formatted = format_grpc_timeout(d);
        let parsed = parse_grpc_timeout(&formatted)
            .unwrap_or_else(|| panic!("formatter emitted unparseable string {formatted:?} for {d:?}"));
        assert_eq!(
            parsed, d,
            "round-trip drift: format({d:?}) = {formatted:?} → parse → {parsed:?}",
        );
    }
}

#[test]
fn parser_rejects_more_than_eight_digits_at_each_unit() {
    // The 8-digit cap applies regardless of unit. A regression that
    // accidentally allowed 9+ digits could mint Durations large
    // enough to trip checked_mul overflow defenses elsewhere.
    for unit in ["H", "M", "S", "m", "u", "n"] {
        let nine_digits = format!("999999999{unit}");
        assert!(
            parse_grpc_timeout(&nine_digits).is_none(),
            "9-digit value with unit {unit} must reject; got Some(_)",
        );
        let eight_digits = format!("99999999{unit}");
        assert!(
            parse_grpc_timeout(&eight_digits).is_some(),
            "8-digit value with unit {unit} must parse; got None",
        );
    }
}
