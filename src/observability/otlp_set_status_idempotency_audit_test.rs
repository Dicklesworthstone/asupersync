//! OTLP-Trace exporter span.set_status() idempotency audit test.
//!
//! Per OTLP specification, span status updates must follow last-write-wins semantics.
//! When multiple set_status() calls occur, the most recent status should always win,
//! regardless of the order (OK→ERROR, ERROR→OK, UNSET→OK, etc.).
//!
//! This audit verifies that:
//! 1. ERROR status can be overwritten by OK status (last-write-wins)
//! 2. OK status can be overwritten by ERROR status
//! 3. All status transitions respect last-write-wins semantics
//! 4. Implementation matches OTLP specification requirements
//!
//! Audit date: 2026-05-03
//! OTLP spec reference: Span status updates are last-write-wins

use crate::observability::otel::span_semantics::TestSpan;
use opentelemetry::trace::{SpanKind, Status};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_status_last_write_wins_error_then_ok() {
        // AUDIT POINT 1: ERROR→OK transition (the failing case)

        let mut span = TestSpan::new("test_span", SpanKind::Internal);

        // Set initial error status
        span.set_status(Status::Error {
            description: "Internal server error".into(),
        });

        // Verify error status is set
        match &span.status {
            Status::Error { description } => {
                assert_eq!(description.as_ref(), "Internal server error");
            }
            _ => panic!("Expected error status after set_status(Error)"),
        }

        // Now set OK status - this should WIN per OTLP spec (last-write-wins)
        span.set_status(Status::Ok);

        // ❌ CURRENT BUG: Implementation ignores OK when current status is Error
        // ✅ EXPECTED: Last write (OK) should win per OTLP spec
        match &span.status {
            Status::Ok => {
                eprintln!("✅ FIXED: ERROR→OK transition respects last-write-wins");
            }
            Status::Error { .. } => {
                eprintln!("❌ BUG: ERROR→OK transition violates OTLP spec");
                eprintln!("   Current: first-write-wins (Error stays)");
                eprintln!("   Expected: last-write-wins (OK should win)");
                panic!("set_status() violates OTLP spec: ERROR status cannot be overwritten by OK");
            }
            _ => panic!("Unexpected status after set_status(Ok)"),
        }
    }

    #[test]
    fn test_set_status_last_write_wins_ok_then_error() {
        // AUDIT POINT 2: OK→ERROR transition (should work correctly)

        let mut span = TestSpan::new("test_span", SpanKind::Internal);

        // Set initial OK status
        span.set_status(Status::Ok);

        // Verify OK status is set
        match &span.status {
            Status::Ok => {}
            _ => panic!("Expected OK status after set_status(Ok)"),
        }

        // Now set error status - this should WIN per OTLP spec (last-write-wins)
        span.set_status(Status::Error {
            description: "Not found".into(),
        });

        // This direction should work correctly
        match &span.status {
            Status::Error { description } => {
                assert_eq!(description.as_ref(), "Not found");
                eprintln!("✅ OK→ERROR transition works correctly");
            }
            _ => panic!("Expected error status after set_status(Error)"),
        }
    }

    #[test]
    fn test_set_status_complete_transition_matrix() {
        // AUDIT POINT 3: Test all possible status transitions

        eprintln!("\n🧪 COMPLETE STATUS TRANSITION MATRIX TEST");
        eprintln!("==========================================");

        let transitions = vec![
            ("UNSET", Status::Unset),
            ("OK", Status::Ok),
            (
                "ERROR",
                Status::Error {
                    description: "Test error".into(),
                },
            ),
        ];

        let mut results = Vec::new();

        for (from_name, from_status) in &transitions {
            for (to_name, to_status) in &transitions {
                let mut span = TestSpan::new("test_span", SpanKind::Internal);

                // Set initial status
                span.set_status(from_status.clone());

                // Set final status (should win per OTLP spec)
                span.set_status(to_status.clone());

                let actual_status_name = match &span.status {
                    Status::Unset => "UNSET",
                    Status::Ok => "OK",
                    Status::Error { .. } => "ERROR",
                };

                let expected_wins = to_name;
                let actual_wins = actual_status_name;
                let last_write_wins = expected_wins == actual_wins;

                results.push((
                    from_name,
                    to_name,
                    expected_wins,
                    actual_wins,
                    last_write_wins,
                ));

                eprintln!(
                    "  {}→{}: Expected={}, Actual={} {}",
                    from_name,
                    to_name,
                    expected_wins,
                    actual_wins,
                    if last_write_wins { "✅" } else { "❌" }
                );
            }
        }

        // Check for any violations
        let violations: Vec<_> = results.iter().filter(|(_, _, _, _, wins)| !wins).collect();

        if !violations.is_empty() {
            eprintln!("\n❌ OTLP SPEC VIOLATIONS DETECTED:");
            for (from, to, expected, actual, _) in violations {
                eprintln!(
                    "   {}→{}: Expected {} (last-write-wins), got {} (wrong)",
                    from, to, expected, actual
                );
            }
            panic!("set_status() implementation violates OTLP last-write-wins semantics");
        } else {
            eprintln!("\n✅ ALL TRANSITIONS RESPECT OTLP SPEC");
            eprintln!("   Last-write-wins semantics correctly implemented");
        }
    }

    #[test]
    fn test_set_status_idempotency() {
        // AUDIT POINT 4: Verify idempotent calls don't change semantics

        let mut span = TestSpan::new("test_span", SpanKind::Internal);

        // Set status multiple times to same value
        span.set_status(Status::Ok);
        span.set_status(Status::Ok);
        span.set_status(Status::Ok);

        match &span.status {
            Status::Ok => {}
            _ => panic!("Multiple OK calls should result in OK status"),
        }

        // Set error multiple times
        span.set_status(Status::Error {
            description: "Bad request".into(),
        });
        span.set_status(Status::Error {
            description: "Unauthorized".into(),
        });

        // Last error should win
        match &span.status {
            Status::Error { description } => {
                assert_eq!(description.as_ref(), "Unauthorized");
                eprintln!("✅ Multiple ERROR calls follow last-write-wins");
            }
            _ => panic!("Expected final error status"),
        }

        // Now try to set OK - should win if bug is fixed
        span.set_status(Status::Ok);

        match &span.status {
            Status::Ok => {
                eprintln!("✅ FIXED: OK can overwrite ERROR (last-write-wins)");
            }
            Status::Error { .. } => {
                panic!("BUG: OK cannot overwrite ERROR (violates OTLP spec)");
            }
            _ => panic!("Unexpected final status"),
        }
    }

    #[test]
    fn test_set_status_spec_compliance_documentation() {
        // AUDIT POINT 5: Document expected OTLP behavior

        eprintln!("\n📋 OTLP SPAN STATUS SPECIFICATION");
        eprintln!("=================================");
        eprintln!("Per OTLP specification:");
        eprintln!("   • Span status updates are last-write-wins");
        eprintln!("   • Any status can overwrite any other status");
        eprintln!("   • No status transitions are forbidden");
        eprintln!("   • Most recent set_status() call determines final status");

        let mut span = TestSpan::new("test_span", SpanKind::Internal);

        eprintln!("\n🧪 SPECIFICATION COMPLIANCE TEST:");

        // Test the spec requirement: ERROR can be overwritten by OK
        span.set_status(Status::Error {
            description: "Service unavailable".into(),
        });
        eprintln!("  1. Set ERROR status");

        span.set_status(Status::Ok);
        eprintln!("  2. Set OK status (should overwrite ERROR per spec)");

        match &span.status {
            Status::Ok => {
                eprintln!("  3. ✅ Result: OK (spec-compliant)");
                eprintln!("\n✅ OTLP SPECIFICATION COMPLIANCE VERIFIED");
                eprintln!("   Last-write-wins semantics implemented correctly");
            }
            Status::Error { .. } => {
                eprintln!("  3. ❌ Result: ERROR (spec violation)");
                eprintln!("\n❌ OTLP SPECIFICATION VIOLATION DETECTED");
                eprintln!("   Implementation prevents OK from overwriting ERROR");
                eprintln!("   This violates the last-write-wins requirement");
                panic!("OTLP spec violation: ERROR status is immutable to OK updates");
            }
            _ => panic!("Unexpected status in compliance test"),
        }
    }
}
