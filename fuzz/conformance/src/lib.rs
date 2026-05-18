//! Conformance test harnesses for asupersync HTTP implementations
//!
//! This crate provides differential testing against reference implementations
//! to ensure protocol compliance and behavioral consistency.

pub mod h2_continuation_ordering_conformance;
pub mod h2_initial_window_size_conformance;
pub mod h2_ping_rtt_measurement_conformance;
pub mod h2_rst_stream_error_propagation_conformance;

#[cfg(test)]
mod h2_reference_claim_ratchet {
    struct Surface {
        path: &'static str,
        contents: &'static str,
    }

    const SURFACES: &[Surface] = &[
        Surface {
            path: "src/h2_rst_stream_error_propagation_conformance.rs",
            contents: include_str!("h2_rst_stream_error_propagation_conformance.rs"),
        },
        Surface {
            path: "src/bin/h2_rst_stream_error_propagation_conformance.rs",
            contents: include_str!("bin/h2_rst_stream_error_propagation_conformance.rs"),
        },
        Surface {
            path: "src/h2_initial_window_size_conformance.rs",
            contents: include_str!("h2_initial_window_size_conformance.rs"),
        },
        Surface {
            path: "src/bin/h2_initial_window_size_conformance.rs",
            contents: include_str!("bin/h2_initial_window_size_conformance.rs"),
        },
        Surface {
            path: "src/h2_continuation_ordering_conformance.rs",
            contents: include_str!("h2_continuation_ordering_conformance.rs"),
        },
        Surface {
            path: "src/bin/h2_continuation_ordering_conformance.rs",
            contents: include_str!("bin/h2_continuation_ordering_conformance.rs"),
        },
        Surface {
            path: "src/h2_ping_rtt_measurement_conformance.rs",
            contents: include_str!("h2_ping_rtt_measurement_conformance.rs"),
        },
        Surface {
            path: "src/bin/h2_ping_rtt_measurement_conformance.rs",
            contents: include_str!("bin/h2_ping_rtt_measurement_conformance.rs"),
        },
    ];

    const FORBIDDEN_REFERENCE_CLAIMS: &[&str] = &[
        "mock for now",
        "simulate h2 crate behavior",
        "would use actual h2 crate",
        "ALL TESTS PASSED",
        "All Tests Passed",
        "All tests passed - implementations are conformant",
        "asupersync and h2 produce identical",
        "asupersync and h2 crate produced identical",
        "asupersync and h2 produced identical",
        "h2 crate reference implementation to ensure identical",
        "ensure identical HeaderMap decoding",
    ];

    const REQUIRED_HONESTY_MARKERS: &[&str] = &[
        "fail-closed",
        "xfail-no-live-h2-reference",
        "xfail-no-live-h2-hpack-reference",
        "unsupported",
        "Unsupported",
        "refusing",
        "no live h2",
        "not wired",
        "LIVE H2 REFERENCE PASSED",
    ];

    #[test]
    fn h2_surfaces_do_not_claim_mocked_reference_success() {
        let mut violations = Vec::new();

        for surface in SURFACES {
            for (line_index, line) in surface.contents.lines().enumerate() {
                if is_negative_regression_assertion(line) {
                    continue;
                }

                for claim in FORBIDDEN_REFERENCE_CLAIMS {
                    if line.contains(claim) {
                        violations.push(format!(
                            "{}:{} contains forbidden reference claim `{}`",
                            surface.path,
                            line_index + 1,
                            claim
                        ));
                    }
                }
            }

            if !REQUIRED_HONESTY_MARKERS
                .iter()
                .any(|marker| surface.contents.contains(marker))
            {
                violations.push(format!(
                    "{} lacks a fail-closed, xfail, unsupported, or live-reference marker",
                    surface.path
                ));
            }
        }

        assert!(
            violations.is_empty(),
            "H2 reference-claim ratchet violations:\n{}",
            violations.join("\n")
        );
    }

    fn is_negative_regression_assertion(line: &str) -> bool {
        let trimmed = line.trim_start();
        trimmed.starts_with("assert!(!")
            || trimmed.contains("!source.contains")
            || trimmed.contains("!report.contains")
            || trimmed.contains("concat!(")
    }
}
