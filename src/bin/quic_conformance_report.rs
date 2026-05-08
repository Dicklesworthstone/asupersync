//! QUIC Stream RFC 9000 Conformance Report Generator
//!
//! This binary intentionally refuses to emit conformance metrics until it is
//! wired to live QUIC conformance results. Previous versions printed static
//! sample scores, which looked authoritative but were not produced by tests.
//!
//! Usage:
//! ```bash
//! rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_cli_docs cargo run --bin quic_conformance_report                    # Console status
//! rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_cli_docs cargo run --bin quic_conformance_report -- --format=json  # JSON status
//! rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_cli_docs cargo run --bin quic_conformance_report -- --format=md    # Markdown status
//! rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_cli_docs cargo run --bin quic_conformance_report -- --ci           # CI status
//! ```

use std::env;

const EXIT_UNAVAILABLE: i32 = 2;
const UNAVAILABLE_REASON: &str =
    "live QUIC stream conformance results are not wired into this binary";
const NEXT_STEP: &str =
    "connect this binary to the maintained QUIC conformance harness before reporting scores";

#[derive(Debug, Clone, PartialEq, Eq)]
struct RenderedReport {
    body: String,
    exit_code: i32,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let format = args
        .iter()
        .find(|arg| arg.starts_with("--format="))
        .map_or("console", |arg| &arg[9..]);

    let ci_mode = args.iter().any(|arg| arg == "--ci");

    match render_report(format, ci_mode) {
        Ok(report) => {
            println!("{}", report.body);
            std::process::exit(report.exit_code);
        }
        Err(message) => {
            eprintln!("{message}");
            eprintln!("Supported formats: console, json, md");
            std::process::exit(1);
        }
    }
}

fn render_report(format: &str, ci_mode: bool) -> Result<RenderedReport, String> {
    let body = match format {
        "json" => json_report(),
        "md" | "markdown" => markdown_report(),
        "console" => console_report(ci_mode),
        _ => return Err(format!("Unknown format: {format}")),
    };

    Ok(RenderedReport {
        body,
        exit_code: EXIT_UNAVAILABLE,
    })
}

fn json_report() -> String {
    let report = serde_json::json!({
        "rfc": "RFC 9000",
        "specification": "QUIC: A UDP-Based Multiplexed and Secure Transport",
        "test_suite": "QUIC Stream State Machine Conformance",
        "status": "unavailable",
        "metrics_available": false,
        "conformant": serde_json::Value::Null,
        "reason": UNAVAILABLE_REASON,
        "next_step": NEXT_STEP,
        "source": {
            "kind": "fail-closed",
            "static_placeholder_metrics_removed": true
        }
    });

    serde_json::to_string_pretty(&report).expect("static JSON report should serialize")
}

fn markdown_report() -> String {
    format!(
        "\
# RFC 9000 QUIC Stream Conformance Report

Status: unavailable

This command does not currently report QUIC stream conformance scores because {UNAVAILABLE_REASON}.

No pass counts, failure counts, percentages, or conformant/non-conformant verdicts are emitted from this binary until those values are produced by a live conformance harness.

Next step: {NEXT_STEP}.
"
    )
}

fn console_report(ci_mode: bool) -> String {
    if ci_mode {
        format!(
            "\
QUIC_CONFORMANCE_STATUS=UNAVAILABLE
QUIC_METRICS_AVAILABLE=false
QUIC_CONFORMANT=unknown
QUIC_REASON={UNAVAILABLE_REASON}
QUIC_NEXT_STEP={NEXT_STEP}"
        )
    } else {
        format!(
            "\
RFC 9000 QUIC Stream Conformance Report
==================================================

Status: unavailable
Reason: {UNAVAILABLE_REASON}

No conformance score is reported. Static placeholder metrics were removed so this command cannot be mistaken for a live RFC 9000 proof.

Next step: {NEXT_STEP}."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_report_fails_closed_without_static_scores() {
        let report = render_report("json", false).expect("json report");
        let body = report.body;
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

        assert_eq!(report.exit_code, EXIT_UNAVAILABLE);
        assert_eq!(json["status"], "unavailable");
        assert_eq!(json["metrics_available"], false);
        assert!(json["conformant"].is_null());
        assert!(!body.contains("overall_score"));
        assert!(!body.contains("passing_tests"));
        assert!(!body.contains("56.25"));
    }

    #[test]
    fn ci_report_has_unavailable_status_without_metric_keys() {
        let report = render_report("console", true).expect("ci report");

        assert_eq!(report.exit_code, EXIT_UNAVAILABLE);
        assert!(report.body.contains("QUIC_CONFORMANCE_STATUS=UNAVAILABLE"));
        assert!(report.body.contains("QUIC_METRICS_AVAILABLE=false"));
        assert!(!report.body.contains("QUIC_OVERALL_SCORE"));
        assert!(!report.body.contains("QUIC_MUST_FAILURES"));
        assert!(!report.body.contains("QUIC_TOTAL_TESTS"));
    }

    #[test]
    fn markdown_report_names_unwired_live_result_source() {
        let report = render_report("md", false).expect("markdown report");

        assert_eq!(report.exit_code, EXIT_UNAVAILABLE);
        assert!(report.body.contains("Status: unavailable"));
        assert!(report.body.contains("live conformance harness"));
        assert!(!report.body.contains("Overall Score"));
        assert!(!report.body.contains("NOT CONFORMANT"));
    }

    #[test]
    fn unknown_format_errors_without_rendering_placeholder() {
        let error = render_report("xml", false).expect_err("unknown format should fail");

        assert_eq!(error, "Unknown format: xml");
    }
}
