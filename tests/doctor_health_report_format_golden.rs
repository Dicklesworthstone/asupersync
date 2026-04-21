//! Golden snapshot for doctor health report text formatting.

use asupersync::cli::doctor::{CoreDiagnosticsFixture, core_diagnostics_report_bundle};
use insta::assert_snapshot;

fn health_status(fixture: &CoreDiagnosticsFixture) -> &'static str {
    if fixture.report.summary.critical_findings > 0 || fixture.report.summary.status == "failed" {
        "critical"
    } else if fixture.report.summary.status == "degraded" {
        "degraded"
    } else {
        "passing"
    }
}

fn next_action(health_status: &str) -> &'static str {
    match health_status {
        "critical" => "block_and_remediate",
        "degraded" => "investigate_and_replay",
        _ => "monitor",
    }
}

fn render_health_fixture(fixture: &CoreDiagnosticsFixture) -> String {
    let health_status = health_status(fixture);
    let mut lines = vec![
        format!("fixture: {}", fixture.fixture_id),
        format!("description: {}", fixture.description),
        format!("report_id: {}", fixture.report.report_id),
        format!("scenario_id: {}", fixture.report.provenance.scenario_id),
        format!("health_status: {health_status}"),
        format!("next_action: {}", next_action(health_status)),
        format!(
            "summary: status={} outcome={} findings={} critical={}",
            fixture.report.summary.status,
            fixture.report.summary.overall_outcome,
            fixture.report.summary.total_findings,
            fixture.report.summary.critical_findings
        ),
        "findings:".to_string(),
    ];

    if fixture.report.findings.is_empty() {
        lines.push("  - none".to_string());
    } else {
        lines.extend(fixture.report.findings.iter().map(|finding| {
            format!(
                "  - {} [{} / {}] evidence={} commands={}",
                finding.title,
                finding.severity,
                finding.status,
                finding.evidence_refs.join(","),
                finding.command_refs.join(",")
            )
        }));
    }

    lines.push("evidence:".to_string());
    if fixture.report.evidence.is_empty() {
        lines.push("  - none".to_string());
    } else {
        lines.extend(fixture.report.evidence.iter().map(|evidence| {
            format!(
                "  - {} source={} outcome={} replay={} artifact={}",
                evidence.evidence_id,
                evidence.source,
                evidence.outcome_class,
                evidence.replay_pointer,
                evidence.artifact_pointer
            )
        }));
    }

    lines.push("commands:".to_string());
    if fixture.report.commands.is_empty() {
        lines.push("  - none".to_string());
    } else {
        lines.extend(fixture.report.commands.iter().map(|command| {
            format!(
                "  - {} tool={} exit={} outcome={} cmd={}",
                command.command_id,
                command.tool,
                command.exit_code,
                command.outcome_class,
                command.command
            )
        }));
    }

    lines.push(format!(
        "provenance: run={} trace={} seed={} generated_by={} generated_at=<scrubbed>",
        fixture.report.provenance.run_id,
        fixture.report.provenance.trace_id,
        fixture.report.provenance.seed,
        fixture.report.provenance.generated_by
    ));

    lines.join("\n")
}

#[test]
fn doctor_health_report_format_snapshot() {
    let bundle = core_diagnostics_report_bundle();
    let rendered = bundle
        .fixtures
        .iter()
        .map(render_health_fixture)
        .collect::<Vec<_>>()
        .join("\n\n===\n\n");

    assert!(rendered.contains("health_status: critical"));
    assert!(rendered.contains("health_status: passing"));
    assert!(rendered.contains("health_status: degraded"));

    assert_snapshot!("doctor_health_report_format", rendered);
}
