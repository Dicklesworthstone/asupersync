//! E2E guard for source-owned conformance reference registry rows.

use asupersync_conformance::ReferenceSurfaceRegistry;
use std::process::ExitCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    Text,
    Json,
}

fn parse_output_mode() -> Result<OutputMode, String> {
    let mut mode = OutputMode::Text;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--json" | "--output=json" => mode = OutputMode::Json,
            "--text" | "--output=text" => mode = OutputMode::Text,
            "--help" | "-h" => {
                println!(
                    "usage: conformance_reference_registry_guard [--text|--json|--output=text|--output=json]"
                );
                return Ok(mode);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(mode)
}

fn main() -> ExitCode {
    let mode = match parse_output_mode() {
        Ok(mode) => mode,
        Err(error) => {
            eprintln!("conformance-reference-registry-guard-v1 error={error}");
            return ExitCode::from(2);
        }
    };
    let registry = match ReferenceSurfaceRegistry::source_contract() {
        Ok(registry) => registry,
        Err(error) => {
            eprintln!("conformance-reference-registry-guard-v1 error={error}");
            return ExitCode::from(2);
        }
    };
    let report = registry.guard_report();

    match mode {
        OutputMode::Json => match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("conformance-reference-registry-guard-v1 error={error}");
                return ExitCode::from(2);
            }
        },
        OutputMode::Text => {
            println!(
                "{} verdict={} checked_surface_count={} failure_count={}",
                report.schema_version,
                report.verdict,
                report.checked_surface_count,
                report.failures.len()
            );
            for failure in &report.failures {
                println!(
                    "surface_id={} binary={} reason={}",
                    failure.surface_id, failure.binary, failure.reason
                );
            }
        }
    }

    if report.is_pass() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_registry_guard_report_passes() {
        let registry = ReferenceSurfaceRegistry::source_contract().expect("source registry loads");
        let report = registry.guard_report();
        assert!(report.is_pass(), "guard failures: {:?}", report.failures);
        assert_eq!(
            report.schema_version,
            "conformance-reference-registry-guard-v1"
        );
    }
}
