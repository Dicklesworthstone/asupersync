use asupersync_conformance::extract_frontier_report;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("lean_frontier_extract error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_usage();
        return Ok(());
    }

    let log_path = required_arg(&args, "--log")?;
    let output_path = required_arg(&args, "--out")?;
    let source_log = optional_arg(&args, "--source-log").unwrap_or_else(|| log_path.clone());
    let gap_plan_path = optional_arg(&args, "--gap-plan");

    let log_text =
        fs::read_to_string(&log_path).map_err(|error| format!("failed to read --log: {error}"))?;
    let gap_plan_json = gap_plan_path
        .as_ref()
        .map(fs::read_to_string)
        .transpose()
        .map_err(|error| format!("failed to read --gap-plan: {error}"))?;

    let report = extract_frontier_report(&log_text, &source_log, gap_plan_json.as_deref());
    let rendered =
        serde_json::to_string_pretty(&report).map_err(|error| format!("json render: {error}"))?;

    let output = PathBuf::from(output_path);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create output parent directory: {error}"))?;
    }
    fs::write(output, format!("{rendered}\n"))
        .map_err(|error| format!("failed to write --out: {error}"))?;
    Ok(())
}

fn required_arg(args: &[String], key: &str) -> Result<String, String> {
    optional_arg(args, key).ok_or_else(|| format!("missing required argument: {key}"))
}

fn optional_arg(args: &[String], key: &str) -> Option<String> {
    args.windows(2).find_map(|window| {
        if window[0] == key {
            Some(window[1].clone())
        } else {
            None
        }
    })
}

fn print_usage() {
    println!(
        "\
Usage:
  cargo run -p asupersync-conformance --bin lean_frontier_extract -- \\
    --log <lake-build.log> \\
    --out <frontier-report.json> \\
    [--gap-plan <formal/lean/coverage/gap_risk_sequencing_plan.json>] \\
    [--source-log <displayed-source-path>]"
    );
}
