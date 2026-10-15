#!/usr/bin/env cargo +nightly -Zscript
//! HPACK encode path baseline benchmark runner.
//!
//! This artifact delegates to `benches/protocol_benchmark.rs`, the canonical
//! Criterion benchmark that imports `asupersync::http::h2::{HpackEncoder,
//! HpackDecoder}` and exercises the real HPACK implementation. Keeping this
//! file as a thin runner avoids a second benchmark-only encoder drifting away
//! from production behavior.

use std::env;
use std::process::{Command, ExitStatus};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy)]
enum Scenario {
    Baseline,
    Request,
    Response,
    Repeated,
    Decode,
    Roundtrip,
}

impl Scenario {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "baseline" => Some(Self::Baseline),
            "request" | "realistic" => Some(Self::Request),
            "response" => Some(Self::Response),
            "repeated" => Some(Self::Repeated),
            "decode" => Some(Self::Decode),
            "roundtrip" | "large" | "huffman" => Some(Self::Roundtrip),
            _ => None,
        }
    }

    fn criterion_filter(self) -> &'static str {
        match self {
            Self::Baseline => "hpack/encode",
            Self::Request => "hpack/encode/request_headers",
            Self::Response => "hpack/encode/response_headers",
            Self::Repeated => "hpack/encode/repeated_headers",
            Self::Decode => "hpack/decode",
            Self::Roundtrip => "protocol/throughput/hpack_roundtrips",
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Request => "request",
            Self::Response => "response",
            Self::Repeated => "repeated",
            Self::Decode => "decode",
            Self::Roundtrip => "roundtrip",
        }
    }
}

#[derive(Debug)]
struct Cli {
    scenario: Scenario,
    sample_size: Option<u32>,
    measurement_time_secs: Option<u32>,
    dry_run: bool,
}

fn main() {
    let cli = parse_cli().unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(2);
    });

    let args = build_bench_args(&cli);

    emit_event(
        "run_start",
        &[
            ("scenario", cli.scenario.as_str().to_string()),
            (
                "criterion_filter",
                cli.scenario.criterion_filter().to_string(),
            ),
            ("command", format!("cargo {}", args.join(" "))),
            ("timestamp_unix_ms", timestamp_unix_ms().to_string()),
        ],
    );

    if cli.dry_run {
        emit_event(
            "dry_run_complete",
            &[("status", "not_executed".to_string())],
        );
        return;
    }

    let status = Command::new("cargo")
        .args(&args)
        .status()
        .unwrap_or_else(|err| {
            emit_event("spawn_failed", &[("error", err.to_string())]);
            std::process::exit(1);
        });

    emit_status(status);
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn parse_cli() -> Result<Cli, String> {
    let args: Vec<String> = env::args().collect();
    let scenario = args
        .get(1)
        .map(String::as_str)
        .map_or(Some(Scenario::Baseline), Scenario::parse)
        .ok_or_else(|| usage(&args[0]))?;

    let mut sample_size = None;
    let mut measurement_time_secs = None;
    let mut dry_run = false;

    for arg in args.iter().skip(2) {
        if arg == "--dry-run" {
            dry_run = true;
        } else if let Some(value) = arg.strip_prefix("--sample-size=") {
            sample_size = Some(parse_positive_u32("--sample-size", value)?);
        } else if let Some(value) = arg.strip_prefix("--measurement-time=") {
            measurement_time_secs = Some(parse_positive_u32("--measurement-time", value)?);
        } else {
            return Err(format!(
                "unrecognized argument '{arg}'\n{}",
                usage(&args[0])
            ));
        }
    }

    Ok(Cli {
        scenario,
        sample_size,
        measurement_time_secs,
        dry_run,
    })
}

fn parse_positive_u32(flag: &str, value: &str) -> Result<u32, String> {
    let parsed = value
        .parse::<u32>()
        .map_err(|err| format!("invalid {flag} value '{value}': {err}"))?;
    if parsed == 0 {
        return Err(format!("{flag} must be > 0"));
    }
    Ok(parsed)
}

fn usage(program: &str) -> String {
    format!(
        "Usage: {program} [baseline|request|response|repeated|decode|roundtrip] \
         [--sample-size=N] [--measurement-time=SECONDS] [--dry-run]"
    )
}

fn build_bench_args(cli: &Cli) -> Vec<String> {
    let mut args = vec![
        "bench".to_string(),
        "--bench".to_string(),
        "protocol_benchmark".to_string(),
        cli.scenario.criterion_filter().to_string(),
        "--".to_string(),
    ];

    if let Some(sample_size) = cli.sample_size {
        args.push("--sample-size".to_string());
        args.push(sample_size.to_string());
    }

    if let Some(measurement_time_secs) = cli.measurement_time_secs {
        args.push("--measurement-time".to_string());
        args.push(measurement_time_secs.to_string());
    }

    args
}

fn emit_status(status: ExitStatus) {
    emit_event(
        "run_complete",
        &[
            ("success", status.success().to_string()),
            (
                "exit_code",
                status
                    .code()
                    .map_or_else(|| "signal".to_string(), |code| code.to_string()),
            ),
        ],
    );
}

fn emit_event(event: &str, fields: &[(&str, String)]) {
    eprint!("{{\"event\":\"{}\"", json_escape(event));
    for (key, value) in fields {
        eprint!(",\"{}\":\"{}\"", json_escape(key), json_escape(value));
    }
    eprintln!("}}");
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => escaped.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => escaped.push(ch),
        }
    }
    escaped
}

fn timestamp_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}
