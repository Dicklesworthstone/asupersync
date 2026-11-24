#![allow(clippy::pedantic, clippy::nursery)]

use super::*;
use crate::{Cli, Command, TraceArgs, TraceCommand};
use asupersync::cli::OutputFormat;
use asupersync::trace::file::{HEADER_SIZE, LEGACY_HEADER_SIZE, TRACE_CHECKSUM_LEN};
use asupersync::trace::{CompressionMode, ReplayEvent, TraceFileConfig, TraceWriter};
use clap::Parser;
use std::ffi::OsString;
use std::sync::{Arc, Mutex};
use tempfile::NamedTempFile;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn invoke(
    input: &Path,
    limit: usize,
    destination: Option<&Path>,
    format: OutputFormat,
) -> (Result<(), CliError>, String) {
    let mut arguments = vec![
        OsString::from("asupersync"),
        OsString::from("trace"),
        OsString::from("recover"),
        input.as_os_str().to_owned(),
        OsString::from("--max-events"),
        OsString::from(limit.to_string()),
    ];
    if let Some(path) = destination {
        arguments.push(OsString::from("--output"));
        arguments.push(path.as_os_str().to_owned());
    }
    let cli = Cli::try_parse_from(arguments).expect("parse trace recovery command");
    let capture = Capture::default();
    let mut output = Output::with_writer(format, capture.clone());
    let result = crate::run(cli.command, None, &mut output);
    output.flush().expect("flush command output");
    let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    (result, text)
}

fn trace_fixture(compression: CompressionMode, unfinished: bool) -> NamedTempFile {
    let file = NamedTempFile::new().unwrap();
    let config = TraceFileConfig::new()
        .with_compression(compression)
        .with_chunk_size(1);
    let mut writer = TraceWriter::create_with_config(file.path(), config).unwrap();
    writer.write_metadata(&TraceMetadata::new(731)).unwrap();
    for seed in 0..3 {
        writer.write_event(&ReplayEvent::RngSeed { seed }).unwrap();
    }
    writer.finish().unwrap();
    if unfinished {
        // The binary cannot access TraceWriter's private buffer. Preserve its
        // real metadata and frames, replacing only the documented count/digest
        // slots with the exact pre-finish sentinel. The library regression uses
        // literal flushed writer output captured before finish/Drop.
        let mut bytes = std::fs::read(file.path()).unwrap();
        let metadata_len = u32::from_le_bytes(
            bytes[LEGACY_HEADER_SIZE - 4..LEGACY_HEADER_SIZE]
                .try_into()
                .unwrap(),
        ) as usize;
        let count_offset = HEADER_SIZE + metadata_len;
        bytes[count_offset..count_offset + 8 + TRACE_CHECKSUM_LEN].fill(0);
        std::fs::write(file.path(), bytes).unwrap();
    }
    file
}

#[test]
fn trace_recover_requires_an_explicit_event_bound() {
    assert!(Cli::try_parse_from(["asupersync", "trace", "recover", "run.trace"]).is_err());
    assert!(
        Cli::try_parse_from([
            "asupersync",
            "trace",
            "recover",
            "run.trace",
            "--max-events=-1",
        ])
        .is_err()
    );
    let cli = Cli::try_parse_from([
        "asupersync",
        "trace",
        "recover",
        "run.trace",
        "--max-events",
        "0",
    ])
    .unwrap();
    let Command::Trace(TraceArgs {
        command: TraceCommand::Recover(args),
    }) = cli.command
    else {
        panic!("expected trace recovery command");
    };
    assert_eq!(args.max_events, 0);
    assert!(args.output.is_none());
}

#[test]
fn trace_recover_emits_one_partial_report_and_preserves_the_crash_source() {
    for compression in [CompressionMode::None, CompressionMode::Lz4 { level: 1 }] {
        let input = trace_fixture(compression, true);
        let before = std::fs::read(input.path()).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("recovered.json");
        let (result, stdout) = invoke(input.path(), 10, Some(&destination), OutputFormat::Json);
        let error = result.expect_err("unfinished recovery must exit partial");
        assert_eq!(error.exit_code, ExitCode::PARTIAL_SUCCESS);
        assert_eq!(error.error_type, "trace_recovery_incomplete");

        // from_str rejects a second JSON object: diagnostics must stay off stdout.
        let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["status"]["kind"], "partial");
        assert_eq!(report["status"]["next_event"], 3);
        assert_eq!(report["declared_events"], 0);
        assert_eq!(report["recovered_events"], 3);
        assert_eq!(report["event_stream_verified"], false);
        assert_eq!(report["replay_executed"], false);
        assert_eq!(report["events"].as_array().unwrap().len(), 3);
        assert_eq!(report["events"][0]["index"], 0);
        assert_eq!(report["events"][0]["kind"], "RngSeed");
        assert_eq!(
            report["events"][0]["event"],
            serde_json::to_value(ReplayEvent::RngSeed { seed: 0 }).unwrap()
        );
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&destination).unwrap()).unwrap();
        assert_eq!(saved, report);
        assert_eq!(std::fs::read(input.path()).unwrap(), before);
    }
}

#[test]
fn trace_recover_output_flush_failure_is_not_reported_as_partial_success() {
    struct FailingFlush;

    impl Write for FailingFlush {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "flush failed"))
        }
    }

    let input = trace_fixture(CompressionMode::None, true);
    let args = RecoverArgs {
        input: input.path().to_owned(),
        max_events: 10,
        output: None,
    };
    let mut output = Output::with_writer(OutputFormat::Json, FailingFlush);
    let error = run(&args, &mut output).expect_err("report could not be flushed");
    assert_eq!(error.error_type, "output_error");
    assert_eq!(error.exit_code, ExitCode::RUNTIME_ERROR);
    assert!(error.detail.contains("flush failed"));
}

#[test]
fn trace_recover_limits_and_truncation_remain_explicit_partial_results() {
    let input = trace_fixture(CompressionMode::None, true);
    for limit in [0, 1, 3] {
        let (result, stdout) = invoke(input.path(), limit, None, OutputFormat::Json);
        assert_eq!(result.unwrap_err().exit_code, ExitCode::PARTIAL_SUCCESS);
        let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(report["status"]["kind"], "limit_reached");
        assert_eq!(report["status"]["max_events"], limit);
        assert_eq!(report["recovered_events"], limit);
        assert_eq!(report["event_stream_verified"], false);
    }

    let mut bytes = std::fs::read(input.path()).unwrap();
    bytes.pop();
    std::fs::write(input.path(), &bytes).unwrap();
    let (result, stdout) = invoke(input.path(), 10, None, OutputFormat::Json);
    assert_eq!(result.unwrap_err().exit_code, ExitCode::PARTIAL_SUCCESS);
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["status"]["kind"], "partial");
    assert_eq!(report["status"]["next_event"], 2);
    assert_eq!(report["recovered_events"], 2);
    assert_eq!(std::fs::read(input.path()).unwrap(), bytes);

    let (result, human) = invoke(input.path(), 10, None, OutputFormat::Human);
    assert_eq!(result.unwrap_err().exit_code, ExitCode::PARTIAL_SUCCESS);
    assert!(human.contains("Status: Partial"));
    assert!(human.contains("unverified evidence"));
    assert!(human.contains("Replay executed: no"));
}

#[test]
fn trace_recover_refuses_existing_outputs_and_the_source_itself() {
    let input = trace_fixture(CompressionMode::None, true);
    let original = std::fs::read(input.path()).unwrap();
    let existing = NamedTempFile::new().unwrap();
    std::fs::write(existing.path(), b"existing evidence").unwrap();
    for destination in [input.path(), existing.path()] {
        let before = std::fs::read(destination).unwrap();
        let (result, stdout) = invoke(input.path(), 10, Some(destination), OutputFormat::Json);
        let error = result.unwrap_err();
        assert_eq!(error.error_type, "output_exists");
        assert_eq!(error.exit_code, ExitCode::USER_ERROR);
        assert!(stdout.is_empty());
        assert_eq!(std::fs::read(destination).unwrap(), before);
    }
    assert_eq!(std::fs::read(input.path()).unwrap(), original);

    #[cfg(unix)]
    {
        let directory = tempfile::tempdir().unwrap();
        let link = directory.path().join("linked.json");
        std::os::unix::fs::symlink(input.path(), &link).unwrap();
        let (result, stdout) = invoke(input.path(), 10, Some(&link), OutputFormat::Json);
        assert_eq!(result.unwrap_err().error_type, "output_exists");
        assert!(stdout.is_empty());
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read(input.path()).unwrap(), original);
    }
}

#[test]
fn trace_recover_completed_legacy_files_are_not_labeled_checksum_verified() {
    let finalized = trace_fixture(CompressionMode::None, false);
    let bytes = std::fs::read(finalized.path()).unwrap();
    let metadata_len = u32::from_le_bytes(
        bytes[LEGACY_HEADER_SIZE - 4..LEGACY_HEADER_SIZE]
            .try_into()
            .unwrap(),
    ) as usize;
    // Retain the writer's metadata/count/frames in the documented v2 layout,
    // omitting the two v3 digest slots and clearing the checksummed flag.
    let mut legacy_bytes = bytes[..LEGACY_HEADER_SIZE].to_vec();
    legacy_bytes[11..13].copy_from_slice(&2u16.to_le_bytes());
    legacy_bytes[13..15].fill(0);
    legacy_bytes.extend_from_slice(&bytes[HEADER_SIZE..HEADER_SIZE + metadata_len + 8]);
    legacy_bytes.extend_from_slice(&bytes[HEADER_SIZE + metadata_len + 8 + TRACE_CHECKSUM_LEN..]);
    let legacy = NamedTempFile::new().unwrap();
    std::fs::write(legacy.path(), &legacy_bytes).unwrap();

    for (path, version, verified) in [(finalized.path(), 3, true), (legacy.path(), 2, false)] {
        let (result, stdout) = invoke(path, 3, None, OutputFormat::Json);
        result.expect("complete trace recovery");
        let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(report["file_version"], version);
        assert_eq!(report["status"]["kind"], "complete");
        assert_eq!(report["event_stream_verified"], verified);
        assert_eq!(report["replay_executed"], false);
        assert_eq!(report["recovered_events"], 3);
    }
}

#[test]
fn trace_recover_rejects_corrupt_metadata_before_publishing_output() {
    let input = trace_fixture(CompressionMode::None, true);
    let mut bytes = std::fs::read(input.path()).unwrap();
    bytes[HEADER_SIZE] ^= 1;
    std::fs::write(input.path(), &bytes).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("must-not-exist.json");
    let (result, stdout) = invoke(input.path(), 10, Some(&destination), OutputFormat::Json);
    assert_eq!(result.unwrap_err().error_type, "checksum_mismatch");
    assert!(stdout.is_empty());
    assert!(!destination.exists());
    assert_eq!(std::fs::read(input.path()).unwrap(), bytes);
}
