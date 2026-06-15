//! CLI contract for `frankenlab trace-recover`
//! (br-asupersync-raptorq-leverage-3bb2pl.2).
//!
//! Builds a crash-durable RaptorQ trace journal on disk with the library writer,
//! then drives the *compiled* `frankenlab` binary to recover it — proving the
//! `trace-recover` subcommand:
//!   * reconstructs the latest checkpoint's original bytes byte-exact,
//!   * survives the loss of a whole stripe file (a lost failure domain),
//!   * can target a specific `--epoch`, and
//!   * exits nonzero with `recovered: false` on an empty journal directory.
//!
//! Uses `repair_count: 4, stripe_count: 3` — the same redundancy the library's
//! `raptorq_journal_writer_io_contract` proves tolerates one stripe loss.

#![allow(missing_docs)]
#![allow(clippy::cast_possible_truncation)]

use asupersync::config::EncodingConfig;
use asupersync::runtime::RuntimeBuilder;
use asupersync::trace::raptorq_journal_writer::{
    DurableTraceJournal, DurableTraceJournalConfig, stripe_file_name,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Varied (non-constant) payload so byte-exact recovery is meaningful — a
/// constant fill would "recover" trivially.
fn varied_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
        .collect()
}

/// A fresh, isolated journal directory under the test binary's temp dir.
fn unique_dir(tag: &str) -> PathBuf {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("trace_recover_cli_{tag}"));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).expect("create journal dir");
    base
}

/// Record `data` as checkpoint `epoch` into a durable journal at `dir`
/// (3 stripes, 4 repair symbols per source block).
fn record_epoch(dir: &Path, epoch: u64, data: &[u8]) {
    let journal = DurableTraceJournal::new(DurableTraceJournalConfig {
        directory: dir.to_path_buf(),
        encoding: EncodingConfig::default(),
        repair_count: 4,
        stripe_count: 3,
    });
    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");
    let data = data.to_vec();
    runtime.block_on(runtime.handle().spawn(async move {
        journal
            .record_epoch(epoch, &data)
            .await
            .expect("record epoch");
    }));
}

fn frankenlab() -> Command {
    Command::new(env!("CARGO_BIN_EXE_frankenlab"))
}

/// Run `frankenlab --json trace-recover <args...>` and return (success, parsed json).
fn run_recover(args: &[&std::ffi::OsStr]) -> (bool, serde_json::Value) {
    let output = frankenlab()
        .arg("--json")
        .arg("trace-recover")
        .args(args)
        .output()
        .expect("run frankenlab");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let report: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "json report parse failed ({e}); stdout={stdout:?} stderr={:?}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.success(), report)
}

#[test]
fn recovers_latest_epoch_byte_exact_to_output_file() {
    let dir = unique_dir("latest");
    let payload = varied_payload(700);
    record_epoch(&dir, 20, &varied_payload(500));
    record_epoch(&dir, 30, &payload);

    let out = dir.join("recovered.bin");
    let (ok, report) = run_recover(&[dir.as_os_str(), "--output".as_ref(), out.as_os_str()]);

    assert!(ok, "recover of a healthy journal must succeed");
    assert_eq!(report["recovered"], serde_json::json!(true));
    assert_eq!(report["epoch"], serde_json::json!(30), "latest epoch wins");
    assert_eq!(report["bytes"], serde_json::json!(700));

    let recovered = fs::read(&out).expect("read recovered file");
    assert_eq!(
        recovered, payload,
        "recovered bytes must equal the original checkpoint"
    );
}

#[test]
fn recovers_after_losing_one_stripe_file() {
    let dir = unique_dir("stripe_loss");
    let payload = varied_payload(600);
    record_epoch(&dir, 77, &payload);

    // Destroy one whole stripe file — a lost failure domain.
    fs::remove_file(dir.join(stripe_file_name(77, 0))).expect("remove stripe 0");

    let out = dir.join("recovered.bin");
    let (ok, report) = run_recover(&[dir.as_os_str(), "--output".as_ref(), out.as_os_str()]);

    assert!(ok, "recover must succeed after losing one of three stripes");
    assert_eq!(report["epoch"], serde_json::json!(77));
    let recovered = fs::read(&out).expect("read recovered file");
    assert_eq!(
        recovered, payload,
        "byte-exact recovery must survive losing one stripe file"
    );
}

#[test]
fn recovers_specific_epoch_with_flag() {
    let dir = unique_dir("specific");
    let older = varied_payload(400);
    record_epoch(&dir, 10, &older);
    record_epoch(&dir, 20, &varied_payload(800));

    let out = dir.join("e10.bin");
    let (ok, report) = run_recover(&[
        dir.as_os_str(),
        "--epoch".as_ref(),
        "10".as_ref(),
        "--output".as_ref(),
        out.as_os_str(),
    ]);

    assert!(ok, "recover of an explicit epoch must succeed");
    assert_eq!(
        report["epoch"],
        serde_json::json!(10),
        "--epoch overrides latest"
    );
    assert_eq!(fs::read(&out).expect("read recovered file"), older);
}

#[test]
fn empty_journal_dir_fails_nonzero() {
    let dir = unique_dir("empty");
    let (ok, report) = run_recover(&[dir.as_os_str()]);

    assert!(
        !ok,
        "an empty journal must exit nonzero so scripts can detect it"
    );
    assert_eq!(report["recovered"], serde_json::json!(false));
    assert_eq!(report["recorded_epochs"], serde_json::json!([]));
}
