//! Real CLI journeys for persistent local directory reconciliation.
//!
//! Beads: asupersync-bi2462.65, asupersync-bi2462.66. Each scenario uses fresh,
//! retained private directories and the Cargo-built binary. Commands, stdout,
//! stderr, state, and quarantined originals remain available after the test.
//! Deletion intent is introduced by moving a fixture outside the sync roots;
//! this harness never unlinks files or removes directories.
//!
//! Replay: `RCH_REQUIRE_REMOTE=1 rch exec -- env
//! CARGO_TARGET_DIR=/tmp/rch_target_atp_local_sync cargo test -p asupersync
//! --features cli --test atp_cli_journey local_sync:: -- --nocapture`.

use asupersync::atp::sync::{
    BidirectionalConflict, BidirectionalSyncAction, BidirectionalSyncDecision,
};
use asupersync::cli::ExitCode;
use serde_json::Value;
use std::cell::Cell;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, File};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const ASUPERSYNC_BIN: &str = env!("CARGO_BIN_EXE_asupersync");
const COMMAND_LIMIT: Duration = Duration::from_secs(60);

struct Fixture {
    root: PathBuf,
    local: PathBuf,
    remote: PathBuf,
    state: PathBuf,
    staging: PathBuf,
    invocation: Cell<u64>,
}

impl Fixture {
    fn new(scenario: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir()
            .canonicalize()
            .expect("canonical temporary directory without symlink ancestors");
        let root = loop {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let candidate = parent.join(format!(
                "asupersync-cli-local-sync-{scenario}-{}-{sequence}",
                std::process::id()
            ));
            match DirBuilder::new().mode(0o700).create(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create retained fixture {}: {error}", candidate.display()),
            }
        };
        let fixture = Self {
            local: root.join("local"),
            remote: root.join("remote"),
            state: root.join("state"),
            staging: root.join("staging"),
            root,
            invocation: Cell::new(0),
        };
        for directory in [
            &fixture.local,
            &fixture.remote,
            &fixture.state,
            &fixture.staging,
        ] {
            private_directory(directory);
        }
        eprintln!(
            "local-sync scenario={scenario} retained={}",
            fixture.root.display()
        );
        fixture
    }

    fn command(&self) -> Command {
        self.command_for(&self.local, &self.remote)
    }

    fn command_for(&self, local: &Path, remote: &Path) -> Command {
        let mut command = Command::new(ASUPERSYNC_BIN);
        command
            .args(["--format", "json", "atp", "local-sync"])
            .arg(local)
            .arg(remote)
            .arg("--state-dir")
            .arg(&self.state)
            .stdin(Stdio::null());
        command
    }

    fn plan(&self, flags: &[&str]) -> Invocation {
        let mut command = self.command();
        command.args(flags);
        self.run(command)
    }

    fn apply(&self, flags: &[&str]) -> Invocation {
        let mut command = self.command();
        command
            .args(["--apply", "--staging-dir"])
            .arg(&self.staging)
            .args(flags);
        self.run(command)
    }

    fn run(&self, command: Command) -> Invocation {
        self.run_with_stdout(command, None)
    }

    fn run_with_stdout(&self, mut command: Command, stdout_override: Option<&Path>) -> Invocation {
        let sequence = self.invocation.get();
        self.invocation.set(sequence + 1);
        let prefix = format!("command-{sequence}");
        let stdout = self.root.join(format!("{prefix}.stdout.json"));
        let stderr = self.root.join(format!("{prefix}.stderr.log"));
        let arguments: Vec<_> = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        fs::write(
            self.root.join(format!("{prefix}.command.json")),
            serde_json::to_vec_pretty(&serde_json::json!({
                "binary": ASUPERSYNC_BIN,
                "arguments": arguments,
                "stdout": stdout_override.unwrap_or(&stdout),
            }))
            .expect("serialize replay command"),
        )
        .expect("retain replay command");
        let stdout_file = match stdout_override {
            Some(path) => File::options()
                .write(true)
                .open(path)
                .expect("open existing stdout failure device"),
            None => File::create_new(&stdout).expect("create retained stdout"),
        };
        command
            .stdout(stdout_file)
            .stderr(File::create_new(&stderr).expect("create retained stderr"));
        let mut child = ReapedChild(command.spawn().expect("run Cargo-built asupersync"));
        let deadline = Instant::now() + COMMAND_LIMIT;
        let (status, timed_out) = loop {
            if let Some(status) = child.0.try_wait().expect("poll local-sync child") {
                break (status, false);
            }
            if Instant::now() >= deadline {
                let _ = child.0.kill();
                break (child.0.wait().expect("reap timed-out local-sync child"), true);
            }
            thread::sleep(Duration::from_millis(10));
        };
        Invocation {
            output: Output {
                status,
                stdout: if stdout_override.is_none() {
                    fs::read(&stdout).expect("read retained stdout")
                } else {
                    // The failure device cannot retain stdout; stderr retains
                    // the observed application receipt instead.
                    Vec::new()
                },
                stderr: fs::read(&stderr).expect("read retained stderr"),
            },
            timed_out,
            artifacts: self.root.clone(),
        }
    }

    fn state_bytes(&self) -> Vec<u8> {
        fs::read(self.state.join("current.state")).expect("read persisted common baseline")
    }

    fn establish(&self, name: &str, contents: &[u8]) {
        fs::write(self.local.join(name), contents).expect("write initial local content");
        let report = self.apply(&["--initialize"]).success_json();
        assert_durable(&report, self, 1);
        assert_eq!(fs::read(self.remote.join(name)).unwrap(), contents);
    }
}

/// A failed assertion or I/O error must not leave a CLI process running.
struct ReapedChild(Child);

impl Drop for ReapedChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

struct Invocation {
    output: Output,
    timed_out: bool,
    artifacts: PathBuf,
}

impl Invocation {
    fn describe(&self) -> String {
        format!(
            "status={} timed_out={} retained={}\nstdout:\n{}\nstderr:\n{}",
            self.output.status,
            self.timed_out,
            self.artifacts.display(),
            String::from_utf8_lossy(&self.output.stdout),
            String::from_utf8_lossy(&self.output.stderr)
        )
    }

    fn assert_failure(&self) {
        assert!(!self.timed_out, "CLI did not finish: {}", self.describe());
        assert!(
            self.output.status.code().is_some_and(|code| code != 0),
            "expected a normal nonzero CLI exit: {}",
            self.describe()
        );
        assert!(
            !self.output.stderr.is_empty(),
            "missing error diagnostic: {}",
            self.describe()
        );
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.output.stdout).unwrap_or_else(|error| {
            panic!("expected exactly one JSON receipt: {error}\n{}", self.describe())
        })
    }

    fn success_json(&self) -> Value {
        assert!(
            !self.timed_out && self.output.status.success(),
            "local-sync command failed: {}",
            self.describe()
        );
        self.json()
    }

    fn failure_json(&self) -> Value {
        self.assert_failure();
        self.json()
    }
}

fn private_directory(path: &Path) {
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .unwrap_or_else(|error| panic!("create private directory {}: {error}", path.display()));
}

fn directory_entries(path: &Path) -> Vec<OsString> {
    let mut entries: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    entries.sort();
    entries
}

fn assert_header(report: &Value, fixture: &Fixture, mode: &str, generation: u64) {
    assert_eq!(report["schema_version"], 1, "{report:#}");
    assert_eq!(report["command"], "atp.local-sync", "{report:#}");
    assert_eq!(report["mode"], mode, "{report:#}");
    assert_eq!(report["baseline_generation"], generation, "{report:#}");
    assert_eq!(report["local_root"].as_str(), fixture.local.to_str());
    assert_eq!(report["remote_root"].as_str(), fixture.remote.to_str());
    assert_eq!(report["state_directory"].as_str(), fixture.state.to_str());
    assert_eq!(report["runtime_quiescent"], true, "{report:#}");
    assert_eq!(report["runtime_stopped"], true, "{report:#}");
    assert!(report["application_error"].is_null(), "{report:#}");
    assert!(report["plan_id"].as_str().is_some_and(|id| !id.is_empty()));
}

fn assert_plan(report: &Value, fixture: &Fixture, generation: u64) {
    assert_header(report, fixture, "plan", generation);
    assert!(
        report["result"].is_null(),
        "preview must not claim effects: {report:#}"
    );
}

fn assert_durable(report: &Value, fixture: &Fixture, generation: u64) {
    assert_header(report, fixture, "apply", generation);
    assert_eq!(report["has_conflicts"], false, "{report:#}");
    let result = &report["result"];
    assert_eq!(result["complete"], true, "{report:#}");
    assert_eq!(result["dry_run"], false, "{report:#}");
    assert_eq!(result["baseline_generation"], generation, "{report:#}");
    assert_eq!(result["publication"]["state"], "durable", "{report:#}");
    assert_eq!(result["publication"]["generation"], generation, "{report:#}");
    assert!(result["failure"].is_null(), "{report:#}");
    assert!(result["persistence_failure"].is_null(), "{report:#}");
}

fn assert_refused_before_effects(report: &Value, fixture: &Fixture, generation: u64) {
    assert_header(report, fixture, "apply", generation);
    let result = &report["result"];
    assert_eq!(result["complete"], false, "{report:#}");
    assert_eq!(result["dry_run"], false, "{report:#}");
    assert_eq!(result["baseline_generation"], generation, "{report:#}");
    assert_eq!(result["publication"]["state"], "unchanged", "{report:#}");
    assert!(
        result["failure"].as_str().is_some_and(|error| !error.is_empty()),
        "{report:#}"
    );
    assert!(result["persistence_failure"].is_null(), "{report:#}");
    assert!(result["staging_directory"].is_null(), "{report:#}");
    let actions = result["actions"].as_array().expect("actual action receipts");
    assert!(!actions.is_empty(), "the refused plan must contain an action");
    for action in actions {
        assert_eq!(action["state"], "not_started", "{report:#}");
        assert_eq!(action["bytes_written"], 0, "{report:#}");
        assert_eq!(action["durable"], false, "{report:#}");
        assert!(action["staged_path"].is_null(), "{report:#}");
        assert!(action["quarantine_path"].is_null(), "{report:#}");
    }
}

fn decisions(report: &Value) -> Vec<BidirectionalSyncDecision> {
    serde_json::from_value(report["decisions"].clone()).expect("native reconciliation decisions")
}

fn decision(report: &Value, path: &str) -> BidirectionalSyncDecision {
    decisions(report)
        .into_iter()
        .find(|decision| decision.path.as_str() == path)
        .unwrap_or_else(|| panic!("missing decision for {path}: {report:#}"))
}

fn receipt<'a>(report: &'a Value, path: &str) -> &'a Value {
    report["result"]["actions"]
        .as_array()
        .expect("actual action receipts")
        .iter()
        .find(|action| action["path"].as_str() == Some(path))
        .unwrap_or_else(|| panic!("missing action receipt for {path}: {report:#}"))
}

#[test]
fn local_sync_initialization_previews_both_directions_without_applying() {
    let fixture = Fixture::new("initialize-plan");
    fs::write(fixture.local.join("local.txt"), b"local original").unwrap();
    fs::write(fixture.remote.join("remote.txt"), b"remote original").unwrap();

    fixture.plan(&[]).assert_failure();
    assert!(
        directory_entries(&fixture.state).is_empty(),
        "reopen must not initialize state"
    );

    let initialized = fixture.plan(&["--initialize"]).success_json();
    assert_plan(&initialized, &fixture, 0);
    assert_eq!(initialized["has_conflicts"], false);
    assert_eq!(initialized["has_destructive_actions"], false);
    assert_eq!(decisions(&initialized).len(), 2);
    assert_eq!(
        decision(&initialized, "local.txt").action,
        BidirectionalSyncAction::CopyLocalToRemote
    );
    assert_eq!(
        decision(&initialized, "remote.txt").action,
        BidirectionalSyncAction::CopyRemoteToLocal
    );
    let state = fixture.state_bytes();

    let reopened = fixture.plan(&[]).success_json();
    assert_plan(&reopened, &fixture, 0);
    assert_eq!(decisions(&initialized), decisions(&reopened));
    assert_eq!(
        fixture.state_bytes(),
        state,
        "preview must not advance history"
    );
    assert_eq!(
        fs::read(fixture.local.join("local.txt")).unwrap(),
        b"local original"
    );
    assert_eq!(
        fs::read(fixture.remote.join("remote.txt")).unwrap(),
        b"remote original"
    );
    assert!(!fixture.local.join("remote.txt").exists());
    assert!(!fixture.remote.join("local.txt").exists());
    assert!(directory_entries(&fixture.staging).is_empty());
}

#[test]
fn local_sync_apply_copies_both_directions_and_persists_convergence() {
    let fixture = Fixture::new("bidirectional-copy");
    private_directory(&fixture.local.join("nested"));
    fs::write(fixture.local.join("nested/local.bin"), b"\0local\xffpayload\n").unwrap();
    fs::write(fixture.remote.join("remote.txt"), b"remote payload").unwrap();

    let report = fixture.apply(&["--initialize"]).success_json();
    assert_durable(&report, &fixture, 1);
    assert_eq!(report["has_destructive_actions"], false);
    assert_eq!(
        decision(&report, "nested/local.bin").action,
        BidirectionalSyncAction::CopyLocalToRemote
    );
    assert_eq!(
        decision(&report, "remote.txt").action,
        BidirectionalSyncAction::CopyRemoteToLocal
    );
    for root in [&fixture.local, &fixture.remote] {
        assert_eq!(
            fs::read(root.join("nested/local.bin")).unwrap(),
            b"\0local\xffpayload\n"
        );
        assert_eq!(fs::read(root.join("remote.txt")).unwrap(), b"remote payload");
    }
    for (path, bytes) in [("nested/local.bin", 15), ("remote.txt", 14)] {
        let action = receipt(&report, path);
        assert_eq!(action["state"], "published", "{report:#}");
        assert_eq!(action["bytes_written"], bytes, "{report:#}");
        assert_eq!(action["durable"], true, "{report:#}");
        assert!(action["staged_path"].is_null());
        assert!(action["quarantine_path"].is_null());
    }

    let reopened = fixture.plan(&[]).success_json();
    assert_plan(&reopened, &fixture, 1);
    assert_eq!(decisions(&reopened).len(), 3);
    assert!(
        decisions(&reopened)
            .iter()
            .all(|item| item.action == BidirectionalSyncAction::Keep)
    );
}

#[test]
fn local_sync_reopen_propagates_remote_edit_and_retains_overwritten_original() {
    let fixture = Fixture::new("reopen-update");
    fixture.establish("shared.txt", b"version one");
    fs::write(fixture.remote.join("shared.txt"), b"remote version two").unwrap();

    let preview = fixture.plan(&[]).success_json();
    assert_plan(&preview, &fixture, 1);
    assert_eq!(preview["has_destructive_actions"], true);
    let edit = decision(&preview, "shared.txt");
    assert_eq!(edit.action, BidirectionalSyncAction::CopyRemoteToLocal);
    assert!(
        edit.baseline.is_some(),
        "reopened plan must use the persisted common version"
    );

    let report = fixture
        .apply(&["--allow-overwrite", "--allow-permission-change"])
        .success_json();
    assert_durable(&report, &fixture, 2);
    for root in [&fixture.local, &fixture.remote] {
        assert_eq!(
            fs::read(root.join("shared.txt")).unwrap(),
            b"remote version two"
        );
    }
    let action = receipt(&report, "shared.txt");
    assert_eq!(action["state"], "published");
    assert_eq!(action["durable"], true);
    let original = Path::new(
        action["quarantine_path"]
            .as_str()
            .expect("retained overwrite original"),
    );
    assert!(original.starts_with(&fixture.staging));
    assert_eq!(fs::read(original).unwrap(), b"version one");

    let reopened = fixture.plan(&[]).success_json();
    assert_plan(&reopened, &fixture, 2);
    assert_eq!(
        decision(&reopened, "shared.txt").action,
        BidirectionalSyncAction::Keep
    );
}

#[test]
fn local_sync_conflict_preserves_both_versions_and_blocks_unrelated_copy() {
    let fixture = Fixture::new("concurrent-edit");
    fixture.establish("shared.txt", b"common version");
    fs::write(fixture.local.join("shared.txt"), b"local edit").unwrap();
    fs::write(fixture.remote.join("shared.txt"), b"remote edit").unwrap();
    fs::write(fixture.local.join("unrelated.txt"), b"must not be copied").unwrap();
    let state = fixture.state_bytes();
    let staging = directory_entries(&fixture.staging);

    let preview = fixture.plan(&[]).success_json();
    assert_plan(&preview, &fixture, 1);
    assert_eq!(preview["has_conflicts"], true);
    assert_eq!(
        decision(&preview, "shared.txt").action,
        BidirectionalSyncAction::Conflict {
            reason: BidirectionalConflict::ConcurrentModification,
        }
    );
    assert_eq!(
        decision(&preview, "unrelated.txt").action,
        BidirectionalSyncAction::CopyLocalToRemote
    );

    let report = fixture
        .apply(&[
            "--allow-overwrite",
            "--allow-permission-change",
            "--allow-delete",
        ])
        .failure_json();
    assert_refused_before_effects(&report, &fixture, 1);
    assert_eq!(report["has_conflicts"], true);
    assert_eq!(
        fs::read(fixture.local.join("shared.txt")).unwrap(),
        b"local edit"
    );
    assert_eq!(
        fs::read(fixture.remote.join("shared.txt")).unwrap(),
        b"remote edit"
    );
    assert!(!fixture.remote.join("unrelated.txt").exists());
    assert_eq!(fixture.state_bytes(), state);
    assert_eq!(directory_entries(&fixture.staging), staging);
}

#[test]
fn local_sync_overwrite_requires_each_explicit_grant_before_effects() {
    let fixture = Fixture::new("overwrite-consent");
    fixture.establish("shared.txt", b"original");
    fs::write(fixture.local.join("shared.txt"), b"edited").unwrap();
    let state = fixture.state_bytes();
    let staging = directory_entries(&fixture.staging);

    for flags in [
        &[][..],
        &["--allow-overwrite"][..],
        &["--allow-permission-change"][..],
    ] {
        let report = fixture.apply(flags).failure_json();
        assert_refused_before_effects(&report, &fixture, 1);
        assert_eq!(report["has_conflicts"], false);
        assert_eq!(report["has_destructive_actions"], true);
        assert_eq!(fs::read(fixture.local.join("shared.txt")).unwrap(), b"edited");
        assert_eq!(
            fs::read(fixture.remote.join("shared.txt")).unwrap(),
            b"original"
        );
        assert_eq!(fixture.state_bytes(), state);
        assert_eq!(directory_entries(&fixture.staging), staging);
    }

    let report = fixture
        .apply(&["--allow-overwrite", "--allow-permission-change"])
        .success_json();
    assert_durable(&report, &fixture, 2);
    assert_eq!(fs::read(fixture.remote.join("shared.txt")).unwrap(), b"edited");
}

#[test]
fn local_sync_deletion_requires_consent_and_returns_recoverable_quarantine() {
    let fixture = Fixture::new("quarantined-deletion");
    fixture.establish("retired.txt", b"retain these bytes");
    let retained_local = fixture.root.join("retained-local-original.txt");
    fs::rename(fixture.local.join("retired.txt"), &retained_local).unwrap();
    let state = fixture.state_bytes();
    let staging = directory_entries(&fixture.staging);

    let preview = fixture.plan(&[]).success_json();
    assert_plan(&preview, &fixture, 1);
    assert_eq!(preview["has_destructive_actions"], true);
    assert_eq!(
        decision(&preview, "retired.txt").action,
        BidirectionalSyncAction::DeleteRemote
    );

    let refused = fixture.apply(&[]).failure_json();
    assert_refused_before_effects(&refused, &fixture, 1);
    assert_eq!(
        fs::read(fixture.remote.join("retired.txt")).unwrap(),
        b"retain these bytes"
    );
    assert_eq!(fixture.state_bytes(), state);
    assert_eq!(directory_entries(&fixture.staging), staging);

    let report = fixture.apply(&["--allow-delete"]).success_json();
    assert_durable(&report, &fixture, 2);
    assert!(!fixture.local.join("retired.txt").exists());
    assert!(!fixture.remote.join("retired.txt").exists());
    let action = receipt(&report, "retired.txt");
    assert_eq!(action["state"], "quarantined");
    assert_eq!(action["bytes_written"], 0);
    assert_eq!(action["durable"], true);
    let quarantine = Path::new(
        action["quarantine_path"]
            .as_str()
            .expect("retained deleted original"),
    );
    assert!(quarantine.starts_with(&fixture.staging));
    assert_eq!(fs::read(quarantine).unwrap(), b"retain these bytes");
    assert_eq!(fs::read(retained_local).unwrap(), b"retain these bytes");

    let reopened = fixture.plan(&[]).success_json();
    assert_plan(&reopened, &fixture, 2);
    assert!(
        decisions(&reopened).is_empty(),
        "deleted path must leave the persisted baseline"
    );
}

#[test]
fn local_sync_reinitialization_and_changed_roots_cannot_reset_history() {
    let fixture = Fixture::new("history-binding");
    fixture.establish("shared.txt", b"committed content");
    let state = fixture.state_bytes();
    let staging = directory_entries(&fixture.staging);

    fixture.plan(&["--initialize"]).assert_failure();
    assert_eq!(
        fixture.state_bytes(),
        state,
        "initialization must not replace history"
    );

    let different_remote = fixture.root.join("different-remote");
    private_directory(&different_remote);
    fixture
        .run(fixture.command_for(&fixture.local, &different_remote))
        .assert_failure();
    fixture
        .run(fixture.command_for(&fixture.remote, &fixture.local))
        .assert_failure();
    assert!(directory_entries(&different_remote).is_empty());
    assert_eq!(
        fixture.state_bytes(),
        state,
        "root mismatch must not replace history"
    );
    assert_eq!(directory_entries(&fixture.staging), staging);
    for root in [&fixture.local, &fixture.remote] {
        assert_eq!(
            fs::read(root.join("shared.txt")).unwrap(),
            b"committed content"
        );
    }

    let reopened = fixture.plan(&[]).success_json();
    assert_plan(&reopened, &fixture, 1);
    assert_eq!(
        decision(&reopened, "shared.txt").action,
        BidirectionalSyncAction::Keep
    );
}

#[test]
fn local_sync_authorization_and_staging_flags_require_explicit_application() {
    let fixture = Fixture::new("argument-authority");
    fs::write(fixture.local.join("local.txt"), b"must remain local").unwrap();
    let initialized = fixture.plan(&["--initialize"]).success_json();
    assert_plan(&initialized, &fixture, 0);
    let state = fixture.state_bytes();

    for flag in [
        "--allow-overwrite",
        "--allow-permission-change",
        "--allow-delete",
        "--apply",
    ] {
        fixture.plan(&[flag]).assert_failure();
    }
    let mut staging_without_apply = fixture.command();
    staging_without_apply.arg("--staging-dir").arg(&fixture.staging);
    fixture.run(staging_without_apply).assert_failure();

    assert_eq!(fixture.state_bytes(), state);
    assert_eq!(
        fs::read(fixture.local.join("local.txt")).unwrap(),
        b"must remain local"
    );
    assert!(!fixture.remote.join("local.txt").exists());
    assert!(directory_entries(&fixture.staging).is_empty());
}

#[test]
fn local_sync_stdout_failure_preserves_durable_receipt_and_reopenable_history() {
    let fixture = Fixture::new("stdout-failure");
    let contents = b"committed before the output failure\n";
    fs::write(fixture.local.join("new.txt"), contents).unwrap();
    let mut command = fixture.command();
    command
        .args(["--initialize", "--apply", "--staging-dir"])
        .arg(&fixture.staging);

    let invocation = fixture.run_with_stdout(command, Some(Path::new("/dev/full")));
    invocation.assert_failure();
    assert_eq!(invocation.output.status.code(), Some(ExitCode::RUNTIME_ERROR));
    let error: Value = serde_json::from_slice(&invocation.output.stderr).unwrap_or_else(|error| {
        panic!(
            "expected a structured stderr error with the observed receipt: {error}\n{}",
            invocation.describe()
        )
    });
    assert_eq!(error["type"], "output_error", "{error:#}");
    assert_eq!(error["exit_code"], ExitCode::RUNTIME_ERROR, "{error:#}");
    let observed = &error["context"]["receipt"];
    assert_durable(observed, &fixture, 1);
    let action = receipt(observed, "new.txt");
    assert_eq!(action["state"], "published");
    assert_eq!(action["durable"], true);
    assert_eq!(action["bytes_written"], contents.len());
    for root in [&fixture.local, &fixture.remote] {
        assert_eq!(fs::read(root.join("new.txt")).unwrap(), contents);
    }
    let state = fixture.state_bytes();

    // A new process must see the committed baseline, even though the applying
    // process returned an output error. A retry must not infer absent effects.
    let reopened = fixture.plan(&[]).success_json();
    assert_plan(&reopened, &fixture, 1);
    assert_eq!(decisions(&reopened).len(), 1);
    assert_eq!(
        decision(&reopened, "new.txt").action,
        BidirectionalSyncAction::Keep
    );
    assert_eq!(fixture.state_bytes(), state);
}
