//! Real-process reviewed mirror and retained-original recovery journeys.
//!
//! Serves asupersync-bi2462.67/.68. Fixtures, receipts and original bytes are
//! retained. No test removes files. Run through RCH with --features cli and
//! --test atp_cli_journey local_mirror:: -- --nocapture.

use asupersync::atp::sync::native::{NativeDirectoryLimits, NativeDirectoryRecoverySource};
use asupersync::cli::ExitCode;
use serde_json::Value;
use std::cell::Cell;
use std::fs::{self, DirBuilder, File};
use std::io;
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_asupersync");

struct Fixture {
    root: PathBuf,
    source: PathBuf,
    destination: PathBuf,
    staging: PathBuf,
    calls: Cell<u64>,
}

fn private_dir(path: &Path) {
    DirBuilder::new().mode(0o700).create(path).unwrap();
}

impl Fixture {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let root = loop {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let candidate = parent.join(format!("asupersync-cli-mirror-{label}-{}-{id}", std::process::id()));
            match DirBuilder::new().mode(0o700).create(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("retained fixture {}: {error}", candidate.display()),
            }
        };
        let fixture = Self {
            source: root.join("source"),
            destination: root.join("destination"),
            staging: root.join("staging"),
            root,
            calls: Cell::new(0),
        };
        for path in [&fixture.source, &fixture.destination, &fixture.staging] {
            private_dir(path);
        }
        eprintln!("scenario=local-mirror-{label} retained={}", fixture.root.display());
        fixture
    }

    fn populated(label: &str) -> Self {
        let fixture = Self::new(label);
        fs::write(fixture.source.join("shared.txt"), b"source version").unwrap();
        fs::write(fixture.source.join("new.bin"), b"\0new\xffbytes").unwrap();
        fs::write(fixture.destination.join("shared.txt"), b"retained old version").unwrap();
        fs::write(fixture.destination.join("extra.txt"), b"retained destination-only bytes").unwrap();
        fixture
    }

    fn command(&self) -> Command {
        let mut command = Command::new(BIN);
        command.args(["--format", "json", "atp", "local-mirror"])
            .arg(&self.source).arg(&self.destination).stdin(Stdio::null());
        command
    }

    fn preview(&self) -> Invocation {
        self.run(self.command())
    }

    fn apply(&self, review_id: &str, grants: &[&str]) -> Invocation {
        let mut command = self.command();
        command.args(["--apply", review_id, "--staging-dir"])
            .arg(&self.staging).args(grants);
        self.run(command)
    }

    fn run(&self, command: Command) -> Invocation {
        self.run_with_stdout(command, None)
    }

    fn run_with_stdout(&self, mut command: Command, stdout_override: Option<&Path>) -> Invocation {
        let sequence = self.calls.get();
        self.calls.set(sequence + 1);
        let stdout_path = self.root.join(format!("invocation-{sequence}.stdout.json"));
        let stderr_path = self.root.join(format!("invocation-{sequence}.stderr.json"));
        let args: Vec<_> = command.get_args().map(|arg| arg.to_string_lossy().into_owned()).collect();
        fs::write(self.root.join(format!("invocation-{sequence}.command.json")),
            serde_json::to_vec_pretty(&serde_json::json!({ "binary": BIN, "args": args })).unwrap()).unwrap();
        let stdout = if let Some(path) = stdout_override {
            File::options().write(true).open(path).unwrap()
        } else {
            File::create_new(&stdout_path).unwrap()
        };
        command.stdout(stdout).stderr(File::create_new(&stderr_path).unwrap());
        let mut child = OwnedChild(command.spawn().expect("run actual Cargo-built CLI"));
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.0.kill();
                let _ = child.0.wait();
                panic!("CLI watchdog expired; retained={}", self.root.display());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        Invocation {
            status,
            stdout: if stdout_override.is_some() { Vec::new() } else { fs::read(&stdout_path).unwrap() },
            stderr: fs::read(&stderr_path).unwrap(),
            stdout_path,
            stderr_path,
        }
    }
}

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

struct Invocation {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl Invocation {
    fn diagnostic(&self) -> String {
        format!("status={} stdout={} stderr={}\n{}\n{}", self.status,
            self.stdout_path.display(), self.stderr_path.display(),
            String::from_utf8_lossy(&self.stdout), String::from_utf8_lossy(&self.stderr))
    }

    fn failed(&self) {
        assert!(self.status.code().is_some_and(|code| code != 0), "{}", self.diagnostic());
        assert!(!self.stderr.is_empty(), "{}", self.diagnostic());
    }

    fn json(&self, success: bool) -> Value {
        if success {
            assert!(self.status.success(), "{}", self.diagnostic());
        } else {
            self.failed();
        }
        serde_json::from_slice(&self.stdout)
            .unwrap_or_else(|error| panic!("single actual JSON receipt: {error}\n{}", self.diagnostic()))
    }
}

fn assert_mirror_header(report: &Value, fixture: &Fixture, mode: &str) {
    assert_eq!(report["schema_version"], 1, "{report:#}");
    assert_eq!(report["command"], "atp.local-mirror", "{report:#}");
    assert_eq!(report["mode"], mode, "{report:#}");
    assert_eq!(report["source_root"].as_str(), fixture.source.to_str());
    assert_eq!(report["destination_root"].as_str(), fixture.destination.to_str());
    assert_eq!(report["runtime_quiescent"], true, "{report:#}");
    assert_eq!(report["runtime_stopped"], true, "{report:#}");
    for field in ["review_id", "plan_id"] {
        assert_eq!(report[field].as_str().unwrap().len(), 64, "{report:#}");
    }
}

fn assert_originals(fixture: &Fixture) {
    assert_eq!(fs::read(fixture.source.join("shared.txt")).unwrap(), b"source version");
    assert_eq!(fs::read(fixture.source.join("new.bin")).unwrap(), b"\0new\xffbytes");
    assert_eq!(fs::read(fixture.destination.join("shared.txt")).unwrap(), b"retained old version");
    assert_eq!(fs::read(fixture.destination.join("extra.txt")).unwrap(), b"retained destination-only bytes");
    assert!(!fixture.destination.join("new.bin").exists());
}

fn assert_unstarted(report: &Value) {
    assert_eq!(report["result"]["complete"], false, "{report:#}");
    assert_eq!(report["result"]["dry_run"], false, "{report:#}");
    assert!(report["application_error"].is_null(), "{report:#}");
    assert!(report["result"]["failure"].is_string(), "{report:#}");
    assert!(report["result"]["staging_directory"].is_null(), "{report:#}");
    let actions = report["result"]["actions"].as_array().unwrap();
    assert!(!actions.is_empty(), "the refused plan must contain actual actions");
    for action in actions {
        assert_eq!(action["state"], "not_started", "{report:#}");
        assert_eq!(action["bytes_written"], 0, "{report:#}");
        assert_eq!(action["durable"], false, "{report:#}");
        assert!(action["staged_path"].is_null() && action["quarantine_path"].is_null());
    }
}

const ALL_GRANTS: &[&str] = &["--allow-overwrite", "--allow-permission-change", "--allow-delete"];

#[test]
fn local_mirror_preview_is_stable_and_preserves_both_trees() {
    let fixture = Fixture::populated("review");
    let first = fixture.preview().json(true);
    let second = fixture.preview().json(true);
    assert_mirror_header(&first, &fixture, "plan");
    assert_mirror_header(&second, &fixture, "plan");
    assert_eq!(first["review_id"], second["review_id"]);
    assert_ne!(first["plan_id"], second["plan_id"], "different processes require fresh recovery identities");
    assert_eq!(first["decisions"], second["decisions"]);
    assert_eq!(first["has_destructive_actions"], true);
    assert!(first["result"].is_null());
    let decisions = first["decisions"].as_array().unwrap();
    assert_eq!(decisions.len(), 3);
    assert!(decisions.iter().any(|entry| entry["path"] == "extra.txt" && entry["action"] == "DeleteRemote"));
    assert_originals(&fixture);
    assert_eq!(fs::read_dir(&fixture.staging).unwrap().count(), 0);
}

#[test]
fn local_mirror_applies_only_destination_changes_and_retains_original_bytes() {
    let fixture = Fixture::populated("apply");
    let preview = fixture.preview().json(true);
    let applied = fixture.apply(preview["review_id"].as_str().unwrap(), ALL_GRANTS).json(true);
    assert_mirror_header(&applied, &fixture, "apply");
    assert_eq!(applied["review_id"], preview["review_id"]);
    assert_eq!(applied["result"]["complete"], true);
    assert_eq!(applied["result"]["dry_run"], false);
    assert!(applied["result"]["failure"].is_null());
    assert!(applied["application_error"].is_null());
    for root in [&fixture.source, &fixture.destination] {
        assert_eq!(fs::read(root.join("shared.txt")).unwrap(), b"source version");
        assert_eq!(fs::read(root.join("new.bin")).unwrap(), b"\0new\xffbytes");
        assert_eq!(fs::read_dir(root).unwrap().count(), 2);
    }
    for (path, original, state) in [
        ("shared.txt", &b"retained old version"[..], "published"),
        ("extra.txt", &b"retained destination-only bytes"[..], "quarantined"),
    ] {
        let action = applied["result"]["actions"].as_array().unwrap().iter()
            .find(|entry| entry["path"] == path).unwrap();
        assert_eq!(action["state"], state);
        assert_eq!(action["durable"], true);
        let quarantine = Path::new(action["quarantine_path"].as_str().unwrap());
        assert!(quarantine.starts_with(&fixture.staging));
        assert_eq!(fs::read(quarantine).unwrap(), original);
    }
    assert_eq!(applied["result"]["recovery_source"]["plan_id"], applied["plan_id"]);
    let again = fixture.preview().json(true);
    assert!(again["decisions"].as_array().unwrap().iter().all(|entry| entry["action"] == "Keep"));
}

#[test]
fn local_mirror_stale_and_foreign_review_ids_refuse_before_any_effect() {
    let fixture = Fixture::populated("stale");
    let other = Fixture::populated("foreign");
    let preview = fixture.preview().json(true);
    let foreign = other.preview().json(true);
    let refused = fixture.apply(foreign["review_id"].as_str().unwrap(), ALL_GRANTS).json(false);
    assert_mirror_header(&refused, &fixture, "apply");
    assert!(refused["result"].is_null());
    assert!(refused["application_error"].is_string());
    assert_originals(&fixture);

    fs::write(fixture.destination.join("shared.txt"), b"concurrent destination edit").unwrap();
    let stale = fixture.apply(preview["review_id"].as_str().unwrap(), ALL_GRANTS).json(false);
    assert_mirror_header(&stale, &fixture, "apply");
    assert_ne!(stale["review_id"], preview["review_id"]);
    assert!(stale["result"].is_null());
    assert!(stale["application_error"].is_string());
    assert_eq!(fs::read(fixture.destination.join("shared.txt")).unwrap(), b"concurrent destination edit");
    assert_eq!(fs::read(fixture.destination.join("extra.txt")).unwrap(), b"retained destination-only bytes");
    assert!(!fixture.destination.join("new.bin").exists());
    assert_eq!(fs::read_dir(&fixture.staging).unwrap().count(), 0);
}

#[test]
fn local_mirror_requires_each_destructive_grant_before_copying_anything() {
    let fixture = Fixture::populated("grants");
    let preview = fixture.preview().json(true);
    for grants in [
        &[][..],
        &["--allow-overwrite"][..],
        &["--allow-permission-change"][..],
        &["--allow-delete"][..],
        &["--allow-overwrite", "--allow-permission-change"][..],
        &["--allow-overwrite", "--allow-delete"][..],
        &["--allow-permission-change", "--allow-delete"][..],
    ] {
        let refused = fixture.apply(preview["review_id"].as_str().unwrap(), grants).json(false);
        assert_mirror_header(&refused, &fixture, "apply");
        assert_unstarted(&refused);
        assert_originals(&fixture);
        assert_eq!(fs::read_dir(&fixture.staging).unwrap().count(), 0);
    }
}

#[test]
fn local_mirror_root_replacement_invalidates_review_and_symlinks_are_refused() {
    let fixture = Fixture::populated("root-identity");
    let preview = fixture.preview().json(true);
    let original = fixture.root.join("retained-original-root");
    fs::rename(&fixture.destination, &original).unwrap();
    private_dir(&fixture.destination);
    fs::copy(original.join("shared.txt"), fixture.destination.join("shared.txt")).unwrap();
    fs::copy(original.join("extra.txt"), fixture.destination.join("extra.txt")).unwrap();
    let refused = fixture.apply(preview["review_id"].as_str().unwrap(), ALL_GRANTS).json(false);
    assert_mirror_header(&refused, &fixture, "apply");
    assert!(refused["result"].is_null());
    assert!(refused["application_error"].is_string());
    assert_ne!(refused["review_id"], preview["review_id"]);
    assert_originals(&fixture);
    assert_eq!(fs::read(original.join("shared.txt")).unwrap(), b"retained old version");

    let outside = fixture.root.join("outside.txt");
    fs::write(&outside, b"must remain outside").unwrap();
    symlink(&outside, fixture.source.join("forbidden-link")).unwrap();
    fixture.preview().failed();
    assert_eq!(fs::read(outside).unwrap(), b"must remain outside");
    assert_eq!(fs::read_dir(&fixture.staging).unwrap().count(), 0);
}

#[test]
fn local_mirror_application_requires_an_explicit_review_and_staging() {
    let fixture = Fixture::populated("argument-authority");
    for flag in ["--allow-delete", "--allow-overwrite", "--allow-permission-change"] {
        let mut command = fixture.command();
        command.arg(flag);
        fixture.run(command).failed();
    }
    let preview = fixture.preview().json(true);
    let mut missing_staging = fixture.command();
    missing_staging.args(["--apply", preview["review_id"].as_str().unwrap()]);
    fixture.run(missing_staging).failed();
    let mut missing_review = fixture.command();
    missing_review.arg("--staging-dir").arg(&fixture.staging);
    fixture.run(missing_review).failed();
    assert_originals(&fixture);
    assert_eq!(fs::read_dir(&fixture.staging).unwrap().count(), 0);
}

#[test]
fn local_mirror_stdout_failure_retains_actual_effects_and_recovery_receipt_on_stderr() {
    let fixture = Fixture::populated("stdout-failure");
    let preview = fixture.preview().json(true);
    let mut command = fixture.command();
    command
        .args(["--apply", preview["review_id"].as_str().unwrap(), "--staging-dir"])
        .arg(&fixture.staging)
        .args(ALL_GRANTS);
    let invocation = fixture.run_with_stdout(command, Some(Path::new("/dev/full")));
    invocation.failed();
    assert_eq!(invocation.status.code(), Some(ExitCode::RUNTIME_ERROR));
    let error: Value = serde_json::from_slice(&invocation.stderr).unwrap_or_else(|error| {
        panic!("expected a structured stderr receipt: {error}\n{}", invocation.diagnostic())
    });
    assert_eq!(error["type"], "output_error", "{error:#}");
    assert_eq!(error["exit_code"], ExitCode::RUNTIME_ERROR, "{error:#}");
    let observed = &error["context"]["receipt"];
    assert_mirror_header(observed, &fixture, "apply");
    assert_eq!(observed["review_id"], preview["review_id"]);
    assert_eq!(observed["result"]["complete"], true, "{observed:#}");
    assert_eq!(observed["result"]["dry_run"], false, "{observed:#}");
    assert!(observed["application_error"].is_null(), "{observed:#}");
    assert!(observed["result"]["failure"].is_null(), "{observed:#}");

    // Output failure follows the real filesystem effects. It must neither
    // conceal the committed mirror nor lose the associations needed to recover.
    for root in [&fixture.source, &fixture.destination] {
        assert_eq!(fs::read(root.join("shared.txt")).unwrap(), b"source version");
        assert_eq!(fs::read(root.join("new.bin")).unwrap(), b"\0new\xffbytes");
        assert_eq!(fs::read_dir(root).unwrap().count(), 2);
    }
    for (path, original, state) in [
        ("shared.txt", &b"retained old version"[..], "published"),
        ("extra.txt", &b"retained destination-only bytes"[..], "quarantined"),
    ] {
        let action = observed["result"]["actions"].as_array().unwrap().iter()
            .find(|entry| entry["path"] == path).unwrap();
        assert_eq!(action["state"], state, "{observed:#}");
        assert_eq!(action["durable"], true, "{observed:#}");
        let quarantine = Path::new(action["quarantine_path"].as_str().unwrap());
        assert!(quarantine.starts_with(&fixture.staging));
        assert_eq!(fs::read(quarantine).unwrap(), original);
    }
    let encoded = serde_json::to_vec(&observed["result"]["recovery_source"]).unwrap();
    let recovery = NativeDirectoryRecoverySource::from_json_slice(
        &encoded, encoded.len(), NativeDirectoryLimits::default(),
    ).expect("stderr preserves canonical associations for all original action indices");
    assert_eq!(Some(recovery.plan_id.as_str()), observed["plan_id"].as_str());
    assert_eq!(recovery.actions.len(), 3);
    assert_eq!(recovery.actions.iter().filter(|action| action.quarantine_path.is_some()).count(), 2);

    let fresh = fixture.preview().json(true);
    assert_mirror_header(&fresh, &fixture, "plan");
    assert_eq!(fresh["decisions"].as_array().unwrap().len(), 2);
    assert!(fresh["decisions"].as_array().unwrap().iter().all(|entry| entry["action"] == "Keep"));
    assert_eq!(fs::read_dir(&fixture.staging).unwrap().count(), 1);
}
