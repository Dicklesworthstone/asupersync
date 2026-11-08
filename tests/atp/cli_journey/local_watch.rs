//! Live-process local watch journeys for asupersync-bi2462.71.
//!
//! Commands, output, source versions, history, and quarantined originals stay
//! in private retained fixtures. No test removes files or fixture directories.
//! Real flushed review/application events establish readiness before edits.
//!
//! Replay: `RCH_REQUIRE_REMOTE=1 rch exec -- env
//! CARGO_TARGET_DIR=/tmp/rch_target_atp_local_watch cargo test -p asupersync
//! --features cli --test atp_cli_journey local_watch:: -- --nocapture`.

use asupersync::atp::sync::{
    BidirectionalConflict, BidirectionalSyncAction, BidirectionalSyncDecision,
};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::Value;
use std::cell::Cell;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, File};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const ASUPERSYNC_BIN: &str = env!("CARGO_BIN_EXE_asupersync");
const EVENT_LIMIT: Duration = Duration::from_secs(30);
const EXIT_LIMIT: Duration = Duration::from_secs(20);
const FAST_POLL: [&str; 4] = ["--poll-interval-ms", "10", "--settle-observations", "1"];
const ALL_GRANTS: [&str; 3] = [
    "--allow-overwrite",
    "--allow-permission-change",
    "--allow-delete",
];

struct Fixture {
    root: PathBuf,
    local: PathBuf,
    remote: PathBuf,
    state: PathBuf,
    staging: PathBuf,
    next_command: Cell<u64>,
    next_edit: Cell<u64>,
}

impl Fixture {
    fn new(scenario: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let root = loop {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let candidate = parent.join(format!(
                "asupersync-cli-local-watch-{scenario}-{}-{sequence}",
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
            next_command: Cell::new(0),
            next_edit: Cell::new(0),
        };
        for path in [
            &fixture.local,
            &fixture.remote,
            &fixture.state,
            &fixture.staging,
        ] {
            private_directory(path);
        }
        eprintln!(
            "local-watch scenario={scenario} retained={}",
            fixture.root.display()
        );
        fixture
    }

    fn command(&self) -> Command {
        let mut command = Command::new(ASUPERSYNC_BIN);
        command
            .args(["--format", "stream-json", "atp", "local-watch"])
            .arg(&self.local)
            .arg(&self.remote)
            .arg("--state-dir")
            .arg(&self.state)
            .stdin(Stdio::null());
        command
    }

    fn preview(&self, initialize: bool, reviews: u64) -> Command {
        let mut command = self.command();
        command
            .args(FAST_POLL)
            .arg("--max-reviews")
            .arg(reviews.to_string());
        if initialize {
            command.arg("--initialize");
        }
        command
    }

    fn apply(&self, initialize: bool, applications: u64, grants: &[&str]) -> Command {
        let mut command = self.command();
        command
            .args(FAST_POLL)
            .arg("--apply-changes")
            .arg("--staging-dir")
            .arg(&self.staging)
            .arg("--max-applications")
            .arg(applications.to_string())
            .args(grants);
        if initialize {
            command.arg("--initialize");
        }
        command
    }

    fn start(&self, mut command: Command) -> LiveProcess {
        let sequence = self.next_command.get();
        self.next_command.set(sequence + 1);
        let stdout_path = self.root.join(format!("command-{sequence}.stdout.jsonl"));
        let stderr_path = self.root.join(format!("command-{sequence}.stderr.log"));
        let arguments: Vec<_> = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        fs::write(
            self.root.join(format!("command-{sequence}.command.json")),
            serde_json::to_vec_pretty(&serde_json::json!({
                "binary": ASUPERSYNC_BIN,
                "arguments": arguments,
            }))
            .unwrap(),
        )
        .unwrap();
        let mut retained_stdout = File::create_new(&stdout_path).unwrap();
        command
            .stdout(Stdio::piped())
            .stderr(File::create_new(&stderr_path).unwrap());
        let mut child = ReapedChild(Some(command.spawn().expect("start Cargo-built watch CLI")));
        let stdout = child.0.as_mut().unwrap().stdout.take().unwrap();
        let (send, receive) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = match line {
                    Ok(line) => line,
                    Err(error) => {
                        let _ = send.send(Err(error.to_string()));
                        return;
                    }
                };
                if let Err(error) =
                    writeln!(retained_stdout, "{line}").and_then(|()| retained_stdout.flush())
                {
                    let _ = send.send(Err(error.to_string()));
                    return;
                }
                if send.send(Ok(line)).is_err() {
                    return;
                }
            }
        });
        LiveProcess {
            child,
            events: receive,
            reader: Some(reader),
            stdout_path,
            stderr_path,
            artifacts: self.root.clone(),
        }
    }

    fn run(&self, command: Command) -> Invocation {
        self.start(command).finish()
    }

    fn state_bytes(&self) -> Vec<u8> {
        fs::read(self.state.join("current.state")).expect("durable common history")
    }

    fn establish(&self) {
        let invocation = self.run(self.apply(true, 1, &[]));
        invocation.assert_success();
        let events = invocation.json_events();
        assert_durable(only_event(&events, "application"), 1);
        assert_stopped(only_event(&events, "stopped"), "max_applications", 1, 1, 1);
    }

    /// Publish a complete external file in one rename so a concurrent scan
    /// cannot see a partially written body. Retain any previous source bytes
    /// outside the watched roots for diagnostics before replacing that file.
    fn publish_external_edit(&self, destination: &Path, contents: &[u8]) {
        let sequence = self.next_edit.get();
        self.next_edit.set(sequence + 1);
        if destination.exists() {
            fs::write(
                self.root.join(format!("external-edit-{sequence}.before")),
                fs::read(destination).unwrap(),
            )
            .unwrap();
        }
        let staged = self.root.join(format!("external-edit-{sequence}.new"));
        fs::write(&staged, contents).unwrap();
        fs::rename(staged, destination).unwrap();
    }
}

struct ReapedChild(Option<Child>);

impl ReapedChild {
    fn wait(&mut self) -> (ExitStatus, bool) {
        let deadline = Instant::now() + EXIT_LIMIT;
        loop {
            if let Some(status) = self.0.as_mut().unwrap().try_wait().unwrap() {
                self.0.take();
                return (status, false);
            }
            if Instant::now() >= deadline {
                let mut child = self.0.take().unwrap();
                let _ = child.kill();
                return (child.wait().expect("reap timed-out watch"), true);
            }
            // Only bounds process exit. Event receipt establishes readiness.
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.0.take() {
            if !matches!(child.try_wait(), Ok(Some(_))) {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

impl Drop for ReapedChild {
    fn drop(&mut self) {
        self.stop();
    }
}

struct LiveProcess {
    child: ReapedChild,
    events: mpsc::Receiver<Result<String, String>>,
    reader: Option<thread::JoinHandle<()>>,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    artifacts: PathBuf,
}

impl LiveProcess {
    fn next_event(&self, wanted: &str) -> Value {
        let deadline = Instant::now() + EVENT_LIMIT;
        loop {
            let line = self
                .events
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|error| {
                    panic!(
                        "missing live {wanted} event: {error}; retained={} stderr={}",
                        self.artifacts.display(),
                        String::from_utf8_lossy(&fs::read(&self.stderr_path).unwrap())
                    )
                })
                .expect("read and retain live output");
            let event: Value = serde_json::from_str(&line)
                .unwrap_or_else(|error| panic!("invalid live event {line:?}: {error}"));
            assert_header(&event);
            if event["event"] == wanted {
                return event;
            }
            assert_ne!(
                event["event"], "stopped",
                "watch stopped before {wanted}: {event:#}"
            );
        }
    }

    fn signal(&self, signal: Signal) {
        let id = self.child.0.as_ref().unwrap().id();
        let pid = Pid::from_raw(i32::try_from(id).unwrap());
        kill(pid, signal).expect("signal the owned local-watch child");
    }

    fn finish(mut self) -> Invocation {
        let (status, timed_out) = self.child.wait();
        self.reader
            .take()
            .unwrap()
            .join()
            .expect("retire stdout reader");
        Invocation {
            status,
            timed_out,
            stdout: fs::read(&self.stdout_path).unwrap(),
            stderr: fs::read(&self.stderr_path).unwrap(),
            artifacts: self.artifacts.clone(),
        }
    }
}

impl Drop for LiveProcess {
    fn drop(&mut self) {
        self.child.stop();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

struct Invocation {
    status: ExitStatus,
    timed_out: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    artifacts: PathBuf,
}

impl Invocation {
    fn describe(&self) -> String {
        format!(
            "status={} timed_out={} retained={}\nstdout:\n{}\nstderr:\n{}",
            self.status,
            self.timed_out,
            self.artifacts.display(),
            String::from_utf8_lossy(&self.stdout),
            String::from_utf8_lossy(&self.stderr)
        )
    }

    fn assert_success(&self) {
        assert!(
            !self.timed_out && self.status.success(),
            "watch failed: {}",
            self.describe()
        );
    }

    fn assert_failure(&self) {
        assert!(
            !self.timed_out,
            "watch failed to retire: {}",
            self.describe()
        );
        assert!(
            self.status.code().is_some_and(|code| code != 0),
            "expected normal nonzero exit: {}",
            self.describe()
        );
        assert!(
            !self.stderr.is_empty(),
            "missing diagnostic: {}",
            self.describe()
        );
    }

    fn json_events(&self) -> Vec<Value> {
        std::str::from_utf8(&self.stdout)
            .expect("UTF-8 JSON stream")
            .lines()
            .map(|line| {
                let event: Value = serde_json::from_str(line).unwrap_or_else(|error| {
                    panic!("invalid event line {line:?}: {error}; {}", self.describe())
                });
                assert_header(&event);
                event
            })
            .collect()
    }
}

fn private_directory(path: &Path) {
    DirBuilder::new().mode(0o700).create(path).unwrap();
}

fn entries(path: &Path) -> Vec<OsString> {
    let mut entries: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    entries.sort();
    entries
}

fn assert_header(event: &Value) {
    assert_eq!(event["schema_version"], 1, "{event:#}");
    assert_eq!(event["command"], "atp.local-watch", "{event:#}");
}

fn matching<'a>(events: &'a [Value], name: &str) -> Vec<&'a Value> {
    events
        .iter()
        .filter(|event| event["event"] == name)
        .collect()
}

fn only_event<'a>(events: &'a [Value], name: &str) -> &'a Value {
    let matches = matching(events, name);
    assert_eq!(matches.len(), 1, "expected one {name}: {events:#?}");
    matches[0]
}

fn assert_stopped(event: &Value, reason: &str, reviews: u64, applications: u64, generation: u64) {
    assert_eq!(event["event"], "stopped", "{event:#}");
    assert_eq!(event["reason"], reason, "{event:#}");
    assert_eq!(event["reviews"], reviews, "{event:#}");
    assert_eq!(event["applications"], applications, "{event:#}");
    assert_eq!(event["baseline_generation"], generation, "{event:#}");
    assert_eq!(event["runtime_quiescent"], true, "{event:#}");
    assert_eq!(event["runtime_stopped"], true, "{event:#}");
}

fn assert_durable(event: &Value, generation: u64) {
    assert_eq!(event["event"], "application", "{event:#}");
    assert!(event["application_error"].is_null(), "{event:#}");
    let result = &event["result"];
    assert_eq!(result["plan_id"], event["plan_id"], "{event:#}");
    assert_eq!(result["complete"], true, "{event:#}");
    assert_eq!(result["dry_run"], false, "{event:#}");
    assert_eq!(result["baseline_generation"], generation, "{event:#}");
    assert_eq!(result["publication"]["state"], "durable", "{event:#}");
    assert_eq!(result["publication"]["generation"], generation, "{event:#}");
    assert!(result["failure"].is_null(), "{event:#}");
    assert!(result["persistence_failure"].is_null(), "{event:#}");
}

fn assert_no_effects(event: &Value, generation: u64) {
    assert_eq!(event["event"], "application", "{event:#}");
    let result = &event["result"];
    assert_eq!(result["complete"], false, "{event:#}");
    assert_eq!(result["dry_run"], false, "{event:#}");
    assert_eq!(result["baseline_generation"], generation, "{event:#}");
    assert_eq!(result["publication"]["state"], "unchanged", "{event:#}");
    assert!(
        result["failure"]
            .as_str()
            .is_some_and(|error| !error.is_empty())
    );
    assert!(result["persistence_failure"].is_null(), "{event:#}");
    assert!(result["staging_directory"].is_null(), "{event:#}");
    assert_eq!(result["plan_id"], event["plan_id"], "{event:#}");
    let actions = result["actions"]
        .as_array()
        .expect("actual action receipts");
    assert!(
        !actions.is_empty(),
        "a refused plan must retain its actions"
    );
    for action in actions {
        assert_eq!(action["state"], "not_started", "{event:#}");
        assert_eq!(action["bytes_written"], 0, "{event:#}");
        assert_eq!(action["durable"], false, "{event:#}");
        assert!(action["staged_path"].is_null(), "{event:#}");
        assert!(action["quarantine_path"].is_null(), "{event:#}");
    }
}

fn decisions(event: &Value) -> Vec<BidirectionalSyncDecision> {
    serde_json::from_value(event["decisions"].clone()).expect("canonical native decisions")
}

fn decision(event: &Value, path: &str) -> BidirectionalSyncDecision {
    decisions(event)
        .into_iter()
        .find(|decision| decision.path.as_str() == path)
        .unwrap_or_else(|| panic!("no decision for {path}: {event:#}"))
}

fn action<'a>(event: &'a Value, path: &str) -> &'a Value {
    event["result"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["path"] == path)
        .unwrap_or_else(|| panic!("no action for {path}: {event:#}"))
}

#[test]
fn local_watch_streams_a_live_preview_then_observes_external_edit_without_applying() {
    let fixture = Fixture::new("live-preview");
    fs::write(fixture.local.join("first.bin"), b"\0first\xff").unwrap();
    let watch = fixture.start(fixture.preview(true, 2));
    let first = watch.next_event("review");
    assert_eq!(first["review"], 1);
    assert_eq!(first["mode"], "preview");
    assert_eq!(first["baseline_generation"], 0);
    assert_eq!(
        decision(&first, "first.bin").action,
        BidirectionalSyncAction::CopyLocalToRemote
    );
    assert!(entries(&fixture.remote).is_empty());
    let state = fixture.state_bytes();

    fixture.publish_external_edit(&fixture.local.join("added.bin"), b"second complete version");
    let second = watch.next_event("review");
    assert_eq!(second["review"], 2);
    assert_ne!(second["plan_id"], first["plan_id"]);
    assert_eq!(
        decision(&second, "added.bin").action,
        BidirectionalSyncAction::CopyLocalToRemote
    );
    assert_eq!(
        decision(&second, "first.bin").action,
        BidirectionalSyncAction::CopyLocalToRemote
    );
    let invocation = watch.finish();
    invocation.assert_success();
    let events = invocation.json_events();
    assert_eq!(matching(&events, "review").len(), 2);
    assert!(matching(&events, "application").is_empty());
    assert_stopped(only_event(&events, "stopped"), "max_reviews", 2, 0, 0);
    assert!(entries(&fixture.remote).is_empty());
    assert!(entries(&fixture.staging).is_empty());
    assert_eq!(fixture.state_bytes(), state);
    assert_eq!(
        fs::read(fixture.local.join("first.bin")).unwrap(),
        b"\0first\xff"
    );
    assert_eq!(
        fs::read(fixture.local.join("added.bin")).unwrap(),
        b"second complete version"
    );
}

#[test]
fn local_watch_applies_live_edits_retains_original_inode_and_reopens_durable_history() {
    let fixture = Fixture::new("live-apply-restart");
    private_directory(&fixture.local.join("nested"));
    let original = b"\0local original\xff\n";
    let updated = b"\0remote replacement\xfe\n";
    fs::write(fixture.local.join("nested/shared.bin"), original).unwrap();
    fs::write(fixture.remote.join("peer.txt"), b"peer original").unwrap();
    let watch = fixture.start(fixture.apply(true, 2, &ALL_GRANTS));
    let first = watch.next_event("application");
    assert_eq!(first["application"], 1);
    assert_durable(&first, 1);
    for root in [&fixture.local, &fixture.remote] {
        assert_eq!(fs::read(root.join("nested/shared.bin")).unwrap(), original);
        assert_eq!(fs::read(root.join("peer.txt")).unwrap(), b"peer original");
    }
    let old_inode = fs::metadata(fixture.local.join("nested/shared.bin"))
        .unwrap()
        .ino();
    let first_state = fixture.state_bytes();
    fixture.publish_external_edit(&fixture.remote.join("nested/shared.bin"), updated);
    let second = watch.next_event("application");
    assert_eq!(second["application"], 2);
    assert_durable(&second, 2);
    assert_ne!(second["plan_id"], first["plan_id"]);
    let replaced = action(&second, "nested/shared.bin");
    assert_eq!(replaced["state"], "published");
    assert_eq!(replaced["bytes_written"], updated.len());
    assert_eq!(replaced["durable"], true);
    let quarantine = PathBuf::from(replaced["quarantine_path"].as_str().unwrap());
    assert!(quarantine.starts_with(&fixture.staging));
    assert_eq!(fs::read(&quarantine).unwrap(), original);
    assert_eq!(fs::metadata(&quarantine).unwrap().ino(), old_inode);
    let invocation = watch.finish();
    invocation.assert_success();
    let events = invocation.json_events();
    assert_eq!(matching(&events, "application").len(), 2);
    assert_stopped(only_event(&events, "stopped"), "max_applications", 2, 2, 2);
    for root in [&fixture.local, &fixture.remote] {
        assert_eq!(fs::read(root.join("nested/shared.bin")).unwrap(), updated);
        assert_eq!(fs::read(root.join("peer.txt")).unwrap(), b"peer original");
    }
    let state = fixture.state_bytes();
    assert_ne!(state, first_state);

    let reopened = fixture.run(fixture.preview(false, 1));
    reopened.assert_success();
    let events = reopened.json_events();
    let review = only_event(&events, "review");
    assert_eq!(review["baseline_generation"], 2);
    assert!(
        decisions(review)
            .iter()
            .all(|decision| decision.action == BidirectionalSyncAction::Keep)
    );
    assert_stopped(only_event(&events, "stopped"), "max_reviews", 1, 0, 2);
    assert_eq!(fixture.state_bytes(), state);
    assert_eq!(fs::read(quarantine).unwrap(), original);
}

#[test]
fn local_watch_each_missing_destructive_grant_refuses_the_entire_application() {
    for missing in 0..ALL_GRANTS.len() {
        let fixture = Fixture::new(&format!("missing-grant-{missing}"));
        fs::write(
            fixture.local.join("replace.bin"),
            b"original replacement target",
        )
        .unwrap();
        fs::write(fixture.local.join("delete.bin"), b"retain deletion target").unwrap();
        fixture.establish();
        fs::write(fixture.local.join("replace.bin"), b"edited source").unwrap();
        let retained = fixture.root.join("retained-deletion-intent.bin");
        fs::rename(fixture.local.join("delete.bin"), &retained).unwrap();
        let state = fixture.state_bytes();
        let staging = entries(&fixture.staging);
        let grants: Vec<_> = ALL_GRANTS
            .iter()
            .enumerate()
            .filter_map(|(index, grant)| (index != missing).then_some(*grant))
            .collect();
        let invocation = fixture.run(fixture.apply(false, 2, &grants));
        invocation.assert_failure();
        let events = invocation.json_events();
        let review = only_event(&events, "review");
        assert_eq!(review["has_conflicts"], false);
        assert_eq!(review["has_destructive_actions"], true);
        assert_eq!(
            decision(review, "replace.bin").action,
            BidirectionalSyncAction::CopyLocalToRemote
        );
        assert_eq!(
            decision(review, "delete.bin").action,
            BidirectionalSyncAction::DeleteRemote
        );
        assert_no_effects(only_event(&events, "application"), 1);
        assert_stopped(
            only_event(&events, "stopped"),
            "application_incomplete",
            1,
            1,
            1,
        );
        assert_eq!(fixture.state_bytes(), state);
        assert_eq!(entries(&fixture.staging), staging);
        assert_eq!(
            fs::read(fixture.remote.join("replace.bin")).unwrap(),
            b"original replacement target"
        );
        assert_eq!(
            fs::read(fixture.remote.join("delete.bin")).unwrap(),
            b"retain deletion target"
        );
        assert_eq!(
            fs::read(fixture.local.join("replace.bin")).unwrap(),
            b"edited source"
        );
        assert_eq!(fs::read(retained).unwrap(), b"retain deletion target");
        assert!(!fixture.local.join("delete.bin").exists());
    }
}

#[test]
fn local_watch_conflict_stops_with_real_refusal_and_keeps_unrelated_copy_unapplied() {
    let fixture = Fixture::new("conflict-stop");
    fs::write(fixture.local.join("shared.txt"), b"common version").unwrap();
    fixture.establish();
    fs::write(fixture.local.join("shared.txt"), b"local version").unwrap();
    fs::write(fixture.remote.join("shared.txt"), b"remote version").unwrap();
    fs::write(fixture.local.join("unrelated.txt"), b"must remain local").unwrap();
    let state = fixture.state_bytes();
    let staging = entries(&fixture.staging);
    let invocation = fixture.run(fixture.apply(false, 5, &ALL_GRANTS));
    invocation.assert_failure();
    let events = invocation.json_events();
    let review = only_event(&events, "review");
    assert_eq!(review["has_conflicts"], true);
    assert_eq!(
        decision(review, "shared.txt").action,
        BidirectionalSyncAction::Conflict {
            reason: BidirectionalConflict::ConcurrentModification
        }
    );
    assert_eq!(
        decision(review, "unrelated.txt").action,
        BidirectionalSyncAction::CopyLocalToRemote
    );
    assert_no_effects(only_event(&events, "application"), 1);
    assert_stopped(
        only_event(&events, "stopped"),
        "application_incomplete",
        1,
        1,
        1,
    );
    assert_eq!(
        fs::read(fixture.local.join("shared.txt")).unwrap(),
        b"local version"
    );
    assert_eq!(
        fs::read(fixture.remote.join("shared.txt")).unwrap(),
        b"remote version"
    );
    assert!(!fixture.remote.join("unrelated.txt").exists());
    assert_eq!(fixture.state_bytes(), state);
    assert_eq!(entries(&fixture.staging), staging);
}

#[test]
fn local_watch_idle_sigint_and_sigterm_drain_before_the_next_poll_and_release_history() {
    for signal in [Signal::SIGINT, Signal::SIGTERM] {
        let fixture = Fixture::new(&format!("idle-signal-{}", signal as i32));
        let mut command = fixture.command();
        command.args([
            "--initialize",
            "--poll-interval-ms",
            "60000",
            "--settle-observations",
            "1",
        ]);
        let watch = fixture.start(command);
        let review = watch.next_event("review");
        assert!(decisions(&review).is_empty());
        assert_eq!(review["baseline_generation"], 0);
        let state = fixture.state_bytes();
        watch.signal(signal);
        let invocation = watch.finish();
        invocation.assert_success();
        let events = invocation.json_events();
        let stopped = only_event(&events, "stopped");
        assert_stopped(stopped, "signal", 1, 0, 0);
        assert_eq!(stopped["signal"], signal as i32);
        assert!(stopped["failure"].is_null());
        assert!(matching(&events, "application").is_empty());
        assert!(entries(&fixture.local).is_empty());
        assert!(entries(&fixture.remote).is_empty());
        assert!(entries(&fixture.staging).is_empty());
        assert_eq!(fixture.state_bytes(), state);

        // A separate process acquires the same history lease after shutdown.
        let reopened = fixture.run(fixture.preview(false, 1));
        reopened.assert_success();
        let events = reopened.json_events();
        assert_stopped(only_event(&events, "stopped"), "max_reviews", 1, 0, 0);
        assert_eq!(fixture.state_bytes(), state);
    }
}

#[test]
fn local_watch_argument_authority_and_finite_apply_limits_refuse_before_initialization() {
    let fixture = Fixture::new("argument-bounds");
    fs::write(fixture.local.join("source.txt"), b"preserved source").unwrap();
    for flags in [
        &[][..],
        &["--max-applications", "1"][..],
        &["--staging-dir", "PLACEHOLDER"][..],
        &["--allow-overwrite"][..],
        &["--allow-permission-change"][..],
        &["--allow-delete"][..],
        &["--max-reviews", "0"][..],
        &["--poll-interval-ms", "0"][..],
        &["--poll-interval-ms", "3600001"][..],
        &["--settle-observations", "0"][..],
        &["--settle-observations", "1025"][..],
    ] {
        let mut command = fixture.command();
        command.arg("--initialize");
        if flags.is_empty() {
            command.arg("--apply-changes");
        } else if flags[0] == "--staging-dir" {
            command.arg("--staging-dir").arg(&fixture.staging);
        } else {
            command.args(flags);
        }
        fixture.run(command).assert_failure();
        assert!(entries(&fixture.state).is_empty());
        assert!(entries(&fixture.staging).is_empty());
        assert!(entries(&fixture.remote).is_empty());
    }
    for applications in [None, Some("0")] {
        let mut command = fixture.command();
        command
            .args(["--initialize", "--apply-changes", "--staging-dir"])
            .arg(&fixture.staging);
        if let Some(applications) = applications {
            command.args(["--max-applications", applications]);
        }
        fixture.run(command).assert_failure();
        assert!(entries(&fixture.state).is_empty());
        assert!(entries(&fixture.staging).is_empty());
        assert!(entries(&fixture.remote).is_empty());
    }
    assert_eq!(
        fs::read(fixture.local.join("source.txt")).unwrap(),
        b"preserved source"
    );
}

#[test]
fn local_watch_changed_tree_bounds_or_symlink_stop_observation_without_advancing_history() {
    for oversized in [false, true] {
        let fixture = Fixture::new(if oversized {
            "live-byte-bound"
        } else {
            "live-symlink"
        });
        let mut command = fixture.preview(true, 5);
        command.args(["--max-file-bytes", "8"]);
        let watch = fixture.start(command);
        let review = watch.next_event("review");
        assert!(decisions(&review).is_empty());
        let state = fixture.state_bytes();
        let outside = fixture.root.join("retained-external-input");
        fs::write(&outside, b"retained external bytes").unwrap();
        if oversized {
            fixture.publish_external_edit(&fixture.local.join("too-big.bin"), b"123456789");
        } else {
            symlink(&outside, fixture.local.join("unsupported-link")).unwrap();
        }
        let invocation = watch.finish();
        invocation.assert_failure();
        let events = invocation.json_events();
        assert_eq!(matching(&events, "review").len(), 1);
        assert!(matching(&events, "application").is_empty());
        let stopped = only_event(&events, "stopped");
        assert_stopped(stopped, "observation_failed", 1, 0, 0);
        assert!(
            stopped["failure"]
                .as_str()
                .is_some_and(|error| !error.is_empty())
        );
        assert!(entries(&fixture.remote).is_empty());
        assert!(entries(&fixture.staging).is_empty());
        assert_eq!(fixture.state_bytes(), state);
        assert_eq!(fs::read(outside).unwrap(), b"retained external bytes");
    }
}
