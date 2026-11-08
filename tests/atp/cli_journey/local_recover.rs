//! Saved-receipt recovery journeys using the parent's real CLI process fixture.
//! All command logs, receipts, roots and retained originals remain on disk.

use super::*;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

const RECOVERY_GRANTS: &[&str] = &["--allow-overwrite", "--allow-permission-change"];

impl Fixture {
    fn recovery_command(&self, receipt: &Path) -> Command {
        let mut command = Command::new(BIN);
        command
            .args(["--format", "json", "atp", "local-recover"])
            .arg(receipt)
            .arg(&self.source)
            .arg(&self.destination)
            .stdin(Stdio::null());
        command
    }

    fn recovery_preview(&self, receipt: &Path) -> Invocation {
        self.run(self.recovery_command(receipt))
    }

    fn recovery_apply(&self, receipt: &Path, review_id: &str, grants: &[&str]) -> Invocation {
        let mut command = self.recovery_command(receipt);
        command.args(["--apply", review_id]).args(grants);
        self.run(command)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct TreeEntry {
    path: PathBuf,
    device: u64,
    inode: u64,
    mode: u32,
    bytes: Option<Vec<u8>>,
}

fn tree_entries(root: &Path) -> Vec<TreeEntry> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries = Vec::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(!metadata.file_type().is_symlink(), "fixture link: {}", path.display());
        let bytes = if metadata.is_dir() {
            pending.extend(fs::read_dir(&path).unwrap().map(|entry| entry.unwrap().path()));
            None
        } else {
            assert!(metadata.is_file(), "fixture special entry: {}", path.display());
            Some(fs::read(&path).unwrap())
        };
        entries.push(TreeEntry {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            bytes,
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries
}

fn operation_trees(fixture: &Fixture) -> Vec<TreeEntry> {
    [&fixture.source, &fixture.destination, &fixture.staging]
        .into_iter()
        .flat_map(|root| tree_entries(root))
        .collect()
}

fn inode(path: &Path) -> (u64, u64) {
    let metadata = fs::metadata(path).unwrap();
    (metadata.dev(), metadata.ino())
}

fn action<'a>(report: &'a Value, path: &str) -> &'a Value {
    report["result"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["path"] == path)
        .unwrap_or_else(|| panic!("missing action {path}: {report:#}"))
}

fn entry<'a>(report: &'a Value, path: &str) -> &'a Value {
    report["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["path"] == path)
        .unwrap_or_else(|| panic!("missing recovery entry {path}: {report:#}"))
}

fn quarantine(report: &Value, path: &str) -> PathBuf {
    PathBuf::from(action(report, path)["quarantine_path"].as_str().unwrap())
}

fn applied_mirror(fixture: &Fixture) -> (Invocation, Value) {
    let preview = fixture.preview().json(true);
    let invocation = fixture.apply(preview["review_id"].as_str().unwrap(), ALL_GRANTS);
    let report = invocation.json(true);
    assert_mirror_header(&report, fixture, "apply");
    assert_eq!(report["result"]["complete"], true, "{report:#}");
    assert!(report["result"]["failure"].is_null(), "{report:#}");
    (invocation, report)
}

fn assert_recovery_header(report: &Value, fixture: &Fixture, source: &Value, mode: &str) {
    assert_eq!(report["schema_version"], 1, "{report:#}");
    assert_eq!(report["command"], "atp.local-recover", "{report:#}");
    assert_eq!(report["mode"], mode, "{report:#}");
    assert_eq!(report["content_profile"], "linux-gnu-content-only-v1", "{report:#}");
    assert_eq!(report["source_plan_id"], source["plan_id"], "{report:#}");
    assert_eq!(report["local_root"].as_str(), fixture.source.to_str());
    assert_eq!(report["remote_root"].as_str(), fixture.destination.to_str());
    assert_eq!(report["recovery_directory"], source["result"]["staging_directory"]);
    let review = report["review_id"].as_str().unwrap();
    assert_eq!(review.len(), 64, "{report:#}");
    assert!(review.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert_eq!(report["runtime_quiescent"], true, "{report:#}");
    assert_eq!(report["runtime_stopped"], true, "{report:#}");
}

fn assert_recovery_complete(report: &Value, fixture: &Fixture, source: &Value) {
    assert_recovery_header(report, fixture, source, "apply");
    assert!(report["application_error"].is_null(), "{report:#}");
    assert_eq!(report["result"]["source_plan_id"], source["plan_id"]);
    assert_eq!(report["result"]["complete"], true, "{report:#}");
    assert_eq!(report["result"]["dry_run"], false, "{report:#}");
    assert!(report["result"]["failure"].is_null(), "{report:#}");
    for action in report["result"]["actions"].as_array().unwrap() {
        assert_eq!(action["durable"], true, "{report:#}");
        assert_eq!(action["destination_root"].as_str(), fixture.destination.to_str());
        assert!(matches!(action["state"].as_str(), Some("restored" | "exchanged")));
    }
}

fn assert_populated_restored(fixture: &Fixture, mirror: &Value) {
    assert_eq!(fs::read(fixture.source.join("shared.txt")).unwrap(), b"source version");
    assert_eq!(fs::read(fixture.destination.join("shared.txt")).unwrap(), b"retained old version");
    assert_eq!(
        fs::read(fixture.destination.join("extra.txt")).unwrap(),
        b"retained destination-only bytes"
    );
    for root in [&fixture.source, &fixture.destination] {
        assert_eq!(fs::read(root.join("new.bin")).unwrap(), b"\0new\xffbytes");
    }
    assert_eq!(fs::read_dir(&fixture.source).unwrap().count(), 2);
    assert_eq!(fs::read_dir(&fixture.destination).unwrap().count(), 3);
    assert_eq!(fs::read(quarantine(mirror, "shared.txt")).unwrap(), b"source version");
    assert!(!quarantine(mirror, "extra.txt").exists());
    assert_eq!(fs::read_dir(&fixture.staging).unwrap().count(), 1);
}

fn stderr_json(invocation: &Invocation) -> Value {
    serde_json::from_slice(&invocation.stderr).unwrap_or_else(|error| {
        panic!("expected structured stderr: {error}\n{}", invocation.diagnostic())
    })
}

fn assert_prepare_refused(invocation: &Invocation) {
    invocation.failed();
    assert_eq!(invocation.status.code(), Some(ExitCode::USER_ERROR));
    assert!(invocation.stdout.is_empty(), "{}", invocation.diagnostic());
    let error = stderr_json(invocation);
    assert!(matches!(
        error["type"].as_str(),
        Some("atp_local_recover_receipt" | "atp_local_operation_refused")
    ), "{error:#}");
    assert_eq!(error["context"]["runtime_quiescent"], true, "{error:#}");
    assert_eq!(error["context"]["runtime_stopped"], true, "{error:#}");
}

fn saved_json(fixture: &Fixture, label: &str, value: &Value) -> PathBuf {
    let path = fixture.root.join(format!("{label}.json"));
    fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    path
}

#[test]
fn local_recover_saved_mirror_receipt_restores_only_retained_originals() {
    let fixture = Fixture::populated("recover-roundtrip");
    let (application, mirror) = applied_mirror(&fixture);
    let before = operation_trees(&fixture);
    let preview = fixture.recovery_preview(&application.stdout_path).json(true);
    let again = fixture.recovery_preview(&application.stdout_path).json(true);
    assert_recovery_header(&preview, &fixture, &mirror, "plan");
    assert_recovery_header(&again, &fixture, &mirror, "plan");
    assert_eq!(preview["receipt"].as_str(), application.stdout_path.to_str());
    assert_eq!(preview["review_id"], again["review_id"]);
    assert_eq!(preview["entries"], again["entries"]);
    assert_eq!(preview["entries"].as_array().unwrap().len(), 2);
    assert_eq!(preview["has_overwrites"], true);
    assert!(preview["result"].is_null());
    assert!(entry(&preview, "shared.txt")["current"].is_object());
    assert!(entry(&preview, "extra.txt")["current"].is_null());
    assert_eq!(operation_trees(&fixture), before, "review must be read-only");

    let original_shared = inode(&quarantine(&mirror, "shared.txt"));
    let original_extra = inode(&quarantine(&mirror, "extra.txt"));
    let displaced_shared = inode(&fixture.destination.join("shared.txt"));
    let created = inode(&fixture.destination.join("new.bin"));
    let restored = fixture.recovery_apply(
        &application.stdout_path,
        preview["review_id"].as_str().unwrap(),
        RECOVERY_GRANTS,
    ).json(true);
    assert_recovery_complete(&restored, &fixture, &mirror);
    assert_eq!(restored["result"]["actions"].as_array().unwrap().len(), 2);
    assert_eq!(action(&restored, "shared.txt")["state"], "exchanged");
    assert_eq!(action(&restored, "extra.txt")["state"], "restored");
    assert_eq!(inode(&fixture.destination.join("shared.txt")), original_shared);
    assert_eq!(inode(&fixture.destination.join("extra.txt")), original_extra);
    assert_eq!(inode(&quarantine(&mirror, "shared.txt")), displaced_shared);
    assert_eq!(inode(&fixture.destination.join("new.bin")), created);
    assert_populated_restored(&fixture, &mirror);
}

#[test]
fn local_recover_requires_both_overwrite_grants_before_any_restore() {
    let fixture = Fixture::populated("recover-grants");
    let (application, mirror) = applied_mirror(&fixture);
    let preview = fixture.recovery_preview(&application.stdout_path).json(true);
    let before = operation_trees(&fixture);
    for grants in [
        &[][..],
        &["--allow-overwrite"][..],
        &["--allow-permission-change"][..],
    ] {
        let refused = fixture.recovery_apply(
            &application.stdout_path,
            preview["review_id"].as_str().unwrap(),
            grants,
        ).json(false);
        assert_recovery_header(&refused, &fixture, &mirror, "apply");
        assert!(refused["application_error"].is_null(), "{refused:#}");
        assert_eq!(refused["result"]["complete"], false, "{refused:#}");
        assert!(refused["result"]["failure"].is_string(), "{refused:#}");
        assert_eq!(refused["result"]["actions"].as_array().unwrap().len(), 2);
        for action in refused["result"]["actions"].as_array().unwrap() {
            assert_eq!(action["state"], "not_started", "{refused:#}");
            assert_eq!(action["durable"], false, "{refused:#}");
        }
        assert_eq!(operation_trees(&fixture), before, "grants={grants:?}");
    }
    for grant in RECOVERY_GRANTS {
        let mut command = fixture.recovery_command(&application.stdout_path);
        command.arg(grant);
        fixture.run(command).failed();
        assert_eq!(operation_trees(&fixture), before, "preview cannot grant {grant}");
    }
}

#[test]
fn local_recover_absent_destinations_need_no_overwrite_grant() {
    let fixture = Fixture::new("recover-absent");
    fs::write(fixture.destination.join("retired.txt"), b"original inode").unwrap();
    let original = inode(&fixture.destination.join("retired.txt"));
    let (application, mirror) = applied_mirror(&fixture);
    assert!(!fixture.destination.join("retired.txt").exists());
    let preview = fixture.recovery_preview(&application.stdout_path).json(true);
    assert_recovery_header(&preview, &fixture, &mirror, "plan");
    assert_eq!(preview["has_overwrites"], false);
    assert!(entry(&preview, "retired.txt")["current"].is_null());
    let restored = fixture.recovery_apply(
        &application.stdout_path,
        preview["review_id"].as_str().unwrap(),
        &[],
    ).json(true);
    assert_recovery_complete(&restored, &fixture, &mirror);
    assert_eq!(action(&restored, "retired.txt")["state"], "restored");
    assert_eq!(inode(&fixture.destination.join("retired.txt")), original);
    assert_eq!(fs::read(fixture.destination.join("retired.txt")).unwrap(), b"original inode");
    assert!(!quarantine(&mirror, "retired.txt").exists());
    assert_eq!(fs::read_dir(&fixture.source).unwrap().count(), 0);
}

#[test]
fn local_recover_stale_review_refuses_destination_and_quarantine_changes() {
    for changed_original in [false, true] {
        let fixture = Fixture::populated(if changed_original {
            "recover-stale-original"
        } else {
            "recover-stale-destination"
        });
        let (application, mirror) = applied_mirror(&fixture);
        let preview = fixture.recovery_preview(&application.stdout_path).json(true);
        let changed = if changed_original {
            quarantine(&mirror, "shared.txt")
        } else {
            fixture.destination.join("shared.txt")
        };
        fs::write(&changed, b"external change must survive stale approval").unwrap();
        let before = operation_trees(&fixture);
        let refused = fixture.recovery_apply(
            &application.stdout_path,
            preview["review_id"].as_str().unwrap(),
            RECOVERY_GRANTS,
        ).json(false);
        assert_recovery_header(&refused, &fixture, &mirror, "apply");
        assert_ne!(refused["review_id"], preview["review_id"]);
        assert!(refused["result"].is_null(), "{refused:#}");
        assert!(refused["application_error"].is_string(), "{refused:#}");
        let fresh = fixture.recovery_preview(&application.stdout_path).json(true);
        assert_eq!(fresh["review_id"], refused["review_id"]);
        assert_eq!(operation_trees(&fixture), before);
        assert_eq!(fs::read(changed).unwrap(), b"external change must survive stale approval");
    }
}

#[test]
fn local_recover_rejects_forged_receipt_associations_before_effects() {
    let fixture = Fixture::populated("recover-forged");
    let (application, mirror) = applied_mirror(&fixture);
    let source = &mirror["result"]["recovery_source"];
    let actions = source["actions"].as_array().unwrap();
    let shared = actions.iter().position(|entry| entry["path"] == "shared.txt").unwrap();
    let extra = actions.iter().position(|entry| entry["path"] == "extra.txt").unwrap();
    let created = actions.iter().position(|entry| entry["path"] == "new.bin").unwrap();
    assert!(actions[created]["quarantine_path"].is_null());
    assert!(created < shared, "the omitted action must shift a retained-original index");
    let outside = fixture.root.join("outside-sentinel.txt");
    fs::write(&outside, b"outside recovery authority").unwrap();
    let outside_inode = inode(&outside);
    let before = operation_trees(&fixture);

    for case in 0..8 {
        let mut forged = source.clone();
        match case {
            0 => forged["plan_id"] = Value::String("f".repeat(64)),
            1 => forged["actions"][shared]["quarantine_path"] =
                source["actions"][extra]["quarantine_path"].clone(),
            2 => forged["actions"][shared]["path"] = Value::String("../outside-sentinel.txt".into()),
            3 => forged["actions"][shared]["path"] = Value::String("extra.txt".into()),
            4 => forged["actions"][extra]["state"] = Value::String("published".into()),
            5 => forged["dry_run"] = Value::Bool(true),
            6 => {
                // Associations use the original action index, including
                // actions that never quarantined a destination.
                forged["actions"].as_array_mut().unwrap().remove(created);
            }
            7 => forged["actions"][shared]["quarantine_path"] =
                Value::String(outside.to_str().unwrap().to_owned()),
            _ => unreachable!(),
        }
        let path = saved_json(&fixture, &format!("forged-source-{case}"), &forged);
        assert_prepare_refused(&fixture.recovery_preview(&path));
        assert_eq!(operation_trees(&fixture), before, "forged association case={case}");
        assert_eq!(inode(&outside), outside_inode);
        assert_eq!(fs::read(&outside).unwrap(), b"outside recovery authority");
    }

    // Wrapper metadata and its nested source must agree. Neither completion
    // claims nor a well-shaped nested source bypass wrapper validation.
    let mut inconsistent = mirror.clone();
    inconsistent["result"]["recovery_source"]["plan_id"] = Value::String("e".repeat(64));
    let path = saved_json(&fixture, "inconsistent-wrapper", &inconsistent);
    assert_prepare_refused(&fixture.recovery_preview(&path));
    let mut unknown_version = mirror.clone();
    unknown_version["schema_version"] = Value::from(2);
    let path = saved_json(&fixture, "unknown-wrapper-version", &unknown_version);
    assert_prepare_refused(&fixture.recovery_preview(&path));
    assert_eq!(operation_trees(&fixture), before);

    // A complete standalone source and the original actual report remain
    // usable after all refusals, without granting execution authority.
    let source_path = saved_json(&fixture, "valid-source", source);
    let direct = fixture.recovery_preview(&source_path).json(true);
    let wrapped = fixture.recovery_preview(&application.stdout_path).json(true);
    assert_eq!(direct["review_id"], wrapped["review_id"]);
    assert_eq!(direct["entries"], wrapped["entries"]);
    assert_eq!(operation_trees(&fixture), before);
}

#[test]
fn local_recover_enforces_receipt_and_inventory_limits_without_effects() {
    let fixture = Fixture::populated("recover-limits");
    let (application, mirror) = applied_mirror(&fixture);
    let before = operation_trees(&fixture);
    let bytes = fs::read(&application.stdout_path).unwrap();
    assert!(bytes.len() > 1);
    let exact = bytes.len().to_string();
    let smaller = (bytes.len() - 1).to_string();
    let mut bounded = fixture.recovery_command(&application.stdout_path);
    bounded.args(["--max-receipt-bytes", smaller.as_str()]);
    let refused = fixture.run(bounded);
    assert_prepare_refused(&refused);
    assert_eq!(stderr_json(&refused)["type"], "atp_local_recover_receipt");
    assert_eq!(operation_trees(&fixture), before);

    let mut exact_command = fixture.recovery_command(&application.stdout_path);
    exact_command.args(["--max-receipt-bytes", exact.as_str()]);
    let preview = fixture.run(exact_command).json(true);
    assert_recovery_header(&preview, &fixture, &mirror, "plan");
    assert_eq!(operation_trees(&fixture), before);

    for bound in ["0", "67108865"] {
        let mut command = fixture.recovery_command(&application.stdout_path);
        command.args(["--max-receipt-bytes", bound]);
        fixture.run(command).failed();
        assert_eq!(operation_trees(&fixture), before, "receipt bound={bound}");
    }
    for (flag, bound) in [
        ("--max-entries", "1"),
        ("--max-file-bytes", "1"),
        ("--max-total-bytes", "1"),
        ("--max-depth", "0"),
    ] {
        let mut command = fixture.recovery_command(&application.stdout_path);
        command.args([flag, bound]);
        let refused = fixture.run(command);
        assert_prepare_refused(&refused);
        assert_eq!(stderr_json(&refused)["type"], "atp_local_operation_refused");
        assert_eq!(operation_trees(&fixture), before, "{flag}={bound}");
    }
    let malformed = fixture.root.join("malformed-receipt.json");
    fs::write(&malformed, b"{\"result\":").unwrap();
    assert_prepare_refused(&fixture.recovery_preview(&malformed));
    assert_eq!(operation_trees(&fixture), before);
    assert_eq!(fs::read(&application.stdout_path).unwrap(), bytes);
}

#[test]
fn local_recover_refuses_fifo_device_symlink_and_directory_receipts_without_effects() {
    let fixture = Fixture::populated("recover-receipt-kinds");
    let (application, _) = applied_mirror(&fixture);
    let fifo = fixture.root.join("receipt-without-writer.fifo");
    nix::unistd::mkfifo(
        fifo.as_path(),
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    ).expect("create retained FIFO without opening a writer");
    let link = fixture.root.join("receipt-link.json");
    symlink(&application.stdout_path, &link).unwrap();
    let directory = fixture.root.join("receipt-directory");
    private_dir(&directory);
    let before = operation_trees(&fixture);
    let receipt_bytes = fs::read(&application.stdout_path).unwrap();
    for (kind, path) in [
        ("fifo-without-writer", fifo.as_path()),
        ("device", Path::new("/dev/null")),
        ("symlink", link.as_path()),
        ("directory", directory.as_path()),
    ] {
        // No writer is ever opened for the FIFO. A blocking open/read cannot
        // succeed accidentally; the owned-child watchdog bounds old behavior.
        let started = Instant::now();
        let refused = fixture.recovery_preview(path);
        assert_prepare_refused(&refused);
        assert_eq!(stderr_json(&refused)["type"], "atp_local_recover_receipt");
        assert_eq!(operation_trees(&fixture), before, "receipt kind={kind}");
        eprintln!(
            "scenario=local-recover-receipt-kind kind={kind} elapsed_ms={} \
             effect=none runtime=Quiescent retained={}",
            started.elapsed().as_millis(),
            fixture.root.display(),
        );
    }
    assert!(fs::symlink_metadata(&fifo).unwrap().file_type().is_fifo());
    assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
    assert_eq!(fs::read_link(&link).unwrap(), application.stdout_path);
    assert!(directory.is_dir());
    assert_eq!(fs::read(&application.stdout_path).unwrap(), receipt_bytes);
}

#[test]
fn local_recover_uses_output_error_receipts_without_inferring_rollback() {
    let fixture = Fixture::populated("recover-output-error");
    let review = fixture.preview().json(true);
    let mut command = fixture.command();
    command
        .args(["--apply", review["review_id"].as_str().unwrap(), "--staging-dir"])
        .arg(&fixture.staging)
        .args(ALL_GRANTS);
    let failed_mirror = fixture.run_with_stdout(command, Some(Path::new("/dev/full")));
    failed_mirror.failed();
    assert_eq!(failed_mirror.status.code(), Some(ExitCode::RUNTIME_ERROR));
    let error = stderr_json(&failed_mirror);
    assert_eq!(error["type"], "output_error");
    let mirror = &error["context"]["receipt"];
    assert_mirror_header(mirror, &fixture, "apply");
    assert_eq!(mirror["result"]["complete"], true);
    let original_shared = inode(&quarantine(mirror, "shared.txt"));
    let displaced_shared = inode(&fixture.destination.join("shared.txt"));

    // Pass the actual saved error envelope to the new process, without
    // extracting or reconstructing an application receipt in the harness.
    let preview = fixture.recovery_preview(&failed_mirror.stderr_path).json(true);
    assert_recovery_header(&preview, &fixture, mirror, "plan");
    let mut command = fixture.recovery_command(&failed_mirror.stderr_path);
    command.args(["--apply", preview["review_id"].as_str().unwrap()]).args(RECOVERY_GRANTS);
    let failed_recovery = fixture.run_with_stdout(command, Some(Path::new("/dev/full")));
    failed_recovery.failed();
    assert_eq!(failed_recovery.status.code(), Some(ExitCode::RUNTIME_ERROR));
    let recovery_error = stderr_json(&failed_recovery);
    assert_eq!(recovery_error["type"], "output_error");
    assert_eq!(recovery_error["exit_code"], ExitCode::RUNTIME_ERROR);
    let observed = &recovery_error["context"]["receipt"];
    assert_recovery_complete(observed, &fixture, mirror);
    assert_eq!(action(observed, "shared.txt")["state"], "exchanged");
    assert_eq!(action(observed, "extra.txt")["state"], "restored");
    assert_eq!(inode(&fixture.destination.join("shared.txt")), original_shared);
    assert_eq!(inode(&quarantine(mirror, "shared.txt")), displaced_shared);
    assert_populated_restored(&fixture, mirror);

    // A recovery report is not an original sync/mirror association. Refusing
    // it prevents an output failure from becoming an accidental second undo.
    let after = operation_trees(&fixture);
    assert_prepare_refused(&fixture.recovery_preview(&failed_recovery.stderr_path));
    assert_eq!(operation_trees(&fixture), after);
}

fn sync_command(fixture: &Fixture, state: &Path) -> Command {
    let mut command = Command::new(BIN);
    command
        .args(["--format", "json", "atp", "local-sync"])
        .arg(&fixture.source)
        .arg(&fixture.destination)
        .arg("--state-dir")
        .arg(state)
        .stdin(Stdio::null());
    command
}

#[test]
fn local_recover_accepts_legacy_local_sync_receipts_without_rewriting_history() {
    let fixture = Fixture::new("recover-legacy-sync");
    let state = fixture.root.join("sync-history");
    private_dir(&state);
    for root in [&fixture.source, &fixture.destination] {
        fs::write(root.join("shared.txt"), b"common original").unwrap();
    }
    let mut initialize = sync_command(&fixture, &state);
    initialize.args(["--initialize", "--apply", "--staging-dir"]).arg(&fixture.staging);
    let initial = fixture.run(initialize).json(true);
    assert_eq!(initial["baseline_generation"], 1);
    assert_eq!(initial["result"]["publication"]["state"], "durable");

    fs::write(fixture.source.join("shared.txt"), b"one-sided new version").unwrap();
    let original = inode(&fixture.destination.join("shared.txt"));
    let mut apply = sync_command(&fixture, &state);
    apply.args(["--apply", "--staging-dir"]).arg(&fixture.staging).args(RECOVERY_GRANTS);
    let application = fixture.run(apply);
    let sync = application.json(true);
    assert_eq!(sync["command"], "atp.local-sync");
    assert_eq!(sync["baseline_generation"], 2);
    assert_eq!(sync["result"]["complete"], true);
    assert_eq!(sync["result"]["publication"]["state"], "durable");
    assert!(sync["result"].get("recovery_source").is_none(), "exercise the legacy receipt shape");
    assert_eq!(fs::read(fixture.destination.join("shared.txt")).unwrap(), b"one-sided new version");
    let current_state = fs::read(state.join("current.state")).unwrap();
    let history = tree_entries(&state);

    let preview = fixture.recovery_preview(&application.stdout_path).json(true);
    assert_recovery_header(&preview, &fixture, &sync, "plan");
    let restored = fixture.recovery_apply(
        &application.stdout_path,
        preview["review_id"].as_str().unwrap(),
        RECOVERY_GRANTS,
    ).json(true);
    assert_recovery_complete(&restored, &fixture, &sync);
    assert_eq!(action(&restored, "shared.txt")["state"], "exchanged");
    assert_eq!(inode(&fixture.destination.join("shared.txt")), original);
    assert_eq!(fs::read(fixture.destination.join("shared.txt")).unwrap(), b"common original");
    assert_eq!(fs::read(fixture.source.join("shared.txt")).unwrap(), b"one-sided new version");
    assert_eq!(fs::read(quarantine(&sync, "shared.txt")).unwrap(), b"one-sided new version");
    assert_eq!(fs::read(state.join("current.state")).unwrap(), current_state);
    assert_eq!(tree_entries(&state), history, "recovery must not rewind or rewrite history");

    let reopened = fixture.run(sync_command(&fixture, &state)).json(true);
    assert_eq!(reopened["baseline_generation"], 2);
    assert!(reopened["result"].is_null());
    assert_eq!(reopened["runtime_quiescent"], true);
    assert_eq!(reopened["runtime_stopped"], true);
    assert!(reopened["decisions"].as_array().unwrap().iter().any(|decision| {
        decision["path"] == "shared.txt" && decision["action"] == "CopyRemoteToLocal"
    }));
    assert_eq!(fs::read(state.join("current.state")).unwrap(), current_state);
    assert_eq!(fs::read(fixture.source.join("shared.txt")).unwrap(), b"one-sided new version");
}

#[test]
fn local_mirror_repeats_the_same_review_after_recovery_with_a_fresh_job() {
    let fixture = Fixture::new("recover-repeat-mirror");
    fs::write(fixture.source.join("shared.txt"), b"source version").unwrap();
    fs::write(fixture.destination.join("shared.txt"), b"original destination").unwrap();
    fs::write(fixture.destination.join("extra.txt"), b"destination-only original").unwrap();
    let original_source = tree_entries(&fixture.source);
    let original_destination = tree_entries(&fixture.destination);
    let (first_application, first) = applied_mirror(&fixture);
    let recovery = fixture.recovery_preview(&first_application.stdout_path).json(true);
    let restored = fixture.recovery_apply(
        &first_application.stdout_path,
        recovery["review_id"].as_str().unwrap(),
        RECOVERY_GRANTS,
    ).json(true);
    assert_recovery_complete(&restored, &fixture, &first);
    assert_eq!(tree_entries(&fixture.source), original_source);
    assert_eq!(tree_entries(&fixture.destination), original_destination);
    let first_job = PathBuf::from(first["result"]["staging_directory"].as_str().unwrap());
    let retained_first_job = tree_entries(&first_job);

    let preview = fixture.preview().json(true);
    assert_eq!(preview["review_id"], first["review_id"], "restored contents repeat the review");
    let second = fixture.apply(preview["review_id"].as_str().unwrap(), ALL_GRANTS).json(true);
    assert_mirror_header(&second, &fixture, "apply");
    assert_eq!(second["result"]["complete"], true);
    assert_ne!(second["plan_id"], first["plan_id"]);
    assert_ne!(second["result"]["staging_directory"], first["result"]["staging_directory"]);
    assert_eq!(tree_entries(&first_job), retained_first_job, "the older job must remain untouched");
    assert_eq!(fs::read_dir(&fixture.staging).unwrap().count(), 2);
    assert_eq!(tree_entries(&fixture.source), original_source);
    assert_eq!(fs::read(fixture.destination.join("shared.txt")).unwrap(), b"source version");
    assert!(!fixture.destination.join("extra.txt").exists());
    assert_eq!(fs::read(quarantine(&second, "shared.txt")).unwrap(), b"original destination");
    assert_eq!(fs::read(quarantine(&second, "extra.txt")).unwrap(), b"destination-only original");
}
