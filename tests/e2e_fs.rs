#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]

//! Filesystem E2E test suite: io_uring and directory operation tests (bd-2auz).
//!
//! Covers file operations, directory operations, symlinks, platform-specific
//! io_uring paths, and cancellation correctness.

#[macro_use]
mod common;

use asupersync::fs;
use asupersync::fs::Vfs as _;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::stream::StreamExt as _;
use futures_lite::future;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut path = std::env::temp_dir();
    path.push(format!("asupersync_e2e_fs_{prefix}_{id}_{nanos}"));
    path
}

fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_dir_all(path);
}

const FS_PARITY_WAVE2_SCENARIOS: &[&str] = &[
    "open-options-seek-sync",
    "open-options-append-truncate",
    "file-create-new-exclusive",
    "file-clone-position-rewind",
    "file-set-len-permissions",
    "read-dir-metadata-disposition",
    "buffered-lines-boundaries",
    "buf-writer-flush-visibility",
    "write-atomic-replace-cleanup",
    "dir-create-remove-boundaries",
    "unix-vfs-equivalence",
    "error-kind-remove-missing",
    "error-kind-invalid-utf8-read-to-string",
    "error-kind-create-dir-existing-file",
    "error-kind-read-dir-non-directory",
    "try-exists-lifecycle",
    "path-ops-copy-hardlink-rename",
    "unix-symlink-metadata-readlink",
    "io-uring-cancellation-support-boundary",
    "io-uring-unknown-completion-attribution",
    "read-dir-drop-cancellation",
    "dormant-fs-normal-recursive-traversal",
    "dormant-fs-simple-symlink-traversal",
    "dormant-fs-circular-symlink-detection",
    "dormant-fs-broken-symlink-handling",
    "dormant-fs-mixed-symlink-tree",
    "dormant-fs-cross-root-vfs-traversal",
    "dormant-fs-bounded-partial-traversal",
];

const FS_PARITY_WAVE2_ROW_FIELDS: &[&str] = &[
    "bead_id",
    "scenario_id",
    "api",
    "backend",
    "platform",
    "feature_flags",
    "temp_root",
    "operation",
    "bytes_expected",
    "bytes_actual",
    "metadata_expected",
    "metadata_actual",
    "cancellation_point",
    "cleanup_status",
    "unsupported_reason",
    "verdict",
    "first_failure",
];

#[derive(Debug)]
struct FsProofEvidence {
    bytes_actual: u64,
    metadata_actual: String,
    unsupported_reason: String,
}

impl FsProofEvidence {
    fn supported(bytes_actual: u64, metadata_actual: impl Into<String>) -> Self {
        Self {
            bytes_actual,
            metadata_actual: metadata_actual.into(),
            unsupported_reason: String::new(),
        }
    }
}

#[derive(Debug)]
struct FsProofScenario {
    scenario_id: &'static str,
    api: &'static str,
    operation: &'static str,
    bytes_expected: u64,
    metadata_expected: &'static str,
    cancellation_point: &'static str,
    result: Result<FsProofEvidence, String>,
}

fn fs_parity_feature_flags() -> String {
    format!(
        "test-internals=true,io-uring={}",
        cfg!(feature = "io-uring")
    )
}

fn fs_parity_platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn fs_parity_backend(scenario_id: &str) -> &'static str {
    if scenario_id.starts_with("io-uring-") {
        "io_uring"
    } else if scenario_id.starts_with("dormant-fs-") {
        "unix_vfs"
    } else {
        "unix-spawn_blocking_io"
    }
}

fn fs_parity_row(
    bead_id: &str,
    scenario: &FsProofScenario,
    temp_root: &Path,
    cleanup_status: &str,
) -> Value {
    let cleanup_failed = cleanup_status != "removed";
    let (bytes_actual, metadata_actual, unsupported_reason, verdict, first_failure) =
        match &scenario.result {
            Ok(evidence) if !cleanup_failed => {
                let verdict = if evidence.unsupported_reason.is_empty() {
                    "pass"
                } else {
                    "skip"
                };
                (
                    evidence.bytes_actual,
                    evidence.metadata_actual.clone(),
                    evidence.unsupported_reason.clone(),
                    verdict.to_string(),
                    String::new(),
                )
            }
            Ok(evidence) => (
                evidence.bytes_actual,
                evidence.metadata_actual.clone(),
                evidence.unsupported_reason.clone(),
                "fail".to_string(),
                format!("cleanup_status={cleanup_status}"),
            ),
            Err(first_failure) => (
                0,
                String::new(),
                String::new(),
                "fail".to_string(),
                first_failure.clone(),
            ),
        };

    json!({
        "bead_id": bead_id,
        "scenario_id": scenario.scenario_id,
        "api": scenario.api,
        "backend": fs_parity_backend(scenario.scenario_id),
        "platform": fs_parity_platform(),
        "feature_flags": fs_parity_feature_flags(),
        "temp_root": temp_root.display().to_string(),
        "operation": scenario.operation,
        "bytes_expected": scenario.bytes_expected,
        "bytes_actual": bytes_actual,
        "metadata_expected": scenario.metadata_expected,
        "metadata_actual": metadata_actual,
        "cancellation_point": scenario.cancellation_point,
        "cleanup_status": cleanup_status,
        "unsupported_reason": unsupported_reason,
        "verdict": verdict,
        "first_failure": first_failure,
    })
}

fn fs_proof_scenario_dir(temp_root: &Path, scenario_id: &str) -> Result<PathBuf, String> {
    let dir = temp_root.join(scenario_id);
    std::fs::create_dir_all(&dir)
        .map_err(|err| format!("{scenario_id}: create scenario dir: {err}"))?;
    Ok(dir)
}

async fn fs_proof_open_options_seek_sync(temp_root: &Path) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "open-options-seek-sync")?;
    let path = dir.join("cursor.txt");
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .await
        .map_err(|err| format!("open read/write/create/truncate: {err}"))?;

    file.write_all(b"0123456789")
        .await
        .map_err(|err| format!("write all: {err}"))?;
    file.sync_data()
        .await
        .map_err(|err| format!("sync data: {err}"))?;
    file.seek(io::SeekFrom::Start(4))
        .await
        .map_err(|err| format!("seek start 4: {err}"))?;
    let mut window = [0_u8; 3];
    file.read_exact(&mut window)
        .await
        .map_err(|err| format!("read exact window: {err}"))?;
    if &window != b"456" {
        return Err(format!(
            "seek/read window drift: expected 456 actual {window:?}"
        ));
    }

    let metadata = file
        .metadata()
        .await
        .map_err(|err| format!("file metadata: {err}"))?;
    if metadata.len() != 10 || !metadata.is_file() {
        return Err(format!(
            "metadata drift: len={} is_file={}",
            metadata.len(),
            metadata.is_file()
        ));
    }

    Ok(FsProofEvidence::supported(
        metadata.len(),
        "len=10,is_file=true,seek_window=456",
    ))
}

async fn fs_proof_open_options_append_truncate(
    temp_root: &Path,
) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "open-options-append-truncate")?;
    let path = dir.join("append-truncate.txt");
    fs::write(&path, b"alpha")
        .await
        .map_err(|err| format!("write initial append/truncate file: {err}"))?;

    let mut appender = fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .await
        .map_err(|err| format!("open append mode: {err}"))?;
    appender
        .write_all(b"_beta")
        .await
        .map_err(|err| format!("append bytes: {err}"))?;
    appender
        .sync_data()
        .await
        .map_err(|err| format!("sync appended bytes: {err}"))?;
    drop(appender);

    let appended = fs::read_to_string(&path)
        .await
        .map_err(|err| format!("read appended contents: {err}"))?;
    if appended != "alpha_beta" {
        return Err(format!(
            "append drift: expected alpha_beta actual {appended}"
        ));
    }

    let mut truncating = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .await
        .map_err(|err| format!("open truncate mode: {err}"))?;
    truncating
        .write_all(b"z")
        .await
        .map_err(|err| format!("write truncated contents: {err}"))?;
    truncating
        .sync_all()
        .await
        .map_err(|err| format!("sync truncated contents: {err}"))?;
    drop(truncating);

    let truncated = fs::read_to_string(&path)
        .await
        .map_err(|err| format!("read truncated contents: {err}"))?;
    let metadata = fs::metadata(&path)
        .await
        .map_err(|err| format!("metadata after append/truncate: {err}"))?;
    let metadata_actual = format!(
        "appended={appended},truncated={truncated},len={}",
        metadata.len()
    );
    let metadata_expected = "appended=alpha_beta,truncated=z,len=1";
    if metadata_actual != metadata_expected {
        return Err(format!(
            "append/truncate drift: actual={metadata_actual} expected={metadata_expected}"
        ));
    }

    Ok(FsProofEvidence::supported(metadata.len(), metadata_actual))
}

async fn fs_proof_file_create_new_exclusive(temp_root: &Path) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "file-create-new-exclusive")?;
    let path = dir.join("new-only.txt");
    let mut file = fs::File::create_new(&path)
        .await
        .map_err(|err| format!("create_new first open: {err}"))?;
    file.write_all(b"exclusive-create")
        .await
        .map_err(|err| format!("create_new write: {err}"))?;
    file.rewind()
        .await
        .map_err(|err| format!("create_new rewind: {err}"))?;

    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .await
        .map_err(|err| format!("create_new read back: {err}"))?;
    if contents != "exclusive-create" {
        return Err(format!(
            "create_new read/write drift: expected exclusive-create actual {contents}"
        ));
    }
    drop(file);

    match fs::File::create_new(&path).await {
        Ok(_) => Err("second create_new unexpectedly succeeded".to_string()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(FsProofEvidence::supported(
            contents.len() as u64,
            "read_write=true,second_error=AlreadyExists",
        )),
        Err(err) => Err(format!(
            "second create_new returned wrong error kind: {:?}: {err}",
            err.kind()
        )),
    }
}

async fn fs_proof_file_clone_position_rewind(temp_root: &Path) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "file-clone-position-rewind")?;
    let path = dir.join("cursor-shared.txt");
    fs::write(&path, b"abcdef")
        .await
        .map_err(|err| format!("write clone cursor fixture: {err}"))?;

    let mut file = fs::File::open(&path)
        .await
        .map_err(|err| format!("open clone cursor fixture: {err}"))?;
    let mut clone = file
        .try_clone()
        .await
        .map_err(|err| format!("try_clone file: {err}"))?;

    let mut first = [0_u8; 2];
    file.read_exact(&mut first)
        .await
        .map_err(|err| format!("read first bytes from original: {err}"))?;
    let original_position = file
        .stream_position()
        .await
        .map_err(|err| format!("stream_position after original read: {err}"))?;
    let clone_position_after_original_read = clone
        .stream_position()
        .await
        .map_err(|err| format!("clone stream_position after original read: {err}"))?;

    let mut clone_next = [0_u8; 2];
    clone
        .read_exact(&mut clone_next)
        .await
        .map_err(|err| format!("read next bytes from clone: {err}"))?;
    let original_position_after_clone_read = file
        .stream_position()
        .await
        .map_err(|err| format!("original stream_position after clone read: {err}"))?;

    file.rewind()
        .await
        .map_err(|err| format!("rewind original file: {err}"))?;
    let clone_position_after_rewind = clone
        .stream_position()
        .await
        .map_err(|err| format!("clone stream_position after rewind: {err}"))?;
    let mut rewound = [0_u8; 3];
    clone
        .read_exact(&mut rewound)
        .await
        .map_err(|err| format!("read rewound bytes from clone: {err}"))?;

    let first = String::from_utf8_lossy(&first);
    let clone_next = String::from_utf8_lossy(&clone_next);
    let rewound = String::from_utf8_lossy(&rewound);
    let metadata_actual = format!(
        "first={first},original_position={original_position},clone_position_after_original_read={clone_position_after_original_read},clone_next={clone_next},original_position_after_clone_read={original_position_after_clone_read},clone_position_after_rewind={clone_position_after_rewind},rewound={rewound}"
    );
    let metadata_expected = "first=ab,original_position=2,clone_position_after_original_read=2,clone_next=cd,original_position_after_clone_read=4,clone_position_after_rewind=0,rewound=abc";
    if metadata_actual != metadata_expected {
        return Err(format!(
            "clone/position/rewind drift: actual={metadata_actual} expected={metadata_expected}"
        ));
    }

    Ok(FsProofEvidence::supported(6, metadata_actual))
}

async fn fs_proof_read_dir_metadata(temp_root: &Path) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "read-dir-metadata-disposition")?;
    fs::write(dir.join("alpha.txt"), b"a")
        .await
        .map_err(|err| format!("write alpha: {err}"))?;
    fs::write(dir.join("beta.txt"), b"bb")
        .await
        .map_err(|err| format!("write beta: {err}"))?;
    fs::create_dir(dir.join("nested"))
        .await
        .map_err(|err| format!("create nested dir: {err}"))?;

    let mut entries = fs::read_dir(&dir)
        .await
        .map_err(|err| format!("read_dir open: {err}"))?;
    let mut names = Vec::new();
    let mut file_count = 0_u64;
    let mut dir_count = 0_u64;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|err| format!("read_dir next_entry: {err}"))?
    {
        let file_type = entry
            .file_type()
            .await
            .map_err(|err| format!("dir entry file_type: {err}"))?;
        if file_type.is_file() {
            file_count += 1;
        }
        if file_type.is_dir() {
            dir_count += 1;
        }
        names.push(entry.file_name().to_string_lossy().to_string());
    }
    names.sort();

    let expected = vec![
        "alpha.txt".to_string(),
        "beta.txt".to_string(),
        "nested".to_string(),
    ];
    if names != expected || file_count != 2 || dir_count != 1 {
        return Err(format!(
            "read_dir drift: names={names:?} file_count={file_count} dir_count={dir_count}"
        ));
    }

    Ok(FsProofEvidence::supported(
        names.len() as u64,
        format!("entries={names:?},file_count=2,dir_count=1"),
    ))
}

async fn fs_proof_buffered_lines(temp_root: &Path) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "buffered-lines-boundaries")?;
    let path = dir.join("lines.txt");
    let contents = b"alpha\n\nbeta-no-newline";
    fs::write(&path, contents)
        .await
        .map_err(|err| format!("write lines fixture: {err}"))?;

    let file = fs::File::open(&path)
        .await
        .map_err(|err| format!("open lines fixture: {err}"))?;
    let reader = fs::BufReader::with_capacity(4, file);
    let mut stream = reader.lines();
    let mut lines = Vec::new();
    while let Some(line) = stream.next().await {
        lines.push(line.map_err(|err| format!("read line: {err}"))?);
    }

    let expected = vec![
        "alpha".to_string(),
        String::new(),
        "beta-no-newline".to_string(),
    ];
    if lines != expected {
        return Err(format!(
            "line boundary drift: expected={expected:?} actual={lines:?}"
        ));
    }

    Ok(FsProofEvidence::supported(
        contents.len() as u64,
        format!("lines={lines:?},capacity=4"),
    ))
}

async fn fs_proof_buf_writer_flush_visibility(temp_root: &Path) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "buf-writer-flush-visibility")?;
    let path = dir.join("buffered-writer.txt");
    let file = fs::File::create(&path)
        .await
        .map_err(|err| format!("create buffered writer target: {err}"))?;
    let mut writer = fs::BufWriter::with_capacity(16, file);

    writer
        .write_all(b"buffered")
        .await
        .map_err(|err| format!("buffered write: {err}"))?;
    let buffered_len_before_flush = writer.buffer().len();
    let capacity = writer.capacity();
    let disk_before_flush = fs::read(&path)
        .await
        .map_err(|err| format!("read before flush: {err}"))?;
    writer
        .flush()
        .await
        .map_err(|err| format!("flush buffered writer: {err}"))?;
    drop(writer);

    let disk_after_flush = fs::read(&path)
        .await
        .map_err(|err| format!("read after flush: {err}"))?;
    if buffered_len_before_flush != 8
        || capacity != 16
        || !disk_before_flush.is_empty()
        || disk_after_flush != b"buffered"
    {
        return Err(format!(
            "buf_writer drift: buffered_before={buffered_len_before_flush} capacity={capacity} disk_before={disk_before_flush:?} disk_after={disk_after_flush:?}"
        ));
    }

    Ok(FsProofEvidence::supported(
        disk_after_flush.len() as u64,
        "buffered_before_flush=8,disk_before_flush=0,disk_after_flush=buffered,capacity=16",
    ))
}

fn fs_proof_write_atomic_metadata_expected() -> &'static str {
    #[cfg(unix)]
    {
        "contents=replacement,len=11,mode=640,entries=[atomic.txt]"
    }
    #[cfg(not(unix))]
    {
        "contents=replacement,len=11,entries=[atomic.txt]"
    }
}

async fn fs_proof_write_atomic_replace_cleanup(
    temp_root: &Path,
) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "write-atomic-replace-cleanup")?;
    let path = dir.join("atomic.txt");

    fs::write(&path, b"initial")
        .await
        .map_err(|err| format!("write initial file: {err}"))?;

    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(&path)
            .await
            .map_err(|err| format!("metadata before permission set: {err}"))?
            .permissions();
        permissions.set_mode(0o640);
        fs::set_permissions(&path, permissions)
            .await
            .map_err(|err| format!("set unix permissions before atomic replace: {err}"))?;
    }

    fs::write_atomic(&path, b"replacement")
        .await
        .map_err(|err| format!("atomic replace: {err}"))?;

    let contents = fs::read_to_string(&path)
        .await
        .map_err(|err| format!("read replaced file as string: {err}"))?;
    let metadata = fs::metadata(&path)
        .await
        .map_err(|err| format!("metadata after atomic replace: {err}"))?;
    let mut read_dir = fs::read_dir(&dir)
        .await
        .map_err(|err| format!("read scenario directory: {err}"))?;
    let mut entries = Vec::new();
    while let Some(entry) = read_dir
        .next_entry()
        .await
        .map_err(|err| format!("iterate scenario directory: {err}"))?
    {
        entries.push(entry.file_name().to_string_lossy().into_owned());
    }
    entries.sort();

    #[cfg(unix)]
    let metadata_actual = {
        let mode = metadata.permissions().mode() & 0o777;
        format!(
            "contents={contents},len={},mode={mode:o},entries=[{}]",
            metadata.len(),
            entries.join(",")
        )
    };
    #[cfg(not(unix))]
    let metadata_actual = format!(
        "contents={contents},len={},entries=[{}]",
        metadata.len(),
        entries.join(",")
    );

    let metadata_expected = fs_proof_write_atomic_metadata_expected();
    if metadata_actual != metadata_expected {
        return Err(format!(
            "write_atomic drift: actual={metadata_actual} expected={metadata_expected}"
        ));
    }

    Ok(FsProofEvidence::supported(metadata.len(), metadata_actual))
}

async fn fs_proof_dir_create_remove_boundaries(
    temp_root: &Path,
) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "dir-create-remove-boundaries")?;
    let single = dir.join("single");
    let nested_leaf = dir.join("nested/a/b");
    let recursive_root = dir.join("recursive");
    let recursive_leaf = recursive_root.join("leaf");

    fs::create_dir(&single)
        .await
        .map_err(|err| format!("create single directory: {err}"))?;
    fs::remove_dir(&single)
        .await
        .map_err(|err| format!("remove empty single directory: {err}"))?;
    let single_removed = !fs::try_exists(&single)
        .await
        .map_err(|err| format!("try_exists removed single directory: {err}"))?;

    fs::create_dir_all(&nested_leaf)
        .await
        .map_err(|err| format!("create nested directory tree: {err}"))?;
    fs::write(nested_leaf.join("payload.txt"), b"payload")
        .await
        .map_err(|err| format!("write nested payload: {err}"))?;
    let nested_created = fs::try_exists(&nested_leaf)
        .await
        .map_err(|err| format!("try_exists nested leaf: {err}"))?;
    let nonempty_error = fs::remove_dir(dir.join("nested/a"))
        .await
        .expect_err("remove_dir must reject non-empty directories")
        .kind();

    fs::create_dir_all(&recursive_leaf)
        .await
        .map_err(|err| format!("create recursive cleanup directory: {err}"))?;
    fs::write(recursive_leaf.join("payload.txt"), b"payload")
        .await
        .map_err(|err| format!("write recursive cleanup payload: {err}"))?;
    fs::remove_dir_all(&recursive_root)
        .await
        .map_err(|err| format!("remove recursive directory tree: {err}"))?;
    let recursive_removed = !fs::try_exists(&recursive_root)
        .await
        .map_err(|err| format!("try_exists removed recursive root: {err}"))?;

    let metadata_actual = format!(
        "single_removed={single_removed},nested_created={nested_created},nonempty_error={nonempty_error:?},recursive_removed={recursive_removed}"
    );
    let metadata_expected = "single_removed=true,nested_created=true,nonempty_error=DirectoryNotEmpty,recursive_removed=true";
    if metadata_actual != metadata_expected {
        return Err(format!(
            "dir create/remove drift: actual={metadata_actual} expected={metadata_expected}"
        ));
    }

    Ok(FsProofEvidence::supported(4, metadata_actual))
}

async fn fs_proof_unix_vfs_equivalence(temp_root: &Path) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "unix-vfs-equivalence")?;
    let path = dir.join("vfs.txt");
    let copied = dir.join("vfs-copy.txt");
    let vfs = fs::UnixVfs::new();

    vfs.write(&path, b"vfs-equivalent")
        .await
        .map_err(|err| format!("vfs write: {err}"))?;
    let direct = fs::read(&path)
        .await
        .map_err(|err| format!("direct read after vfs write: {err}"))?;
    let copied_len = vfs
        .copy(&path, &copied)
        .await
        .map_err(|err| format!("vfs copy: {err}"))?;
    let copied_bytes = fs::read(&copied)
        .await
        .map_err(|err| format!("direct read vfs copy: {err}"))?;
    let metadata = vfs
        .metadata(&path)
        .await
        .map_err(|err| format!("vfs metadata: {err}"))?;

    if direct != b"vfs-equivalent" || copied_bytes != direct || copied_len != direct.len() as u64 {
        return Err(format!(
            "vfs equivalence drift: direct={direct:?} copied={copied_bytes:?} copied_len={copied_len}"
        ));
    }
    if metadata.len() != direct.len() as u64 || !metadata.is_file() {
        return Err(format!(
            "vfs metadata drift: len={} is_file={}",
            metadata.len(),
            metadata.is_file()
        ));
    }

    Ok(FsProofEvidence::supported(
        direct.len() as u64,
        "unix_vfs_matches_direct_fs_read_copy_metadata",
    ))
}

async fn fs_proof_remove_missing_error_kind(temp_root: &Path) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "error-kind-remove-missing")?;
    let missing = dir.join("missing.txt");
    match fs::remove_file(&missing).await {
        Ok(()) => Err("remove_file unexpectedly succeeded for missing path".to_string()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(FsProofEvidence::supported(
            0,
            "error_kind=NotFound,path_absent=true",
        )),
        Err(err) => Err(format!(
            "remove_file missing path returned wrong error kind: {:?}: {err}",
            err.kind()
        )),
    }
}

async fn fs_proof_invalid_utf8_read_to_string(temp_root: &Path) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "error-kind-invalid-utf8-read-to-string")?;
    let path = dir.join("invalid-utf8.txt");
    let invalid = [0xff, b'a', 0xfe];
    fs::write(&path, invalid)
        .await
        .map_err(|err| format!("write invalid utf8 fixture: {err}"))?;

    let raw = fs::read(&path)
        .await
        .map_err(|err| format!("read invalid utf8 fixture as bytes: {err}"))?;
    let err = fs::read_to_string(&path)
        .await
        .expect_err("read_to_string must reject invalid UTF-8");

    if raw != invalid || err.kind() != io::ErrorKind::InvalidData {
        return Err(format!(
            "invalid UTF-8 error drift: raw={raw:?} error_kind={:?}",
            err.kind()
        ));
    }

    Ok(FsProofEvidence::supported(
        raw.len() as u64,
        "read_bytes=3,read_to_string_error=InvalidData",
    ))
}

async fn fs_proof_create_dir_existing_file_error_kind(
    temp_root: &Path,
) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "error-kind-create-dir-existing-file")?;
    let file_path = dir.join("not-a-directory");
    fs::write(&file_path, b"file")
        .await
        .map_err(|err| format!("write existing file fixture: {err}"))?;

    let err = fs::create_dir(&file_path)
        .await
        .expect_err("create_dir must reject an existing file path");
    if err.kind() != io::ErrorKind::AlreadyExists {
        return Err(format!(
            "create_dir existing-file error drift: error_kind={:?}",
            err.kind()
        ));
    }

    let still_file = fs::metadata(&file_path)
        .await
        .map_err(|err| format!("metadata after rejected create_dir: {err}"))?
        .is_file();
    if !still_file {
        return Err("create_dir existing-file rejection changed file disposition".to_string());
    }

    Ok(FsProofEvidence::supported(
        0,
        "error_kind=AlreadyExists,existing_file_preserved=true",
    ))
}

async fn fs_proof_read_dir_non_directory_error_kind(
    temp_root: &Path,
) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "error-kind-read-dir-non-directory")?;
    let file_path = dir.join("regular-file.txt");
    fs::write(&file_path, b"not-a-dir")
        .await
        .map_err(|err| format!("write read_dir non-directory fixture: {err}"))?;

    let err = fs::read_dir(&file_path)
        .await
        .expect_err("read_dir must reject a regular file path");
    if err.kind() != io::ErrorKind::NotADirectory {
        return Err(format!(
            "read_dir non-directory error drift: error_kind={:?}",
            err.kind()
        ));
    }

    let metadata = fs::metadata(&file_path)
        .await
        .map_err(|err| format!("metadata after rejected read_dir: {err}"))?;
    if !metadata.is_file() || metadata.len() != 9 {
        return Err(format!(
            "read_dir non-directory rejection changed file disposition: is_file={} len={}",
            metadata.is_file(),
            metadata.len()
        ));
    }

    Ok(FsProofEvidence::supported(
        metadata.len(),
        "error_kind=NotADirectory,existing_file_preserved=true,len=9",
    ))
}

async fn fs_proof_file_set_len_permissions(temp_root: &Path) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "file-set-len-permissions")?;
    let path = dir.join("set-len-permissions.txt");
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .await
        .map_err(|err| format!("open read-write set_len file: {err}"))?;

    file.write_all(b"abcdefgh")
        .await
        .map_err(|err| format!("write set_len fixture: {err}"))?;
    file.set_len(4)
        .await
        .map_err(|err| format!("truncate file to four bytes: {err}"))?;
    file.rewind()
        .await
        .map_err(|err| format!("rewind truncated file: {err}"))?;

    let mut truncated = String::new();
    file.read_to_string(&mut truncated)
        .await
        .map_err(|err| format!("read truncated file: {err}"))?;
    file.set_len(10)
        .await
        .map_err(|err| format!("extend file to ten bytes: {err}"))?;

    let mut permissions = file
        .metadata()
        .await
        .map_err(|err| format!("metadata before permission update: {err}"))?
        .permissions();
    permissions.set_readonly(true);
    file.set_permissions(permissions)
        .await
        .map_err(|err| format!("set readonly permission: {err}"))?;
    let readonly = file
        .metadata()
        .await
        .map_err(|err| format!("metadata after readonly update: {err}"))?
        .permissions()
        .readonly();

    let mut writable_permissions = file
        .metadata()
        .await
        .map_err(|err| format!("metadata before writable reset: {err}"))?
        .permissions();
    writable_permissions.set_readonly(false);
    file.set_permissions(writable_permissions)
        .await
        .map_err(|err| format!("reset writable permission: {err}"))?;
    drop(file);

    let metadata = fs::metadata(&path)
        .await
        .map_err(|err| format!("metadata after set_len/permission roundtrip: {err}"))?;
    if truncated != "abcd" || metadata.len() != 10 || !readonly {
        return Err(format!(
            "set_len/permissions drift: truncated={truncated:?} len={} readonly={readonly}",
            metadata.len()
        ));
    }

    Ok(FsProofEvidence::supported(
        metadata.len(),
        "truncated=abcd,extended_len=10,readonly_roundtrip=true",
    ))
}

async fn fs_proof_try_exists_lifecycle(temp_root: &Path) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "try-exists-lifecycle")?;
    let path = dir.join("lifecycle.txt");

    let before = fs::try_exists(&path)
        .await
        .map_err(|err| format!("try_exists before create: {err}"))?;
    fs::write(&path, b"exists")
        .await
        .map_err(|err| format!("write lifecycle file: {err}"))?;
    let after_create = fs::try_exists(&path)
        .await
        .map_err(|err| format!("try_exists after create: {err}"))?;
    fs::remove_file(&path)
        .await
        .map_err(|err| format!("remove lifecycle file: {err}"))?;
    let after_remove = fs::try_exists(&path)
        .await
        .map_err(|err| format!("try_exists after remove: {err}"))?;

    if before || !after_create || after_remove {
        return Err(format!(
            "try_exists lifecycle drift: before={before} after_create={after_create} after_remove={after_remove}"
        ));
    }

    Ok(FsProofEvidence::supported(
        3,
        "exists_sequence=false,true,false",
    ))
}

async fn fs_proof_path_ops_copy_hardlink_rename(
    temp_root: &Path,
) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "path-ops-copy-hardlink-rename")?;
    let source = dir.join("source.txt");
    let copied = dir.join("copied.txt");
    let renamed = dir.join("renamed.txt");
    let hard_link = dir.join("hard-link.txt");

    fs::write(&source, b"path-ops")
        .await
        .map_err(|err| format!("write source: {err}"))?;
    let copy_len = fs::copy(&source, &copied)
        .await
        .map_err(|err| format!("copy source: {err}"))?;
    fs::hard_link(&source, &hard_link)
        .await
        .map_err(|err| format!("hard_link source: {err}"))?;
    fs::rename(&copied, &renamed)
        .await
        .map_err(|err| format!("rename copied file: {err}"))?;

    let source_bytes = fs::read(&source)
        .await
        .map_err(|err| format!("read source: {err}"))?;
    let renamed_bytes = fs::read(&renamed)
        .await
        .map_err(|err| format!("read renamed: {err}"))?;
    let hard_link_bytes = fs::read(&hard_link)
        .await
        .map_err(|err| format!("read hard link: {err}"))?;
    let canonical = fs::canonicalize(&renamed)
        .await
        .map_err(|err| format!("canonicalize renamed: {err}"))?;
    let copied_still_exists = fs::try_exists(&copied)
        .await
        .map_err(|err| format!("try_exists copied after rename: {err}"))?;

    if copy_len != 8
        || source_bytes != b"path-ops"
        || renamed_bytes != source_bytes
        || hard_link_bytes != source_bytes
        || !canonical.ends_with("renamed.txt")
        || copied_still_exists
    {
        return Err(format!(
            "path ops drift: copy_len={copy_len} source={source_bytes:?} renamed={renamed_bytes:?} hard_link={hard_link_bytes:?} canonical={} copied_exists={copied_still_exists}",
            canonical.display()
        ));
    }

    Ok(FsProofEvidence::supported(
        source_bytes.len() as u64,
        "copy_len=8,hard_link_matches=true,rename_removed_source_copy=true,canonicalized=true",
    ))
}

async fn fs_proof_unix_symlink_metadata_readlink(
    temp_root: &Path,
) -> Result<FsProofEvidence, String> {
    #[cfg(unix)]
    {
        let dir = fs_proof_scenario_dir(temp_root, "unix-symlink-metadata-readlink")?;
        let target = dir.join("target.txt");
        let link = dir.join("link.txt");

        fs::write(&target, b"symlink-target")
            .await
            .map_err(|err| format!("write symlink target: {err}"))?;
        fs::symlink(&target, &link)
            .await
            .map_err(|err| format!("create symlink: {err}"))?;

        let read_link = fs::read_link(&link)
            .await
            .map_err(|err| format!("read_link: {err}"))?;
        let link_metadata = fs::symlink_metadata(&link)
            .await
            .map_err(|err| format!("symlink_metadata: {err}"))?;
        let target_metadata = fs::metadata(&link)
            .await
            .map_err(|err| format!("metadata follows symlink: {err}"))?;
        let contents = fs::read_to_string(&link)
            .await
            .map_err(|err| format!("read symlink contents: {err}"))?;

        if read_link != target
            || !link_metadata.is_symlink()
            || !target_metadata.is_file()
            || contents != "symlink-target"
        {
            return Err(format!(
                "symlink drift: read_link={} target={} link_is_symlink={} target_is_file={} contents={contents}",
                read_link.display(),
                target.display(),
                link_metadata.is_symlink(),
                target_metadata.is_file()
            ));
        }

        Ok(FsProofEvidence::supported(
            contents.len() as u64,
            "read_link_matches_target=true,symlink_metadata_is_symlink=true,metadata_follows_to_file=true",
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = temp_root;
        Ok(FsProofEvidence {
            bytes_actual: 0,
            metadata_actual: "unsupported_platform=non_unix".to_string(),
            unsupported_reason: "symlink proof requires unix symlink support".to_string(),
        })
    }
}

async fn fs_proof_io_uring_cancellation_support_boundary(
    temp_root: &Path,
) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "io-uring-cancellation-support-boundary")?;

    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    {
        let path = dir.join("uring-boundary.txt");
        std::fs::write(&path, b"uring-boundary")
            .map_err(|err| format!("write io_uring boundary fixture: {err}"))?;

        let file = match fs::IoUringFile::open(&path) {
            Ok(file) => file,
            Err(err) => {
                return Ok(FsProofEvidence {
                    bytes_actual: 0,
                    metadata_actual: format!(
                        "io_uring_feature_enabled=true,runtime_available=false,error_kind={:?}",
                        err.kind()
                    ),
                    unsupported_reason: format!("io_uring runtime unavailable: {err}"),
                });
            }
        };
        let mut buf = [0_u8; 14];
        let n = file
            .read(&mut buf)
            .await
            .map_err(|err| format!("io_uring boundary read: {err}"))?;
        if &buf[..n] != b"uring-boundary" {
            return Err(format!(
                "io_uring boundary read drift: bytes={:?}",
                &buf[..n]
            ));
        }
        let pending_read = fs::uring::test_internals::drop_drains_pending_read(
            &dir.join("drop-drain-read.txt"),
            b"drop-drained-read",
        )
        .map_err(|err| format!("io_uring pending read drop-drain probe: {err}"))?;
        let pending_write = fs::uring::test_internals::drop_drains_pending_write(
            &dir.join("drop-drain-write.txt"),
            b"drop-drained-write",
        )
        .map_err(|err| format!("io_uring pending write drop-drain probe: {err}"))?;
        let pending_sync = fs::uring::test_internals::drop_drains_pending_sync(
            &dir.join("drop-drain-sync.txt"),
            b"sync-before-drop",
        )
        .map_err(|err| format!("io_uring pending sync drop-drain probe: {err}"))?;

        Ok(FsProofEvidence::supported(
            n as u64,
            format!(
                "kernel_inflight_cancel=not_assumed,drop_drains_pending_ops=read:{pending_read}|write:{pending_write}|sync:{pending_sync},drop_probes=fs::uring::test_internals::drop_drains_pending_read|drop_drains_pending_write|drop_drains_pending_sync,stale_completion_attribution=src/fs/uring.rs::test_uring_completion_attribution_ignores_unrelated_cqe"
            ),
        ))
    }
    #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
    {
        Ok(FsProofEvidence {
            bytes_actual: 0,
            metadata_actual:
                "io_uring_feature_enabled=false,kernel_inflight_cancel=false,spawn_blocking_fs_path_unaffected=true"
                    .to_string(),
            unsupported_reason: "io_uring filesystem cancellation proof requires linux target and io-uring feature"
                .to_string(),
        })
    }
}

async fn fs_proof_io_uring_unknown_completion_attribution(
    temp_root: &Path,
) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "io-uring-unknown-completion-attribution")?;

    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    {
        let payload = b"unknown-cqe-proof";
        fs::uring::test_internals::ignores_unknown_completion_before_read(
            &dir.join("unknown-cqe-read.txt"),
            payload,
        )
        .await
        .map_err(|err| format!("io_uring unknown read completion attribution probe: {err}"))?;
        fs::uring::test_internals::ignores_unknown_completion_before_write(
            &dir.join("unknown-cqe-write.txt"),
            payload,
        )
        .await
        .map_err(|err| format!("io_uring unknown write completion attribution probe: {err}"))?;
        fs::uring::test_internals::ignores_unknown_completion_before_sync(
            &dir.join("unknown-cqe-sync.txt"),
            payload,
        )
        .await
        .map_err(|err| format!("io_uring unknown sync completion attribution probe: {err}"))?;
        let truncated_len = fs::uring::test_internals::truncate_is_sync_boundary(
            &dir.join("truncate-sync-boundary.txt"),
            b"truncate-boundary",
            8,
        )
        .map_err(|err| format!("io_uring truncate boundary probe: {err}"))?;
        if truncated_len != 8 {
            return Err(format!(
                "io_uring truncate boundary drift: expected len=8 actual len={truncated_len}"
            ));
        }

        Ok(FsProofEvidence::supported(
            payload.len() as u64,
            "unknown_completion_ignored=true,tracked_read_matches_payload=true,tracked_write_matches_payload=true,tracked_sync_preserves_payload=true,truncate_boundary=ftruncate_sync_no_pending_ops",
        ))
    }
    #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
    {
        Ok(FsProofEvidence {
            bytes_actual: 0,
            metadata_actual:
                "io_uring_feature_enabled=false,unknown_completion_and_truncate_boundary_probe=unsupported".to_string(),
            unsupported_reason: "io_uring unknown-completion attribution proof requires linux target and io-uring feature"
                .to_string(),
        })
    }
}

async fn fs_proof_read_dir_drop_cancellation(temp_root: &Path) -> Result<FsProofEvidence, String> {
    let dir = fs_proof_scenario_dir(temp_root, "read-dir-drop-cancellation")?;
    for idx in 0..8 {
        fs::write(dir.join(format!("entry-{idx}.txt")), format!("entry-{idx}"))
            .await
            .map_err(|err| format!("write cancellation fixture {idx}: {err}"))?;
    }

    let mut entries = fs::read_dir(&dir)
        .await
        .map_err(|err| format!("read_dir open for cancellation drop: {err}"))?;
    let first = entries
        .next_entry()
        .await
        .map_err(|err| format!("read_dir first entry: {err}"))?
        .ok_or_else(|| "read_dir fixture unexpectedly empty".to_string())?;
    let first_name = first.file_name().to_string_lossy().to_string();
    drop(first);
    drop(entries);

    let metadata = fs::metadata(&dir)
        .await
        .map_err(|err| format!("metadata after dropping read_dir: {err}"))?;
    if !metadata.is_dir() {
        return Err("read_dir drop left scenario directory unavailable".to_string());
    }

    Ok(FsProofEvidence::supported(
        8,
        format!("dropped_after_first={first_name},dir_still_accessible=true"),
    ))
}

#[derive(Debug, Default)]
struct RealVfsTraversalEvidence {
    entries_seen: u64,
    directories_visited: u64,
    files_read: u64,
    bytes_read: u64,
    symlinks_seen: u64,
    symlinks_followed: u64,
    cycles_detected: u64,
    broken_links: u64,
    max_depth: usize,
    truncated: bool,
    pending_items_after_stop: usize,
    canonical_files: HashSet<PathBuf>,
}

impl RealVfsTraversalEvidence {
    fn metadata_summary(&self) -> String {
        format!(
            "entries={},dirs={},files={},bytes={},symlinks={},followed={},cycles={},broken={},max_depth={},truncated={},pending_after_stop={}",
            self.entries_seen,
            self.directories_visited,
            self.files_read,
            self.bytes_read,
            self.symlinks_seen,
            self.symlinks_followed,
            self.cycles_detected,
            self.broken_links,
            self.max_depth,
            self.truncated,
            self.pending_items_after_stop,
        )
    }
}

#[derive(Debug)]
struct RealVfsTraversalItem {
    path: PathBuf,
    depth: usize,
    ancestor_directories: Vec<PathBuf>,
}

async fn walk_real_vfs_tree(
    root: &Path,
    entry_budget: Option<usize>,
) -> Result<RealVfsTraversalEvidence, String> {
    let vfs = fs::UnixVfs::new();
    let mut evidence = RealVfsTraversalEvidence::default();
    let mut visited_directories = HashSet::new();
    let mut pending = vec![RealVfsTraversalItem {
        path: root.to_path_buf(),
        depth: 0,
        ancestor_directories: Vec::new(),
    }];

    while let Some(item) = pending.pop() {
        if entry_budget.is_some_and(|budget| evidence.entries_seen as usize >= budget) {
            evidence.truncated = true;
            pending.push(item);
            break;
        }

        evidence.entries_seen += 1;
        evidence.max_depth = evidence.max_depth.max(item.depth);
        let link_metadata = vfs
            .symlink_metadata(&item.path)
            .await
            .map_err(|err| format!("symlink_metadata {}: {err}", item.path.display()))?;

        if link_metadata.is_symlink() {
            evidence.symlinks_seen += 1;
            vfs.read_link(&item.path)
                .await
                .map_err(|err| format!("read_link {}: {err}", item.path.display()))?;

            let canonical_target = match vfs.canonicalize(&item.path).await {
                Ok(target) => target,
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    evidence.broken_links += 1;
                    continue;
                }
                Err(err) => {
                    return Err(format!(
                        "canonicalize symlink {}: {:?}: {err}",
                        item.path.display(),
                        err.kind()
                    ));
                }
            };

            if item.ancestor_directories.contains(&canonical_target) {
                evidence.cycles_detected += 1;
                continue;
            }

            evidence.symlinks_followed += 1;
            let target_metadata = vfs.metadata(&item.path).await.map_err(|err| {
                format!("metadata through symlink {}: {err}", item.path.display())
            })?;
            if target_metadata.is_file() {
                if evidence.canonical_files.insert(canonical_target) {
                    let bytes = vfs.read(&item.path).await.map_err(|err| {
                        format!("read through symlink {}: {err}", item.path.display())
                    })?;
                    evidence.files_read += 1;
                    evidence.bytes_read += bytes.len() as u64;
                }
                continue;
            }
            if !target_metadata.is_dir() {
                continue;
            }
            if !visited_directories.insert(canonical_target.clone()) {
                continue;
            }

            evidence.directories_visited += 1;
            let mut read_dir = vfs.read_dir(&item.path).await.map_err(|err| {
                format!("read_dir through symlink {}: {err}", item.path.display())
            })?;
            let mut children = Vec::new();
            while let Some(entry) = read_dir.next_entry().await.map_err(|err| {
                format!("next_entry through symlink {}: {err}", item.path.display())
            })? {
                children.push(entry.path());
            }
            drop(read_dir);
            children.sort();
            let mut ancestors = item.ancestor_directories;
            ancestors.push(canonical_target);
            for child in children.into_iter().rev() {
                pending.push(RealVfsTraversalItem {
                    path: child,
                    depth: item.depth + 1,
                    ancestor_directories: ancestors.clone(),
                });
            }
            continue;
        }

        if link_metadata.is_file() {
            let canonical_file = vfs
                .canonicalize(&item.path)
                .await
                .map_err(|err| format!("canonicalize file {}: {err}", item.path.display()))?;
            if evidence.canonical_files.insert(canonical_file) {
                let bytes = vfs
                    .read(&item.path)
                    .await
                    .map_err(|err| format!("read file {}: {err}", item.path.display()))?;
                evidence.files_read += 1;
                evidence.bytes_read += bytes.len() as u64;
            }
            continue;
        }

        if !link_metadata.is_dir() {
            continue;
        }
        let canonical_directory = vfs
            .canonicalize(&item.path)
            .await
            .map_err(|err| format!("canonicalize directory {}: {err}", item.path.display()))?;
        if item.ancestor_directories.contains(&canonical_directory) {
            evidence.cycles_detected += 1;
            continue;
        }
        if !visited_directories.insert(canonical_directory.clone()) {
            continue;
        }

        evidence.directories_visited += 1;
        let mut read_dir = vfs
            .read_dir(&item.path)
            .await
            .map_err(|err| format!("read_dir {}: {err}", item.path.display()))?;
        let mut children = Vec::new();
        while let Some(entry) = read_dir
            .next_entry()
            .await
            .map_err(|err| format!("next_entry {}: {err}", item.path.display()))?
        {
            children.push(entry.path());
        }
        drop(read_dir);
        children.sort();
        let mut ancestors = item.ancestor_directories;
        ancestors.push(canonical_directory);
        for child in children.into_iter().rev() {
            pending.push(RealVfsTraversalItem {
                path: child,
                depth: item.depth + 1,
                ancestor_directories: ancestors.clone(),
            });
        }
    }

    evidence.pending_items_after_stop = pending.len();
    Ok(evidence)
}

async fn fs_proof_dormant_normal_traversal(temp_root: &Path) -> Result<FsProofEvidence, String> {
    let root = temp_root.join("dormant-fs-normal-recursive-traversal");
    let vfs = fs::UnixVfs::new();
    vfs.create_dir_all(&root.join("alpha/beta"))
        .await
        .map_err(|err| format!("create nested normal fixture: {err}"))?;
    vfs.create_dir(&root.join("empty-dir"))
        .await
        .map_err(|err| format!("create empty normal fixture: {err}"))?;
    vfs.write(&root.join("empty.bin"), b"")
        .await
        .map_err(|err| format!("write empty normal fixture: {err}"))?;
    vfs.write(&root.join("alpha/alpha.txt"), b"alpha")
        .await
        .map_err(|err| format!("write nested normal fixture: {err}"))?;
    vfs.write(&root.join("alpha/beta/omega.txt"), b"omega")
        .await
        .map_err(|err| format!("write deep normal fixture: {err}"))?;
    let large = vec![0x5a; 256 * 1024];
    vfs.write(&root.join("large.bin"), &large)
        .await
        .map_err(|err| format!("write large normal fixture: {err}"))?;

    let evidence = walk_real_vfs_tree(&root, None).await?;
    let expected_bytes = large.len() as u64 + 10;
    if evidence.directories_visited != 4
        || evidence.files_read != 4
        || evidence.bytes_read != expected_bytes
        || evidence.symlinks_seen != 0
        || evidence.truncated
    {
        return Err(format!(
            "normal traversal drift: {} expected_dirs=4 expected_files=4 expected_bytes={expected_bytes}",
            evidence.metadata_summary()
        ));
    }

    Ok(FsProofEvidence::supported(
        evidence.bytes_read,
        evidence.metadata_summary(),
    ))
}

#[cfg(unix)]
async fn fs_proof_dormant_simple_symlinks_unix(
    temp_root: &Path,
) -> Result<FsProofEvidence, String> {
    let root = temp_root.join("dormant-fs-simple-symlink-traversal");
    let vfs = fs::UnixVfs::new();
    vfs.create_dir_all(&root.join("targets/nested"))
        .await
        .map_err(|err| format!("create simple symlink targets: {err}"))?;
    vfs.create_dir(&root.join("links"))
        .await
        .map_err(|err| format!("create simple symlink links dir: {err}"))?;
    vfs.write(&root.join("targets/target.txt"), b"target")
        .await
        .map_err(|err| format!("write simple symlink file target: {err}"))?;
    vfs.write(&root.join("targets/nested/nested.txt"), b"nested")
        .await
        .map_err(|err| format!("write simple symlink dir target: {err}"))?;
    fs::symlink(
        root.join("targets/target.txt"),
        root.join("links/link-file"),
    )
    .await
    .map_err(|err| format!("create simple file symlink: {err}"))?;
    fs::symlink(root.join("targets/nested"), root.join("links/link-dir"))
        .await
        .map_err(|err| format!("create simple directory symlink: {err}"))?;

    let evidence = walk_real_vfs_tree(&root, None).await?;
    if evidence.files_read != 2
        || evidence.bytes_read != 12
        || evidence.symlinks_seen != 2
        || evidence.symlinks_followed != 2
        || evidence.cycles_detected != 0
        || evidence.broken_links != 0
    {
        return Err(format!(
            "simple symlink traversal drift: {}",
            evidence.metadata_summary()
        ));
    }
    Ok(FsProofEvidence::supported(
        evidence.bytes_read,
        evidence.metadata_summary(),
    ))
}

#[cfg(unix)]
async fn fs_proof_dormant_circular_symlinks_unix(
    temp_root: &Path,
) -> Result<FsProofEvidence, String> {
    let root = temp_root.join("dormant-fs-circular-symlink-detection");
    let vfs = fs::UnixVfs::new();
    for name in ["a", "b", "c", "self"] {
        vfs.create_dir_all(&root.join(name))
            .await
            .map_err(|err| format!("create circular directory {name}: {err}"))?;
        vfs.write(
            &root.join(name).join(format!("{name}.txt")),
            name.as_bytes(),
        )
        .await
        .map_err(|err| format!("write circular file {name}: {err}"))?;
    }
    fs::symlink(root.join("b"), root.join("a/to-b"))
        .await
        .map_err(|err| format!("create a-to-b symlink: {err}"))?;
    fs::symlink(root.join("c"), root.join("b/to-c"))
        .await
        .map_err(|err| format!("create b-to-c symlink: {err}"))?;
    fs::symlink(root.join("a"), root.join("c/to-a"))
        .await
        .map_err(|err| format!("create c-to-a symlink: {err}"))?;
    fs::symlink(root.join("self"), root.join("self/to-self"))
        .await
        .map_err(|err| format!("create self symlink: {err}"))?;

    let evidence = walk_real_vfs_tree(&root, None).await?;
    if evidence.directories_visited != 5
        || evidence.files_read != 4
        || evidence.bytes_read != 7
        || evidence.symlinks_seen != 4
        || evidence.cycles_detected != 2
        || evidence.entries_seen > 16
    {
        return Err(format!(
            "circular symlink traversal drift: {}",
            evidence.metadata_summary()
        ));
    }
    Ok(FsProofEvidence::supported(
        evidence.bytes_read,
        evidence.metadata_summary(),
    ))
}

#[cfg(unix)]
async fn fs_proof_dormant_broken_symlinks_unix(
    temp_root: &Path,
) -> Result<FsProofEvidence, String> {
    let root = temp_root.join("dormant-fs-broken-symlink-handling");
    let vfs = fs::UnixVfs::new();
    vfs.create_dir_all(&root)
        .await
        .map_err(|err| format!("create broken symlink root: {err}"))?;
    vfs.write(&root.join("valid.txt"), b"valid")
        .await
        .map_err(|err| format!("write broken symlink control file: {err}"))?;
    fs::symlink(root.join("never-created"), root.join("missing-link"))
        .await
        .map_err(|err| format!("create missing-target symlink: {err}"))?;
    let removed_target = root.join("removed-target");
    vfs.write(&removed_target, b"remove-me")
        .await
        .map_err(|err| format!("write removed symlink target: {err}"))?;
    fs::symlink(&removed_target, root.join("removed-link"))
        .await
        .map_err(|err| format!("create removed-target symlink: {err}"))?;
    vfs.remove_file(&removed_target)
        .await
        .map_err(|err| format!("remove symlink target: {err}"))?;

    let evidence = walk_real_vfs_tree(&root, None).await?;
    if evidence.files_read != 1
        || evidence.bytes_read != 5
        || evidence.symlinks_seen != 2
        || evidence.broken_links != 2
        || evidence.cycles_detected != 0
    {
        return Err(format!(
            "broken symlink traversal drift: {}",
            evidence.metadata_summary()
        ));
    }
    Ok(FsProofEvidence::supported(
        evidence.bytes_read,
        evidence.metadata_summary(),
    ))
}

#[cfg(unix)]
async fn fs_proof_dormant_mixed_symlinks_unix(temp_root: &Path) -> Result<FsProofEvidence, String> {
    let root = temp_root.join("dormant-fs-mixed-symlink-tree");
    let vfs = fs::UnixVfs::new();
    vfs.create_dir_all(&root.join("real/tree"))
        .await
        .map_err(|err| format!("create mixed real tree: {err}"))?;
    vfs.create_dir_all(&root.join("cycle"))
        .await
        .map_err(|err| format!("create mixed cycle dir: {err}"))?;
    vfs.write(&root.join("real/tree/data.txt"), b"mixed-data")
        .await
        .map_err(|err| format!("write mixed data file: {err}"))?;
    vfs.write(&root.join("real/root.txt"), b"root-data")
        .await
        .map_err(|err| format!("write mixed root file: {err}"))?;
    fs::symlink(root.join("real/tree"), root.join("link-to-tree"))
        .await
        .map_err(|err| format!("create mixed directory link: {err}"))?;
    fs::symlink(root.join("real/root.txt"), root.join("link-to-file"))
        .await
        .map_err(|err| format!("create mixed file link: {err}"))?;
    fs::symlink(root.join("cycle"), root.join("cycle/back"))
        .await
        .map_err(|err| format!("create mixed cycle link: {err}"))?;
    fs::symlink(root.join("missing"), root.join("broken"))
        .await
        .map_err(|err| format!("create mixed broken link: {err}"))?;

    let evidence = walk_real_vfs_tree(&root, None).await?;
    if evidence.files_read != 2
        || evidence.bytes_read != 19
        || evidence.symlinks_seen != 4
        || evidence.cycles_detected != 1
        || evidence.broken_links != 1
        || evidence.truncated
    {
        return Err(format!(
            "mixed symlink traversal drift: {}",
            evidence.metadata_summary()
        ));
    }
    Ok(FsProofEvidence::supported(
        evidence.bytes_read,
        evidence.metadata_summary(),
    ))
}

#[cfg(unix)]
async fn fs_proof_dormant_cross_root_vfs_unix(temp_root: &Path) -> Result<FsProofEvidence, String> {
    let root = temp_root.join("dormant-fs-cross-root-vfs-traversal");
    let root_a = root.join("root-a");
    let root_b = root.join("root-b");
    let vfs = fs::UnixVfs::new();
    vfs.create_dir_all(&root_a)
        .await
        .map_err(|err| format!("create cross-root a: {err}"))?;
    vfs.create_dir_all(&root_b)
        .await
        .map_err(|err| format!("create cross-root b: {err}"))?;
    vfs.write(&root_a.join("a.txt"), b"root-a")
        .await
        .map_err(|err| format!("write cross-root a file: {err}"))?;
    let root_b_file = root_b.join("b.txt");
    vfs.write(&root_b_file, b"root-b")
        .await
        .map_err(|err| format!("write cross-root b file: {err}"))?;
    fs::symlink(&root_b, root_a.join("to-b"))
        .await
        .map_err(|err| format!("create cross-root a-to-b link: {err}"))?;
    fs::symlink(&root_a, root_b.join("to-a"))
        .await
        .map_err(|err| format!("create cross-root b-to-a link: {err}"))?;

    let evidence = walk_real_vfs_tree(&root_a, None).await?;
    let canonical_b_file = vfs
        .canonicalize(&root_b_file)
        .await
        .map_err(|err| format!("canonicalize cross-root b file: {err}"))?;
    if evidence.directories_visited != 2
        || evidence.files_read != 2
        || evidence.bytes_read != 12
        || evidence.symlinks_seen != 2
        || evidence.cycles_detected != 1
        || !evidence.canonical_files.contains(&canonical_b_file)
    {
        return Err(format!(
            "cross-root VFS traversal drift: {}",
            evidence.metadata_summary()
        ));
    }
    Ok(FsProofEvidence::supported(
        evidence.bytes_read,
        format!(
            "{},cross_root_file_observed=true,mount_isolation_claim=false",
            evidence.metadata_summary()
        ),
    ))
}

async fn fs_proof_dormant_partial_traversal(temp_root: &Path) -> Result<FsProofEvidence, String> {
    let root = temp_root.join("dormant-fs-bounded-partial-traversal");
    let vfs = fs::UnixVfs::new();
    for dir_idx in 0..4 {
        let dir = root.join(format!("dir-{dir_idx}"));
        vfs.create_dir_all(&dir)
            .await
            .map_err(|err| format!("create partial traversal dir {dir_idx}: {err}"))?;
        for file_idx in 0..4 {
            let payload = format!("payload-{dir_idx}{file_idx}");
            vfs.write(
                &dir.join(format!("file-{file_idx}.txt")),
                payload.as_bytes(),
            )
            .await
            .map_err(|err| format!("write partial traversal file {dir_idx}/{file_idx}: {err}"))?;
        }
    }

    let partial = walk_real_vfs_tree(&root, Some(5)).await?;
    let complete = walk_real_vfs_tree(&root, None).await?;
    if !partial.truncated
        || partial.entries_seen != 5
        || partial.pending_items_after_stop == 0
        || complete.truncated
        || complete.entries_seen != 21
        || complete.directories_visited != 5
        || complete.files_read != 16
        || complete.bytes_read != 160
    {
        return Err(format!(
            "bounded partial traversal drift: partial=({}) complete=({})",
            partial.metadata_summary(),
            complete.metadata_summary()
        ));
    }
    Ok(FsProofEvidence::supported(
        complete.bytes_read,
        format!(
            "partial=({}),complete=({}),all_iterators_dropped=true",
            partial.metadata_summary(),
            complete.metadata_summary()
        ),
    ))
}

fn unsupported_unix_symlink_traversal(scenario_id: &str) -> FsProofEvidence {
    FsProofEvidence {
        bytes_actual: 0,
        metadata_actual: format!("scenario={scenario_id},unsupported_platform=non_unix"),
        unsupported_reason: "real symlink traversal recovery requires Unix symlink support"
            .to_string(),
    }
}

async fn fs_proof_dormant_simple_symlinks(temp_root: &Path) -> Result<FsProofEvidence, String> {
    #[cfg(unix)]
    {
        fs_proof_dormant_simple_symlinks_unix(temp_root).await
    }
    #[cfg(not(unix))]
    {
        let _ = temp_root;
        Ok(unsupported_unix_symlink_traversal(
            "dormant-fs-simple-symlink-traversal",
        ))
    }
}

async fn fs_proof_dormant_circular_symlinks(temp_root: &Path) -> Result<FsProofEvidence, String> {
    #[cfg(unix)]
    {
        fs_proof_dormant_circular_symlinks_unix(temp_root).await
    }
    #[cfg(not(unix))]
    {
        let _ = temp_root;
        Ok(unsupported_unix_symlink_traversal(
            "dormant-fs-circular-symlink-detection",
        ))
    }
}

async fn fs_proof_dormant_broken_symlinks(temp_root: &Path) -> Result<FsProofEvidence, String> {
    #[cfg(unix)]
    {
        fs_proof_dormant_broken_symlinks_unix(temp_root).await
    }
    #[cfg(not(unix))]
    {
        let _ = temp_root;
        Ok(unsupported_unix_symlink_traversal(
            "dormant-fs-broken-symlink-handling",
        ))
    }
}

async fn fs_proof_dormant_mixed_symlinks(temp_root: &Path) -> Result<FsProofEvidence, String> {
    #[cfg(unix)]
    {
        fs_proof_dormant_mixed_symlinks_unix(temp_root).await
    }
    #[cfg(not(unix))]
    {
        let _ = temp_root;
        Ok(unsupported_unix_symlink_traversal(
            "dormant-fs-mixed-symlink-tree",
        ))
    }
}

async fn fs_proof_dormant_cross_root_vfs(temp_root: &Path) -> Result<FsProofEvidence, String> {
    #[cfg(unix)]
    {
        fs_proof_dormant_cross_root_vfs_unix(temp_root).await
    }
    #[cfg(not(unix))]
    {
        let _ = temp_root;
        Ok(unsupported_unix_symlink_traversal(
            "dormant-fs-cross-root-vfs-traversal",
        ))
    }
}

async fn fs_parity_wave2_run() -> io::Result<Vec<Value>> {
    let bead_id = std::env::var("ASUPERSYNC_FS_PARITY_BEAD_ID")
        .unwrap_or_else(|_| "asupersync-oc0ybw".to_string());
    let temp = tempfile::Builder::new()
        .prefix("asupersync_fs_parity_wave2_")
        .tempdir()?;
    let temp_root = temp.path().to_path_buf();

    let scenarios = vec![
        FsProofScenario {
            scenario_id: "open-options-seek-sync",
            api: "File/OpenOptions",
            operation: "open_write_sync_seek_read_metadata",
            bytes_expected: 10,
            metadata_expected: "len=10,is_file=true,seek_window=456",
            cancellation_point: "none",
            result: fs_proof_open_options_seek_sync(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "open-options-append-truncate",
            api: "OpenOptions",
            operation: "append_preserves_existing_truncate_clears",
            bytes_expected: 1,
            metadata_expected: "appended=alpha_beta,truncated=z,len=1",
            cancellation_point: "none",
            result: fs_proof_open_options_append_truncate(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "file-create-new-exclusive",
            api: "File::create_new",
            operation: "atomic_create_new_read_write_second_open_rejects",
            bytes_expected: 16,
            metadata_expected: "read_write=true,second_error=AlreadyExists",
            cancellation_point: "none",
            result: fs_proof_file_create_new_exclusive(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "file-clone-position-rewind",
            api: "File",
            operation: "try_clone_shared_cursor_stream_position_rewind",
            bytes_expected: 6,
            metadata_expected: "first=ab,original_position=2,clone_position_after_original_read=2,clone_next=cd,original_position_after_clone_read=4,clone_position_after_rewind=0,rewound=abc",
            cancellation_point: "none",
            result: fs_proof_file_clone_position_rewind(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "file-set-len-permissions",
            api: "File",
            operation: "set_len_truncate_extend_set_permissions",
            bytes_expected: 10,
            metadata_expected: "truncated=abcd,extended_len=10,readonly_roundtrip=true",
            cancellation_point: "none",
            result: fs_proof_file_set_len_permissions(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "read-dir-metadata-disposition",
            api: "ReadDir/DirEntry",
            operation: "read_dir_next_entry_file_type",
            bytes_expected: 3,
            metadata_expected: "entries=[alpha.txt,beta.txt,nested],file_count=2,dir_count=1",
            cancellation_point: "none",
            result: fs_proof_read_dir_metadata(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "buffered-lines-boundaries",
            api: "BufReader/Lines",
            operation: "buffered_line_iteration_empty_and_final_unterminated",
            bytes_expected: 22,
            metadata_expected: "lines=[alpha,,beta-no-newline],capacity=4",
            cancellation_point: "none",
            result: fs_proof_buffered_lines(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "buf-writer-flush-visibility",
            api: "BufWriter",
            operation: "buffered_write_flush_visibility",
            bytes_expected: 8,
            metadata_expected: "buffered_before_flush=8,disk_before_flush=0,disk_after_flush=buffered,capacity=16",
            cancellation_point: "none",
            result: fs_proof_buf_writer_flush_visibility(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "write-atomic-replace-cleanup",
            api: "path_ops::write_atomic",
            operation: "write_replace_preserve_permissions_cleanup_temp",
            bytes_expected: 11,
            metadata_expected: fs_proof_write_atomic_metadata_expected(),
            cancellation_point: "none",
            result: fs_proof_write_atomic_replace_cleanup(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "dir-create-remove-boundaries",
            api: "dir",
            operation: "create_dir_create_dir_all_remove_dir_remove_dir_all",
            bytes_expected: 4,
            metadata_expected: "single_removed=true,nested_created=true,nonempty_error=DirectoryNotEmpty,recursive_removed=true",
            cancellation_point: "none",
            result: fs_proof_dir_create_remove_boundaries(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "unix-vfs-equivalence",
            api: "UnixVfs/VfsFile",
            operation: "vfs_write_direct_read_vfs_copy_metadata",
            bytes_expected: 14,
            metadata_expected: "unix_vfs_matches_direct_fs_read_copy_metadata",
            cancellation_point: "none",
            result: fs_proof_unix_vfs_equivalence(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "error-kind-remove-missing",
            api: "path_ops::remove_file",
            operation: "missing_path_error_mapping",
            bytes_expected: 0,
            metadata_expected: "error_kind=NotFound,path_absent=true",
            cancellation_point: "none",
            result: fs_proof_remove_missing_error_kind(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "error-kind-invalid-utf8-read-to-string",
            api: "path_ops::read_to_string",
            operation: "invalid_utf8_error_mapping",
            bytes_expected: 3,
            metadata_expected: "read_bytes=3,read_to_string_error=InvalidData",
            cancellation_point: "none",
            result: fs_proof_invalid_utf8_read_to_string(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "error-kind-create-dir-existing-file",
            api: "dir::create_dir",
            operation: "existing_file_error_mapping",
            bytes_expected: 0,
            metadata_expected: "error_kind=AlreadyExists,existing_file_preserved=true",
            cancellation_point: "none",
            result: fs_proof_create_dir_existing_file_error_kind(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "error-kind-read-dir-non-directory",
            api: "read_dir",
            operation: "regular_file_error_mapping",
            bytes_expected: 9,
            metadata_expected: "error_kind=NotADirectory,existing_file_preserved=true,len=9",
            cancellation_point: "none",
            result: fs_proof_read_dir_non_directory_error_kind(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "try-exists-lifecycle",
            api: "try_exists",
            operation: "missing_create_remove_transitions",
            bytes_expected: 3,
            metadata_expected: "exists_sequence=false,true,false",
            cancellation_point: "none",
            result: fs_proof_try_exists_lifecycle(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "path-ops-copy-hardlink-rename",
            api: "path_ops",
            operation: "write_copy_hard_link_rename_canonicalize",
            bytes_expected: 8,
            metadata_expected: "copy_len=8,hard_link_matches=true,rename_removed_source_copy=true,canonicalized=true",
            cancellation_point: "none",
            result: fs_proof_path_ops_copy_hardlink_rename(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "unix-symlink-metadata-readlink",
            api: "path_ops::symlink_metadata",
            operation: "symlink_read_link_metadata_follow_boundary",
            bytes_expected: 14,
            metadata_expected: "read_link_matches_target=true,symlink_metadata_is_symlink=true,metadata_follows_to_file=true",
            cancellation_point: "none",
            result: fs_proof_unix_symlink_metadata_readlink(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "io-uring-cancellation-support-boundary",
            api: "IoUringFile",
            operation: "drop_pending_operation_boundary",
            bytes_expected: 14,
            metadata_expected: "kernel_inflight_cancel=not_assumed,drop_drains_pending_ops=read|write|sync_or_unsupported,stale_completion_attribution=true_or_unsupported",
            cancellation_point: "drop_pending_read",
            result: fs_proof_io_uring_cancellation_support_boundary(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "io-uring-unknown-completion-attribution",
            api: "IoUringFile",
            operation: "unknown_completion_before_tracked_read_write_sync",
            bytes_expected: 17,
            metadata_expected: "unknown_completion_ignored=true,tracked_read_matches_payload=true,tracked_write_matches_payload=true,tracked_sync_preserves_payload=true,truncate_boundary=ftruncate_sync_no_pending_ops",
            cancellation_point: "unknown_cqe_before_read",
            result: fs_proof_io_uring_unknown_completion_attribution(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "read-dir-drop-cancellation",
            api: "ReadDir",
            operation: "drop_iterator_after_first_entry",
            bytes_expected: 8,
            metadata_expected: "dropped_after_first_entry,dir_still_accessible=true",
            cancellation_point: "drop_after_first_entry",
            result: fs_proof_read_dir_drop_cancellation(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "dormant-fs-normal-recursive-traversal",
            api: "UnixVfs/Vfs/ReadDir",
            operation: "real_recursive_empty_large_nested_file_traversal",
            bytes_expected: 262_154,
            metadata_expected: "dirs=4,files=4,bytes=262154,symlinks=0,truncated=false",
            cancellation_point: "none_all_operations_awaited",
            result: fs_proof_dormant_normal_traversal(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "dormant-fs-simple-symlink-traversal",
            api: "UnixVfs/Vfs/ReadDir/fs::symlink",
            operation: "real_file_and_directory_symlink_traversal",
            bytes_expected: 12,
            metadata_expected: "files=2,symlinks=2,followed=2,cycles=0,broken=0",
            cancellation_point: "none_all_operations_awaited",
            result: fs_proof_dormant_simple_symlinks(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "dormant-fs-circular-symlink-detection",
            api: "UnixVfs/Vfs/ReadDir/fs::symlink",
            operation: "real_three_directory_and_self_cycle_traversal",
            bytes_expected: 7,
            metadata_expected: "dirs=5,files=4,symlinks=4,cycles=2,entries_bounded=true",
            cancellation_point: "cycle_detected_before_revisit",
            result: fs_proof_dormant_circular_symlinks(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "dormant-fs-broken-symlink-handling",
            api: "UnixVfs/Vfs/ReadDir/fs::symlink",
            operation: "real_never_created_and_removed_target_handling",
            bytes_expected: 5,
            metadata_expected: "files=1,symlinks=2,broken=2,cycles=0",
            cancellation_point: "none_all_operations_awaited",
            result: fs_proof_dormant_broken_symlinks(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "dormant-fs-mixed-symlink-tree",
            api: "UnixVfs/Vfs/ReadDir/fs::symlink",
            operation: "real_files_directories_valid_cycle_and_broken_links",
            bytes_expected: 19,
            metadata_expected: "files=2,symlinks=4,cycles=1,broken=1,truncated=false",
            cancellation_point: "cycle_detected_before_revisit",
            result: fs_proof_dormant_mixed_symlinks(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "dormant-fs-cross-root-vfs-traversal",
            api: "UnixVfs/Vfs/ReadDir/fs::symlink",
            operation: "real_cross_root_bidirectional_symlink_traversal",
            bytes_expected: 12,
            metadata_expected: "dirs=2,files=2,symlinks=2,cycles=1,cross_root_file_observed=true,mount_isolation_claim=false",
            cancellation_point: "cross_root_cycle_detected_before_revisit",
            result: fs_proof_dormant_cross_root_vfs(&temp_root).await,
        },
        FsProofScenario {
            scenario_id: "dormant-fs-bounded-partial-traversal",
            api: "UnixVfs/Vfs/ReadDir",
            operation: "entry_budget_stop_drop_iterators_then_complete_replay",
            bytes_expected: 160,
            metadata_expected: "partial_entries=5,pending_after_stop_positive,complete_entries=21,files=16,all_iterators_dropped=true",
            cancellation_point: "entry_budget_exhausted",
            result: fs_proof_dormant_partial_traversal(&temp_root).await,
        },
    ];

    let cleanup_status = match temp.close() {
        Ok(()) => "removed".to_string(),
        Err(err) => format!("failed:{err}"),
    };
    let rows: Vec<Value> = scenarios
        .iter()
        .map(|scenario| fs_parity_row(&bead_id, scenario, &temp_root, &cleanup_status))
        .collect();

    if let Some(output_dir) = std::env::var_os("ASUPERSYNC_FS_PARITY_PROOF_DIR") {
        let output_dir = PathBuf::from(output_dir);
        std::fs::create_dir_all(&output_dir)?;
        let rows_path = output_dir.join("test_rows.jsonl");
        let mut rows_file = std::fs::File::create(&rows_path)?;
        for row in &rows {
            use std::io::Write as _;
            writeln!(rows_file, "{row}")?;
        }
        let pass_count = rows
            .iter()
            .filter(|row| row["verdict"].as_str() == Some("pass"))
            .count();
        let skip_count = rows
            .iter()
            .filter(|row| row["verdict"].as_str() == Some("skip"))
            .count();
        let fail_count = rows
            .iter()
            .filter(|row| row["verdict"].as_str() == Some("fail"))
            .count();
        let test_report = json!({
            "bead_id": bead_id,
            "scenario_count": rows.len(),
            "pass_count": pass_count,
            "skip_count": skip_count,
            "fail_count": fail_count,
            "expected_scenarios": FS_PARITY_WAVE2_SCENARIOS,
            "required_row_fields": FS_PARITY_WAVE2_ROW_FIELDS,
            "temp_root": temp_root.display().to_string(),
            "cleanup_status": cleanup_status,
            "rows_path": rows_path.display().to_string(),
            "validation_passed": fail_count == 0,
        });
        let report_bytes = serde_json::to_vec_pretty(&test_report).map_err(io::Error::other)?;
        std::fs::write(output_dir.join("test_report.json"), report_bytes)?;
    }

    Ok(rows)
}

#[test]
fn fs_parity_wave2_proof_runner_logs_required_scenarios() {
    common::init_test_logging();
    let rows = future::block_on(fs_parity_wave2_run()).expect("fs parity proof runner");
    for row in &rows {
        println!("{row}");
    }

    let missing: Vec<_> = FS_PARITY_WAVE2_SCENARIOS
        .iter()
        .copied()
        .filter(|scenario_id| {
            !rows
                .iter()
                .any(|row| row["scenario_id"].as_str() == Some(*scenario_id))
        })
        .collect();
    let drifts: Vec<_> = rows
        .iter()
        .filter(|row| match row["verdict"].as_str() {
            Some("pass") => false,
            Some("skip") => row["unsupported_reason"].as_str().is_none_or(str::is_empty),
            _ => true,
        })
        .collect();
    let missing_fields: Vec<_> = rows
        .iter()
        .flat_map(|row| {
            FS_PARITY_WAVE2_ROW_FIELDS
                .iter()
                .copied()
                .filter(|field| {
                    !row.as_object()
                        .is_some_and(|object| object.contains_key(*field))
                })
                .map(|field| {
                    (
                        row["scenario_id"]
                            .as_str()
                            .unwrap_or("<missing>")
                            .to_string(),
                        field,
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let invalid_io_uring_rows: Vec<_> = rows
        .iter()
        .filter(|row| {
            row["scenario_id"]
                .as_str()
                .is_some_and(|scenario_id| scenario_id.starts_with("io-uring-"))
        })
        .filter(|row| {
            row["backend"].as_str() != Some("io_uring")
                || !matches!(row["verdict"].as_str(), Some("pass" | "skip"))
                || (row["verdict"].as_str() == Some("skip")
                    && row["unsupported_reason"].as_str().is_none_or(str::is_empty))
        })
        .collect();

    assert!(
        missing.is_empty(),
        "missing fs parity proof scenarios: {missing:?}"
    );
    assert!(
        missing_fields.is_empty(),
        "fs parity proof rows missing required fields: {missing_fields:?}"
    );
    assert!(
        invalid_io_uring_rows.is_empty(),
        "invalid io_uring proof rows: {invalid_io_uring_rows:#?}"
    );
    assert!(
        drifts.is_empty(),
        "fs parity proof failures or skips without unsupported_reason: {drifts:#?}"
    );
    assert_eq!(rows.len(), FS_PARITY_WAVE2_SCENARIOS.len());
}

// === File Operations ===

#[test]
fn e2e_file_create_write_read_roundtrip() {
    common::init_test_logging();
    let base = unique_temp_dir("file_rw");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let path = base.join("hello.txt");
        let mut file = fs::File::create(&path).await.unwrap();
        file.write_all(b"hello e2e").await.unwrap();
        file.sync_all().await.unwrap();
        drop(file);

        let mut file = fs::File::open(&path).await.unwrap();
        let mut buf = String::new();
        file.read_to_string(&mut buf).await.unwrap();
        assert_eq!(buf, "hello e2e");
    });

    cleanup(&base);
}

#[test]
fn e2e_file_open_options_combinations() {
    common::init_test_logging();
    let base = unique_temp_dir("open_opts");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let path = base.join("opts.txt");

        // create + write
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&path)
            .await
            .unwrap();
        f.write_all(b"first").await.unwrap();
        drop(f);

        // append
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .await
            .unwrap();
        f.write_all(b"_second").await.unwrap();
        drop(f);

        let contents = fs::read_to_string(&path).await.unwrap();
        assert_eq!(contents, "first_second");

        // truncate
        let mut f = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .await
            .unwrap();
        f.write_all(b"new").await.unwrap();
        drop(f);

        let contents = fs::read_to_string(&path).await.unwrap();
        assert_eq!(contents, "new");
    });

    cleanup(&base);
}

#[test]
fn e2e_file_set_len_and_metadata() {
    common::init_test_logging();
    let base = unique_temp_dir("set_len");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let path = base.join("trunc.txt");
        fs::write(&path, b"hello world 12345").await.unwrap();

        let file = fs::File::open(&path).await.unwrap();
        let meta = file.metadata().await.unwrap();
        assert_eq!(meta.len(), 17);
        assert!(meta.is_file());
        drop(file);

        let file = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .await
            .unwrap();
        file.set_len(5).await.unwrap();
        file.sync_all().await.unwrap();
        drop(file);

        let contents = fs::read_to_string(&path).await.unwrap();
        assert_eq!(contents, "hello");
    });

    cleanup(&base);
}

// === Path Operations ===

#[test]
fn e2e_path_read_write_roundtrip() {
    common::init_test_logging();
    let base = unique_temp_dir("path_rw");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let path = base.join("data.bin");
        let data: Vec<u8> = (0u8..=255).collect();
        fs::write(&path, &data).await.unwrap();

        let read_back = fs::read(&path).await.unwrap();
        assert_eq!(read_back, data);

        let as_str = fs::read_to_string(base.join("data.bin")).await;
        // binary data won't be valid utf8
        assert!(as_str.is_err());
    });

    cleanup(&base);
}

#[test]
fn e2e_try_exists_transitions() {
    common::init_test_logging();
    let base = unique_temp_dir("try_exists");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let path = base.join("probe.txt");
        assert!(!fs::try_exists(&path).await.unwrap());

        fs::write(&path, b"present").await.unwrap();
        assert!(fs::try_exists(&path).await.unwrap());

        fs::remove_file(&path).await.unwrap();
        assert!(!fs::try_exists(&path).await.unwrap());
    });

    cleanup(&base);
}

#[test]
fn e2e_copy_rename_remove_chain() {
    common::init_test_logging();
    let base = unique_temp_dir("copy_chain");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let src = base.join("src.txt");
        let copied = base.join("copied.txt");
        let renamed = base.join("renamed.txt");

        fs::write(&src, b"chain test").await.unwrap();

        // copy
        let bytes = fs::copy(&src, &copied).await.unwrap();
        assert_eq!(bytes, 10);
        assert!(copied.exists());

        // rename
        fs::rename(&copied, &renamed).await.unwrap();
        assert!(!copied.exists());
        assert!(renamed.exists());

        let contents = fs::read_to_string(&renamed).await.unwrap();
        assert_eq!(contents, "chain test");

        // remove
        fs::remove_file(&renamed).await.unwrap();
        assert!(!renamed.exists());

        // original still exists
        assert!(src.exists());
    });

    cleanup(&base);
}

#[test]
fn e2e_hard_link() {
    common::init_test_logging();
    let base = unique_temp_dir("hardlink");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let original = base.join("original.txt");
        let link = base.join("link.txt");

        fs::write(&original, b"linked").await.unwrap();
        fs::hard_link(&original, &link).await.unwrap();

        let contents = fs::read_to_string(&link).await.unwrap();
        assert_eq!(contents, "linked");

        // Both point to same inode
        let meta_orig = fs::metadata(&original).await.unwrap();
        let meta_link = fs::metadata(&link).await.unwrap();
        assert_eq!(meta_orig.len(), meta_link.len());
    });

    cleanup(&base);
}

#[cfg(unix)]
#[test]
fn e2e_symlink_and_readlink() {
    common::init_test_logging();
    let base = unique_temp_dir("symlink");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let target = base.join("target.txt");
        let link = base.join("sym.txt");

        fs::write(&target, b"symlinked").await.unwrap();
        fs::symlink(&target, &link).await.unwrap();

        // read through symlink
        let contents = fs::read_to_string(&link).await.unwrap();
        assert_eq!(contents, "symlinked");

        // readlink
        let read_target = fs::read_link(&link).await.unwrap();
        assert_eq!(read_target, target);

        // metadata follows symlink
        let meta = fs::metadata(&link).await.unwrap();
        assert!(meta.is_file());

        // symlink_metadata does not follow
        let sym_meta = fs::symlink_metadata(&link).await.unwrap();
        assert!(sym_meta.file_type().is_symlink());
    });

    cleanup(&base);
}

#[test]
fn e2e_canonicalize() {
    common::init_test_logging();
    let base = unique_temp_dir("canonicalize");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let file = base.join("real.txt");
        fs::write(&file, b"x").await.unwrap();

        let canonical = fs::canonicalize(&file).await.unwrap();
        assert!(canonical.is_absolute());
        assert!(canonical.exists());
    });

    cleanup(&base);
}

// === Directory Operations ===

#[test]
fn e2e_create_dir_and_remove_dir() {
    common::init_test_logging();
    let base = unique_temp_dir("dir_ops");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let dir = base.join("subdir");
        fs::create_dir(&dir).await.unwrap();
        assert!(dir.is_dir());

        fs::remove_dir(&dir).await.unwrap();
        assert!(!dir.exists());
    });

    cleanup(&base);
}

#[test]
fn e2e_create_dir_all_nested() {
    common::init_test_logging();
    let base = unique_temp_dir("dir_all");
    // Don't pre-create base - let create_dir_all handle it

    future::block_on(async {
        let deep = base.join("a").join("b").join("c").join("d");
        fs::create_dir_all(&deep).await.unwrap();
        assert!(deep.is_dir());
    });

    cleanup(&base);
}

#[test]
fn e2e_remove_dir_all_recursive() {
    common::init_test_logging();
    let base = unique_temp_dir("rmdir_all");
    std::fs::create_dir_all(base.join("a/b/c")).unwrap();
    std::fs::write(base.join("a/file1.txt"), b"1").unwrap();
    std::fs::write(base.join("a/b/file2.txt"), b"2").unwrap();
    std::fs::write(base.join("a/b/c/file3.txt"), b"3").unwrap();

    future::block_on(async {
        fs::remove_dir_all(&base).await.unwrap();
        assert!(!base.exists());
    });
}

#[test]
fn e2e_dir_error_cases() {
    common::init_test_logging();
    let base = unique_temp_dir("dir_errors");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        // remove non-empty dir should fail
        let dir = base.join("notempty");
        fs::create_dir(&dir).await.unwrap();
        fs::write(dir.join("file.txt"), b"x").await.unwrap();
        let result = fs::remove_dir(&dir).await;
        assert!(result.is_err());

        // create dir where file exists should fail
        let file = base.join("afile");
        fs::write(&file, b"x").await.unwrap();
        let result = fs::create_dir(&file).await;
        assert!(result.is_err());

        // remove non-existent dir
        let result = fs::remove_dir(base.join("nope")).await;
        assert!(result.is_err());
    });

    cleanup(&base);
}

// === Platform-specific: io_uring verification ===

#[cfg(all(target_os = "linux", feature = "io-uring"))]
mod platform_uring {
    use super::*;

    #[test]
    fn e2e_uring_file_read_write() {
        common::init_test_logging();
        let base = unique_temp_dir("uring_rw");
        std::fs::create_dir_all(&base).unwrap();

        future::block_on(async {
            let path = base.join("uring.txt");

            // Uses io_uring path on Linux
            fs::write(&path, b"io_uring test data").await.unwrap();
            let data = fs::read(&path).await.unwrap();
            assert_eq!(data, b"io_uring test data");
        });

        cleanup(&base);
    }

    #[test]
    fn e2e_uring_rename() {
        common::init_test_logging();
        let base = unique_temp_dir("uring_rename");
        std::fs::create_dir_all(&base).unwrap();

        future::block_on(async {
            let src = base.join("before.txt");
            let dst = base.join("after.txt");
            fs::write(&src, b"rename via uring").await.unwrap();

            fs::rename(&src, &dst).await.unwrap();
            assert!(!src.exists());
            let contents = fs::read_to_string(&dst).await.unwrap();
            assert_eq!(contents, "rename via uring");
        });

        cleanup(&base);
    }

    #[test]
    fn e2e_uring_remove_file() {
        common::init_test_logging();
        let base = unique_temp_dir("uring_rm");
        std::fs::create_dir_all(&base).unwrap();

        future::block_on(async {
            let path = base.join("to_remove.txt");
            fs::write(&path, b"remove me").await.unwrap();
            assert!(path.exists());

            fs::remove_file(&path).await.unwrap();
            assert!(!path.exists());
        });

        cleanup(&base);
    }

    #[test]
    fn e2e_uring_mkdir_rmdir() {
        common::init_test_logging();
        let base = unique_temp_dir("uring_dir");
        std::fs::create_dir_all(&base).unwrap();

        future::block_on(async {
            let dir = base.join("uring_created");
            fs::create_dir(&dir).await.unwrap();
            assert!(dir.is_dir());

            fs::remove_dir(&dir).await.unwrap();
            assert!(!dir.exists());
        });

        cleanup(&base);
    }

    #[cfg(unix)]
    #[test]
    fn e2e_uring_symlink() {
        common::init_test_logging();
        let base = unique_temp_dir("uring_sym");
        std::fs::create_dir_all(&base).unwrap();

        future::block_on(async {
            let target = base.join("target.txt");
            let link = base.join("link.txt");
            fs::write(&target, b"sym target").await.unwrap();

            fs::symlink(&target, &link).await.unwrap();
            let contents = fs::read_to_string(&link).await.unwrap();
            assert_eq!(contents, "sym target");
        });

        cleanup(&base);
    }
}

// === Large file handling ===

#[test]
fn e2e_large_file_roundtrip() {
    common::init_test_logging();
    let base = unique_temp_dir("large_file");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let path = base.join("big.bin");
        // 1MB of data
        let data: Vec<u8> = (0u32..1_048_576)
            .map(|i| u8::try_from(i % 251).expect("remainder fits in u8"))
            .collect();
        fs::write(&path, &data).await.unwrap();

        let read_back = fs::read(&path).await.unwrap();
        assert_eq!(read_back.len(), data.len());
        assert_eq!(read_back, data);
    });

    cleanup(&base);
}

// === Error handling ===

#[test]
fn e2e_file_not_found() {
    common::init_test_logging();
    future::block_on(async {
        let result = fs::File::open("/nonexistent/path/file.txt").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    });
}

#[test]
fn e2e_remove_nonexistent() {
    common::init_test_logging();
    future::block_on(async {
        let result = fs::remove_file("/nonexistent/file.txt").await;
        assert!(result.is_err());
    });
}

#[cfg(unix)]
#[test]
fn e2e_permissions() {
    common::init_test_logging();
    let base = unique_temp_dir("perms");
    std::fs::create_dir_all(&base).unwrap();

    future::block_on(async {
        let path = base.join("perm_test.txt");
        fs::write(&path, b"test").await.unwrap();

        let meta = fs::metadata(&path).await.unwrap();
        let perms = meta.permissions();
        // Should not be readonly by default
        assert!(!perms.readonly());

        // Set readonly
        let mut new_perms = perms.clone();
        new_perms.set_readonly(true);
        fs::set_permissions(&path, new_perms).await.unwrap();

        let meta = fs::metadata(&path).await.unwrap();
        assert!(meta.permissions().readonly());

        // Reset for cleanup
        let mut reset_perms = meta.permissions().clone();
        reset_perms.set_readonly(false);
        fs::set_permissions(&path, reset_perms).await.unwrap();
    });

    cleanup(&base);
}
