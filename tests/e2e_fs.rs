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
    "file-set-len-permissions",
    "read-dir-metadata-disposition",
    "buffered-lines-boundaries",
    "buf-writer-flush-visibility",
    "write-atomic-replace-cleanup",
    "dir-create-remove-boundaries",
    "unix-vfs-equivalence",
    "error-kind-remove-missing",
    "try-exists-lifecycle",
    "path-ops-copy-hardlink-rename",
    "unix-symlink-metadata-readlink",
    "read-dir-drop-cancellation",
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

fn fs_parity_row(
    bead_id: &str,
    scenario: &FsProofScenario,
    temp_root: &Path,
    cleanup_status: &str,
) -> Value {
    let cleanup_failed = cleanup_status != "removed";
    let (bytes_actual, metadata_actual, unsupported_reason, verdict, first_failure) =
        match &scenario.result {
            Ok(evidence) if !cleanup_failed => (
                evidence.bytes_actual,
                evidence.metadata_actual.clone(),
                evidence.unsupported_reason.clone(),
                "pass".to_string(),
                String::new(),
            ),
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
        "backend": "unix-spawn_blocking_io",
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
            scenario_id: "read-dir-drop-cancellation",
            api: "ReadDir",
            operation: "drop_iterator_after_first_entry",
            bytes_expected: 8,
            metadata_expected: "dropped_after_first_entry,dir_still_accessible=true",
            cancellation_point: "drop_after_first_entry",
            result: fs_proof_read_dir_drop_cancellation(&temp_root).await,
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
        let test_report = json!({
            "bead_id": bead_id,
            "scenario_count": rows.len(),
            "expected_scenarios": FS_PARITY_WAVE2_SCENARIOS,
            "temp_root": temp_root.display().to_string(),
            "cleanup_status": cleanup_status,
            "rows_path": rows_path.display().to_string(),
            "validation_passed": rows.iter().all(|row| row["verdict"] == "pass"),
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
        .filter(|row| row["verdict"].as_str() != Some("pass"))
        .collect();

    assert!(
        missing.is_empty(),
        "missing fs parity proof scenarios: {missing:?}"
    );
    assert!(drifts.is_empty(), "fs parity proof drifts: {drifts:#?}");
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
