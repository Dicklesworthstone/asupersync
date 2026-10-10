//! Async path utilities and metadata helpers.
//!
//! On Linux with `io-uring`, `remove_file` uses `IORING_OP_UNLINKAT`,
//! `rename` uses `IORING_OP_RENAMEAT`, and `symlink` uses `IORING_OP_SYMLINKAT`.
//! Other operations use `spawn_blocking_io` for true async offloading.

use super::metadata::{Metadata, Permissions};
use crate::cx::io_gate::spawn_blocking_io;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "test-internals")]
use std::sync::{Arc, Condvar, Mutex as StdMutex};
#[cfg(feature = "test-internals")]
use std::time::Duration;

mod scoped_atomic;

/// Deterministic handshake for testing soft-cancelled filesystem operations.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
#[derive(Debug)]
pub struct FilesystemOperationProbe {
    blocked: StdMutex<bool>,
    blocked_cv: Condvar,
    released: StdMutex<bool>,
    released_cv: Condvar,
    completed: StdMutex<bool>,
    completed_cv: Condvar,
}

#[cfg(feature = "test-internals")]
impl FilesystemOperationProbe {
    /// Creates a probe that blocks the instrumented operation once.
    #[must_use]
    pub fn new() -> Self {
        Self {
            blocked: StdMutex::new(false),
            blocked_cv: Condvar::new(),
            released: StdMutex::new(false),
            released_cv: Condvar::new(),
            completed: StdMutex::new(false),
            completed_cv: Condvar::new(),
        }
    }

    fn block_until_released(&self) {
        {
            let mut blocked = self
                .blocked
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *blocked = true;
            self.blocked_cv.notify_all();
        }

        let released = self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(
            self.released_cv
                .wait_while(released, |released| !*released)
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
    }

    fn mark_completed(&self) {
        let mut completed = self
            .completed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *completed = true;
        self.completed_cv.notify_all();
    }

    /// Waits until the instrumented operation reaches its deterministic gate.
    #[must_use]
    pub fn wait_until_blocked(&self, timeout: Duration) -> bool {
        let blocked = self
            .blocked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (blocked, _) = self
            .blocked_cv
            .wait_timeout_while(blocked, timeout, |blocked| !*blocked)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *blocked
    }

    /// Allows the instrumented operation to continue.
    pub fn release(&self) {
        let mut released = self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *released = true;
        self.released_cv.notify_all();
    }

    /// Waits until the operation or discarded staged result has completed.
    #[must_use]
    pub fn wait_until_completed(&self, timeout: Duration) -> bool {
        let completed = self
            .completed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (completed, _) = self
            .completed_cv
            .wait_timeout_while(completed, timeout, |completed| !*completed)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *completed
    }
}

#[cfg(feature = "test-internals")]
impl Default for FilesystemOperationProbe {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
struct OperationProbeHook {
    #[cfg(feature = "test-internals")]
    probe: Option<Arc<FilesystemOperationProbe>>,
}

impl OperationProbeHook {
    #[cfg(feature = "test-internals")]
    fn with_probe(probe: Arc<FilesystemOperationProbe>) -> Self {
        Self { probe: Some(probe) }
    }

    fn block_until_released(&self) {
        #[cfg(feature = "test-internals")]
        if let Some(probe) = &self.probe {
            probe.block_until_released();
        }
    }

    fn mark_completed(&self) {
        #[cfg(feature = "test-internals")]
        if let Some(probe) = &self.probe {
            probe.mark_completed();
        }
    }

    #[cfg(feature = "test-internals")]
    fn completion_probe(&self) -> Option<Arc<FilesystemOperationProbe>> {
        self.probe.clone()
    }
}

/// Validates a path to prevent directory traversal attacks.
///
/// Rejects paths containing:
/// - Parent directory references (`..`)
/// - Absolute paths (for relative path functions)
/// - Null bytes
/// - Empty paths
///
/// This is a security mitigation against path traversal attacks that could
/// allow access to files outside the intended directory scope.
fn validate_safe_path(path: &Path, allow_absolute: bool) -> io::Result<()> {
    // Check for null bytes in path components
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains null bytes",
        ));
    }

    // Check for empty path
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path cannot be empty",
        ));
    }

    // Reject absolute paths if not allowed
    if !allow_absolute && path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "absolute paths not allowed in this context",
        ));
    }

    // Check each component for parent directory references
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path contains parent directory reference (..)",
                ));
            }
            std::path::Component::CurDir => {
                // Current directory references are generally safe but unnecessary
            }
            std::path::Component::Prefix(_)
            | std::path::Component::RootDir
            | std::path::Component::Normal(_) => {
                // These are safe components
            }
        }
    }

    Ok(())
}

/// Get metadata for a path (follows symlinks).
pub async fn metadata(path: impl AsRef<Path>) -> io::Result<Metadata> {
    let path = path.as_ref().to_owned();
    let inner = spawn_blocking_io(move || std::fs::metadata(&path)).await?;
    Ok(Metadata::from_std(inner))
}

/// Get metadata for a path (does not follow symlinks).
pub async fn symlink_metadata(path: impl AsRef<Path>) -> io::Result<Metadata> {
    let path = path.as_ref().to_owned();
    let inner = spawn_blocking_io(move || std::fs::symlink_metadata(&path)).await?;
    Ok(Metadata::from_std(inner))
}

/// Set permissions for a path.
///
/// This uses soft cancellation. A started permission change may commit after
/// the returned future is dropped.
pub async fn set_permissions(path: impl AsRef<Path>, perm: Permissions) -> io::Result<()> {
    let path = path.as_ref().to_owned();
    spawn_blocking_io(move || std::fs::set_permissions(&path, perm.into_inner())).await
}

/// Canonicalize a path (resolve symlinks, make absolute).
pub async fn canonicalize(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let path = path.as_ref().to_owned();
    spawn_blocking_io(move || std::fs::canonicalize(&path)).await
}

/// Read a symlink target.
pub async fn read_link(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let path = path.as_ref().to_owned();
    spawn_blocking_io(move || std::fs::read_link(&path)).await
}

/// Copy a file from `src` to `dst`.
///
/// This uses soft cancellation. A started copy may create, truncate, or
/// partially populate `dst` after the returned future is dropped.
pub async fn copy(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<u64> {
    let src_path = src.as_ref();
    let dst_path = dst.as_ref();

    // Validate paths to prevent directory traversal attacks
    validate_safe_path(src_path, true)?;
    validate_safe_path(dst_path, true)?;

    let src = src_path.to_owned();
    let dst = dst_path.to_owned();
    spawn_blocking_io(move || std::fs::copy(&src, &dst)).await
}

/// Rename or move a file.
///
/// On Linux with `io-uring`, uses `IORING_OP_RENAMEAT`.
/// A submitted rename may commit after the returned future is dropped.
pub async fn rename(from: impl AsRef<Path>, to: impl AsRef<Path>) -> io::Result<()> {
    let from_path = from.as_ref();
    let to_path = to.as_ref();

    // Validate paths to prevent directory traversal attacks
    validate_safe_path(from_path, true)?;
    validate_safe_path(to_path, true)?;

    let from = from_path.to_owned();
    let to = to_path.to_owned();
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    {
        uring_renameat(&from, &to)
    }
    #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
    {
        spawn_blocking_io(move || std::fs::rename(&from, &to)).await
    }
}

/// Remove a file.
///
/// On Linux with `io-uring`, uses `IORING_OP_UNLINKAT`.
/// A submitted removal may commit after the returned future is dropped.
pub async fn remove_file(path: impl AsRef<Path>) -> io::Result<()> {
    let path_ref = path.as_ref();

    // Validate path to prevent directory traversal attacks
    validate_safe_path(path_ref, true)?;

    let path = path_ref.to_owned();
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    {
        uring_unlinkat(&path)
    }
    #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
    {
        spawn_blocking_io(move || std::fs::remove_file(&path)).await
    }
}

/// Create a hard link.
///
/// This uses soft cancellation. A started link creation may commit after the
/// returned future is dropped.
pub async fn hard_link(original: impl AsRef<Path>, link: impl AsRef<Path>) -> io::Result<()> {
    let original = original.as_ref().to_owned();
    let link = link.as_ref().to_owned();
    spawn_blocking_io(move || std::fs::hard_link(&original, &link)).await
}

/// Filesystem object type declared for a symbolic link target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkKind {
    /// A link created with file-target semantics.
    File,
    /// A link created with directory-target semantics.
    Directory,
}

/// Create a symbolic link with an explicit target kind.
///
/// Unix does not encode this distinction and ignores `kind`. Windows requires
/// it even for relative, dangling, or later-created targets, so callers must
/// carry the sender's declared type instead of probing relative to the process
/// working directory.
/// Link creation uses soft cancellation and may commit after future drop.
#[cfg(unix)]
pub async fn symlink_typed(
    original: impl AsRef<Path>,
    link: impl AsRef<Path>,
    _kind: SymlinkKind,
) -> io::Result<()> {
    symlink(original, link).await
}

/// Windows counterpart of [`symlink_typed`] with an explicit target kind.
#[cfg(windows)]
pub async fn symlink_typed(
    original: impl AsRef<Path>,
    link: impl AsRef<Path>,
    kind: SymlinkKind,
) -> io::Result<()> {
    match kind {
        SymlinkKind::File => symlink_file(original, link).await,
        SymlinkKind::Directory => symlink_dir(original, link).await,
    }
}

/// Unsupported-platform fallback for the typed symlink API.
#[cfg(not(any(unix, windows)))]
pub async fn symlink_typed(
    _original: impl AsRef<Path>,
    _link: impl AsRef<Path>,
    _kind: SymlinkKind,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "symbolic links are unsupported on this platform",
    ))
}

/// Create a symlink (Unix).
///
/// On Linux with `io-uring`, uses `IORING_OP_SYMLINKAT`.
/// A submitted link creation may commit after the returned future is dropped.
#[cfg(unix)]
pub async fn symlink(original: impl AsRef<Path>, link: impl AsRef<Path>) -> io::Result<()> {
    let original = original.as_ref().to_owned();
    let link = link.as_ref().to_owned();
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    {
        uring_symlinkat(&original, &link)
    }
    #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
    {
        spawn_blocking_io(move || std::os::unix::fs::symlink(&original, &link)).await
    }
}

/// Create a symlink to a file (Windows).
///
/// A started link creation may commit after the returned future is dropped.
#[cfg(windows)]
pub async fn symlink_file(original: impl AsRef<Path>, link: impl AsRef<Path>) -> io::Result<()> {
    let original = original.as_ref().to_owned();
    let link = link.as_ref().to_owned();
    spawn_blocking_io(move || std::os::windows::fs::symlink_file(&original, &link)).await
}

/// Create a symlink to a directory (Windows).
///
/// A started link creation may commit after the returned future is dropped.
#[cfg(windows)]
pub async fn symlink_dir(original: impl AsRef<Path>, link: impl AsRef<Path>) -> io::Result<()> {
    let original = original.as_ref().to_owned();
    let link = link.as_ref().to_owned();
    spawn_blocking_io(move || std::os::windows::fs::symlink_dir(&original, &link)).await
}

/// Create a symlink (Windows), choosing file vs directory from a live target.
///
/// Mirrors the unix `symlink` so callers can use a single `crate::fs::symlink`
/// across platforms for non-ATP callers. Relative targets are resolved from the
/// link's parent, matching Windows link semantics. Call [`symlink_typed`] when
/// the target may be dangling or created later.
/// A started link creation may commit after the returned future is dropped.
#[cfg(windows)]
pub async fn symlink(original: impl AsRef<Path>, link: impl AsRef<Path>) -> io::Result<()> {
    let original = original.as_ref().to_owned();
    let link = link.as_ref().to_owned();
    spawn_blocking_io(move || {
        let resolved = if original.is_absolute() {
            original.clone()
        } else {
            link.parent()
                .unwrap_or_else(|| Path::new("."))
                .join(&original)
        };
        if resolved.is_dir() {
            std::os::windows::fs::symlink_dir(&original, &link)
        } else {
            std::os::windows::fs::symlink_file(&original, &link)
        }
    })
    .await
}

/// Read an entire file into a byte vector.
pub async fn read(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    let path = path.as_ref().to_owned();
    spawn_blocking_io(move || std::fs::read(&path)).await
}

/// Read an entire file into a string.
pub async fn read_to_string(path: impl AsRef<Path>) -> io::Result<String> {
    let path = path.as_ref().to_owned();
    spawn_blocking_io(move || std::fs::read_to_string(&path)).await
}

/// Write bytes to a file (creates or truncates).
///
/// This uses soft cancellation. A started write may create, truncate, or
/// partially update the target after the returned future is dropped. Use
/// [`write_atomic`] when cancellation must not change the target.
pub async fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let path_ref = path.as_ref();

    // Validate path to prevent directory traversal attacks
    validate_safe_path(path_ref, true)?;

    write_owned(
        path_ref.to_owned(),
        contents.as_ref().to_owned(),
        OperationProbeHook::default(),
    )
    .await
}

async fn write_owned(path: PathBuf, contents: Vec<u8>, hook: OperationProbeHook) -> io::Result<()> {
    spawn_blocking_io(move || {
        hook.block_until_released();
        let result = std::fs::write(&path, &contents);
        hook.mark_completed();
        result
    })
    .await
}

/// Runs [`write`] with a deterministic started-operation handshake.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub async fn write_with_probe_for_test(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
    probe: Arc<FilesystemOperationProbe>,
) -> io::Result<()> {
    let path_ref = path.as_ref();
    validate_safe_path(path_ref, true)?;
    write_owned(
        path_ref.to_owned(),
        contents.as_ref().to_owned(),
        OperationProbeHook::with_probe(probe),
    )
    .await
}

/// A fully written and synced atomic-replacement candidate.
///
/// Staging never changes the target path. [`commit`](Self::commit) performs a
/// synchronous rename with no cancellation point. Dropping this value discards
/// its temporary file.
#[derive(Debug)]
#[must_use = "a staged atomic write must be committed or deliberately dropped"]
pub struct StagedAtomicWrite {
    target_path: PathBuf,
    temp_path: TempPathGuard,
    #[cfg(feature = "test-internals")]
    completion_probe: Option<Arc<FilesystemOperationProbe>>,
}

impl StagedAtomicWrite {
    /// Atomically installs the staged contents at the target path.
    ///
    /// The rename is synchronous: once this method begins, async cancellation
    /// cannot interleave with the target mutation. If the subsequent parent
    /// directory sync fails, the replacement has already committed.
    ///
    /// Note: This method runs synchronously on the caller's thread (performing
    /// `rename` and parent directory fsync). If called directly on an async worker
    /// thread, it will block the worker during those syscalls. For non-blocking
    /// async execution, use [`Self::commit_async`].
    pub fn commit(self) -> io::Result<()> {
        self.commit_with_hook(OperationProbeHook::default())
    }

    /// Atomically installs the staged contents at the target path on the blocking pool.
    ///
    /// Unlike [`Self::commit`], which performs the rename and parent directory sync
    /// synchronously on the calling async worker thread, `commit_async` offloads both
    /// operations to the runtime's blocking thread pool so slow filesystem metadata
    /// operations do not stall async worker threads.
    ///
    /// # Cancellation Semantics
    /// Once the blocking commit task begins execution on the blocking thread pool,
    /// it completes to conclusion: dropping the returned future does not cancel,
    /// rollback, or prevent the rename from taking effect. If this future is dropped
    /// before offload begins, the temporary file is cleaned up and the target
    /// remains unchanged.
    ///
    /// The claimed commit is not owned by the caller's region: region close does not
    /// wait for it, and a rename still pending after drop can overwrite a later write
    /// to the same path. For a region-owned offloaded replacement use
    /// [`crate::fs::ScopedFs::write_atomic`].
    ///
    /// An error from the parent-directory sync is reported after the replacement has
    /// committed; it is not proof of rollback.
    ///
    /// When running without a blocking pool (e.g. `blocking_threads(0, 0)` or
    /// `LabRuntime`), both staging and commit execute synchronously on the polling task.
    /// If this future is dropped before a blocking thread claims the queued commit,
    /// the temporary file is cleaned up when the queued job is subsequently dequeued
    /// and discarded.
    pub async fn commit_async(self) -> io::Result<()> {
        self.commit_async_with_hook(OperationProbeHook::default()).await
    }

    fn commit_with_hook(mut self, hook: OperationProbeHook) -> io::Result<()> {
        hook.block_until_released();
        let parent = normalized_parent(&self.target_path);
        let rename_res = std::fs::rename(self.temp_path.path(), &self.target_path);
        if rename_res.is_ok() {
            self.temp_path.disarm();
        }
        let result = match rename_res {
            Ok(()) => sync_parent_dir(parent),
            Err(err) => Err(err),
        };
        hook.mark_completed();
        result
    }

    async fn commit_async_with_hook(self, hook: OperationProbeHook) -> io::Result<()> {
        spawn_blocking_io(move || self.commit_with_hook(hook)).await
    }

    /// Runs [`Self::commit_async`] with an explicit handshake probe before rename.
    #[cfg(feature = "test-internals")]
    #[doc(hidden)]
    pub async fn commit_async_with_probe_for_test(
        self,
        probe: Arc<FilesystemOperationProbe>,
    ) -> io::Result<()> {
        self.commit_async_with_hook(OperationProbeHook::with_probe(probe)).await
    }
}

impl Drop for StagedAtomicWrite {
    fn drop(&mut self) {
        self.temp_path.cleanup();
        #[cfg(feature = "test-internals")]
        if let Some(probe) = &self.completion_probe {
            probe.mark_completed();
        }
    }
}

/// Stages an atomic replacement without changing the target path.
///
/// The temporary file is created beside the target, fully written, permission
/// adjusted, and synced on the blocking pool. If this future is dropped after
/// staging starts, background work may finish, but the discarded staged value
/// removes the temporary file and never renames it over the target.
pub async fn stage_write_atomic(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> io::Result<StagedAtomicWrite> {
    stage_write_atomic_with_hook(path, contents, OperationProbeHook::default()).await
}

async fn stage_write_atomic_with_hook(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
    hook: OperationProbeHook,
) -> io::Result<StagedAtomicWrite> {
    let path_ref = path.as_ref();
    validate_safe_path(path_ref, true)?;

    let path = path_ref.to_owned();
    let contents = contents.as_ref().to_owned();
    spawn_blocking_io(move || stage_write_atomic_blocking(&path, &contents, hook)).await
}

/// Runs [`stage_write_atomic`] with a deterministic post-stage handshake.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub async fn stage_write_atomic_with_probe_for_test(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
    probe: Arc<FilesystemOperationProbe>,
) -> io::Result<StagedAtomicWrite> {
    stage_write_atomic_with_hook(path, contents, OperationProbeHook::with_probe(probe)).await
}

/// Atomically replace file contents via temp-file + rename.
///
/// The temporary file is created in the target directory, fully written and
/// `sync_all()`'d, then renamed into place. On Unix, the parent directory is
/// also `sync_all()`'d after the rename so directory-entry durability is
/// explicit.
///
/// If the operation fails before rename, the temporary file is cleaned up.
/// If this future is dropped during staging, the target path remains unchanged;
/// the target rename occurs synchronously only after staging returns.
///
/// Note: While staging is offloaded to the blocking pool, [`StagedAtomicWrite::commit`]
/// runs synchronously on the calling async worker thread (performing `rename` and
/// parent directory fsync). For workloads on slow filesystems where worker threads must
/// not be blocked during commit, use [`write_atomic_offloaded`] or [`stage_write_atomic`]
/// followed by [`StagedAtomicWrite::commit_async`].
pub async fn write_atomic(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    stage_write_atomic(path, contents).await?.commit()
}

/// Atomically replace file contents via temp-file + rename with offloaded commit.
///
/// Unlike [`write_atomic`], which executes [`StagedAtomicWrite::commit`] synchronously
/// on the calling async worker thread, `write_atomic_offloaded` stages the file on the
/// blocking pool and offloads the target rename and directory sync to the blocking pool
/// via [`StagedAtomicWrite::commit_async`].
///
/// # Cancellation Semantics
/// If this future is dropped during staging, the target path remains unchanged and the
/// temporary file is cleaned up. Once the commit operation begins on the blocking pool,
/// the rename completes to conclusion: dropping the returned future does not cancel or
/// rollback the replacement.
///
/// The claimed commit is not owned by the caller's region: region close does not
/// wait for it, and a rename still pending after drop can overwrite a later write
/// to the same path. For a region-owned offloaded replacement use
/// [`crate::fs::ScopedFs::write_atomic`].
///
/// An error from the parent-directory sync is reported after the replacement has
/// committed; it is not proof of rollback.
///
/// When running without a blocking pool (e.g. `blocking_threads(0, 0)` or
/// `LabRuntime`), both staging and commit execute synchronously on the polling task.
/// If this future is dropped before a blocking thread claims the queued commit,
/// the temporary file is cleaned up when the queued job is subsequently dequeued
/// and discarded.
pub async fn write_atomic_offloaded(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> io::Result<()> {
    stage_write_atomic(path, contents)
        .await?
        .commit_async()
        .await
}

/// Runs [`write_atomic_offloaded`] with an explicit handshake probe during commit.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub async fn write_atomic_offloaded_with_probe_for_test(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
    probe: Arc<FilesystemOperationProbe>,
) -> io::Result<()> {
    stage_write_atomic(path, contents)
        .await?
        .commit_async_with_probe_for_test(probe)
        .await
}

static ATOMIC_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn stage_write_atomic_blocking(
    path: &Path,
    contents: &[u8],
    hook: OperationProbeHook,
) -> io::Result<StagedAtomicWrite> {
    scoped_atomic::stage_with(path, false, || Ok(()), |file| file.write_all(contents), hook)
}

fn normalized_parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn unique_tmp_path(parent: &Path, file_name: &std::ffi::OsStr) -> PathBuf {
    // br-asupersync-vbr1zf: prior implementation embedded
    // `std::process::id()` in the temp-file name, leaking host PID
    // into the filesystem and producing run-to-run differences in
    // path strings even for identical workloads. Replaced with a
    // 64-bit OS-entropy random nonce (rendered as fixed-width hex)
    // plus the existing per-process monotone counter for in-process
    // collision avoidance. The nonce is drawn from `OsEntropy`,
    // which is the project's documented ambient-authority boundary
    // for entropy. Across replays the nonce differs (good — that's
    // its purpose), but the PID leak is gone and the format stays
    // wasm-portable (`std::process::id()` is meaningless on wasm32).
    use crate::util::entropy::{EntropySource, OsEntropy};
    let counter = ATOMIC_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nonce = OsEntropy.next_u64();
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".asupersync-tmp-{nonce:016x}-{counter}"));
    parent.join(tmp_name)
}

#[cfg(unix)]
fn sync_parent_dir(parent: &Path) -> io::Result<()> {
    let dir = std::fs::File::open(parent)?;
    dir.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_dir(_parent: &Path) -> io::Result<()> {
    Ok(())
}

#[derive(Debug)]
struct TempPathGuard {
    path: PathBuf,
    armed: bool,
}

impl TempPathGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn cleanup(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
            self.armed = false;
        }
    }
}

impl Drop for TempPathGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
}

// ---- io_uring helpers ----

#[cfg(all(target_os = "linux", feature = "io-uring"))]
#[allow(unsafe_code)]
fn uring_submit_one(entry: &io_uring::squeue::Entry) -> io::Result<()> {
    use io_uring::IoUring;

    let mut ring = IoUring::new(2)?;
    unsafe {
        ring.submission()
            .push(entry)
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "submission queue full"))?;
    }
    ring.submit_and_wait(1)?;
    let result = ring
        .completion()
        .next()
        .map(|cqe| cqe.result())
        .ok_or_else(|| io::Error::other("no completion received"))?;
    if result < 0 {
        Err(io::Error::from_raw_os_error(-result))
    } else {
        Ok(())
    }
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
fn path_to_cstring(path: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;

    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null bytes"))
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
fn uring_unlinkat(path: &Path) -> io::Result<()> {
    use io_uring::{opcode, types};
    crate::cx::io_gate::require_ambient_io("fs")?;
    let c_path = path_to_cstring(path)?;
    let entry = opcode::UnlinkAt::new(types::Fd(libc::AT_FDCWD), c_path.as_ptr())
        .flags(0)
        .build();
    uring_submit_one(&entry)
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
fn uring_renameat(from: &Path, to: &Path) -> io::Result<()> {
    use io_uring::{opcode, types};
    crate::cx::io_gate::require_ambient_io("fs")?;
    let c_from = path_to_cstring(from)?;
    let c_to = path_to_cstring(to)?;
    let entry = opcode::RenameAt::new(
        types::Fd(libc::AT_FDCWD),
        c_from.as_ptr(),
        types::Fd(libc::AT_FDCWD),
        c_to.as_ptr(),
    )
    .build();
    uring_submit_one(&entry)
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
fn uring_symlinkat(target: &Path, linkpath: &Path) -> io::Result<()> {
    use io_uring::{opcode, types};
    crate::cx::io_gate::require_ambient_io("fs")?;
    let c_target = path_to_cstring(target)?;
    let c_link = path_to_cstring(linkpath)?;
    let entry = opcode::SymlinkAt::new(
        types::Fd(libc::AT_FDCWD),
        c_target.as_ptr(),
        c_link.as_ptr(),
    )
    .build();
    uring_submit_one(&entry)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use futures_lite::future;
    #[cfg(all(target_os = "linux", feature = "io-uring", unix))]
    use std::ffi::OsString;
    use std::fs;
    #[cfg(all(target_os = "linux", feature = "io-uring", unix))]
    use std::os::unix::ffi::OsStringExt;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(prefix: &str) -> io::Result<Self> {
            let mut path = std::env::temp_dir();
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            path.push(format!("asupersync_{prefix}_{nanos}"));
            fs::create_dir_all(&path)?;
            Ok(Self { path })
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[cfg(all(target_os = "linux", feature = "io-uring", unix))]
    #[test]
    fn path_to_cstring_accepts_non_utf8_unix_paths() {
        init_test("path_to_cstring_accepts_non_utf8_unix_paths");
        let raw = vec![b'f', b's', b'_', 0xFE];
        let path = PathBuf::from(OsString::from_vec(raw.clone()));

        let c = path_to_cstring(&path).expect("non-utf8 unix path should be accepted");
        crate::assert_with_log!(
            c.as_bytes() == raw.as_slice(),
            "raw bytes preserved",
            raw.as_slice(),
            c.as_bytes()
        );
        crate::test_complete!("path_to_cstring_accepts_non_utf8_unix_paths");
    }

    #[cfg(all(target_os = "linux", feature = "io-uring", unix))]
    #[test]
    fn path_to_cstring_rejects_nul_bytes() {
        init_test("path_to_cstring_rejects_nul_bytes");
        let path = PathBuf::from(OsString::from_vec(vec![b'b', b'a', b'd', 0, b'x']));

        let err = path_to_cstring(&path).expect_err("path with nul must be rejected");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidInput,
            "invalid input error",
            io::ErrorKind::InvalidInput,
            err.kind()
        );
        crate::test_complete!("path_to_cstring_rejects_nul_bytes");
    }

    #[test]
    fn metadata_basic() {
        init_test("metadata_basic");
        let dir = TempDir::new("meta").unwrap();
        let file_path = dir.path().join("test.txt");

        future::block_on(async {
            write(&file_path, b"hello").await.unwrap();
            let meta = metadata(&file_path).await.unwrap();
            let is_file = meta.is_file();
            crate::assert_with_log!(is_file, "is_file", true, is_file);
            let is_dir = meta.is_dir();
            crate::assert_with_log!(!is_dir, "is_dir false", false, is_dir);
            let len = meta.len();
            crate::assert_with_log!(len == 5, "len", 5, len);
        });
        crate::test_complete!("metadata_basic");
    }

    #[test]
    fn read_write_roundtrip() {
        init_test("read_write_roundtrip");
        let dir = TempDir::new("rw").unwrap();
        let file_path = dir.path().join("read_write.txt");

        future::block_on(async {
            write(&file_path, "hello world").await.unwrap();
            let contents = read_to_string(&file_path).await.unwrap();
            crate::assert_with_log!(
                contents == "hello world",
                "contents",
                "hello world",
                contents
            );
            let bytes = read(&file_path).await.unwrap();
            crate::assert_with_log!(bytes == b"hello world", "bytes", b"hello world", bytes);
        });
        crate::test_complete!("read_write_roundtrip");
    }

    #[test]
    fn copy_rename_remove() {
        init_test("copy_rename_remove");
        let dir = TempDir::new("ops").unwrap();
        let src = dir.path().join("src.txt");
        let dst = dir.path().join("dst.txt");
        let renamed = dir.path().join("renamed.txt");

        future::block_on(async {
            write(&src, b"copy me").await.unwrap();
            let copied = copy(&src, &dst).await.unwrap();
            crate::assert_with_log!(copied == 7, "copied bytes", 7, copied);
            rename(&dst, &renamed).await.unwrap();
            let exists = dst.exists();
            crate::assert_with_log!(!exists, "dst removed", false, exists);
            let contents = read(&renamed).await.unwrap();
            crate::assert_with_log!(contents == b"copy me", "contents", b"copy me", contents);
            remove_file(&renamed).await.unwrap();
            let exists = renamed.exists();
            crate::assert_with_log!(!exists, "renamed removed", false, exists);
        });
        crate::test_complete!("copy_rename_remove");
    }

    #[test]
    fn hard_link_roundtrip() {
        init_test("hard_link_roundtrip");
        let dir = TempDir::new("hard_link").unwrap();
        let src = dir.path().join("source.txt");
        let link = dir.path().join("link.txt");

        future::block_on(async {
            write(&src, b"same-bytes").await.unwrap();
            hard_link(&src, &link).await.unwrap();

            let source = read(&src).await.unwrap();
            let linked = read(&link).await.unwrap();
            crate::assert_with_log!(
                linked == source,
                "linked bytes match source",
                source,
                linked
            );
        });
        crate::test_complete!("hard_link_roundtrip");
    }

    #[test]
    fn set_permissions_readonly_roundtrip() {
        init_test("set_permissions_readonly_roundtrip");
        let dir = TempDir::new("permissions").unwrap();
        let path = dir.path().join("file.txt");

        future::block_on(async {
            write(&path, b"content").await.unwrap();

            let mut perms = metadata(&path).await.unwrap().permissions();
            perms.set_readonly(true);
            set_permissions(&path, perms).await.unwrap();

            let readonly_after_set = metadata(&path).await.unwrap().permissions().readonly();
            crate::assert_with_log!(readonly_after_set, "readonly set", true, readonly_after_set);

            let mut perms = metadata(&path).await.unwrap().permissions();
            perms.set_readonly(false);
            set_permissions(&path, perms).await.unwrap();

            let readonly_after_clear = metadata(&path).await.unwrap().permissions().readonly();
            crate::assert_with_log!(
                !readonly_after_clear,
                "readonly cleared",
                false,
                readonly_after_clear
            );
        });
        crate::test_complete!("set_permissions_readonly_roundtrip");
    }

    #[test]
    fn write_atomic_creates_and_replaces_without_temp_leaks() {
        init_test("write_atomic_creates_and_replaces_without_temp_leaks");
        let dir = TempDir::new("write_atomic").unwrap();
        let path = dir.path().join("target.txt");

        future::block_on(async {
            write_atomic(&path, b"v1").await.unwrap();
            let first = read(&path).await.unwrap();
            crate::assert_with_log!(first == b"v1", "initial write", b"v1", first);

            write_atomic(&path, b"v2").await.unwrap();
            let second = read(&path).await.unwrap();
            crate::assert_with_log!(second == b"v2", "replacement write", b"v2", second);

            let mut leaked_tmp = Vec::new();
            for entry in std::fs::read_dir(dir.path()).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name();
                if name.to_string_lossy().contains(".asupersync-tmp-") {
                    leaked_tmp.push(name.to_string_lossy().to_string());
                }
            }
            crate::assert_with_log!(
                leaked_tmp.is_empty(),
                "no leaked temporary files",
                "[]",
                format!("{leaked_tmp:?}")
            );
        });
        crate::test_complete!("write_atomic_creates_and_replaces_without_temp_leaks");
    }

    #[test]
    fn write_atomic_missing_parent_fails_cleanly() {
        init_test("write_atomic_missing_parent_fails_cleanly");
        let dir = TempDir::new("write_atomic_missing_parent").unwrap();
        let missing_parent = dir.path().join("missing");
        let target = missing_parent.join("target.txt");

        future::block_on(async {
            let err = write_atomic(&target, b"data")
                .await
                .expect_err("missing parent should fail");
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::NotFound,
                "missing parent returns NotFound",
                io::ErrorKind::NotFound,
                err.kind()
            );
            let target_exists = target.exists();
            crate::assert_with_log!(
                !target_exists,
                "target should not be created on failure",
                false,
                target_exists
            );
        });
        crate::test_complete!("write_atomic_missing_parent_fails_cleanly");
    }

    #[test]
    fn write_atomic_preserves_preexisting_stale_temp_files() {
        init_test("write_atomic_preserves_preexisting_stale_temp_files");
        let dir = TempDir::new("write_atomic_stale_temp").unwrap();
        let path = dir.path().join("target.txt");
        let file_name = path.file_name().expect("target file name");
        let start = ATOMIC_WRITE_COUNTER.load(Ordering::Relaxed);

        for offset in 0..8 {
            let counter = start.saturating_add(offset);
            let stale = dir.path().join(format!(
                ".{}.asupersync-tmp-deadbeefdeadbeef-{counter}",
                file_name.to_string_lossy(),
            ));
            fs::write(stale, b"stale-temp").unwrap();
        }

        future::block_on(async {
            write_atomic(&path, b"fresh").await.unwrap();

            let bytes = read(&path).await.unwrap();
            crate::assert_with_log!(bytes == b"fresh", "fresh content written", b"fresh", bytes);

            let stale_count = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .contains(".asupersync-tmp-")
                })
                .count();
            crate::assert_with_log!(
                stale_count >= 8,
                "preexisting stale temp files preserved",
                ">= 8",
                stale_count
            );
        });
        crate::test_complete!("write_atomic_preserves_preexisting_stale_temp_files");
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_preserves_existing_unix_permissions() {
        init_test("write_atomic_preserves_existing_unix_permissions");
        let dir = TempDir::new("write_atomic_permissions").unwrap();
        let path = dir.path().join("script.sh");

        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();

        future::block_on(async {
            write_atomic(&path, b"new").await.unwrap();

            let bytes = read(&path).await.unwrap();
            crate::assert_with_log!(bytes == b"new", "new content written", b"new", bytes);

            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            crate::assert_with_log!(mode == 0o700, "existing permissions preserved", 0o700, mode);
        });
        crate::test_complete!("write_atomic_preserves_existing_unix_permissions");
    }

    #[test]
    fn write_atomic_offloaded_creates_and_replaces_without_temp_leaks() {
        init_test("write_atomic_offloaded_creates_and_replaces_without_temp_leaks");
        let dir = TempDir::new("write_atomic_offloaded").unwrap();
        let path = dir.path().join("target.txt");

        future::block_on(async {
            write_atomic_offloaded(&path, b"offloaded_v1")
                .await
                .unwrap();
            let first = read(&path).await.unwrap();
            crate::assert_with_log!(
                first == b"offloaded_v1",
                "initial write",
                b"offloaded_v1",
                first
            );

            write_atomic_offloaded(&path, b"offloaded_v2")
                .await
                .unwrap();
            let second = read(&path).await.unwrap();
            crate::assert_with_log!(
                second == b"offloaded_v2",
                "replacement write",
                b"offloaded_v2",
                second
            );

            let mut leaked_tmp = Vec::new();
            for entry in std::fs::read_dir(dir.path()).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name();
                if name.to_string_lossy().contains(".asupersync-tmp-") {
                    leaked_tmp.push(name.to_string_lossy().to_string());
                }
            }
            crate::assert_with_log!(
                leaked_tmp.is_empty(),
                "no leaked temporary files",
                "[]",
                format!("{leaked_tmp:?}")
            );
        });
        crate::test_complete!("write_atomic_offloaded_creates_and_replaces_without_temp_leaks");
    }

    #[test]
    fn write_atomic_offloaded_missing_parent_fails_cleanly() {
        init_test("write_atomic_offloaded_missing_parent_fails_cleanly");
        let dir = TempDir::new("write_atomic_offloaded_missing_parent").unwrap();
        let missing_parent = dir.path().join("missing");
        let target = missing_parent.join("target.txt");

        future::block_on(async {
            let err = write_atomic_offloaded(&target, b"data")
                .await
                .expect_err("missing parent should fail");
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::NotFound,
                "missing parent returns NotFound",
                io::ErrorKind::NotFound,
                err.kind()
            );
            let target_exists = target.exists();
            crate::assert_with_log!(
                !target_exists,
                "target should not be created on failure",
                false,
                target_exists
            );
        });
        crate::test_complete!("write_atomic_offloaded_missing_parent_fails_cleanly");
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn write_atomic_offloaded_slow_commit_probe_progresses_and_drops() {
        init_test("write_atomic_offloaded_slow_commit_probe_progresses_and_drops");
        let dir = TempDir::new("write_atomic_offloaded_probe").unwrap();
        let path = dir.path().join("target.txt");
        std::fs::write(&path, b"original").unwrap();

        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(1, 2)
            .build()
            .unwrap();

        runtime.block_on(async {
            // Case 1: Drop staged write BEFORE commit begins -> leaves target unchanged
            let staged = stage_write_atomic(&path, b"staged_only").await.unwrap();
            drop(staged);
            assert_eq!(std::fs::read(&path).unwrap(), b"original");

            // Case 2: While commit_async is parked in rename, another task on the single worker makes progress.
            // When the future is dropped after rename starts on the blocking pool,
            // the target is still replaced cleanly without temp file leaks.
            let probe = Arc::new(FilesystemOperationProbe::new());
            let staged2 = stage_write_atomic(&path, b"replaced_content")
                .await
                .unwrap();

            let mut commit_fut =
                Box::pin(staged2.commit_async_with_probe_for_test(Arc::clone(&probe)));

            // Poll once to launch the blocking task
            assert!(
                futures_lite::future::poll_once(commit_fut.as_mut())
                    .await
                    .is_none(),
                "commit_async must yield while waiting on the blocking task"
            );

            // Wait until the blocking task has started and is parked at the probe
            assert!(
                probe.wait_until_blocked(Duration::from_secs(5)),
                "blocking commit task must reach the probe gate"
            );

            // Verify another task on the SAME single worker can make progress while commit is parked
            let mut other_handle = runtime.spawn_local(async { 42 });
            assert_eq!(
                other_handle.await.unwrap(),
                42,
                "another task spawned on the worker must make progress"
            );

            // Target is still "original" before probe releases rename
            assert_eq!(std::fs::read(&path).unwrap(), b"original");

            // Drop the commit future while the blocking task is parked
            drop(commit_fut);

            // Now release the probe so the blocking task completes its rename and fsync
            probe.release();
            assert!(
                probe.wait_until_completed(Duration::from_secs(5)),
                "offloaded commit must finish"
            );

            // The target should now be replaced because the offloaded rename ran to completion
            assert_eq!(std::fs::read(&path).unwrap(), b"replaced_content");

            // Verify no leaked temporary files
            let leaked_tmp: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .contains(".asupersync-tmp-")
                })
                .collect();
            assert!(
                leaked_tmp.is_empty(),
                "no leaked temporary files: {leaked_tmp:?}"
            );
        });

        crate::test_complete!("write_atomic_offloaded_slow_commit_probe_progresses_and_drops");
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn write_atomic_offloaded_parks_on_pool_while_worker_progresses() {
        init_test("write_atomic_offloaded_parks_on_pool_while_worker_progresses");
        let dir = TempDir::new("write_atomic_offloaded_t_a").unwrap();
        let path = dir.path().join("target.txt");
        std::fs::write(&path, b"original").unwrap();

        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(1, 1)
            .build()
            .unwrap();

        runtime.block_on(async {
            // Stage new content over original
            let staged = stage_write_atomic(&path, b"new").await.unwrap();

            // Occupy the only blocking pool thread with a parked probe
            let gate = Arc::new(FilesystemOperationProbe::new());
            let blocker_path = dir.path().join("blocker.txt");
            let mut blocker =
                Box::pin(write_with_probe_for_test(&blocker_path, b"x", Arc::clone(&gate)));
            assert!(
                futures_lite::future::poll_once(blocker.as_mut())
                    .await
                    .is_none(),
                "blocker must yield pending"
            );
            assert!(
                gate.wait_until_blocked(Duration::from_secs(5)),
                "blocker must reach gate"
            );

            // Now commit_async: must yield None (queued behind blocker on pool)
            let mut commit_fut = Box::pin(staged.commit_async());
            assert!(
                futures_lite::future::poll_once(commit_fut.as_mut())
                    .await
                    .is_none(),
                "commit_async must offload to pool and not run inline"
            );

            // Target remains original while queued on pool
            assert_eq!(std::fs::read(&path).unwrap(), b"original");

            // Release blocker and wait for both to finish
            gate.release();
            blocker.await.unwrap();
            commit_fut.await.unwrap();

            assert_eq!(std::fs::read(&path).unwrap(), b"new");
        });

        crate::test_complete!("write_atomic_offloaded_parks_on_pool_while_worker_progresses");
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn write_atomic_offloaded_drop_before_claim_preserves_target_and_cleans_temp() {
        init_test("write_atomic_offloaded_drop_before_claim_preserves_target_and_cleans_temp");
        let dir = TempDir::new("write_atomic_offloaded_t_b").unwrap();
        let path = dir.path().join("target.txt");
        std::fs::write(&path, b"original").unwrap();

        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(1, 1)
            .build()
            .unwrap();

        runtime.block_on(async {
            // 1. Stage before blocking pool is occupied
            let staged = stage_write_atomic(&path, b"new2").await.unwrap();

            // 2. Block the only pool worker
            let gate = Arc::new(FilesystemOperationProbe::new());
            let blocker_path = dir.path().join("blocker.txt");
            let mut blocker =
                Box::pin(write_with_probe_for_test(&blocker_path, b"x", Arc::clone(&gate)));
            assert!(
                futures_lite::future::poll_once(blocker.as_mut())
                    .await
                    .is_none()
            );
            assert!(gate.wait_until_blocked(Duration::from_secs(5)));

            // 3. Queue commit_async behind blocker
            let mut commit_fut = Box::pin(staged.commit_async());
            assert!(
                futures_lite::future::poll_once(commit_fut.as_mut())
                    .await
                    .is_none()
            );

            // Drop commit_fut before pool worker claims it
            drop(commit_fut);

            // 4. Release blocker
            gate.release();
            blocker.await.unwrap();

            // 5. Run one more pool job to ensure cancelled job is dequeued and discarded
            let read_bytes = crate::fs::read(&path).await.unwrap();
            assert_eq!(read_bytes, b"original");

            // 6. Target remains original and no temp files are leaked
            assert_eq!(std::fs::read(&path).unwrap(), b"original");
            let leaked_tmp: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().contains(".asupersync-tmp-"))
                .collect();
            assert!(
                leaked_tmp.is_empty(),
                "no leaked temp files: {leaked_tmp:?}"
            );
        });

        crate::test_complete!(
            "write_atomic_offloaded_drop_before_claim_preserves_target_and_cleans_temp"
        );
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn write_atomic_offloaded_restricted_cx_capability_denied() {
        init_test("write_atomic_offloaded_restricted_cx_capability_denied");
        let dir = TempDir::new("write_atomic_offloaded_t_c").unwrap();
        let path = dir.path().join("target.txt");
        std::fs::write(&path, b"original").unwrap();

        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(1, 2)
            .build()
            .unwrap();

        runtime.block_on(async {
            // Case 1: write_atomic_offloaded under restricted Cx
            let restricted_cx = crate::cx::Cx::for_testing().restrict::<crate::cx::cap::None>();
            let res = restricted_cx
                .with_ambient(write_atomic_offloaded(&path, b"unauthorized"))
                .await;
            assert!(res.is_err());
            assert_eq!(res.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(std::fs::read(&path).unwrap(), b"original");

            // Case 2: Stage under full authority, commit_async under restricted authority
            let staged = stage_write_atomic(&path, b"staged_auth").await.unwrap();
            let res2 = restricted_cx.with_ambient(staged.commit_async()).await;
            assert!(res2.is_err());
            assert_eq!(res2.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(std::fs::read(&path).unwrap(), b"original");

            // Temp file must be cleaned up
            let leaked_tmp: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().contains(".asupersync-tmp-"))
                .collect();
            assert!(
                leaked_tmp.is_empty(),
                "temp file must be cleaned up on capability denial"
            );
        });

        crate::test_complete!("write_atomic_offloaded_restricted_cx_capability_denied");
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn write_atomic_offloaded_commit_phase_error_cleanup() {
        init_test("write_atomic_offloaded_commit_phase_error_cleanup");
        let dir = TempDir::new("write_atomic_offloaded_t_d").unwrap();
        let target_dir = dir.path().join("existing_dir");
        std::fs::create_dir(&target_dir).unwrap();
        std::fs::write(target_dir.join("file.txt"), b"keep me").unwrap();

        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(1, 2)
            .build()
            .unwrap();

        runtime.block_on(async {
            // Staging succeeds; rename over non-empty directory fails in commit phase
            let staged = stage_write_atomic(&target_dir, b"cannot overwrite dir")
                .await
                .unwrap();
            let commit_res = staged.commit_async().await;
            assert!(commit_res.is_err(), "commit over directory must fail");
            assert!(target_dir.is_dir());
            assert!(target_dir.join("file.txt").exists());

            // Temp file must be cleaned up
            let leaked_tmp: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().contains(".asupersync-tmp-"))
                .collect();
            assert!(
                leaked_tmp.is_empty(),
                "temp file must be cleaned up on commit failure: {leaked_tmp:?}"
            );
        });

        crate::test_complete!("write_atomic_offloaded_commit_phase_error_cleanup");
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn write_atomic_offloaded_no_pool_executes_inline() {
        init_test("write_atomic_offloaded_no_pool_executes_inline");
        let dir = TempDir::new("write_atomic_offloaded_t_e").unwrap();
        let path = dir.path().join("target.txt");

        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();

        runtime.block_on(async {
            let mut fut = Box::pin(write_atomic_offloaded(&path, b"inline_val"));
            let poll_res = futures_lite::future::poll_once(fut.as_mut()).await;
            assert!(
                poll_res.is_some(),
                "without blocking pool, executes inline on first poll"
            );
            assert!(poll_res.unwrap().is_ok());
            assert_eq!(std::fs::read(&path).unwrap(), b"inline_val");
        });

        crate::test_complete!("write_atomic_offloaded_no_pool_executes_inline");
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn write_atomic_offloaded_with_probe_for_test_exercises_export() {
        init_test("write_atomic_offloaded_with_probe_for_test_exercises_export");
        let dir = TempDir::new("write_atomic_offloaded_t_f").unwrap();
        let path = dir.path().join("target.txt");
        let probe = Arc::new(FilesystemOperationProbe::new());

        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(1, 2)
            .build()
            .unwrap();

        runtime.block_on(async {
            let mut fut = Box::pin(write_atomic_offloaded_with_probe_for_test(
                &path,
                b"probed_val",
                Arc::clone(&probe),
            ));
            assert!(futures_lite::future::poll_once(fut.as_mut()).await.is_none());
            assert!(probe.wait_until_blocked(Duration::from_secs(5)));
            probe.release();
            fut.await.unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), b"probed_val");
        });

        crate::test_complete!("write_atomic_offloaded_with_probe_for_test_exercises_export");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_metadata_basic() {
        init_test("symlink_metadata_basic");
        let dir = TempDir::new("symlink").unwrap();
        let file_path = dir.path().join("file.txt");
        let link_path = dir.path().join("link");

        future::block_on(async {
            write(&file_path, b"content").await.unwrap();
            symlink(&file_path, &link_path).await.unwrap();

            let meta = metadata(&link_path).await.unwrap();
            let is_file = meta.is_file();
            crate::assert_with_log!(is_file, "is_file", true, is_file);
            let len = meta.len();
            crate::assert_with_log!(len == 7, "len", 7, len);

            let link_meta = symlink_metadata(&link_path).await.unwrap();
            let is_symlink = link_meta.file_type().is_symlink();
            crate::assert_with_log!(is_symlink, "is_symlink", true, is_symlink);
        });
        crate::test_complete!("symlink_metadata_basic");
    }
}
