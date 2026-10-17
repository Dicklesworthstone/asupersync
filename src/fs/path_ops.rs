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
        spawn_blocking_io(move || uring_renameat(&from, &to)).await
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
        spawn_blocking_io(move || uring_unlinkat(&path)).await
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
        spawn_blocking_io(move || uring_symlinkat(&original, &link)).await
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
    /// [`crate::fs::scoped::ScopedFs::write_atomic`].
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
/// [`crate::fs::scoped::ScopedFs::write_atomic`].
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
    submit_and_wait_one(&mut ring)?;
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

/// Submit the queued entry and wait for its completion. A signal can
/// interrupt the wait after the kernel took the entry, and the operation then
/// still commits; waiting again collects its completion without submitting it
/// twice, where returning the interruption reported a committed rename as
/// failed (br-asupersync-pxg07b M2).
#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub(super) fn submit_and_wait_one(ring: &mut io_uring::IoUring) -> io::Result<()> {
    loop {
        match ring.submit_and_wait(1) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result.map(drop),
        }
    }
}

/// Whether io_uring itself refused the work, rather than the operation
/// failing: no kernel support (ENOSYS, as under gVisor), a seccomp filter or
/// `kernel.io_uring_disabled` (EPERM, as in Docker's default profile), a
/// locked-memory limit (ENOMEM), or an opcode this kernel does not know
/// (EINVAL, EOPNOTSUPP). The same errno from the operation itself means it did
/// nothing, so the blocking syscall returns it again.
#[cfg(all(target_os = "linux", feature = "io-uring"))]
fn io_uring_refused(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOSYS | libc::EPERM | libc::ENOMEM | libc::EINVAL | libc::EOPNOTSUPP)
    )
}

/// Run a path operation through io_uring, or through the blocking syscall
/// when io_uring is refused, so the operation never fails only because the
/// kernel or sandbox does not offer io_uring (br-asupersync-pxg07b M2).
/// Callers run this on a blocking thread: the io_uring wait blocks it.
#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub(super) fn uring_or_blocking(
    uring: impl FnOnce() -> io::Result<()>,
    blocking: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    #[cfg(test)]
    let uring = || match tests::forced_uring_refusal() {
        Some(errno) => Err(io::Error::from_raw_os_error(errno)),
        None => uring(),
    };
    match uring() {
        Err(error) if io_uring_refused(&error) => {
            #[cfg(test)]
            tests::note_blocking_fallback();
            blocking()
        }
        result => result,
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
    uring_or_blocking(|| uring_submit_one(&entry), || std::fs::remove_file(path))
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
    uring_or_blocking(|| uring_submit_one(&entry), || std::fs::rename(from, to))
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
    uring_or_blocking(
        || uring_submit_one(&entry),
        || std::os::unix::fs::symlink(target, linkpath),
    )
}

#[cfg(test)]
#[path = "path_ops_inline_tests.rs"]
mod tests;
