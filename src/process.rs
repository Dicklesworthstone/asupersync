#![allow(unsafe_code)]
//! Async child process management.
//!
//! This module uses unsafe code for Unix process spawning (fork/exec) and
//! signal handling (waitpid).
//!
//! This module provides async equivalents of `std::process` types for spawning
//! and managing child processes. It enables non-blocking process spawning,
//! I/O piping, and wait operations.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::process::Command;
//!
//! fn run_command() -> std::io::Result<()> {
//!     let mut cmd = Command::new("echo");
//!     let output = cmd
//!         .arg("hello")
//!         .output()?;
//!
//!     println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
//!     Ok(())
//! }
//! ```
//!
//! # Cancel-Safety
//!
//! - Process spawning itself is synchronous (the syscall).
//! - `wait()` can be cancelled; the process continues running.
//! - Use `kill_on_drop(true)` for automatic cleanup on cancellation.
//! - I/O operations are cancel-safe (partial reads/writes are fine).

use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::runtime::io_driver::IoRegistration;
use crate::runtime::reactor::Interest;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process as std_process;
use std::task::{Context, Poll};

#[cfg(windows)]
use std::cmp::Ordering;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::{
    ffi::OsStrExt,
    io::{AsRawHandle, RawHandle},
};

#[cfg(unix)]
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_nonblocking() -> io::Result<()> {
    Ok(())
}

fn drain_nonblocking<R: Read>(reader: &mut R, out: &mut Vec<u8>) -> io::Result<(bool, bool)> {
    let mut any = false;
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Ok((true, any)),
            Ok(n) => {
                any = true;
                out.extend_from_slice(&buf[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok((false, any)),
            Err(e) => return Err(e),
        }
    }
}

fn register_interest(
    registration: &mut Option<IoRegistration>,
    source: &dyn crate::runtime::reactor::Source,
    cx: &Context<'_>,
    interest: Interest,
) -> io::Result<()> {
    if let Some(reg) = registration {
        let target_interest = interest;
        // Re-arm reactor interest and conditionally update the waker in a
        // single lock acquisition (will_wake guard skips the clone).
        match reg.rearm(target_interest, cx.waker()) {
            Ok(true) => return Ok(()),
            Ok(false) => {
                *registration = None;
            }
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                *registration = None;
                cx.waker().wake_by_ref();
                return Ok(());
            }
            Err(err) => return Err(err),
        }
    }

    let Some(current) = Cx::current() else {
        cx.waker().wake_by_ref();
        return Ok(());
    };
    let Some(driver) = current.io_driver_handle() else {
        cx.waker().wake_by_ref();
        return Ok(());
    };

    match driver.register(source, interest, cx.waker().clone()) {
        Ok(reg) => {
            *registration = Some(reg);
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::Unsupported => {
            cx.waker().wake_by_ref();
            Ok(())
        }
        Err(err) => Err(err),
    }
}

fn cleanup_child_after_spawn_setup_failure(child: &mut std_process::Child) {
    // `kill()` alone still leaves a zombie on Unix until the parent reaps it.
    // Best-effort reap here keeps spawn-time setup failures from leaking the child.
    let _ = child.kill();
    let _ = child.wait();
}

/// Error type for process operations.
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// The process was not found (ENOENT).
    #[error("process not found: {0}")]
    NotFound(String),

    /// Permission denied (EACCES).
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// The process was terminated by a signal.
    #[error("process terminated by signal {0}")]
    Signaled(i32),
}

impl From<ProcessError> for io::Error {
    fn from(err: ProcessError) -> Self {
        match err {
            ProcessError::Io(inner) => inner,
            other => Self::other(other.to_string()),
        }
    }
}

/// Standard I/O configuration for child processes.
///
/// Configures how the child's stdin, stdout, and stderr are handled.
#[derive(Debug, Clone, Default)]
pub enum Stdio {
    /// Inherit from the parent process.
    ///
    /// The child will share the same stdin/stdout/stderr as the parent.
    #[default]
    Inherit,

    /// Create a pipe to/from the child process.
    ///
    /// For stdin, the parent can write to the child.
    /// For stdout/stderr, the parent can read from the child.
    Pipe,

    /// Discard (redirect to /dev/null).
    ///
    /// For stdin, the child will read EOF immediately.
    /// For stdout/stderr, the output is discarded.
    Null,
}

impl Stdio {
    /// Creates an `Inherit` configuration.
    #[must_use]
    pub fn inherit() -> Self {
        Self::Inherit
    }

    /// Creates a `Pipe` configuration.
    #[must_use]
    pub fn piped() -> Self {
        Self::Pipe
    }

    /// Creates a `Null` configuration.
    #[must_use]
    pub fn null() -> Self {
        Self::Null
    }

    /// Converts to std::process::Stdio.
    fn to_std(&self) -> std_process::Stdio {
        match self {
            Self::Inherit => std_process::Stdio::inherit(),
            Self::Pipe => std_process::Stdio::piped(),
            Self::Null => std_process::Stdio::null(),
        }
    }
}

impl From<Stdio> for std_process::Stdio {
    fn from(stdio: Stdio) -> Self {
        stdio.to_std()
    }
}

#[cfg(not(windows))]
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
struct EnvKey(OsString);

#[cfg(not(windows))]
impl From<OsString> for EnvKey {
    fn from(key: OsString) -> Self {
        Self(key)
    }
}

#[cfg(not(windows))]
impl From<&OsStr> for EnvKey {
    fn from(key: &OsStr) -> Self {
        Self(key.to_os_string())
    }
}

#[cfg(not(windows))]
impl AsRef<OsStr> for EnvKey {
    fn as_ref(&self) -> &OsStr {
        &self.0
    }
}

#[cfg(windows)]
#[link(name = "Kernel32")]
unsafe extern "system" {
    #[link_name = "CompareStringOrdinal"]
    fn compare_string_ordinal(
        string1: *const u16,
        count1: i32,
        string2: *const u16,
        count2: i32,
        ignore_case: i32,
    ) -> i32;
}

// Cancel-drain escalation knobs (br-asupersync-nhk8ur).
//
// On parent-Cx cancel, `wait_async` / `wait_with_output_async` send SIGTERM
// (Unix) or TerminateProcess (Windows) and poll `try_wait` for up to roughly
// 2 seconds before escalating to SIGKILL. The 2-second budget is the rough
// industry default for graceful-shutdown deadlines (Docker, Kubernetes,
// systemd's TimeoutStopSec all default in this neighborhood) and is the
// cap on cancel-path latency the parent task experiences.
//
// `GRACEFUL_KILL_POLLS = 200` × `GRACEFUL_KILL_POLL_MAX_BACKOFF_MS = 10`
// gives the upper bound; with exponential backoff starting at 1ms doubling
// to the cap, the actual wall-clock spent on a non-exiting child is just
// over 2 seconds.
//
// (NB: removed an orphaned `#[cfg(windows)]` here — Rust attribute scope
// applies to the next *item*, which made `GRACEFUL_KILL_POLLS` invisible
// on Linux and broke every cargo build.)
const GRACEFUL_KILL_POLLS: u32 = 200;
const GRACEFUL_KILL_POLL_MAX_BACKOFF_MS: u64 = 10;
const REAP_AFTER_KILL_POLLS: u32 = 200;

#[cfg(windows)]
const WINDOWS_TRUE: i32 = 1;
#[cfg(windows)]
const WINDOWS_CSTR_LESS_THAN: i32 = 1;
#[cfg(windows)]
const WINDOWS_CSTR_EQUAL: i32 = 2;
#[cfg(windows)]
const WINDOWS_CSTR_GREATER_THAN: i32 = 3;

#[cfg(windows)]
#[derive(Debug, Clone, Eq)]
struct EnvKey {
    os_string: OsString,
    utf16: Vec<u16>,
}

#[cfg(windows)]
impl From<OsString> for EnvKey {
    fn from(key: OsString) -> Self {
        Self {
            utf16: key.encode_wide().collect(),
            os_string: key,
        }
    }
}

#[cfg(windows)]
impl From<&OsStr> for EnvKey {
    fn from(key: &OsStr) -> Self {
        Self::from(key.to_os_string())
    }
}

#[cfg(windows)]
impl AsRef<OsStr> for EnvKey {
    fn as_ref(&self) -> &OsStr {
        &self.os_string
    }
}

#[cfg(windows)]
impl Ord for EnvKey {
    fn cmp(&self, other: &Self) -> Ordering {
        let (Ok(count1), Ok(count2)) = (
            i32::try_from(self.utf16.len()),
            i32::try_from(other.utf16.len()),
        ) else {
            return self.utf16.cmp(&other.utf16);
        };
        let result = unsafe {
            compare_string_ordinal(
                self.utf16.as_ptr(),
                count1,
                other.utf16.as_ptr(),
                count2,
                WINDOWS_TRUE,
            )
        };
        match result {
            WINDOWS_CSTR_LESS_THAN => Ordering::Less,
            WINDOWS_CSTR_EQUAL => Ordering::Equal,
            WINDOWS_CSTR_GREATER_THAN => Ordering::Greater,
            _ => self.utf16.cmp(&other.utf16),
        }
    }
}

#[cfg(windows)]
impl PartialOrd for EnvKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(windows)]
impl PartialEq for EnvKey {
    fn eq(&self, other: &Self) -> bool {
        self.utf16.len() == other.utf16.len() && self.cmp(other) == Ordering::Equal
    }
}

/// Builder for spawning child processes.
///
/// Provides a fluent API for configuring and spawning processes.
///
/// # Example
///
/// ```ignore
/// use asupersync::process::Command;
///
/// let child = Command::new("ls")
///     .arg("-la")
///     .current_dir("/tmp")
///     .env("LANG", "C")
///     .spawn()?;
/// ```
#[derive(Debug, Clone)]
pub struct Command {
    program: OsString,
    args: Vec<OsString>,
    env: BTreeMap<EnvKey, Option<OsString>>,
    env_clear: bool,
    current_dir: Option<PathBuf>,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
    kill_on_drop: bool,
}

impl Command {
    fn set_env_change(&mut self, key: EnvKey, value: Option<OsString>) {
        self.env.remove(&key);
        self.env.insert(key, value);
    }

    /// Creates a new command for the given program.
    ///
    /// # Arguments
    ///
    /// * `program` - The program to execute. This can be:
    ///   - An absolute path (`/usr/bin/ls`)
    ///   - A relative path (`./script.sh`)
    ///   - A program name to be found in PATH (`ls`)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let cmd = Command::new("echo");
    /// ```
    #[must_use]
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self {
        Self {
            program: program.as_ref().to_os_string(),
            args: Vec::new(),
            env: BTreeMap::new(),
            env_clear: false,
            current_dir: None,
            stdin: Stdio::default(),
            stdout: Stdio::default(),
            stderr: Stdio::default(),
            kill_on_drop: false,
        }
    }

    /// Adds an argument to the command.
    ///
    /// # Example
    ///
    /// ```ignore
    /// Command::new("echo")
    ///     .arg("hello")
    ///     .arg("world");
    /// ```
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    /// Adds multiple arguments to the command.
    ///
    /// # Example
    ///
    /// ```ignore
    /// Command::new("echo")
    ///     .args(["hello", "world"]);
    /// ```
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for arg in args {
            self.args.push(arg.as_ref().to_os_string());
        }
        self
    }

    /// Sets an environment variable for the child process.
    ///
    /// # Example
    ///
    /// ```ignore
    /// Command::new("printenv")
    ///     .env("MY_VAR", "my_value");
    /// ```
    pub fn env<K, V>(&mut self, key: K, val: V) -> &mut Self
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        let key = EnvKey::from(key.as_ref());
        self.set_env_change(key, Some(val.as_ref().to_os_string()));
        self
    }

    /// Sets multiple environment variables for the child process.
    ///
    /// # Example
    ///
    /// ```ignore
    /// Command::new("env")
    ///     .envs([("VAR1", "val1"), ("VAR2", "val2")]);
    /// ```
    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        for (key, val) in vars {
            let key = EnvKey::from(key.as_ref());
            self.set_env_change(key, Some(val.as_ref().to_os_string()));
        }
        self
    }

    /// Removes an environment variable from the child process.
    ///
    /// # Example
    ///
    /// ```ignore
    /// Command::new("env")
    ///     .env_remove("PATH");
    /// ```
    pub fn env_remove<K: AsRef<OsStr>>(&mut self, key: K) -> &mut Self {
        let key = EnvKey::from(key.as_ref());
        if self.env_clear {
            self.env.remove(&key);
        } else {
            self.set_env_change(key, None);
        }
        self
    }

    /// Clears the entire environment for the child process.
    ///
    /// After calling this, only variables set with `env()` will be present.
    ///
    /// # Example
    ///
    /// ```ignore
    /// Command::new("env")
    ///     .env_clear()
    ///     .env("PATH", "/usr/bin");
    /// ```
    pub fn env_clear(&mut self) -> &mut Self {
        self.env_clear = true;
        self.env.clear();
        self
    }

    /// Sets the working directory for the child process.
    ///
    /// # Example
    ///
    /// ```ignore
    /// Command::new("ls")
    ///     .current_dir("/tmp");
    /// ```
    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.current_dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Configures stdin for the child process.
    ///
    /// # Example
    ///
    /// ```ignore
    /// Command::new("cat")
    ///     .stdin(Stdio::piped());
    /// ```
    pub fn stdin(&mut self, cfg: Stdio) -> &mut Self {
        self.stdin = cfg;
        self
    }

    /// Configures stdout for the child process.
    ///
    /// # Example
    ///
    /// ```ignore
    /// Command::new("ls")
    ///     .stdout(Stdio::piped());
    /// ```
    pub fn stdout(&mut self, cfg: Stdio) -> &mut Self {
        self.stdout = cfg;
        self
    }

    /// Configures stderr for the child process.
    ///
    /// # Example
    ///
    /// ```ignore
    /// Command::new("ls")
    ///     .stderr(Stdio::null());
    /// ```
    pub fn stderr(&mut self, cfg: Stdio) -> &mut Self {
        self.stderr = cfg;
        self
    }

    /// Configures whether to kill the process when the `Child` is dropped.
    ///
    /// When set to `true`, dropping the `Child` handle will send SIGKILL
    /// to the process. This is useful for ensuring cleanup on cancellation.
    ///
    /// Default: `false`
    ///
    /// # Example
    ///
    /// ```ignore
    /// let child = Command::new("sleep")
    ///     .arg("100")
    ///     .kill_on_drop(true)
    ///     .spawn()?;
    ///
    /// // If we drop `child` here, the sleep process will be killed
    /// ```
    pub fn kill_on_drop(&mut self, kill: bool) -> &mut Self {
        self.kill_on_drop = kill;
        self
    }

    /// Spawns the command as a child process.
    ///
    /// Returns a `Child` handle that can be used to interact with the process.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The program doesn't exist
    /// - Permission is denied
    /// - Another I/O error occurs
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut child = Command::new("ls")
    ///     .stdout(Stdio::piped())
    ///     .spawn()?;
    ///
    /// let status = child.wait()?;
    /// ```
    pub fn spawn(&mut self) -> Result<Child, ProcessError> {
        let mut cmd = std_process::Command::new(&self.program);

        cmd.args(&self.args);

        if self.env_clear {
            cmd.env_clear();
        }

        for (key, maybe_val) in &self.env {
            if let Some(val) = maybe_val {
                cmd.env(key.as_ref(), val);
            } else {
                cmd.env_remove(key.as_ref());
            }
        }

        if let Some(ref dir) = self.current_dir {
            cmd.current_dir(dir);
        }

        cmd.stdin(self.stdin.to_std());
        cmd.stdout(self.stdout.to_std());
        cmd.stderr(self.stderr.to_std());

        let mut child = cmd.spawn().map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => {
                ProcessError::NotFound(self.program.to_string_lossy().into_owned())
            }
            io::ErrorKind::PermissionDenied => {
                ProcessError::PermissionDenied(self.program.to_string_lossy().into_owned())
            }
            _ => ProcessError::Io(e),
        })?;

        // Extract the I/O handles before wrapping (use take() to avoid partial move).
        // If set_nonblocking fails for any handle, kill the child to prevent zombies.
        let stdin = child
            .stdin
            .take()
            .map(ChildStdin::from_std)
            .transpose()
            .inspect_err(|_| {
                cleanup_child_after_spawn_setup_failure(&mut child);
            })?;
        let stdout = child
            .stdout
            .take()
            .map(ChildStdout::from_std)
            .transpose()
            .inspect_err(|_| {
                cleanup_child_after_spawn_setup_failure(&mut child);
            })?;
        let stderr = child
            .stderr
            .take()
            .map(ChildStderr::from_std)
            .transpose()
            .inspect_err(|_| {
                cleanup_child_after_spawn_setup_failure(&mut child);
            })?;

        Ok(Child {
            inner: Some(child),
            stdin,
            stdout,
            stderr,
            kill_on_drop: self.kill_on_drop,
        })
    }

    fn spawn_with_temporary_stdio(
        &mut self,
        stdin: Stdio,
        stdout: Stdio,
        stderr: Stdio,
    ) -> Result<Child, ProcessError> {
        let previous = (
            std::mem::replace(&mut self.stdin, stdin),
            std::mem::replace(&mut self.stdout, stdout),
            std::mem::replace(&mut self.stderr, stderr),
        );
        let result = self.spawn();
        self.stdin = previous.0;
        self.stdout = previous.1;
        self.stderr = previous.2;
        result
    }

    /// Spawns the command and waits for it to complete, collecting output.
    ///
    /// Stdout and stderr are captured; stdin is set to null.
    ///
    /// # Errors
    ///
    /// Returns an error if spawning or waiting fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let output = Command::new("echo")
    ///     .arg("hello")
    ///     .output()?;
    ///
    /// println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    /// ```
    pub fn output(&mut self) -> Result<Output, ProcessError> {
        let child = self.spawn_with_temporary_stdio(Stdio::Null, Stdio::Pipe, Stdio::Pipe)?;
        child.wait_with_output()
    }

    /// Async variant of [`output`](Self::output).
    ///
    /// Uses cooperative polling to avoid blocking the runtime thread while
    /// waiting for process exit and draining pipes. (br-asupersync-nhk8ur)
    pub async fn output_async(&mut self, cx: &Cx) -> Result<Output, ProcessError> {
        let child = self.spawn_with_temporary_stdio(Stdio::Null, Stdio::Pipe, Stdio::Pipe)?;
        child.wait_with_output_async(cx).await
    }

    /// Spawns the command and waits for it to complete, returning status.
    ///
    /// Stdin, stdout, and stderr are inherited.
    ///
    /// # Errors
    ///
    /// Returns an error if spawning or waiting fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let status = Command::new("ls")
    ///     .status()?;
    ///
    /// if status.success() {
    ///     println!("Command succeeded");
    /// }
    /// ```
    pub fn status(&mut self) -> Result<ExitStatus, ProcessError> {
        let mut child =
            self.spawn_with_temporary_stdio(Stdio::Inherit, Stdio::Inherit, Stdio::Inherit)?;
        child.wait()
    }

    /// Async variant of [`status`](Self::status).
    ///
    /// Uses cooperative polling to avoid blocking the runtime thread while
    /// waiting for process exit. (br-asupersync-nhk8ur)
    pub async fn status_async(&mut self, cx: &Cx) -> Result<ExitStatus, ProcessError> {
        let mut child =
            self.spawn_with_temporary_stdio(Stdio::Inherit, Stdio::Inherit, Stdio::Inherit)?;
        child.wait_async(cx).await
    }
}

/// Handle to a spawned child process.
///
/// This handle can be used to:
/// - Access stdin/stdout/stderr pipes
/// - Wait for the process to exit
/// - Kill the process
/// - Check exit status
///
/// # Drop Behavior
///
/// By default, dropping a `Child` does *not* kill the process. Set
/// `kill_on_drop(true)` on the `Command` to enable automatic cleanup.
#[derive(Debug)]
pub struct Child {
    inner: Option<std_process::Child>,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    kill_on_drop: bool,
}

impl Child {
    /// Returns the process ID of the child.
    ///
    /// Returns `None` if the process has already been waited on.
    #[must_use]
    pub fn id(&self) -> Option<u32> {
        self.inner.as_ref().map(std::process::Child::id)
    }

    /// Takes ownership of the child's stdin handle.
    ///
    /// This can only be called once; subsequent calls return `None`.
    pub fn stdin(&mut self) -> Option<ChildStdin> {
        self.stdin.take()
    }

    /// Takes ownership of the child's stdout handle.
    ///
    /// This can only be called once; subsequent calls return `None`.
    pub fn stdout(&mut self) -> Option<ChildStdout> {
        self.stdout.take()
    }

    /// Takes ownership of the child's stderr handle.
    ///
    /// This can only be called once; subsequent calls return `None`.
    pub fn stderr(&mut self) -> Option<ChildStderr> {
        self.stderr.take()
    }

    /// Waits for the child process to exit.
    ///
    /// This is cancel-safe: if cancelled, the process continues running.
    /// Use `kill_on_drop(true)` for automatic cleanup on cancellation.
    ///
    /// # Errors
    ///
    /// Returns an error if waiting fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut child = Command::new("sleep").arg("1").spawn()?;
    /// let status = child.wait()?;
    /// println!("Exit code: {:?}", status.code());
    /// ```
    pub fn wait(&mut self) -> Result<ExitStatus, ProcessError> {
        // Match std::process::Child::wait semantics: close the parent write end
        // first so children blocked on stdin EOF can terminate instead of
        // deadlocking the wait.
        drop(self.stdin.take());

        // Use kernel blocking wait for the common "wait until exit" path.
        // This avoids a user-space poll/sleep loop while still preserving
        // ownership on errors (non-destructive wait semantics).
        let child = self.inner.as_mut().ok_or_else(|| {
            ProcessError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "child already waited",
            ))
        })?;

        let status = child.wait()?;
        self.inner = None;
        Ok(ExitStatus::from_std(status))
    }

    /// Async variant of [`wait`](Self::wait).
    ///
    /// Uses `try_wait()` + cooperative yielding to avoid blocking the runtime
    /// worker thread while waiting for process completion.
    ///
    /// # Cancellation
    ///
    /// `wait_async` takes the parent task's [`Cx`] so cancellation propagates
    /// to the child per asupersync's structured-concurrency invariant: a
    /// spawned subprocess is an owned resource of its parent region, and on
    /// region close the parent must not return Cancelled while the child is
    /// still running. (br-asupersync-nhk8ur)
    ///
    /// On cancel detection the child is escalated:
    ///
    ///   1. SIGTERM (Unix) / `TerminateProcess` (Windows) — request graceful
    ///      shutdown.
    ///   2. Poll for graceful exit for up to `GRACEFUL_KILL_POLLS *
    ///      GRACEFUL_KILL_POLL_MS` = 2 seconds.
    ///   3. SIGKILL — if still running, force-terminate.
    ///   4. Reap — drive `try_wait` until the child exits so no zombie
    ///      remains.
    ///
    /// The escalation runs without honoring further cancellation
    /// checkpoints — the parent's cancel has already fired, this is the
    /// drain phase. The function returns `Cancelled` after the child has
    /// been fully reaped.
    pub async fn wait_async(&mut self, cx: &Cx) -> Result<ExitStatus, ProcessError> {
        // Match the synchronous wait path and std semantics so async wait does
        // not keep the child's stdin pipe open indefinitely.
        drop(self.stdin.take());

        // Use exponential backoff to avoid busy-looping the executor.
        // Starts at 1ms, doubles up to 50ms between checks.
        let mut backoff_ms = 1u64;
        loop {
            if cx.checkpoint().is_err() {
                self.cancel_drain_child().await;
                return Err(ProcessError::Io(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled",
                )));
            }
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            let now = crate::time::wall_now();
            crate::time::sleep(now, std::time::Duration::from_millis(backoff_ms)).await;
            backoff_ms = (backoff_ms * 2).min(50);
        }
    }

    /// Drain phase of cancel propagation: SIGTERM, brief grace window, then
    /// SIGKILL, then reap. Best-effort — every step ignores its own errors
    /// because the caller is already returning Cancelled and the only goal
    /// of this drain is to leave no zombie behind.
    /// (br-asupersync-nhk8ur)
    async fn cancel_drain_child(&mut self) {
        // Step 1: graceful-termination request.
        #[cfg(unix)]
        {
            let _ = self.signal(libc::SIGTERM);
        }
        #[cfg(not(unix))]
        {
            let _ = self.kill();
        }

        // Step 2: poll for graceful exit. Cap is 2 seconds total so a
        // misbehaving child cannot stall the cancel path indefinitely.
        let mut polls = 0u32;
        let mut backoff_ms = 1u64;
        while polls < GRACEFUL_KILL_POLLS {
            polls += 1;
            match self.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => {}
                Err(_) => return, // child gone or already reaped — done.
            }
            let now = crate::time::wall_now();
            crate::time::sleep(now, std::time::Duration::from_millis(backoff_ms)).await;
            backoff_ms = (backoff_ms * 2).min(GRACEFUL_KILL_POLL_MAX_BACKOFF_MS);
        }

        // Step 3: force-kill.
        let _ = self.kill();

        // Step 4: reap. The child has been SIGKILL'd; this loop is bounded
        // by the kernel's delivery of the kill signal, which is essentially
        // immediate. We still cap reap polls so a kernel quirk cannot
        // deadlock the cancel path.
        let mut reap_polls = 0u32;
        while reap_polls < REAP_AFTER_KILL_POLLS {
            reap_polls += 1;
            match self.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => {}
            }
            let now = crate::time::wall_now();
            crate::time::sleep(now, std::time::Duration::from_millis(2)).await;
        }
    }

    /// Waits for the child and collects all output.
    ///
    /// This consumes the `Child` and returns the collected stdout/stderr.
    ///
    /// # Errors
    ///
    /// Returns an error if waiting or reading fails.
    pub fn wait_with_output(mut self) -> Result<Output, ProcessError> {
        #[cfg(windows)]
        {
            return self.wait_with_output_windows();
        }

        // Take the handles before waiting
        let mut stdout_handle = self.stdout.take();
        let mut stderr_handle = self.stderr.take();
        drop(self.stdin.take()); // Close stdin

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        // Avoid deadlocks: interleave drain attempts with `try_wait`.
        let mut status = None;
        let mut stdout_done = stdout_handle.is_none();
        let mut stderr_done = stderr_handle.is_none();

        while status.is_none() || !stdout_done || !stderr_done {
            if crate::cx::Cx::current().is_some_and(|c| c.checkpoint().is_err()) {
                return Err(ProcessError::Io(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled",
                )));
            }

            let mut progressed = false;

            if status.is_none() {
                match self.try_wait() {
                    Ok(Some(s)) => {
                        status = Some(s);
                        progressed = true;
                    }
                    Ok(None) => {}
                    // Some environments can surface EAGAIN for non-blocking waitpid
                    // style checks. Treat it as "still running" and keep draining.
                    Err(ProcessError::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }

            if let Some(handle) = stdout_handle.as_mut() {
                let (done, any) = drain_nonblocking(&mut handle.inner, &mut stdout_buf)?;
                if done {
                    stdout_handle = None;
                    stdout_done = true;
                }
                progressed |= any || done;
            }

            if let Some(handle) = stderr_handle.as_mut() {
                let (done, any) = drain_nonblocking(&mut handle.inner, &mut stderr_buf)?;
                if done {
                    stderr_handle = None;
                    stderr_done = true;
                }
                progressed |= any || done;
            }

            if status.is_some() && stdout_done && stderr_done {
                break;
            }

            if !progressed {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }

        let status = match status {
            Some(s) => s,
            None => self.wait()?,
        };

        Ok(Output {
            status,
            stdout: stdout_buf,
            stderr: stderr_buf,
        })
    }

    /// Async variant of [`wait_with_output`](Self::wait_with_output).
    ///
    /// Uses cooperative yielding instead of thread sleeps while waiting for
    /// process exit and pipe drain progress. Takes the parent task's [`Cx`]
    /// so cancellation propagates to the child via the SIGTERM-then-SIGKILL
    /// drain escalation in [`wait_async`]. (br-asupersync-nhk8ur)
    pub async fn wait_with_output_async(mut self, cx: &Cx) -> Result<Output, ProcessError> {
        #[cfg(windows)]
        {
            return crate::runtime::spawn_blocking_io(move || {
                self.wait_with_output_windows().map_err(io::Error::from)
            })
            .await
            .map_err(ProcessError::Io);
        }

        // Take the handles before waiting
        let mut stdout_handle = self.stdout.take();
        let mut stderr_handle = self.stderr.take();
        drop(self.stdin.take()); // Close stdin

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        let mut status = None;
        let mut stdout_done = stdout_handle.is_none();
        let mut stderr_done = stderr_handle.is_none();
        let mut backoff_ms = 1u64;

        while status.is_none() || !stdout_done || !stderr_done {
            if cx.checkpoint().is_err() {
                // br-asupersync-nhk8ur: drain the child via the same
                // escalation wait_async uses so wait_with_output_async also
                // leaves no zombie behind on parent-task cancel.
                self.cancel_drain_child().await;
                return Err(ProcessError::Io(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled",
                )));
            }

            let mut progressed = false;

            if status.is_none() {
                match self.try_wait() {
                    Ok(Some(s)) => {
                        status = Some(s);
                        progressed = true;
                    }
                    Ok(None) => {}
                    Err(ProcessError::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }

            if let Some(handle) = stdout_handle.as_mut() {
                let (done, any) = drain_nonblocking(&mut handle.inner, &mut stdout_buf)?;
                if done {
                    stdout_handle = None;
                    stdout_done = true;
                }
                progressed |= any || done;
            }

            if let Some(handle) = stderr_handle.as_mut() {
                let (done, any) = drain_nonblocking(&mut handle.inner, &mut stderr_buf)?;
                if done {
                    stderr_handle = None;
                    stderr_done = true;
                }
                progressed |= any || done;
            }

            if status.is_some() && stdout_done && stderr_done {
                break;
            }

            if progressed {
                backoff_ms = 1;
                crate::runtime::yield_now().await;
            } else {
                let now = crate::time::wall_now();
                crate::time::sleep(now, std::time::Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(50);
            }
        }

        let status = match status {
            Some(s) => s,
            None => self.wait_async(cx).await?,
        };

        Ok(Output {
            status,
            stdout: stdout_buf,
            stderr: stderr_buf,
        })
    }

    /// Sends SIGKILL to the child process.
    ///
    /// This does not wait for the process to exit. Call `wait()` after
    /// to clean up the zombie process.
    ///
    /// # Errors
    ///
    /// Returns an error if the signal cannot be sent (e.g., process already exited).
    pub fn kill(&mut self) -> Result<(), ProcessError> {
        let child = self.inner.as_mut().ok_or_else(|| {
            ProcessError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "child already waited",
            ))
        })?;

        child.kill()?;
        Ok(())
    }

    /// Sends an arbitrary signal to the child process (Unix only).
    ///
    /// Common signals: `libc::SIGTERM` (15), `libc::SIGHUP` (1),
    /// `libc::SIGINT` (2), `libc::SIGUSR1` (10), `libc::SIGUSR2` (12).
    ///
    /// # Errors
    ///
    /// Returns an error if the process has already been waited on, or if
    /// the `kill(2)` syscall fails (e.g., process already exited).
    #[cfg(unix)]
    pub fn signal(&mut self, sig: i32) -> Result<(), ProcessError> {
        let child = self.inner.as_ref().ok_or_else(|| {
            ProcessError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "child already waited",
            ))
        })?;

        #[allow(clippy::cast_possible_wrap)]
        let pid = child.id() as i32; // POSIX pid_t is i32; u32->i32 wrapping is safe for valid PIDs
        let ret = unsafe { libc::kill(pid, sig) };
        if ret != 0 {
            return Err(ProcessError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Attempts to check exit status without blocking.
    ///
    /// Returns `Ok(None)` if the process is still running.
    /// Returns `Ok(Some(status))` if the process has exited.
    ///
    /// # Errors
    ///
    /// Returns an error if checking status fails.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, ProcessError> {
        let child = self.inner.as_mut().ok_or_else(|| {
            ProcessError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "child already waited",
            ))
        })?;

        match child.try_wait()? {
            Some(status) => {
                self.inner = None;
                Ok(Some(ExitStatus::from_std(status)))
            }
            None => Ok(None),
        }
    }

    /// Starts killing the process without waiting.
    ///
    /// Alias for `kill()` for API compatibility.
    pub fn start_kill(&mut self) -> Result<(), ProcessError> {
        self.kill()
    }

    #[cfg(windows)]
    fn wait_with_output_windows(mut self) -> Result<Output, ProcessError> {
        // Take the handles before waiting to avoid writer-side deadlocks.
        let stdout_handle = self.stdout.take().map(|handle| handle.inner);
        let stderr_handle = self.stderr.take().map(|handle| handle.inner);
        drop(self.stdin.take());

        let stdout_thread = stdout_handle.map(|mut stream| {
            std::thread::spawn(move || -> io::Result<Vec<u8>> {
                let mut buf = Vec::new();
                stream.read_to_end(&mut buf)?;
                Ok(buf)
            })
        });
        let stderr_thread = stderr_handle.map(|mut stream| {
            std::thread::spawn(move || -> io::Result<Vec<u8>> {
                let mut buf = Vec::new();
                stream.read_to_end(&mut buf)?;
                Ok(buf)
            })
        });

        let status = self.wait()?;

        let stdout = match stdout_thread {
            Some(handle) => handle
                .join()
                .map_err(|_| io::Error::other("stdout reader thread panicked"))??,
            None => Vec::new(),
        };
        let stderr = match stderr_thread {
            Some(handle) => handle
                .join()
                .map_err(|_| io::Error::other("stderr reader thread panicked"))??,
            None => Vec::new(),
        };

        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KillOnDropReapStrategy {
    DirectWait,
    BlockingPool,
    DetachedThread,
}

fn blocking_pool_for_kill_on_drop_reap() -> Option<crate::runtime::blocking_pool::BlockingPoolHandle>
{
    Cx::current()
        .and_then(|cx| cx.blocking_pool_handle())
        .filter(|pool| !pool.is_shutdown())
        .or_else(|| {
            crate::runtime::Runtime::current_handle()
                .and_then(|handle| handle.blocking_handle())
                .filter(|pool| !pool.is_shutdown())
        })
}

fn kill_on_drop_reap_strategy() -> KillOnDropReapStrategy {
    if blocking_pool_for_kill_on_drop_reap().is_some() {
        return KillOnDropReapStrategy::BlockingPool;
    }
    if Cx::current().is_some() || crate::runtime::Runtime::current_handle().is_some() {
        return KillOnDropReapStrategy::DetachedThread;
    }
    KillOnDropReapStrategy::DirectWait
}

fn try_dispatch_kill_on_drop_reap_on_pool(
    pool: &crate::runtime::blocking_pool::BlockingPoolHandle,
    child: std_process::Child,
) -> Result<(), std_process::Child> {
    let shared_child = std::sync::Arc::new(parking_lot::Mutex::new(Some(child)));
    let worker_child = std::sync::Arc::clone(&shared_child);
    let handle = pool.spawn(move || {
        let mut child_slot = worker_child.lock();
        if let Some(mut child) = child_slot.take() {
            let _ = child.wait();
        }
    });

    if handle.is_done() && handle.is_cancelled() {
        let mut child_slot = shared_child.lock();
        if let Some(child) = child_slot.take() {
            return Err(child);
        }
    }
    Ok(())
}

fn spawn_detached_kill_on_drop_reaper(child: std_process::Child) -> Result<(), std_process::Child> {
    let shared_child = std::sync::Arc::new(parking_lot::Mutex::new(Some(child)));
    let thread_child = std::sync::Arc::clone(&shared_child);

    // ubs:ignore - intentional detach by dropping JoinHandle in Drop to avoid blocking runtime
    if std::thread::Builder::new()
        .name("asupersync-process-reaper".to_owned())
        .spawn(move || {
            let mut child_slot = thread_child.lock();
            if let Some(mut child) = child_slot.take() {
                let _ = child.wait();
            }
        })
        .is_ok()
    {
        return Ok(());
    }

    let mut child_slot = shared_child.lock();
    if let Some(child) = child_slot.take() {
        return Err(child);
    }
    drop(child_slot);
    Ok(())
}

fn reap_kill_on_drop_child(mut child: std_process::Child) {
    match kill_on_drop_reap_strategy() {
        KillOnDropReapStrategy::DirectWait => {
            let _ = child.wait();
        }
        KillOnDropReapStrategy::BlockingPool => {
            if let Some(pool) = blocking_pool_for_kill_on_drop_reap() {
                match try_dispatch_kill_on_drop_reap_on_pool(&pool, child) {
                    Ok(()) => return,
                    Err(recovered_child) => {
                        child = recovered_child;
                    }
                }
            }

            if Cx::current().is_some() || crate::runtime::Runtime::current_handle().is_some() {
                match spawn_detached_kill_on_drop_reaper(child) {
                    Ok(()) => {}
                    Err(mut recovered_child) => {
                        let _ = recovered_child.wait();
                    }
                }
            } else {
                let _ = child.wait();
            }
        }
        KillOnDropReapStrategy::DetachedThread => match spawn_detached_kill_on_drop_reaper(child) {
            Ok(()) => {}
            Err(mut recovered_child) => {
                let _ = recovered_child.wait();
            }
        },
    }
}

impl Drop for Child {
    /// Drop the child handle.
    ///
    /// The previous behavior was: with `kill_on_drop = false` (the default),
    /// the OS-level child was leaked as a zombie until the parent process
    /// exited — `std::process::Child` does NOT reap on drop, and we did
    /// nothing either. Long-lived parents (servers, the runtime itself) would
    /// accumulate zombies.
    ///
    /// New behavior (br-asupersync-bn2iln):
    ///
    ///   * If `kill_on_drop = true`: as before, signal the child and reap
    ///     it via the runtime's blocking pool / detached reaper / direct
    ///     wait fallback.
    ///   * If `kill_on_drop = false` (default): do a non-blocking
    ///     `waitpid(pid, &mut status, WNOHANG)` to reap the child if it
    ///     has already exited. This eliminates the zombie-leak class for
    ///     the common case where the child completed before the handle
    ///     dropped (test harnesses, short-lived helper processes, racing
    ///     primitives that drop the loser). If the child is still running,
    ///     `WNOHANG` returns immediately with 0 and we leave the OS
    ///     reaping responsibility to whoever called us — preserving the
    ///     "drop does not kill" contract while removing the silent
    ///     accumulation.
    ///
    /// Windows: no-op. Win32 cleans up child process handles automatically
    /// via the kernel handle's reference count; there is no zombie class.
    fn drop(&mut self) {
        drop(self.stdin.take());

        if self.kill_on_drop {
            if let Some(mut child) = self.inner.take() {
                let _ = child.kill();
                // Preserve the no-zombie guarantee from kill_on_drop, but
                // do not surprise a runtime worker thread with a blocking
                // OS wait in Drop.
                reap_kill_on_drop_child(child);
            }
            return;
        }

        // kill_on_drop = false: opportunistic non-blocking reap so an
        // already-exited child does not linger as a zombie.
        #[cfg(unix)]
        {
            if let Some(child) = self.inner.as_ref() {
                let pid = child.id() as libc::pid_t;
                let mut status: libc::c_int = 0;
                // Safety: pid is the kernel-assigned PID for our owned
                // child; `&mut status` is a valid out-pointer.
                // `WNOHANG` makes this non-blocking — returns 0 if the
                // child is still running, the pid if it was reaped, -1 on
                // error. We ignore the result: success reaps the zombie,
                // ECHILD means already reaped or never existed, EINTR
                // means try-later (and we don't), and any other error is
                // best-effort cleanup.
                let _ = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            }
        }

        // Drop std_process::Child without further action. The descriptor
        // closes, but on Unix the OS still requires SOMEONE to wait() the
        // child if WNOHANG above didn't catch it. That responsibility
        // remains with the original caller (per the documented contract:
        // "drop does not kill"); this commit only added the non-blocking
        // best-effort reap.
        let _ = self.inner.take();
    }
}

/// Async handle to the child's standard input.
///
/// Implements `AsyncWrite` for sending data to the child.
///
/// # Example
///
/// ```ignore
/// use asupersync::io::AsyncWriteExt;
///
/// let mut child = Command::new("cat")
///     .stdin(Stdio::piped())
///     .stdout(Stdio::piped())
///     .spawn()?;
///
/// if let Some(mut stdin) = child.stdin() {
///     stdin.write_all(b"hello\n").await?;
/// }
/// ```
#[derive(Debug)]
pub struct ChildStdin {
    inner: Option<std_process::ChildStdin>,
    registration: Option<IoRegistration>,
}

impl ChildStdin {
    #[cfg(unix)]
    fn from_std(stdin: std_process::ChildStdin) -> io::Result<Self> {
        set_nonblocking(stdin.as_raw_fd())?;
        Ok(Self {
            inner: Some(stdin),
            registration: None,
        })
    }

    #[cfg(not(unix))]
    fn from_std(stdin: std_process::ChildStdin) -> io::Result<Self> {
        set_nonblocking()?;
        Ok(Self {
            inner: Some(stdin),
            registration: None,
        })
    }

    /// Returns the raw file descriptor.
    #[cfg(unix)]
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.inner
            .as_ref()
            .expect("child stdin already closed")
            .as_raw_fd()
    }

    /// Returns the raw handle on Windows.
    #[cfg(windows)]
    #[must_use]
    pub fn as_raw_handle(&self) -> RawHandle {
        self.inner
            .as_ref()
            .expect("child stdin already closed")
            .as_raw_handle()
    }
}

impl AsyncWrite for ChildStdin {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if crate::cx::Cx::current().is_some_and(|c| c.checkpoint().is_err()) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let this = self.get_mut();
        #[cfg(unix)]
        {
            let Some(inner) = this.inner.as_mut() else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "child stdin already closed",
                )));
            };

            match inner.write(buf) {
                Ok(n) => Poll::Ready(Ok(n)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let source = this
                        .inner
                        .as_ref()
                        .expect("child stdin must exist while registering write interest");
                    if let Err(err) =
                        register_interest(&mut this.registration, source, cx, Interest::WRITABLE)
                    {
                        return Poll::Ready(Err(err));
                    }
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (this, cx, buf);
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "async child stdin is only supported on Unix in this build",
            )))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if crate::cx::Cx::current().is_some_and(|c| c.checkpoint().is_err()) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let this = self.get_mut();
        #[cfg(unix)]
        {
            let Some(inner) = this.inner.as_mut() else {
                return Poll::Ready(Ok(()));
            };

            match inner.flush() {
                Ok(()) => Poll::Ready(Ok(())),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let source = this
                        .inner
                        .as_ref()
                        .expect("child stdin must exist while registering flush interest");
                    if let Err(err) =
                        register_interest(&mut this.registration, source, cx, Interest::WRITABLE)
                    {
                        return Poll::Ready(Err(err));
                    }
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (this, cx);
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "async child stdin is only supported on Unix in this build",
            )))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if crate::cx::Cx::current().is_some_and(|c| c.checkpoint().is_err()) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let this = self.get_mut();
        this.registration = None;
        drop(this.inner.take());
        Poll::Ready(Ok(()))
    }
}

/// Async handle to the child's standard output.
///
/// Implements `AsyncRead` for receiving data from the child.
///
/// # Example
///
/// ```ignore
/// use asupersync::io::AsyncReadExt;
///
/// let mut child = Command::new("echo")
///     .arg("hello")
///     .stdout(Stdio::piped())
///     .spawn()?;
///
/// let mut output = String::new();
/// if let Some(mut stdout) = child.stdout() {
///     stdout.read_to_string(&mut output).await?;
/// }
/// ```
#[derive(Debug)]
pub struct ChildStdout {
    inner: std_process::ChildStdout,
    registration: Option<IoRegistration>,
}

impl ChildStdout {
    #[cfg(unix)]
    fn from_std(stdout: std_process::ChildStdout) -> io::Result<Self> {
        set_nonblocking(stdout.as_raw_fd())?;
        Ok(Self {
            inner: stdout,
            registration: None,
        })
    }

    #[cfg(not(unix))]
    fn from_std(stdout: std_process::ChildStdout) -> io::Result<Self> {
        set_nonblocking()?;
        Ok(Self {
            inner: stdout,
            registration: None,
        })
    }

    /// Returns the raw file descriptor.
    #[cfg(unix)]
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }

    /// Returns the raw handle on Windows.
    #[cfg(windows)]
    #[must_use]
    pub fn as_raw_handle(&self) -> RawHandle {
        self.inner.as_raw_handle()
    }
}

impl AsyncRead for ChildStdout {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if crate::cx::Cx::current().is_some_and(|c| c.checkpoint().is_err()) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let this = self.get_mut();
        #[cfg(unix)]
        {
            let unfilled = buf.unfilled();
            match this.inner.read(unfilled) {
                Ok(n) => {
                    buf.advance(n);
                    Poll::Ready(Ok(()))
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(err) = register_interest(
                        &mut this.registration,
                        &this.inner,
                        cx,
                        Interest::READABLE,
                    ) {
                        return Poll::Ready(Err(err));
                    }
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (this, cx, buf);
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "async child stdout is only supported on Unix in this build",
            )))
        }
    }
}

/// Async handle to the child's standard error.
///
/// Implements `AsyncRead` for receiving error output from the child.
///
/// # Example
///
/// ```ignore
/// use asupersync::io::AsyncReadExt;
///
/// let mut child = Command::new("ls")
///     .arg("/nonexistent")
///     .stderr(Stdio::piped())
///     .spawn()?;
///
/// let mut errors = String::new();
/// if let Some(mut stderr) = child.stderr() {
///     stderr.read_to_string(&mut errors).await?;
/// }
/// ```
#[derive(Debug)]
pub struct ChildStderr {
    inner: std_process::ChildStderr,
    registration: Option<IoRegistration>,
}

impl ChildStderr {
    #[cfg(unix)]
    fn from_std(stderr: std_process::ChildStderr) -> io::Result<Self> {
        set_nonblocking(stderr.as_raw_fd())?;
        Ok(Self {
            inner: stderr,
            registration: None,
        })
    }

    #[cfg(not(unix))]
    fn from_std(stderr: std_process::ChildStderr) -> io::Result<Self> {
        set_nonblocking()?;
        Ok(Self {
            inner: stderr,
            registration: None,
        })
    }

    /// Returns the raw file descriptor.
    #[cfg(unix)]
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }

    /// Returns the raw handle on Windows.
    #[cfg(windows)]
    #[must_use]
    pub fn as_raw_handle(&self) -> RawHandle {
        self.inner.as_raw_handle()
    }
}

impl AsyncRead for ChildStderr {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if crate::cx::Cx::current().is_some_and(|c| c.checkpoint().is_err()) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")));
        }
        let this = self.get_mut();
        #[cfg(unix)]
        {
            let unfilled = buf.unfilled();
            match this.inner.read(unfilled) {
                Ok(n) => {
                    buf.advance(n);
                    Poll::Ready(Ok(()))
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(err) = register_interest(
                        &mut this.registration,
                        &this.inner,
                        cx,
                        Interest::READABLE,
                    ) {
                        return Poll::Ready(Err(err));
                    }
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (this, cx, buf);
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "async child stderr is only supported on Unix in this build",
            )))
        }
    }
}

/// Collected output from a child process.
///
/// Contains the exit status and captured stdout/stderr.
#[derive(Debug, Clone)]
pub struct Output {
    /// The exit status of the process.
    pub status: ExitStatus,
    /// Captured standard output bytes.
    pub stdout: Vec<u8>,
    /// Captured standard error bytes.
    pub stderr: Vec<u8>,
}

/// Exit status of a process.
///
/// Contains the exit code or signal information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus {
    code: Option<i32>,
    #[cfg(unix)]
    signal: Option<i32>,
}

impl ExitStatus {
    /// Constructs an `ExitStatus` from explicit parts.
    ///
    /// Primarily useful for testing. On non-Unix platforms, `signal` is ignored.
    #[must_use]
    pub fn from_parts(code: Option<i32>, signal: Option<i32>) -> Self {
        #[cfg(unix)]
        {
            Self { code, signal }
        }
        #[cfg(not(unix))]
        {
            let _ = signal;
            Self { code }
        }
    }

    fn from_std(status: std_process::ExitStatus) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            Self {
                code: status.code(),
                signal: status.signal(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                code: status.code(),
            }
        }
    }

    /// Returns `true` if the process exited successfully.
    ///
    /// A successful exit typically means exit code 0.
    #[must_use]
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// Returns the exit code of the process, if available.
    ///
    /// Returns `None` if the process was terminated by a signal.
    #[must_use]
    pub fn code(&self) -> Option<i32> {
        self.code
    }

    /// Returns the signal that terminated the process, if any.
    ///
    /// Returns `None` if the process exited normally.
    #[cfg(unix)]
    #[must_use]
    pub fn signal(&self) -> Option<i32> {
        self.signal
    }
}

impl std::fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(code) = self.code {
            write!(f, "exit code: {code}")
        } else {
            #[cfg(unix)]
            if let Some(sig) = self.signal {
                return write!(f, "signal: {sig}");
            }
            write!(f, "unknown exit status")
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use crate::types::{Budget, RegionId, TaskId};

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_command_echo() {
        init_test("test_command_echo");

        let child = Command::new("echo")
            .arg("hello")
            .stdout(Stdio::Pipe)
            .spawn()
            .expect("spawn failed");

        let result = child.wait_with_output().expect("output failed");

        crate::assert_with_log!(
            result.status.success(),
            "success",
            true,
            result.status.success()
        );
        crate::assert_with_log!(
            result.stdout == b"hello\n",
            "stdout",
            "hello\\n",
            String::from_utf8_lossy(&result.stdout)
        );
        crate::test_complete!("test_command_echo");
    }

    #[test]
    fn test_command_echo_async_output() {
        init_test("test_command_echo_async_output");

        let result = futures_lite::future::block_on(async {
            let child = Command::new("echo")
                .arg("hello")
                .stdout(Stdio::Pipe)
                .spawn()?;
            let cx = crate::cx::Cx::for_testing();
            child.wait_with_output_async(&cx).await
        })
        .expect("async output failed");

        crate::assert_with_log!(
            result.status.success(),
            "success",
            true,
            result.status.success()
        );
        crate::assert_with_log!(
            result.stdout == b"hello\n",
            "stdout",
            "hello\\n",
            String::from_utf8_lossy(&result.stdout)
        );
        crate::test_complete!("test_command_echo_async_output");
    }

    #[test]
    fn test_command_exit_code() {
        init_test("test_command_exit_code");

        let mut child = Command::new("sh")
            .arg("-c")
            .arg("exit 42")
            .spawn()
            .expect("spawn failed");

        let result = child.wait().expect("wait failed");

        crate::assert_with_log!(!result.success(), "not success", false, result.success());
        crate::assert_with_log!(
            result.code() == Some(42),
            "exit code",
            Some(42),
            result.code()
        );
        crate::test_complete!("test_command_exit_code");
    }

    #[test]
    fn test_command_exit_code_async_status() {
        init_test("test_command_exit_code_async_status");

        let result = futures_lite::future::block_on(async {
            let mut child = Command::new("sh").arg("-c").arg("exit 42").spawn()?;
            let cx = crate::cx::Cx::for_testing();
            child.wait_async(&cx).await
        })
        .expect("async wait failed");

        crate::assert_with_log!(!result.success(), "not success", false, result.success());
        crate::assert_with_log!(
            result.code() == Some(42),
            "exit code",
            Some(42),
            result.code()
        );
        crate::test_complete!("test_command_exit_code_async_status");
    }

    #[test]
    fn test_command_env() {
        init_test("test_command_env");

        let child = Command::new("sh")
            .arg("-c")
            .arg("echo $MY_VAR")
            .env("MY_VAR", "test_value")
            .stdout(Stdio::Pipe)
            .spawn()
            .expect("spawn failed");

        let result = child.wait_with_output().expect("output failed");

        crate::assert_with_log!(
            result.stdout == b"test_value\n",
            "env value",
            "test_value\\n",
            String::from_utf8_lossy(&result.stdout)
        );
        crate::test_complete!("test_command_env");
    }

    #[test]
    fn test_command_env_remove_prevents_inheritance() {
        init_test("test_command_env_remove_prevents_inheritance");

        let inherited = Command::new("sh")
            .arg("-c")
            .arg("env")
            .stdout(Stdio::Pipe)
            .spawn()
            .expect("spawn failed")
            .wait_with_output()
            .expect("baseline output failed");
        let inherited_stdout = String::from_utf8_lossy(&inherited.stdout);

        crate::assert_with_log!(
            inherited_stdout
                .lines()
                .any(|line| line.starts_with("PATH=")),
            "baseline PATH inherited",
            true,
            inherited_stdout.as_ref()
        );

        let removed = Command::new("sh")
            .arg("-c")
            .arg("env")
            .env_remove("PATH")
            .stdout(Stdio::Pipe)
            .spawn()
            .expect("spawn failed")
            .wait_with_output()
            .expect("env_remove output failed");
        let removed_stdout = String::from_utf8_lossy(&removed.stdout);

        crate::assert_with_log!(
            !removed_stdout.lines().any(|line| line.starts_with("PATH=")),
            "PATH removed",
            false,
            removed_stdout.as_ref()
        );
        crate::test_complete!("test_command_env_remove_prevents_inheritance");
    }

    #[cfg(windows)]
    #[test]
    fn test_command_env_remove_is_case_insensitive_after_clear() {
        init_test("test_command_env_remove_is_case_insensitive_after_clear");

        let mut command = Command::new("cmd");
        command
            .env_clear()
            .env("Path", r"C:\custom\bin")
            .env_remove("PATH");

        crate::assert_with_log!(
            command.env.is_empty(),
            "case-insensitive removal after clear",
            true,
            command.env.len()
        );
        crate::test_complete!("test_command_env_remove_is_case_insensitive_after_clear");
    }

    #[cfg(windows)]
    #[test]
    fn test_command_env_overwrite_preserves_latest_case() {
        init_test("test_command_env_overwrite_preserves_latest_case");

        let mut command = Command::new("cmd");
        command
            .env("PATH", r"C:\base\bin")
            .env("Path", r"C:\custom\bin");

        crate::assert_with_log!(
            command.env.len() == 1,
            "single builder entry after case-insensitive overwrite",
            1,
            command.env.len()
        );

        let mut entries = command.env.iter();
        let (key, value) = entries.next().expect("missing environment entry");
        crate::assert_with_log!(
            key.as_ref() == OsStr::new("Path"),
            "latest casing preserved",
            "Path",
            key.as_ref().to_string_lossy()
        );
        crate::assert_with_log!(
            value.as_deref() == Some(OsStr::new(r"C:\custom\bin")),
            "latest value preserved",
            r"C:\custom\bin",
            value
                .as_deref()
                .map_or_else(|| "<removed>".into(), |v| v.to_string_lossy())
        );
        crate::assert_with_log!(
            entries.next().is_none(),
            "no duplicate entries remain",
            true,
            false
        );
        crate::test_complete!("test_command_env_overwrite_preserves_latest_case");
    }

    #[cfg(windows)]
    #[test]
    fn test_command_env_set_restores_removed_key_case_insensitively() {
        init_test("test_command_env_set_restores_removed_key_case_insensitively");

        let mut command = Command::new("cmd");
        command.env_remove("PATH").env("Path", r"C:\custom\bin");

        crate::assert_with_log!(
            command.env.len() == 1,
            "single builder entry after restore",
            1,
            command.env.len()
        );

        let mut entries = command.env.iter();
        let (key, value) = entries.next().expect("missing environment entry");
        crate::assert_with_log!(
            key.as_ref() == OsStr::new("Path"),
            "restored key preserves latest case",
            "Path",
            key.as_ref().to_string_lossy()
        );
        crate::assert_with_log!(
            value.as_deref() == Some(OsStr::new(r"C:\custom\bin")),
            "restored key keeps value",
            r"C:\custom\bin",
            value
                .as_deref()
                .map_or_else(|| "<removed>".into(), |v| v.to_string_lossy())
        );
        crate::assert_with_log!(
            entries.next().is_none(),
            "no stale removed entry remains",
            true,
            false
        );
        crate::test_complete!("test_command_env_set_restores_removed_key_case_insensitively");
    }

    #[test]
    fn test_command_current_dir() {
        init_test("test_command_current_dir");

        let child = Command::new("pwd")
            .current_dir("/tmp")
            .stdout(Stdio::Pipe)
            .spawn()
            .expect("spawn failed");

        let result = child.wait_with_output().expect("output failed");

        let stdout = String::from_utf8_lossy(&result.stdout);
        crate::assert_with_log!(
            stdout.trim() == "/tmp",
            "current dir",
            "/tmp",
            stdout.trim()
        );
        crate::test_complete!("test_command_current_dir");
    }

    #[test]
    fn test_command_stdin_pipe() {
        init_test("test_command_stdin_pipe");

        let mut child = Command::new("cat")
            .stdin(Stdio::Pipe)
            .stdout(Stdio::Pipe)
            .spawn()
            .expect("spawn failed");

        // Write to stdin
        if let Some(mut stdin) = child.stdin() {
            stdin
                .inner
                .as_mut()
                .expect("stdin should remain open before drop")
                .write_all(b"hello from stdin")
                .expect("write failed");
        }
        // stdin is automatically closed when dropped after the if block

        let output = child.wait_with_output().expect("output failed");

        crate::assert_with_log!(
            output.stdout == b"hello from stdin",
            "stdin echo",
            "hello from stdin",
            String::from_utf8_lossy(&output.stdout)
        );
        crate::test_complete!("test_command_stdin_pipe");
    }

    #[test]
    #[allow(clippy::option_if_let_else, clippy::manual_map)]
    fn test_wait_closes_piped_stdin_before_blocking() {
        use std::sync::mpsc;

        init_test("test_wait_closes_piped_stdin_before_blocking");

        let child = Command::new("cat")
            .stdin(Stdio::Pipe)
            .stdout(Stdio::Null)
            .spawn()
            .expect("spawn failed");
        let pid = child.id().expect("child pid missing");
        let (tx, rx) = mpsc::channel();

        let join = std::thread::spawn(move || {
            let mut child = child;
            tx.send(child.wait()).expect("send wait result");
        });

        let recv = rx.recv_timeout(std::time::Duration::from_secs(1));
        if recv.is_err() {
            #[allow(clippy::cast_possible_wrap)]
            let _ = unsafe { libc::kill(pid.cast_signed(), libc::SIGKILL) };
            join.join().expect("wait thread panicked after timeout");
            panic!("wait() should close stdin and finish without hanging");
        }
        let status = recv.unwrap().expect("wait failed");
        join.join().expect("wait thread panicked");

        crate::assert_with_log!(
            status.success(),
            "wait closes piped stdin",
            true,
            status.success()
        );
        crate::test_complete!("test_wait_closes_piped_stdin_before_blocking");
    }

    #[test]
    fn test_wait_async_closes_piped_stdin_before_blocking() {
        use std::sync::mpsc;

        init_test("test_wait_async_closes_piped_stdin_before_blocking");

        let child = Command::new("cat")
            .stdin(Stdio::Pipe)
            .stdout(Stdio::Null)
            .spawn()
            .expect("spawn failed");
        let pid = child.id().expect("child pid missing");
        let (tx, rx) = mpsc::channel();

        let join = std::thread::spawn(move || {
            let mut child = child;
            let cx = crate::cx::Cx::for_testing();
            let result = futures_lite::future::block_on(child.wait_async(&cx));
            tx.send(result).expect("send async wait result");
        });

        let recv = rx.recv_timeout(std::time::Duration::from_secs(1));
        if recv.is_err() {
            #[allow(clippy::cast_possible_wrap)]
            let _ = unsafe { libc::kill(pid.cast_signed(), libc::SIGKILL) };
            join.join()
                .expect("async wait thread panicked after timeout");
            panic!("wait_async() should close stdin and finish without hanging");
        }
        let status = recv.unwrap().expect("wait_async failed");
        join.join().expect("async wait thread panicked");

        crate::assert_with_log!(
            status.success(),
            "wait_async closes piped stdin",
            true,
            status.success()
        );
        crate::test_complete!("test_wait_async_closes_piped_stdin_before_blocking");
    }

    #[test]
    fn test_child_stdin_shutdown_closes_pipe_and_delivers_eof() {
        use crate::io::AsyncWriteExt;

        init_test("test_child_stdin_shutdown_closes_pipe_and_delivers_eof");

        let mut child = Command::new("cat")
            .stdin(Stdio::Pipe)
            .stdout(Stdio::Pipe)
            .spawn()
            .expect("spawn failed");
        let mut stdin = child.stdin().expect("missing stdin pipe");

        futures_lite::future::block_on(stdin.shutdown()).expect("shutdown failed");
        crate::assert_with_log!(
            stdin.inner.is_none(),
            "stdin handle closed",
            true,
            stdin.inner.is_none()
        );

        let mut exited = false;
        for _ in 0..20 {
            if child.try_wait().expect("try_wait failed").is_some() {
                exited = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        if !exited {
            let _ = child.kill();
            let _ = child.wait();
        }

        crate::assert_with_log!(exited, "shutdown delivers eof", true, exited);
        crate::test_complete!("test_child_stdin_shutdown_closes_pipe_and_delivers_eof");
    }

    #[test]
    fn test_command_stderr_capture() {
        init_test("test_command_stderr_capture");

        let child = Command::new("sh")
            .arg("-c")
            .arg("echo error message >&2")
            .stdout(Stdio::Null)
            .stderr(Stdio::Pipe)
            .spawn()
            .expect("spawn failed");

        let result = child.wait_with_output().expect("output failed");

        crate::assert_with_log!(
            result.stderr == b"error message\n",
            "stderr",
            "error message\\n",
            String::from_utf8_lossy(&result.stderr)
        );
        crate::test_complete!("test_command_stderr_capture");
    }

    #[test]
    fn test_command_try_wait() {
        init_test("test_command_try_wait");

        // Start a quick command
        let mut child = Command::new("true").spawn().expect("spawn failed");

        // Give it time to complete
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Should be done by now
        let status = child.try_wait().expect("try_wait failed");
        crate::assert_with_log!(status.is_some(), "completed", true, status.is_some());
        crate::test_complete!("test_command_try_wait");
    }

    #[test]
    fn test_command_kill() {
        init_test("test_command_kill");

        let mut child = Command::new("sleep")
            .arg("10")
            .spawn()
            .expect("spawn failed");

        // Kill the process
        child.kill().expect("kill failed");

        // Wait for it
        let status = child.wait().expect("wait failed");

        // Should have been killed by signal
        #[cfg(unix)]
        {
            crate::assert_with_log!(
                status.signal().is_some(),
                "killed by signal",
                true,
                status.signal().is_some()
            );
        }
        crate::test_complete!("test_command_kill");
    }

    #[test]
    fn test_command_kill_on_drop() {
        init_test("test_command_kill_on_drop");

        let child = Command::new("sleep")
            .arg("100")
            .kill_on_drop(true)
            .spawn()
            .expect("spawn failed");

        let _pid = child.id().expect("no pid");

        // Drop the child - should kill it
        drop(child);

        // Give it time to be killed
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Process should no longer exist (we can't easily check this portably,
        // but we can verify the test runs to completion)
        crate::test_complete!("test_command_kill_on_drop");
    }

    #[cfg(unix)]
    #[test]
    fn test_command_kill_on_drop_reaps_process() {
        init_test("test_command_kill_on_drop_reaps_process");

        let pid = {
            let child = Command::new("sleep")
                .arg("100")
                .kill_on_drop(true)
                .spawn()
                .expect("spawn failed");
            child.id().expect("no pid")
        };

        #[allow(clippy::cast_possible_wrap)]
        let pid = pid.cast_signed();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            let mut status = 0;
            let waited = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
            if waited == -1 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                crate::assert_with_log!(
                    err.raw_os_error() == Some(libc::ECHILD),
                    "kill_on_drop reaps child",
                    libc::ECHILD,
                    err.raw_os_error().unwrap_or_default()
                );
                break;
            }
            assert!(
                waited != pid,
                "kill_on_drop should reap the child before drop returns"
            );
            assert!(
                std::time::Instant::now() < deadline,
                "kill_on_drop should reap the child before timeout"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        crate::test_complete!("test_command_kill_on_drop_reaps_process");
    }

    #[cfg(unix)]
    #[test]
    fn test_spawn_setup_failure_cleanup_reaps_child() {
        init_test("test_spawn_setup_failure_cleanup_reaps_child");

        let mut child = std_process::Command::new("sleep")
            .arg("100")
            .spawn()
            .expect("spawn failed");
        #[allow(clippy::cast_possible_wrap)]
        let pid = child.id() as i32;

        cleanup_child_after_spawn_setup_failure(&mut child);

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        let err = io::Error::last_os_error();
        crate::assert_with_log!(
            waited == -1 && err.raw_os_error() == Some(libc::ECHILD),
            "spawn setup cleanup reaps child",
            format!("waitpid=-1 errno={}", libc::ECHILD),
            format!("waitpid={waited} errno={:?}", err.raw_os_error())
        );

        crate::test_complete!("test_spawn_setup_failure_cleanup_reaps_child");
    }

    #[test]
    fn test_kill_on_drop_reap_strategy_without_runtime_or_cx_is_direct_wait() {
        init_test("test_kill_on_drop_reap_strategy_without_runtime_or_cx_is_direct_wait");

        crate::assert_with_log!(
            kill_on_drop_reap_strategy() == KillOnDropReapStrategy::DirectWait,
            "no runtime context uses direct wait",
            KillOnDropReapStrategy::DirectWait,
            kill_on_drop_reap_strategy()
        );
        crate::test_complete!(
            "test_kill_on_drop_reap_strategy_without_runtime_or_cx_is_direct_wait"
        );
    }

    #[test]
    fn test_kill_on_drop_reap_strategy_tracks_ambient_cx_without_pool() {
        init_test("test_kill_on_drop_reap_strategy_tracks_ambient_cx_without_pool");

        let cx = Cx::new(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
        );
        let _guard = Cx::set_current(Some(cx));

        crate::assert_with_log!(
            kill_on_drop_reap_strategy() == KillOnDropReapStrategy::DetachedThread,
            "ambient cx without blocking pool uses detached reaper thread",
            KillOnDropReapStrategy::DetachedThread,
            kill_on_drop_reap_strategy()
        );

        crate::test_complete!("test_kill_on_drop_reap_strategy_tracks_ambient_cx_without_pool");
    }

    #[test]
    fn test_kill_on_drop_reap_strategy_prefers_cx_blocking_pool() {
        init_test("test_kill_on_drop_reap_strategy_prefers_cx_blocking_pool");

        let runtime = crate::runtime::RuntimeBuilder::new()
            .worker_threads(1)
            .blocking_threads(1, 1)
            .build()
            .expect("runtime build");
        let cx = Cx::new(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
        )
        .with_blocking_pool_handle(runtime.blocking_handle());
        let _guard = Cx::set_current(Some(cx));

        crate::assert_with_log!(
            kill_on_drop_reap_strategy() == KillOnDropReapStrategy::BlockingPool,
            "ambient cx with blocking pool prefers bounded pool reaper",
            KillOnDropReapStrategy::BlockingPool,
            kill_on_drop_reap_strategy()
        );

        drop(runtime);
        crate::test_complete!("test_kill_on_drop_reap_strategy_prefers_cx_blocking_pool");
    }

    #[test]
    fn test_kill_on_drop_background_reap_branch_detects_runtime_worker_without_cx() {
        init_test("test_kill_on_drop_background_reap_branch_detects_runtime_worker_without_cx");

        let runtime = crate::runtime::RuntimeBuilder::new()
            .worker_threads(1)
            .blocking_threads(1, 1)
            .build()
            .expect("runtime build");

        let (has_runtime_handle, has_ambient_cx, reap_strategy) =
            runtime.block_on(runtime.handle().spawn(async {
                (
                    crate::runtime::Runtime::current_handle().is_some(),
                    Cx::current().is_some(),
                    kill_on_drop_reap_strategy(),
                )
            }));

        crate::assert_with_log!(
            has_runtime_handle,
            "spawned runtime task exposes ambient runtime handle",
            true,
            has_runtime_handle
        );
        crate::assert_with_log!(
            has_ambient_cx,
            "spawned task runs with ambient cx",
            true,
            has_ambient_cx
        );
        crate::assert_with_log!(
            reap_strategy == KillOnDropReapStrategy::BlockingPool,
            "runtime worker without task cx should prefer bounded blocking pool reaper",
            KillOnDropReapStrategy::BlockingPool,
            reap_strategy
        );

        drop(runtime);
        crate::test_complete!(
            "test_kill_on_drop_background_reap_branch_detects_runtime_worker_without_cx"
        );
    }

    #[test]
    fn test_command_not_found() {
        init_test("test_command_not_found");

        let result = Command::new("nonexistent_command_that_does_not_exist_12345").spawn();

        crate::assert_with_log!(
            matches!(result, Err(ProcessError::NotFound(_))),
            "not found error",
            true,
            result.is_err()
        );
        crate::test_complete!("test_command_not_found");
    }

    #[test]
    fn test_stdio_null() {
        init_test("test_stdio_null");

        let mut cmd = Command::new("echo");
        cmd.arg("should not appear")
            .stdout(Stdio::Null)
            .stderr(Stdio::Null);

        let child = cmd.spawn().expect("spawn failed");
        let result = child.wait_with_output().expect("output failed");

        // stdout/stderr should be empty because they were null (not piped)
        crate::assert_with_log!(
            result.stdout.is_empty(),
            "stdout empty",
            true,
            result.stdout.is_empty()
        );
        crate::test_complete!("test_stdio_null");
    }

    #[test]
    fn test_exit_status_display() {
        init_test("test_exit_status_display");

        let status_success = ExitStatus {
            code: Some(0),
            #[cfg(unix)]
            signal: None,
        };

        let status_failure = ExitStatus {
            code: Some(1),
            #[cfg(unix)]
            signal: None,
        };

        #[cfg(unix)]
        let status_signal = ExitStatus {
            code: None,
            signal: Some(9),
        };

        crate::assert_with_log!(
            status_success.to_string() == "exit code: 0",
            "success display",
            "exit code: 0",
            status_success.to_string()
        );

        crate::assert_with_log!(
            status_failure.to_string() == "exit code: 1",
            "failure display",
            "exit code: 1",
            status_failure.to_string()
        );

        #[cfg(unix)]
        crate::assert_with_log!(
            status_signal.to_string() == "signal: 9",
            "signal display",
            "signal: 9",
            status_signal.to_string()
        );

        crate::test_complete!("test_exit_status_display");
    }

    /// Invariant: Command::args adds multiple arguments at once.
    #[test]
    fn test_command_args() {
        init_test("test_command_args");

        let child = Command::new("echo")
            .args(["hello", "world", "foo"])
            .stdout(Stdio::Pipe)
            .spawn()
            .expect("spawn failed");

        let result = child.wait_with_output().expect("output failed");

        crate::assert_with_log!(
            result.stdout == b"hello world foo\n",
            "args",
            "hello world foo\\n",
            String::from_utf8_lossy(&result.stdout)
        );
        crate::test_complete!("test_command_args");
    }

    /// Invariant: Command::envs sets multiple env vars at once.
    #[test]
    fn test_command_envs() {
        init_test("test_command_envs");

        let child = Command::new("sh")
            .arg("-c")
            .arg("echo $A-$B")
            .envs([("A", "alpha"), ("B", "beta")])
            .stdout(Stdio::Pipe)
            .spawn()
            .expect("spawn failed");

        let result = child.wait_with_output().expect("output failed");

        crate::assert_with_log!(
            result.stdout == b"alpha-beta\n",
            "envs",
            "alpha-beta\\n",
            String::from_utf8_lossy(&result.stdout)
        );
        crate::test_complete!("test_command_envs");
    }

    /// Invariant: Command::output() runs synchronously and returns Output.
    #[test]
    fn test_command_output() {
        init_test("test_command_output");

        let output = Command::new("echo")
            .arg("sync_output")
            .stdout(Stdio::Pipe)
            .output()
            .expect("output failed");

        crate::assert_with_log!(
            output.status.success(),
            "output success",
            true,
            output.status.success()
        );
        crate::assert_with_log!(
            output.stdout == b"sync_output\n",
            "output stdout",
            "sync_output\\n",
            String::from_utf8_lossy(&output.stdout)
        );
        crate::test_complete!("test_command_output");
    }

    #[test]
    fn test_command_output_preserves_stdio_configuration() {
        init_test("test_command_output_preserves_stdio_configuration");

        let mut cmd = Command::new("echo");
        cmd.arg("preserved").stdout(Stdio::Null);

        let output = cmd.output().expect("output failed");
        crate::assert_with_log!(
            output.stdout == b"preserved\n",
            "output stdout",
            "preserved\\n",
            String::from_utf8_lossy(&output.stdout)
        );

        let child = cmd.spawn().expect("spawn after output failed");
        let result = child.wait_with_output().expect("post-output wait failed");
        crate::assert_with_log!(
            result.stdout.is_empty(),
            "stdout config preserved after output",
            true,
            result.stdout.is_empty()
        );
        crate::test_complete!("test_command_output_preserves_stdio_configuration");
    }

    #[test]
    fn test_command_output_async_preserves_stdio_configuration() {
        init_test("test_command_output_async_preserves_stdio_configuration");

        let mut cmd = Command::new("echo");
        cmd.arg("preserved-async").stdout(Stdio::Null);

        let cx = Cx::for_testing();
        let output = futures_lite::future::block_on(cmd.output_async(&cx)).expect("output failed");
        crate::assert_with_log!(
            output.stdout == b"preserved-async\n",
            "async output stdout",
            "preserved-async\\n",
            String::from_utf8_lossy(&output.stdout)
        );

        let child = cmd.spawn().expect("spawn after async output failed");
        let result = child
            .wait_with_output()
            .expect("post-async-output wait failed");
        crate::assert_with_log!(
            result.stdout.is_empty(),
            "stdout config preserved after output_async",
            true,
            result.stdout.is_empty()
        );
        crate::test_complete!("test_command_output_async_preserves_stdio_configuration");
    }

    #[test]
    fn test_command_status_preserves_stdio_configuration() {
        init_test("test_command_status_preserves_stdio_configuration");

        let mut cmd = Command::new("echo");
        cmd.arg("status-preserved").stdout(Stdio::Pipe);

        let status = cmd.status().expect("status failed");
        crate::assert_with_log!(status.success(), "status success", true, status.success());

        let child = cmd.spawn().expect("spawn after status failed");
        let result = child.wait_with_output().expect("post-status wait failed");
        crate::assert_with_log!(
            result.stdout == b"status-preserved\n",
            "stdout config preserved after status",
            "status-preserved\\n",
            String::from_utf8_lossy(&result.stdout)
        );
        crate::test_complete!("test_command_status_preserves_stdio_configuration");
    }

    #[test]
    fn test_command_status_async_preserves_stdio_configuration() {
        init_test("test_command_status_async_preserves_stdio_configuration");

        let mut cmd = Command::new("echo");
        cmd.arg("status-async-preserved").stdout(Stdio::Pipe);

        let cx = Cx::for_testing();
        let status = futures_lite::future::block_on(cmd.status_async(&cx)).expect("status failed");
        crate::assert_with_log!(
            status.success(),
            "async status success",
            true,
            status.success()
        );

        let child = cmd.spawn().expect("spawn after status_async failed");
        let result = child
            .wait_with_output()
            .expect("post-status_async wait failed");
        crate::assert_with_log!(
            result.stdout == b"status-async-preserved\n",
            "stdout config preserved after status_async",
            "status-async-preserved\\n",
            String::from_utf8_lossy(&result.stdout)
        );
        crate::test_complete!("test_command_status_async_preserves_stdio_configuration");
    }

    /// Invariant: ProcessError has Debug and Display formatting.
    #[test]
    fn test_process_error_display() {
        init_test("test_process_error_display");

        let err = Command::new("nonexistent_command_xyz_12345").spawn();
        if let Err(e) = err {
            let disp = format!("{e}");
            let dbg_str = format!("{e:?}");
            let disp_empty = disp.is_empty();
            crate::assert_with_log!(!disp_empty, "display non-empty", true, !disp_empty);
            let dbg_empty = dbg_str.is_empty();
            crate::assert_with_log!(!dbg_empty, "debug non-empty", true, !dbg_empty);
        }
        crate::test_complete!("test_process_error_display");
    }

    // =========================================================================
    // Process Signal Handling Conformance Tests - Child Process Management
    // =========================================================================

    /// Test SIGTERM-then-SIGKILL escalation with grace period.
    ///
    /// Verifies that process termination follows the standard Unix pattern:
    /// 1. Send SIGTERM for graceful shutdown
    /// 2. Wait grace period
    /// 3. Send SIGKILL if process hasn't exited
    #[cfg(unix)]
    #[test]
    fn test_sigterm_sigkill_escalation() {
        init_test("test_sigterm_sigkill_escalation");

        use std::time::{Duration, Instant};

        // Spawn a process that ignores SIGTERM but responds to SIGKILL
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("trap '' TERM; sleep 30") // Ignore SIGTERM, sleep for 30s
            .spawn()
            .expect("spawn failed");

        let pid = child.id().expect("no pid");
        let start = Instant::now();

        // Send SIGTERM first (graceful)
        let sigterm_result = unsafe { libc::kill(pid.cast_signed(), libc::SIGTERM) };
        crate::assert_with_log!(
            sigterm_result == 0,
            "SIGTERM sent successfully",
            0,
            sigterm_result
        );

        // Wait grace period (shorter for test)
        std::thread::sleep(Duration::from_millis(100));

        // Check if process is still alive (should be, since it ignores SIGTERM)
        let still_alive = unsafe {
            libc::kill(pid.cast_signed(), 0) == 0 // Signal 0 checks existence
        };
        crate::assert_with_log!(
            still_alive,
            "Process still alive after SIGTERM",
            true,
            still_alive
        );

        // Now send SIGKILL (force kill)
        let sigkill_result = unsafe { libc::kill(pid.cast_signed(), libc::SIGKILL) };
        crate::assert_with_log!(
            sigkill_result == 0,
            "SIGKILL sent successfully",
            0,
            sigkill_result
        );

        // Wait for the process to die
        let status = child.wait().expect("wait failed");
        let elapsed = start.elapsed();

        // Verify process was killed by signal (not natural exit)
        crate::assert_with_log!(
            status.signal().is_some(),
            "Process killed by signal",
            true,
            status.signal().is_some()
        );

        // Should have been killed quickly (much less than 30s sleep)
        crate::assert_with_log!(
            elapsed < Duration::from_secs(5),
            "Process killed quickly",
            true,
            elapsed.as_secs() < 5
        );

        crate::test_complete!("test_sigterm_sigkill_escalation");
    }

    /// Test zombie reaping correctness.
    ///
    /// Verifies that child processes don't become zombies and are properly reaped.
    #[cfg(unix)]
    #[test]
    fn test_zombie_reaping_correctness() {
        init_test("test_zombie_reaping_correctness");

        let mut children = Vec::new();

        // Spawn multiple short-lived processes
        for i in 0..3 {
            let child = Command::new("sh")
                .arg("-c")
                .arg(format!("exit {}", i))
                .spawn()
                .expect("spawn failed");

            let pid = child.id().expect("no pid");
            children.push((child, pid, i));
        }

        // Wait for all children and verify they're properly reaped
        for (mut child, pid, expected_code) in children {
            let status = child.wait().expect("wait failed");

            // Verify the expected exit code
            assert_eq!(
                status.code(),
                Some(expected_code),
                "Process {} should have exit code {}",
                pid,
                expected_code
            );

            // After wait(), the process should be reaped (not zombie)
            // Sending signal 0 should fail with ESRCH (No such process)
            let process_gone = unsafe {
                libc::kill(pid.cast_signed(), 0) == -1 && *libc::__errno_location() == libc::ESRCH
            };

            crate::assert_with_log!(
                process_gone,
                &format!("Process {} reaped after wait", pid),
                true,
                process_gone
            );
        }

        crate::test_complete!("test_zombie_reaping_correctness");
    }

    /// Test stdio pipe close after exit.
    ///
    /// Verifies that stdio pipes are properly closed when child process exits.
    #[test]
    fn test_stdio_pipe_close_after_exit() {
        init_test("test_stdio_pipe_close_after_exit");

        // Spawn process with piped stdout
        let child = Command::new("echo")
            .arg("test output")
            .stdout(Stdio::Pipe)
            .stdin(Stdio::Pipe)
            .stderr(Stdio::Pipe)
            .spawn()
            .expect("spawn failed");

        let output = child.wait_with_output().expect("wait_with_output failed");

        // Verify output was captured
        crate::assert_with_log!(
            output.stdout == b"test output\n",
            "stdout captured correctly",
            "test output\\n",
            String::from_utf8_lossy(&output.stdout)
        );

        // Verify status indicates successful completion
        crate::assert_with_log!(
            output.status.success(),
            "process exited successfully",
            true,
            output.status.success()
        );

        // The stdio pipes should be automatically closed after process exit
        // This is verified by the fact that wait_with_output() succeeded
        // and returned complete output without hanging

        crate::test_complete!("test_stdio_pipe_close_after_exit");
    }

    /// Test setsid isolation preventing signal propagation.
    ///
    /// Verifies that child processes in new session don't receive signals
    /// intended for parent process group.
    #[cfg(unix)]
    #[test]
    fn test_setsid_isolation() {
        init_test("test_setsid_isolation");

        use std::time::Duration;

        // Create a child process that creates its own session
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("setsid sleep 30") // Create new session and sleep
            .spawn()
            .expect("spawn failed");

        let child_pid = child.id().expect("no pid");

        // Get our own process group
        let our_pgid = unsafe { libc::getpgid(0) };

        // Get child's process group (should be different after setsid)
        let child_pgid = unsafe { libc::getpgid(child_pid.cast_signed()) };

        crate::assert_with_log!(
            child_pgid != our_pgid,
            "Child in different process group",
            true,
            child_pgid != our_pgid
        );

        // Send signal to our process group - child should not receive it
        let signal_result = unsafe {
            libc::kill(-our_pgid, libc::SIGUSR1) // Negative PID = process group
        };
        crate::assert_with_log!(
            signal_result == 0,
            "Signal sent to our process group",
            0,
            signal_result
        );

        // Give signal time to be delivered (if it were going to be)
        std::thread::sleep(Duration::from_millis(50));

        // Child should still be alive (signal was isolated)
        let child_alive = unsafe { libc::kill(child_pid.cast_signed(), 0) == 0 };
        crate::assert_with_log!(
            child_alive,
            "Child survived signal to parent group",
            true,
            child_alive
        );

        // Clean up the child
        child.kill().expect("kill failed");
        let _status = child.wait().expect("wait failed");

        crate::test_complete!("test_setsid_isolation");
    }

    /// Test exit code preservation across 256-bit exit status.
    ///
    /// Verifies that process exit codes are correctly preserved and accessible,
    /// including edge cases around the 8-bit exit code space.
    #[test]
    fn test_exit_code_preservation() {
        init_test("test_exit_code_preservation");

        // Test various exit codes including edge cases
        let test_codes = [0, 1, 127, 128, 255];

        for &exit_code in &test_codes {
            let mut child = Command::new("sh")
                .arg("-c")
                .arg(format!("exit {}", exit_code))
                .spawn()
                .expect("spawn failed");

            let status = child.wait().expect("wait failed");

            // Exit code should be preserved exactly
            let actual_code = status.code().unwrap_or(-1);
            crate::assert_with_log!(
                actual_code == exit_code,
                &format!("Exit code {} preserved", exit_code),
                exit_code,
                actual_code
            );

            // Success should only be true for exit code 0
            let expected_success = exit_code == 0;
            crate::assert_with_log!(
                status.success() == expected_success,
                &format!("Success status for exit {}", exit_code),
                expected_success,
                status.success()
            );
        }

        // Test signal termination vs exit code distinction
        #[cfg(unix)]
        {
            let mut child = Command::new("sh")
                .arg("-c")
                .arg("kill -9 $$") // Self-terminate with SIGKILL
                .spawn()
                .expect("spawn failed");

            let status = child.wait().expect("wait failed");

            // Should be terminated by signal, not exit code
            crate::assert_with_log!(
                status.signal().is_some(),
                "Terminated by signal",
                true,
                status.signal().is_some()
            );

            crate::assert_with_log!(
                status.code().is_none(),
                "No exit code for signal termination",
                true,
                status.code().is_none()
            );
        }

        crate::test_complete!("test_exit_code_preservation");
    }
}
