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
#[derive(Debug, Clone)]
pub enum Stdio {
    /// Inherit from the parent process.
    ///
    /// The child will share the same stdin/stdout/stderr as the parent.
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

impl Default for Stdio {
    /// Default is `Inherit` to match typical command-line tool behavior.
    fn default() -> Self {
        Self::Inherit
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

        // Extract the I/O handles before wrapping (use take() to avoid partial move)
        let stdin = child.stdin.take().map(ChildStdin::from_std).transpose()?;
        let stdout = child.stdout.take().map(ChildStdout::from_std).transpose()?;
        let stderr = child.stderr.take().map(ChildStderr::from_std).transpose()?;

        Ok(Child {
            inner: Some(child),
            stdin,
            stdout,
            stderr,
            kill_on_drop: self.kill_on_drop,
        })
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
        self.stdin(Stdio::Null);
        self.stdout(Stdio::Pipe);
        self.stderr(Stdio::Pipe);

        let child = self.spawn()?;
        child.wait_with_output()
    }

    /// Async variant of [`output`](Self::output).
    ///
    /// Uses cooperative polling to avoid blocking the runtime thread while
    /// waiting for process exit and draining pipes.
    pub async fn output_async(&mut self) -> Result<Output, ProcessError> {
        self.stdin(Stdio::Null);
        self.stdout(Stdio::Pipe);
        self.stderr(Stdio::Pipe);

        let child = self.spawn()?;
        child.wait_with_output_async().await
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
        let mut child = self.spawn()?;
        child.wait()
    }

    /// Async variant of [`status`](Self::status).
    ///
    /// Uses cooperative polling to avoid blocking the runtime thread while
    /// waiting for process exit.
    pub async fn status_async(&mut self) -> Result<ExitStatus, ProcessError> {
        let mut child = self.spawn()?;
        child.wait_async().await
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
    pub async fn wait_async(&mut self) -> Result<ExitStatus, ProcessError> {
        // Match the synchronous wait path and std semantics so async wait does
        // not keep the child's stdin pipe open indefinitely.
        drop(self.stdin.take());

        // Use exponential backoff to avoid busy-looping the executor.
        // Starts at 1ms, doubles up to 50ms between checks.
        let mut backoff_ms = 1u64;
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            let now = crate::time::wall_now();
            crate::time::sleep(now, std::time::Duration::from_millis(backoff_ms)).await;
            backoff_ms = (backoff_ms * 2).min(50);
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
    /// process exit and pipe drain progress.
    pub async fn wait_with_output_async(mut self) -> Result<Output, ProcessError> {
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
            None => self.wait_async().await?,
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

fn should_background_reap_kill_on_drop() -> bool {
    Cx::current().is_some() || crate::runtime::Runtime::current_handle().is_some()
}

fn reap_kill_on_drop_child(child: std_process::Child) {
    if !should_background_reap_kill_on_drop() {
        let mut child = child;
        let _ = child.wait();
        return;
    }

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
        return;
    }

    let mut shared_child = shared_child.lock();
    if let Some(mut child) = shared_child.take() {
        let _ = child.wait();
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if !self.kill_on_drop {
            return;
        }

        drop(self.stdin.take());

        if let Some(mut child) = self.inner.take() {
            let _ = child.kill();
            // Preserve the no-zombie guarantee from kill_on_drop, but do not
            // surprise a runtime worker thread with a blocking OS wait in Drop.
            reap_kill_on_drop_child(child);
        }
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
            child.wait_with_output_async().await
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
            child.wait_async().await
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
            let _ = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
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
            let result = futures_lite::future::block_on(child.wait_async());
            tx.send(result).expect("send async wait result");
        });

        let recv = rx.recv_timeout(std::time::Duration::from_secs(1));
        if recv.is_err() {
            #[allow(clippy::cast_possible_wrap)]
            let _ = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
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
        let pid = pid as i32;
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

    #[test]
    fn test_kill_on_drop_background_reap_branch_tracks_ambient_cx() {
        init_test("test_kill_on_drop_background_reap_branch_tracks_ambient_cx");

        crate::assert_with_log!(
            !should_background_reap_kill_on_drop(),
            "no ambient cx uses direct reap",
            false,
            should_background_reap_kill_on_drop()
        );

        let cx = Cx::new(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
        );
        let _guard = Cx::set_current(Some(cx));

        crate::assert_with_log!(
            should_background_reap_kill_on_drop(),
            "ambient cx enables background reap",
            true,
            should_background_reap_kill_on_drop()
        );

        crate::test_complete!("test_kill_on_drop_background_reap_branch_tracks_ambient_cx");
    }

    #[test]
    fn test_kill_on_drop_background_reap_branch_detects_runtime_worker_without_cx() {
        use std::sync::mpsc;

        init_test("test_kill_on_drop_background_reap_branch_detects_runtime_worker_without_cx");

        let (tx, rx) = mpsc::sync_channel(1);
        let runtime = crate::runtime::RuntimeBuilder::new()
            .worker_threads(1)
            .on_thread_start(move || {
                let _ = tx.send((
                    crate::runtime::Runtime::current_handle().is_some(),
                    Cx::current().is_some(),
                    should_background_reap_kill_on_drop(),
                ));
            })
            .build()
            .expect("runtime build");

        let (has_runtime_handle, has_ambient_cx, should_background_reap) = rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("worker startup callback should report runtime context");

        crate::assert_with_log!(
            has_runtime_handle,
            "worker thread exposes runtime handle before first task poll",
            true,
            has_runtime_handle
        );
        crate::assert_with_log!(
            !has_ambient_cx,
            "worker startup callback runs outside task poll cx",
            false,
            has_ambient_cx
        );
        crate::assert_with_log!(
            should_background_reap,
            "runtime worker without task cx should still background reap kill_on_drop",
            true,
            should_background_reap
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
}
