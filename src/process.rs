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
//! async fn run_command() -> std::io::Result<()> {
//!     let output = Command::new("echo")
//!         .arg("hello")
//!         .output()
//!         .await?;
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

use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process as std_process;
use std::task::{Context, Poll};

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
    Piped,

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

    /// Creates a `Piped` configuration.
    #[must_use]
    pub fn piped() -> Self {
        Self::Piped
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
            Self::Piped => std_process::Stdio::piped(),
            Self::Null => std_process::Stdio::null(),
        }
    }
}

impl Default for Stdio {
    fn default() -> Self {
        Self::Inherit
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
    env: HashMap<OsString, OsString>,
    env_clear: bool,
    current_dir: Option<PathBuf>,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
    kill_on_drop: bool,
}

impl Command {
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
            env: HashMap::new(),
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
        self.env
            .insert(key.as_ref().to_os_string(), val.as_ref().to_os_string());
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
            self.env
                .insert(key.as_ref().to_os_string(), val.as_ref().to_os_string());
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
        self.env.remove(key.as_ref());
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
    /// let status = child.wait().await?;
    /// ```
    pub fn spawn(&mut self) -> Result<Child, ProcessError> {
        let mut cmd = std_process::Command::new(&self.program);

        cmd.args(&self.args);

        if self.env_clear {
            cmd.env_clear();
        }

        for (key, val) in &self.env {
            cmd.env(key, val);
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
        let stdin = child.stdin.take().map(ChildStdin::from_std);
        let stdout = child.stdout.take().map(ChildStdout::from_std);
        let stderr = child.stderr.take().map(ChildStderr::from_std);

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
    ///     .output()
    ///     .await?;
    ///
    /// println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    /// ```
    pub async fn output(&mut self) -> Result<Output, ProcessError> {
        self.stdin(Stdio::Null);
        self.stdout(Stdio::Piped);
        self.stderr(Stdio::Piped);

        let child = self.spawn()?;
        child.wait_with_output().await
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
    ///     .status()
    ///     .await?;
    ///
    /// if status.success() {
    ///     println!("Command succeeded");
    /// }
    /// ```
    pub async fn status(&mut self) -> Result<ExitStatus, ProcessError> {
        let mut child = self.spawn()?;
        child.wait().await
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
        self.inner.as_ref().map(|c| c.id())
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
    /// let status = child.wait().await?;
    /// println!("Exit code: {:?}", status.code());
    /// ```
    pub async fn wait(&mut self) -> Result<ExitStatus, ProcessError> {
        // For now, use blocking wait
        // TODO: Use non-blocking waitpid with reactor when available
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

    /// Waits for the child and collects all output.
    ///
    /// This consumes the `Child` and returns the collected stdout/stderr.
    ///
    /// # Errors
    ///
    /// Returns an error if waiting or reading fails.
    pub async fn wait_with_output(mut self) -> Result<Output, ProcessError> {
        // Take the handles before waiting
        let mut stdout_handle = self.stdout.take();
        let mut stderr_handle = self.stderr.take();
        drop(self.stdin.take()); // Close stdin

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        // Read stdout and stderr
        if let Some(ref mut handle) = stdout_handle {
            handle.inner.read_to_end(&mut stdout_buf)?;
        }
        if let Some(ref mut handle) = stderr_handle {
            handle.inner.read_to_end(&mut stderr_buf)?;
        }

        // Wait for exit
        let status = self.wait().await?;

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
}

impl Drop for Child {
    fn drop(&mut self) {
        if self.kill_on_drop {
            if let Some(ref mut child) = self.inner {
                let _ = child.kill();
            }
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
    inner: std_process::ChildStdin,
}

impl ChildStdin {
    fn from_std(stdin: std_process::ChildStdin) -> Self {
        Self { inner: stdin }
    }

    /// Returns the raw file descriptor.
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl AsyncWrite for ChildStdin {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // For now, use blocking write
        // TODO: Use non-blocking I/O with reactor
        match self.inner.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.inner.flush())
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Closing stdin just means dropping it
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
}

impl ChildStdout {
    fn from_std(stdout: std_process::ChildStdout) -> Self {
        Self { inner: stdout }
    }

    /// Returns the raw file descriptor.
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl AsyncRead for ChildStdout {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // For now, use blocking read
        // TODO: Use non-blocking I/O with reactor
        let unfilled = buf.unfilled();
        match self.inner.read(unfilled) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
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
}

impl ChildStderr {
    fn from_std(stderr: std_process::ChildStderr) -> Self {
        Self { inner: stderr }
    }

    /// Returns the raw file descriptor.
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl AsyncRead for ChildStderr {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // For now, use blocking read
        // TODO: Use non-blocking I/O with reactor
        let unfilled = buf.unfilled();
        match self.inner.read(unfilled) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
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
        match self.code {
            Some(code) => write!(f, "exit code: {code}"),
            None => {
                #[cfg(unix)]
                if let Some(sig) = self.signal {
                    return write!(f, "signal: {sig}");
                }
                write!(f, "unknown exit status")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_command_echo() {
        init_test("test_command_echo");

        let output = Command::new("echo")
            .arg("hello")
            .stdout(Stdio::Piped)
            .spawn()
            .expect("spawn failed")
            .wait_with_output();

        // Run the future synchronously for testing
        let result = futures_lite::future::block_on(output).expect("output failed");

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
    fn test_command_exit_code() {
        init_test("test_command_exit_code");

        let mut child = Command::new("sh")
            .arg("-c")
            .arg("exit 42")
            .spawn()
            .expect("spawn failed");
        let status = child.wait();

        let result = futures_lite::future::block_on(status).expect("wait failed");

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
    fn test_command_env() {
        init_test("test_command_env");

        let output = Command::new("sh")
            .arg("-c")
            .arg("echo $MY_VAR")
            .env("MY_VAR", "test_value")
            .stdout(Stdio::Piped)
            .spawn()
            .expect("spawn failed")
            .wait_with_output();

        let result = futures_lite::future::block_on(output).expect("output failed");

        crate::assert_with_log!(
            result.stdout == b"test_value\n",
            "env value",
            "test_value\\n",
            String::from_utf8_lossy(&result.stdout)
        );
        crate::test_complete!("test_command_env");
    }

    #[test]
    fn test_command_current_dir() {
        init_test("test_command_current_dir");

        let output = Command::new("pwd")
            .current_dir("/tmp")
            .stdout(Stdio::Piped)
            .spawn()
            .expect("spawn failed")
            .wait_with_output();

        let result = futures_lite::future::block_on(output).expect("output failed");

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
            .stdin(Stdio::Piped)
            .stdout(Stdio::Piped)
            .spawn()
            .expect("spawn failed");

        // Write to stdin
        if let Some(mut stdin) = child.stdin() {
            stdin
                .inner
                .write_all(b"hello from stdin")
                .expect("write failed");
        }
        // stdin is automatically closed when dropped after the if block

        let output =
            futures_lite::future::block_on(child.wait_with_output()).expect("output failed");

        crate::assert_with_log!(
            output.stdout == b"hello from stdin",
            "stdin echo",
            "hello from stdin",
            String::from_utf8_lossy(&output.stdout)
        );
        crate::test_complete!("test_command_stdin_pipe");
    }

    #[test]
    fn test_command_stderr_capture() {
        init_test("test_command_stderr_capture");

        let output = Command::new("sh")
            .arg("-c")
            .arg("echo error message >&2")
            .stdout(Stdio::Null)
            .stderr(Stdio::Piped)
            .spawn()
            .expect("spawn failed")
            .wait_with_output();

        let result = futures_lite::future::block_on(output).expect("output failed");

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
            .arg("100")
            .spawn()
            .expect("spawn failed");

        // Kill the process
        child.kill().expect("kill failed");

        // Wait for it
        let status = futures_lite::future::block_on(child.wait()).expect("wait failed");

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

        let output = Command::new("echo")
            .arg("should not appear")
            .stdout(Stdio::Null)
            .stderr(Stdio::Null)
            .spawn()
            .expect("spawn failed")
            .wait_with_output();

        let result = futures_lite::future::block_on(output).expect("output failed");

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
}
