//! Bounded, owned subprocess output capture for Unix nonblocking pipes.

use super::{Child, Command, ExitStatus, Output, ProcessError, Stdio, cancel_drain_delay};
use crate::cx::Cx;
use std::future::Future;
use std::io::{self, Read};
use std::time::Duration;

/// Maximum retained bytes for each captured output stream.
///
/// Limits apply independently to stdout and stderr, including zero. Reaching
/// a limit exactly is allowed; the next byte from that stream is an overflow.
/// Allocation requests grow with observed output and never request more than
/// the corresponding limit; allocator bookkeeping is outside these limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputCaptureLimits {
    /// Maximum bytes retained from standard output.
    pub stdout_bytes: usize,
    /// Maximum bytes retained from standard error.
    pub stderr_bytes: usize,
}

impl OutputCaptureLimits {
    /// Set independent stdout and stderr byte limits.
    #[must_use]
    pub const fn new(stdout_bytes: usize, stderr_bytes: usize) -> Self {
        Self {
            stdout_bytes,
            stderr_bytes,
        }
    }
}

/// The stream whose first excess byte stopped capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CapturedOutputStream {
    /// Standard output exceeded its limit.
    Stdout,
    /// Standard error exceeded its limit.
    Stderr,
}

/// A capture limit was exceeded and the direct child has been reaped.
///
/// The output contains the bounded prefixes read before overflow and the
/// actual reaped exit status. The excess byte is discarded. Bytes still in
/// either pipe when overflow is detected are not read or retained.
#[derive(Debug, Clone)]
pub struct OutputLimitExceeded {
    /// First stream observed exceeding its configured limit.
    pub stream: CapturedOutputStream,
    /// Limits used for this capture.
    pub limits: OutputCaptureLimits,
    /// Retained prefixes and actual child exit status after termination/reap.
    pub output: Output,
}

impl std::fmt::Display for OutputLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (stream, limit) = match self.stream {
            CapturedOutputStream::Stdout => ("stdout", self.limits.stdout_bytes),
            CapturedOutputStream::Stderr => ("stderr", self.limits.stderr_bytes),
        };
        write!(
            f,
            "child {stream} exceeded its {limit}-byte capture limit; reaped status: {:?}",
            self.output.status
        )
    }
}

impl std::error::Error for OutputLimitExceeded {}

/// Failure from bounded subprocess capture.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BoundedOutputError {
    /// Spawn, pipe, cancellation, termination, or reap failure.
    #[error(transparent)]
    Process(#[from] ProcessError),
    /// Output exceeded a limit; the configured target was signalled and the
    /// direct child was reaped before this error was published.
    #[error(transparent)]
    LimitExceeded(#[from] OutputLimitExceeded),
}

impl Command {
    /// Spawn and collect stdout/stderr with independent byte limits.
    ///
    /// As with [`Self::output_async`], stdin is temporarily null and both output
    /// streams are temporarily piped. The command's stored stdio configuration
    /// is restored even when spawning fails. A pre-cancelled context refuses
    /// before spawning.
    ///
    /// On overflow, cancellation, or a pipe error, capture closes both pipes,
    /// immediately sends SIGKILL to the configured process or managed process
    /// group, and attempts an uncancellable asynchronous reap. This additive
    /// API deliberately uses immediate termination rather than a TERM grace
    /// period. An overflow error always includes an actual reaped status;
    /// failure to terminate or reap is reported as a process error instead.
    ///
    /// Cancellation of the returned future after spawning retains its configured
    /// termination and shared-reaper ownership. Normal capture has no implicit execution
    /// timeout; use the context's cancellation/deadline for an idle process.
    ///
    /// # Errors
    ///
    /// Returns a typed limit error with reaped status on overflow, or a process
    /// error if spawning, reading, cancellation, termination, or reaping fails.
    pub async fn output_bounded_async(
        &mut self,
        cx: &Cx,
        limits: OutputCaptureLimits,
    ) -> Result<Output, BoundedOutputError> {
        cx.checkpoint()
            .map_err(|_| BoundedOutputError::Process(super::process_cancelled()))?;
        let child = self.spawn_with_temporary_stdio(Stdio::Null, Stdio::Pipe, Stdio::Pipe)?;
        child.wait_with_output_bounded_async(cx, limits).await
    }
}

impl Child {
    /// Own this child while collecting bounded stdout and stderr prefixes.
    ///
    /// This method closes stdin when first polled. Only pipe handles still
    /// owned by this child are captured; a handle previously taken by the
    /// caller is outside this operation's limits and ownership.
    ///
    /// Ownership is installed before the returned future is polled: even an
    /// unpolled future signals its configured target and transfers the direct
    /// child to the already-started shared reaper when dropped. Drop never waits
    /// for process exit or starts a helper thread. Consuming capture establishes
    /// its own termination policy regardless of the previous kill-on-drop setting.
    ///
    /// The first excess byte triggers immediate SIGKILL of the configured
    /// target, followed by asynchronous reap before a typed limit error.
    /// Cancellation and pipe errors take the same termination/reap path.
    /// A failed reap returns a process error while preserving kill/reaper
    /// ownership; it never fabricates a completed limit receipt.
    ///
    /// The direct child's PID is not reaped while either owned pipe remains
    /// open. This keeps the signal target's identity alive until the decision
    /// to terminate, including when descendants outlive their group leader.
    /// The default signal target covers only the direct process; choose a
    /// managed process-group target to terminate its group on failure.
    pub fn wait_with_output_bounded_async(
        self,
        cx: &Cx,
        limits: OutputCaptureLimits,
    ) -> impl Future<Output = Result<Output, BoundedOutputError>> + '_ {
        capture(CaptureOwner(self), cx, limits)
    }
}

/// Installs termination ownership before the capture future is first polled.
/// Spawn starts the Unix shared reaper before creating the OS child, so Drop
/// can transfer ownership without waiting for exit or starting another worker.
struct CaptureOwner(Child);

impl Drop for CaptureOwner {
    fn drop(&mut self) {
        if self.0.inner.is_some() {
            let _ = self.0.kill();
        }
        // The signal was attempted while the PID is still owned. Let Child's
        // default Unix Drop reap or enqueue it, including after failed cleanup.
        self.0.kill_on_drop = false;
    }
}

enum ReadProgress {
    Pending,
    Data,
    Eof,
    Overflow,
}

/// Read at most one small chunk so a busy stream cannot starve its sibling.
fn read_bounded(
    reader: &mut impl Read,
    output: &mut Vec<u8>,
    limit: usize,
) -> io::Result<ReadProgress> {
    let remaining = limit.saturating_sub(output.len());
    let mut buffer = [0_u8; 4096];
    // At the exact boundary, distinguish EOF from overflow with a stack-only
    // probe. The probe byte is never retained or added to the output Vec.
    let count = remaining.clamp(1, buffer.len());
    match reader.read(&mut buffer[..count]) {
        Ok(0) => Ok(ReadProgress::Eof),
        Ok(_) if remaining == 0 => Ok(ReadProgress::Overflow),
        Ok(count) => {
            let needed = output.len() + count;
            if needed > output.capacity() {
                let target = output.capacity().saturating_mul(2).max(needed).min(limit);
                output
                    .try_reserve_exact(target - output.len())
                    .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
            }
            output.extend_from_slice(&buffer[..count]);
            Ok(ReadProgress::Data)
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(ReadProgress::Pending)
        }
        Err(error) => Err(error),
    }
}

enum CaptureStop {
    Complete,
    Overflow(CapturedOutputStream),
    Failed(ProcessError),
}

/// Signal before try_wait can release the PID/managed process-group identity.
async fn terminate_and_reap(child: &mut Child) -> Result<ExitStatus, ProcessError> {
    match child.kill() {
        Ok(()) => {}
        // A naturally exited target may have disappeared before kill. Its
        // direct child status still must be collected before reporting success.
        Err(ProcessError::Io(error)) if error.raw_os_error() == Some(libc::ESRCH) => {}
        Err(error) => return Err(error),
    }

    for _ in 0..super::REAP_AFTER_KILL_POLLS {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(ProcessError::Io(error)) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
        // This deadline-only delay does not shorten when the owner is cancelled.
        cancel_drain_delay(Duration::from_millis(2)).await;
    }
    Err(ProcessError::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        "bounded output capture could not reap the terminated child",
    )))
}

#[allow(clippy::too_many_lines)] // One ownership path spans pipe drain and final reap.
async fn capture(
    mut owner: CaptureOwner,
    cx: &Cx,
    limits: OutputCaptureLimits,
) -> Result<Output, BoundedOutputError> {
    let child = &mut owner.0;
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    drop(child.stdin.take());
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut backoff_ms = 1_u64;

    let stop = loop {
        if cx.checkpoint().is_err() {
            break CaptureStop::Failed(super::process_cancelled());
        }
        if stdout.is_none() && stderr.is_none() {
            break CaptureStop::Complete;
        }
        let mut progressed = false;
        if let Some(pipe) = stdout.as_mut() {
            match read_bounded(&mut pipe.inner, &mut stdout_bytes, limits.stdout_bytes) {
                Ok(ReadProgress::Pending) => {}
                Ok(ReadProgress::Data) => progressed = true,
                Ok(ReadProgress::Eof) => {
                    stdout = None;
                    progressed = true;
                }
                Ok(ReadProgress::Overflow) => {
                    break CaptureStop::Overflow(CapturedOutputStream::Stdout);
                }
                Err(error) => break CaptureStop::Failed(ProcessError::Io(error)),
            }
        }
        if let Some(pipe) = stderr.as_mut() {
            match read_bounded(&mut pipe.inner, &mut stderr_bytes, limits.stderr_bytes) {
                Ok(ReadProgress::Pending) => {}
                Ok(ReadProgress::Data) => progressed = true,
                Ok(ReadProgress::Eof) => {
                    stderr = None;
                    progressed = true;
                }
                Ok(ReadProgress::Overflow) => {
                    break CaptureStop::Overflow(CapturedOutputStream::Stderr);
                }
                Err(error) => break CaptureStop::Failed(ProcessError::Io(error)),
            }
        }
        if progressed {
            backoff_ms = 1;
            crate::runtime::yield_now().await;
        } else {
            crate::time::sleep(crate::time::wall_now(), Duration::from_millis(backoff_ms)).await;
            backoff_ms = (backoff_ms * 2).min(50);
        }
    };

    // No detached reader owns a pipe after the capture decision.
    drop(stdout);
    drop(stderr);

    match stop {
        CaptureStop::Overflow(stream) => {
            let status = terminate_and_reap(child).await?;
            Err(OutputLimitExceeded {
                stream,
                limits,
                output: Output {
                    status,
                    stdout: stdout_bytes,
                    stderr: stderr_bytes,
                },
            }
            .into())
        }
        CaptureStop::Failed(error) => {
            terminate_and_reap(child).await?;
            Err(error.into())
        }
        CaptureStop::Complete => {
            // The pipes have reached EOF, but the process may still be alive.
            // Check cancellation before each reap attempt; never signal after
            // try_wait has collected the status and released process identity.
            loop {
                if cx.checkpoint().is_err() {
                    terminate_and_reap(child).await?;
                    return Err(super::process_cancelled().into());
                }
                match child.try_wait() {
                    Ok(Some(status)) => {
                        return Ok(Output {
                            status,
                            stdout: stdout_bytes,
                            stderr: stderr_bytes,
                        });
                    }
                    Ok(None) => {}
                    Err(ProcessError::Io(error)) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error.into()),
                }
                crate::time::sleep(crate::time::wall_now(), Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(50);
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "bounded_output_tests.rs"]
mod tests;
