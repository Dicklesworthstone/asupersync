//! Async I/O on the parent's end of a Windows child pipe.
//!
//! std creates the parent's end of every piped child stream in overlapped
//! mode (`sys/process/windows/child_pipe.rs`: "the `ours` pipe is always a
//! handle opened up in overlapped mode"; the child's end is synchronous), so
//! reads and writes here are overlapped operations instead of blocking
//! calls. The system thread pool watches each operation's completion event
//! (`RegisterWaitForSingleObject`) and its callback wakes the task: no thread
//! blocks on the pipe and nothing polls in a loop. An operation that the
//! kernel finishes at once is not registered at all.
//!
//! Every operation owns its buffer, `OVERLAPPED` and event on the heap.
//! Dropping an unfinished operation cancels it and waits for the
//! cancellation (prompt for a pipe) before anything is released, so the
//! kernel never writes into freed memory. The owner must drop this state
//! before it closes the handle.
//!
//! Writes are accepted once they start: the next write, `poll_flush` or
//! `poll_shutdown` waits for the one in flight and reports its error. A write
//! still in flight when the stream is dropped without a flush is cancelled,
//! like any other unfinished operation: it can only be in flight because the
//! child is not reading.
use std::ffi::c_void;
use std::fmt;
use std::io;
use std::os::windows::io::{FromRawHandle, OwnedHandle, RawHandle};
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};
use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_MORE_DATA,
    GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, RegisterWaitForSingleObject, UnregisterWaitEx, WT_EXECUTEONLYONCE,
};

/// Bytes asked of the kernel per read: std's child pipe capacity.
const READ_CHUNK: usize = 64 * 1024;
/// Bytes handed to the kernel per write.
const WRITE_CHUNK: usize = 64 * 1024;

/// The child closed its end: a pipe's end of file.
fn is_end(error: &io::Error) -> bool {
    error.raw_os_error().is_some_and(|code| {
        code == ERROR_BROKEN_PIPE.cast_signed() || code == ERROR_HANDLE_EOF.cast_signed()
    })
}

/// Read and write state for one parent pipe end. Only one direction is used
/// per stream (std pipes are one-way).
#[derive(Default)]
pub(super) struct Overlapped {
    /// The read in flight, if any.
    reading: Option<Operation>,
    /// A completed read's bytes not yet handed out, from `unread_at`.
    unread: Vec<u8>,
    unread_at: usize,
    /// The child closed its end.
    ended: bool,
    /// The write in flight: `poll_write` reports bytes accepted once the
    /// write starts, and the next write or `poll_flush` waits for it.
    writing: Option<Operation>,
}

impl fmt::Debug for Overlapped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Overlapped")
            .field("reading", &self.reading.is_some())
            .field("unread", &(self.unread.len() - self.unread_at))
            .field("ended", &self.ended)
            .field("writing", &self.writing.is_some())
            .finish()
    }
}

impl Overlapped {
    /// Reads into `out` from `handle`; `Ok(0)` once the child has closed its
    /// end.
    pub(super) fn poll_read(
        &mut self,
        handle: RawHandle,
        cx: &Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            if self.unread_at < self.unread.len() {
                let count = out.len().min(self.unread.len() - self.unread_at);
                out[..count].copy_from_slice(&self.unread[self.unread_at..self.unread_at + count]);
                self.unread_at += count;
                return Poll::Ready(Ok(count));
            }
            if self.ended {
                return Poll::Ready(Ok(0));
            }
            if self.reading.is_none() {
                // The consumed buffer is reused for the next read.
                let mut buffer = std::mem::take(&mut self.unread);
                buffer.resize(READ_CHUNK, 0);
                self.unread_at = 0;
                match Operation::start(handle, buffer, Direction::Read, cx) {
                    Ok(operation) => self.reading = Some(operation),
                    Err(error) if is_end(&error) => {
                        self.ended = true;
                        return Poll::Ready(Ok(0));
                    }
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
            let Some(operation) = self.reading.as_mut() else {
                return Poll::Ready(Err(io::ErrorKind::Other.into()));
            };
            let result = match operation.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result,
            };
            let finished = self.reading.take();
            match result {
                // A zero-byte write by the child: read again on the next
                // poll instead of spinning inside this one.
                Ok(0) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Ok(read) => {
                    let mut buffer = finished.map(Operation::into_buffer).unwrap_or_default();
                    buffer.truncate(read);
                    self.unread = buffer;
                    self.unread_at = 0;
                }
                Err(error) if is_end(&error) => {
                    self.ended = true;
                    return Poll::Ready(Ok(0));
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }

    /// Starts writing up to [`WRITE_CHUNK`] of `bytes` to `handle` and
    /// reports them accepted; a write still in flight is waited for first,
    /// and an error it ended with is reported here or by
    /// [`Self::poll_flush`].
    pub(super) fn poll_write(
        &mut self,
        handle: RawHandle,
        cx: &Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Err(error) = std::task::ready!(self.poll_flush(cx)) {
            return Poll::Ready(Err(error));
        }
        let accepted = &bytes[..bytes.len().min(WRITE_CHUNK)];
        match Operation::start(handle, accepted.to_vec(), Direction::Write, cx) {
            Ok(operation) => {
                self.writing = Some(operation);
                Poll::Ready(Ok(accepted.len()))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    /// Waits for the write in flight, if any.
    pub(super) fn poll_flush(&mut self, cx: &Context<'_>) -> Poll<io::Result<()>> {
        let Some(operation) = self.writing.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let expected = operation.buffer.len();
        let result = std::task::ready!(operation.poll(cx));
        self.writing = None;
        Poll::Ready(match result {
            Ok(written) if written == expected => Ok(()),
            Ok(_) => Err(io::ErrorKind::WriteZero.into()),
            Err(error) => Err(error),
        })
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Read,
    Write,
}

/// What the thread-pool callback reaches: the waker to wake.
struct Signal {
    waker: Mutex<Option<Waker>>,
}

impl Signal {
    fn set(&self, waker: &Waker) {
        if let Ok(mut slot) = self.waker.lock() {
            match slot.as_ref() {
                Some(current) if current.will_wake(waker) => {}
                _ => *slot = Some(waker.clone()),
            }
        }
    }
}

/// Thread-pool callback for a completed operation's event.
unsafe extern "system" fn completed(context: *mut c_void, _timed_out: bool) {
    // SAFETY: `context` is the boxed `Signal` of a live `Operation`, which
    // unregisters this wait (waiting for a running callback to return)
    // before that box is released.
    let signal = unsafe { &*context.cast::<Signal>() };
    let waker = signal.waker.lock().ok().and_then(|mut slot| slot.take());
    if let Some(waker) = waker {
        waker.wake();
    }
}

/// One overlapped read or write. Its `OVERLAPPED`, buffer, event and
/// `Signal` live on the heap or in the kernel, so moving the value never
/// moves what the kernel or the callback points at.
struct Operation {
    handle: HANDLE,
    overlapped: Box<OVERLAPPED>,
    buffer: Vec<u8>,
    /// Manual-reset completion event; stays set once the operation ends.
    event: OwnedHandle,
    signal: Box<Signal>,
    /// The thread-pool wait, absent when the kernel finished at once.
    wait: Option<HANDLE>,
    /// The kernel has finished with the buffer and `OVERLAPPED`.
    done: bool,
}

// SAFETY: `HANDLE` and `OVERLAPPED` are not `Send` only because they hold
// raw pointers. These are kernel handles, valid from any thread of the
// process, and the `OVERLAPPED` is reached only through this value (and by
// the kernel). Every call made on them (`GetOverlappedResult`, `CancelIoEx`,
// which unlike `CancelIo` cancels I/O issued by any thread, and
// `UnregisterWaitEx`) may come from any thread. The callback shares only the
// `Signal`, behind its mutex.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for Operation {}
// SAFETY: every method takes `&mut self`; a shared reference reaches nothing.
unsafe impl Sync for Operation {}

fn last_error() -> io::Error {
    // SAFETY: reads the calling thread's last-error value.
    io::Error::from_raw_os_error(unsafe { GetLastError() }.cast_signed())
}

impl Operation {
    fn start(
        handle: RawHandle,
        buffer: Vec<u8>,
        direction: Direction,
        cx: &Context<'_>,
    ) -> io::Result<Self> {
        let handle: HANDLE = handle;
        let length = u32::try_from(buffer.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
        // SAFETY: an unnamed manual-reset event with default security.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(last_error());
        }
        // SAFETY: the new event handle, owned only by this value from here.
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        // SAFETY: all-zero is a valid `OVERLAPPED` (offset 0, no event yet).
        let mut overlapped: Box<OVERLAPPED> = Box::new(unsafe { std::mem::zeroed() });
        overlapped.hEvent = std::os::windows::io::AsRawHandle::as_raw_handle(&event);
        let mut operation = Self {
            handle,
            overlapped,
            buffer,
            event,
            signal: Box::new(Signal {
                waker: Mutex::new(Some(cx.waker().clone())),
            }),
            wait: None,
            done: true,
        };
        let overlapped: *mut OVERLAPPED = &raw mut *operation.overlapped;
        // SAFETY: the buffer and `OVERLAPPED` are heap allocations owned by
        // `operation`, whose `Drop` cancels and drains an unfinished
        // operation before releasing them. `handle` is the open parent end
        // of a std child pipe, opened for overlapped I/O.
        let finished = unsafe {
            match direction {
                Direction::Read => ReadFile(
                    handle,
                    operation.buffer.as_mut_ptr(),
                    length,
                    std::ptr::null_mut(),
                    overlapped,
                ),
                Direction::Write => WriteFile(
                    handle,
                    operation.buffer.as_ptr(),
                    length,
                    std::ptr::null_mut(),
                    overlapped,
                ),
            }
        } != 0;
        if !finished {
            let error = last_error();
            if error.raw_os_error() != Some(ERROR_IO_PENDING.cast_signed()) {
                // Nothing was queued; the kernel holds no reference.
                return Err(error);
            }
        }
        operation.done = false;
        if finished {
            // `poll` collects the result without a wait.
            return Ok(operation);
        }
        let mut wait: HANDLE = std::ptr::null_mut();
        let context: *const Signal = &raw const *operation.signal;
        // SAFETY: one wait on this operation's event, whose context is the
        // boxed `Signal`; `Drop` unregisters it before the box is released.
        // On failure `operation` drops here, cancelling the started I/O.
        let registered = unsafe {
            RegisterWaitForSingleObject(
                &raw mut wait,
                std::os::windows::io::AsRawHandle::as_raw_handle(&operation.event),
                Some(completed),
                context.cast(),
                INFINITE,
                WT_EXECUTEONLYONCE,
            )
        } != 0;
        if !registered {
            return Err(last_error());
        }
        operation.wait = Some(wait);
        Ok(operation)
    }

    /// Bytes moved, once the operation has ended.
    fn poll(&mut self, cx: &Context<'_>) -> Poll<io::Result<usize>> {
        // The waker is current before the completion is checked, so a
        // completion after the check wakes this task.
        self.signal.set(cx.waker());
        let mut moved = 0_u32;
        // SAFETY: asks without waiting about the operation started with this
        // live `OVERLAPPED` on the still-open handle.
        let ended = unsafe {
            GetOverlappedResult(self.handle, &raw const *self.overlapped, &raw mut moved, 0)
        } != 0;
        if ended {
            self.done = true;
            return Poll::Ready(Ok(moved as usize));
        }
        let error = last_error();
        match error.raw_os_error().map(i32::cast_unsigned) {
            Some(ERROR_IO_INCOMPLETE) => Poll::Pending,
            // A message-mode pipe's partial read still carries data.
            Some(ERROR_MORE_DATA) => {
                self.done = true;
                Poll::Ready(Ok(moved as usize))
            }
            _ => {
                self.done = true;
                Poll::Ready(Err(error))
            }
        }
    }

    fn into_buffer(mut self) -> Vec<u8> {
        std::mem::take(&mut self.buffer)
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        if !self.done {
            let mut moved = 0_u32;
            // SAFETY: cancels exactly this operation and waits for it to
            // end, after which the kernel holds no reference to the buffer
            // or `OVERLAPPED`. The handle is still open (the stream drops
            // this state before its handle).
            unsafe {
                CancelIoEx(self.handle, &raw const *self.overlapped);
                GetOverlappedResult(self.handle, &raw const *self.overlapped, &raw mut moved, 1);
            }
        }
        if let Some(wait) = self.wait.take() {
            // SAFETY: `INVALID_HANDLE_VALUE` makes this wait for a running
            // callback to return; none starts afterwards, so the `Signal`
            // may then be released.
            unsafe {
                UnregisterWaitEx(wait, INVALID_HANDLE_VALUE);
            }
        }
    }
}
