//! macOS/BSD kqueue-based reactor implementation.
//!
//! This module provides [`KqueueReactor`], a reactor implementation that uses
//! BSD kqueue for efficient I/O event notification with edge-triggered mode.
//!
//! # Safety
//!
//! This module uses `unsafe` code to interface with the kqueue system calls
//! via libc. The unsafe operations are:
//!
//! - `libc::kqueue()`: Creates a kqueue instance
//! - `libc::kevent()`: Registers/polls events
//! - `libc::pipe()`: Creates wake pipe
//! - `libc::close()`: Closes file descriptors
//! - `BorrowedFd::borrow_raw()`: Creates borrowed fd for operations
//!
//! These are unsafe because the compiler cannot verify that file descriptors
//! remain valid for the duration of their registration. The `KqueueReactor`
//! maintains this invariant through careful bookkeeping.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                       KqueueReactor                              │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
//! │  │  kqueue fd  │  │  wake pipe  │  │    registration map     │  │
//! │  │             │  │ (read,write)│  │   HashMap<Token, info>  │  │
//! │  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Thread Safety
//!
//! `KqueueReactor` is `Send + Sync` and can be shared across threads via `Arc`.
//! Internal state is protected by `Mutex` for registration/deregistration,
//! while `poll()` and `wake()` are designed for concurrent access.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::runtime::reactor::{KqueueReactor, Reactor, Interest, Events};
//! use std::net::TcpListener;
//!
//! let reactor = KqueueReactor::new()?;
//! let listener = TcpListener::bind("127.0.0.1:0")?;
//!
//! // Register the listener with kqueue (edge-triggered mode)
//! reactor.register(&listener, Token::new(1), Interest::READABLE)?;
//!
//! // Poll for events
//! let mut events = Events::with_capacity(64);
//! let count = reactor.poll(&mut events, Some(Duration::from_secs(1)))?;
//! ```

// Allow unsafe code for kqueue FFI operations via libc.
// The unsafe operations are necessary because the compiler cannot verify
// file descriptor validity at compile time.
#![allow(unsafe_code)]

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
mod kqueue_impl {
    use super::super::{Event, Events, Interest, Reactor, Source, Token};
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::io;
    use std::os::fd::RawFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// Special token value for the wake pipe (distinct from user tokens).
    const WAKE_TOKEN: usize = usize::MAX;

    /// Registration state for a source.
    #[derive(Debug)]
    struct RegistrationInfo {
        /// The raw file descriptor (for bookkeeping).
        raw_fd: RawFd,
        /// The current interest flags.
        interest: Interest,
    }

    /// BSD kqueue-based reactor with edge-triggered mode.
    ///
    /// This reactor uses kqueue directly via libc for efficient I/O event
    /// notification for async operations on macOS and BSD systems.
    ///
    /// # Features
    ///
    /// - `register()`: Adds fd to kqueue with EV_CLEAR (edge-triggered)
    /// - `modify()`: Updates interest flags for a registered fd
    /// - `deregister()`: Removes fd from kqueue
    /// - `poll()`: Waits for and collects ready events
    /// - `wake()`: Interrupts a blocking poll from another thread
    ///
    /// # Edge-Triggered Mode
    ///
    /// This reactor uses edge-triggered mode (`EV_CLEAR`) for efficiency.
    /// Events fire when state *changes*, not while the condition persists.
    /// Applications must read/write until `EAGAIN` before the next event.
    pub struct KqueueReactor {
        /// The kqueue file descriptor.
        kq_fd: RawFd,
        /// Pipe for cross-thread wakeup (read_fd, write_fd).
        wake_pipe: (RawFd, RawFd),
        /// Flag to coalesce multiple wake() calls.
        wake_pending: AtomicBool,
        /// Maps tokens to registration info for bookkeeping.
        registrations: Mutex<HashMap<Token, RegistrationInfo>>,
    }

    impl KqueueReactor {
        /// Creates a new kqueue-based reactor.
        ///
        /// This initializes a kqueue instance and sets up a wake pipe for
        /// cross-thread notification.
        ///
        /// # Errors
        ///
        /// Returns an error if:
        /// - `kqueue()` fails (e.g., out of file descriptors)
        /// - `pipe()` fails
        /// - Failed to set non-blocking mode on wake pipe
        ///
        /// # Example
        ///
        /// ```ignore
        /// let reactor = KqueueReactor::new()?;
        /// assert!(reactor.is_empty());
        /// ```
        pub fn new() -> io::Result<Self> {
            // Create kqueue instance
            let kq_fd = unsafe { libc::kqueue() };
            if kq_fd < 0 {
                return Err(io::Error::last_os_error());
            }

            // Create wake pipe
            let mut fds = [0i32; 2];
            if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
                unsafe {
                    libc::close(kq_fd);
                }
                return Err(io::Error::last_os_error());
            }

            let wake_pipe = (fds[0], fds[1]); // (read, write)

            // Make wake pipe non-blocking
            for &fd in &[wake_pipe.0, wake_pipe.1] {
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                if flags < 0 {
                    unsafe {
                        libc::close(kq_fd);
                        libc::close(wake_pipe.0);
                        libc::close(wake_pipe.1);
                    }
                    return Err(io::Error::last_os_error());
                }
                if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
                    unsafe {
                        libc::close(kq_fd);
                        libc::close(wake_pipe.0);
                        libc::close(wake_pipe.1);
                    }
                    return Err(io::Error::last_os_error());
                }
            }

            let reactor = Self {
                kq_fd,
                wake_pipe,
                wake_pending: AtomicBool::new(false),
                registrations: Mutex::new(HashMap::new()),
            };

            // Register the wake pipe read end with kqueue
            reactor.register_wake_pipe()?;

            Ok(reactor)
        }

        /// Registers the wake pipe read end with kqueue.
        fn register_wake_pipe(&self) -> io::Result<()> {
            let kev = libc::kevent {
                ident: self.wake_pipe.0 as usize,
                filter: libc::EVFILT_READ,
                flags: libc::EV_ADD | libc::EV_CLEAR,
                fflags: 0,
                data: 0,
                udata: WAKE_TOKEN as *mut libc::c_void,
            };

            let ret = unsafe {
                libc::kevent(
                    self.kq_fd,
                    &kev,
                    1,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            };

            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// Drains any data from the wake pipe to reset the wake signal.
        fn drain_wake_pipe(&self) {
            let mut buf = [0u8; 64];
            loop {
                let ret = unsafe {
                    libc::read(
                        self.wake_pipe.0,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if ret <= 0 {
                    break;
                }
            }
            self.wake_pending.store(false, Ordering::Release);
        }

        /// Converts our Interest flags to kqueue filters.
        ///
        /// Returns a vector of kevents to register (one for each active filter).
        fn interest_to_kevents(
            fd: RawFd,
            token: Token,
            interest: Interest,
            add: bool,
        ) -> Vec<libc::kevent> {
            let mut kevents = Vec::with_capacity(2);
            let base_flags = if add {
                libc::EV_ADD | libc::EV_CLEAR
            } else {
                libc::EV_DELETE
            };

            if interest.is_readable() || !add {
                kevents.push(libc::kevent {
                    ident: fd as usize,
                    filter: libc::EVFILT_READ,
                    flags: if add && interest.is_readable() {
                        base_flags
                    } else {
                        libc::EV_DELETE
                    },
                    fflags: 0,
                    data: 0,
                    udata: token.0 as *mut libc::c_void,
                });
            }

            if interest.is_writable() || !add {
                kevents.push(libc::kevent {
                    ident: fd as usize,
                    filter: libc::EVFILT_WRITE,
                    flags: if add && interest.is_writable() {
                        base_flags
                    } else {
                        libc::EV_DELETE
                    },
                    fflags: 0,
                    data: 0,
                    udata: token.0 as *mut libc::c_void,
                });
            }

            kevents
        }

        /// Converts kqueue event to our Interest type.
        fn kevent_to_interest(filter: i16, flags: u16) -> Interest {
            let mut interest = Interest::NONE;

            if filter == libc::EVFILT_READ {
                interest = interest.add(Interest::READABLE);
            }
            if filter == libc::EVFILT_WRITE {
                interest = interest.add(Interest::WRITABLE);
            }
            if flags & libc::EV_EOF != 0 {
                interest = interest.add(Interest::HUP);
            }
            if flags & libc::EV_ERROR != 0 {
                interest = interest.add(Interest::ERROR);
            }

            interest
        }
    }

    impl Reactor for KqueueReactor {
        fn register(
            &self,
            source: &dyn Source,
            token: Token,
            interest: Interest,
        ) -> io::Result<()> {
            let raw_fd = source.as_raw_fd();

            // Check for duplicate registration first
            let mut regs = self.registrations.lock();
            if regs.contains_key(&token) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "token already registered",
                ));
            }

            // Build kevents for the registration
            let kevents = Self::interest_to_kevents(raw_fd, token, interest, true);

            // Register with kqueue
            if !kevents.is_empty() {
                let ret = unsafe {
                    libc::kevent(
                        self.kq_fd,
                        kevents.as_ptr(),
                        kevents.len() as i32,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null(),
                    )
                };

                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }

            // Track the registration for modify/deregister
            regs.insert(token, RegistrationInfo { raw_fd, interest });

            Ok(())
        }

        fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
            let mut regs = self.registrations.lock();
            let info = regs
                .get_mut(&token)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "token not registered"))?;

            let old_interest = info.interest;

            // Build kevents to update filters
            // We need to delete old filters and add new ones
            let mut kevents = Vec::with_capacity(4);

            // Delete old read filter if no longer wanted
            if old_interest.is_readable() && !interest.is_readable() {
                kevents.push(libc::kevent {
                    ident: info.raw_fd as usize,
                    filter: libc::EVFILT_READ,
                    flags: libc::EV_DELETE,
                    fflags: 0,
                    data: 0,
                    udata: token.0 as *mut libc::c_void,
                });
            }

            // Delete old write filter if no longer wanted
            if old_interest.is_writable() && !interest.is_writable() {
                kevents.push(libc::kevent {
                    ident: info.raw_fd as usize,
                    filter: libc::EVFILT_WRITE,
                    flags: libc::EV_DELETE,
                    fflags: 0,
                    data: 0,
                    udata: token.0 as *mut libc::c_void,
                });
            }

            // Add new read filter if newly wanted
            if interest.is_readable() && !old_interest.is_readable() {
                kevents.push(libc::kevent {
                    ident: info.raw_fd as usize,
                    filter: libc::EVFILT_READ,
                    flags: libc::EV_ADD | libc::EV_CLEAR,
                    fflags: 0,
                    data: 0,
                    udata: token.0 as *mut libc::c_void,
                });
            }

            // Add new write filter if newly wanted
            if interest.is_writable() && !old_interest.is_writable() {
                kevents.push(libc::kevent {
                    ident: info.raw_fd as usize,
                    filter: libc::EVFILT_WRITE,
                    flags: libc::EV_ADD | libc::EV_CLEAR,
                    fflags: 0,
                    data: 0,
                    udata: token.0 as *mut libc::c_void,
                });
            }

            // Apply changes if any
            if !kevents.is_empty() {
                let ret = unsafe {
                    libc::kevent(
                        self.kq_fd,
                        kevents.as_ptr(),
                        kevents.len() as i32,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null(),
                    )
                };

                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }

            // Update our bookkeeping
            info.interest = interest;

            Ok(())
        }

        fn deregister(&self, token: Token) -> io::Result<()> {
            let mut regs = self.registrations.lock();
            let info = regs
                .remove(&token)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "token not registered"))?;

            // Build kevents to delete filters
            let mut kevents = Vec::with_capacity(2);

            if info.interest.is_readable() {
                kevents.push(libc::kevent {
                    ident: info.raw_fd as usize,
                    filter: libc::EVFILT_READ,
                    flags: libc::EV_DELETE,
                    fflags: 0,
                    data: 0,
                    udata: token.0 as *mut libc::c_void,
                });
            }

            if info.interest.is_writable() {
                kevents.push(libc::kevent {
                    ident: info.raw_fd as usize,
                    filter: libc::EVFILT_WRITE,
                    flags: libc::EV_DELETE,
                    fflags: 0,
                    data: 0,
                    udata: token.0 as *mut libc::c_void,
                });
            }

            // Remove from kqueue
            if !kevents.is_empty() {
                // Note: We ignore errors here because the fd might already be closed
                unsafe {
                    libc::kevent(
                        self.kq_fd,
                        kevents.as_ptr(),
                        kevents.len() as i32,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null(),
                    );
                }
            }

            Ok(())
        }

        fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
            events.clear();

            // Prepare timeout
            let timespec = timeout.map(|d| libc::timespec {
                tv_sec: d.as_secs() as libc::time_t,
                tv_nsec: d.subsec_nanos() as libc::c_long,
            });
            let timeout_ptr = timespec
                .as_ref()
                .map(|t| t as *const libc::timespec)
                .unwrap_or(std::ptr::null());

            // Allocate buffer for kevent results
            let capacity = events.capacity().max(1);
            let mut kevents: Vec<libc::kevent> = Vec::with_capacity(capacity);

            let ret = unsafe {
                libc::kevent(
                    self.kq_fd,
                    std::ptr::null(),
                    0,
                    kevents.as_mut_ptr(),
                    capacity as i32,
                    timeout_ptr,
                )
            };

            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    // EINTR - just return 0 events
                    return Ok(0);
                }
                return Err(err);
            }

            // SAFETY: kevent wrote `ret` events into the buffer
            unsafe {
                kevents.set_len(ret as usize);
            }

            // Convert kevent results to our Event type.
            // `Events` may drop entries when capacity is reached; report only
            // the number of events actually stored in `events`.
            for kev in &kevents {
                let token_val = kev.udata as usize;

                // Skip wake pipe events
                if token_val == WAKE_TOKEN {
                    self.drain_wake_pipe();
                    continue;
                }

                let token = Token(token_val);
                let interest = Self::kevent_to_interest(kev.filter, kev.flags);
                events.push(Event::new(token, interest));
            }

            Ok(events.len())
        }

        fn wake(&self) -> io::Result<()> {
            // Use atomic flag to coalesce multiple wake() calls
            if self
                .wake_pending
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                // Write a byte to the wake pipe
                let buf = [1u8];
                let ret = unsafe {
                    libc::write(
                        self.wake_pipe.1,
                        buf.as_ptr() as *const libc::c_void,
                        buf.len(),
                    )
                };

                if ret < 0 {
                    let err = io::Error::last_os_error();
                    // EAGAIN is OK - pipe buffer is full but poll will still wake
                    if err.kind() != io::ErrorKind::WouldBlock {
                        self.wake_pending.store(false, Ordering::Release);
                        return Err(err);
                    }
                }
            }
            Ok(())
        }

        fn registration_count(&self) -> usize {
            self.registrations.lock().len()
        }
    }

    impl Drop for KqueueReactor {
        fn drop(&mut self) {
            // Close all file descriptors
            unsafe {
                libc::close(self.kq_fd);
                libc::close(self.wake_pipe.0);
                libc::close(self.wake_pipe.1);
            }
        }
    }

    impl std::fmt::Debug for KqueueReactor {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let reg_count = self.registrations.lock().len();
            f.debug_struct("KqueueReactor")
                .field("kq_fd", &self.kq_fd)
                .field("wake_pipe", &self.wake_pipe)
                .field("registration_count", &reg_count)
                .finish_non_exhaustive()
        }
    }

    // Ensure thread safety
    unsafe impl Send for KqueueReactor {}
    unsafe impl Sync for KqueueReactor {}
}

// Re-export on supported platforms
#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub use kqueue_impl::KqueueReactor;

// Stub for unsupported platforms (for documentation purposes)
#[cfg(not(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
mod stub {
    use super::super::{Events, Interest, Reactor, Source, Token};
    use std::io;
    use std::time::Duration;

    /// kqueue-based reactor (only available on macOS/BSD).
    #[derive(Debug, Default)]
    pub struct KqueueReactor;

    impl KqueueReactor {
        /// Create a new kqueue reactor.
        ///
        /// # Errors
        ///
        /// Always returns `Unsupported` on non-BSD platforms.
        pub fn new() -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "KqueueReactor is only available on macOS and BSD systems",
            ))
        }
    }

    impl Reactor for KqueueReactor {
        fn register(
            &self,
            _source: &dyn Source,
            _token: Token,
            _interest: Interest,
        ) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "KqueueReactor is only available on macOS and BSD systems",
            ))
        }

        fn modify(&self, _token: Token, _interest: Interest) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "KqueueReactor is only available on macOS and BSD systems",
            ))
        }

        fn deregister(&self, _token: Token) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "KqueueReactor is only available on macOS and BSD systems",
            ))
        }

        fn poll(&self, _events: &mut Events, _timeout: Option<Duration>) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "KqueueReactor is only available on macOS and BSD systems",
            ))
        }

        fn wake(&self) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "KqueueReactor is only available on macOS and BSD systems",
            ))
        }

        fn registration_count(&self) -> usize {
            0
        }
    }
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
pub use stub::KqueueReactor;

#[cfg(all(
    test,
    any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )
))]
mod tests {
    use super::*;
    use crate::runtime::reactor::{Events, Interest, Reactor, Token};
    use crate::test_utils::init_test_logging;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn create_reactor() {
        init_test("kqueue_create_reactor");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        crate::assert_with_log!(
            reactor.is_empty(),
            "reactor empty",
            true,
            reactor.is_empty()
        );
        crate::assert_with_log!(
            reactor.registration_count() == 0,
            "registration count",
            0usize,
            reactor.registration_count()
        );
        crate::test_complete!("kqueue_create_reactor");
    }

    #[test]
    fn register_and_deregister() {
        init_test("kqueue_register_and_deregister");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let (sock1, _sock2) = UnixStream::pair().expect("failed to create unix stream pair");

        let token = Token::new(42);
        reactor
            .register(&sock1, token, Interest::READABLE)
            .expect("register failed");

        crate::assert_with_log!(
            reactor.registration_count() == 1,
            "registration count",
            1usize,
            reactor.registration_count()
        );
        crate::assert_with_log!(
            !reactor.is_empty(),
            "reactor not empty",
            false,
            reactor.is_empty()
        );

        reactor.deregister(token).expect("deregister failed");

        crate::assert_with_log!(
            reactor.registration_count() == 0,
            "registration count",
            0usize,
            reactor.registration_count()
        );
        crate::assert_with_log!(
            reactor.is_empty(),
            "reactor empty",
            true,
            reactor.is_empty()
        );
        crate::test_complete!("kqueue_register_and_deregister");
    }

    #[test]
    fn deregister_not_found() {
        init_test("kqueue_deregister_not_found");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let result = reactor.deregister(Token::new(999));
        crate::assert_with_log!(result.is_err(), "deregister fails", true, result.is_err());
        let kind = result.unwrap_err().kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::NotFound,
            "not found kind",
            io::ErrorKind::NotFound,
            kind
        );
        crate::test_complete!("kqueue_deregister_not_found");
    }

    #[test]
    fn modify_interest() {
        init_test("kqueue_modify_interest");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let (sock1, _sock2) = UnixStream::pair().expect("failed to create unix stream pair");

        let token = Token::new(1);
        reactor
            .register(&sock1, token, Interest::READABLE)
            .expect("register failed");

        // Modify to writable
        reactor
            .modify(token, Interest::WRITABLE)
            .expect("modify failed");

        // Verify bookkeeping was updated
        let regs = reactor.registrations.lock();
        let info = regs.get(&token).unwrap();
        crate::assert_with_log!(
            info.interest == Interest::WRITABLE,
            "interest updated",
            Interest::WRITABLE,
            info.interest
        );
        drop(regs);

        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("kqueue_modify_interest");
    }

    #[test]
    fn modify_not_found() {
        init_test("kqueue_modify_not_found");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let result = reactor.modify(Token::new(999), Interest::READABLE);
        crate::assert_with_log!(result.is_err(), "modify fails", true, result.is_err());
        let kind = result.unwrap_err().kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::NotFound,
            "not found kind",
            io::ErrorKind::NotFound,
            kind
        );
        crate::test_complete!("kqueue_modify_not_found");
    }

    #[test]
    fn wake_unblocks_poll() {
        init_test("kqueue_wake_unblocks_poll");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let mut events = Events::with_capacity(64);

        // Spawn a thread to wake us
        let reactor_ref = &reactor;
        std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(50));
                reactor_ref.wake().expect("wake failed");
            });

            // This should return early due to wake
            let start = std::time::Instant::now();
            let _count = reactor
                .poll(&mut events, Some(Duration::from_secs(5)))
                .expect("poll failed");

            // Should return quickly, not wait 5 seconds
            let elapsed = start.elapsed();
            crate::assert_with_log!(
                elapsed < Duration::from_secs(1),
                "poll woke early",
                true,
                elapsed < Duration::from_secs(1)
            );
        });
        crate::test_complete!("kqueue_wake_unblocks_poll");
    }

    #[test]
    fn poll_timeout() {
        init_test("kqueue_poll_timeout");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let mut events = Events::with_capacity(64);

        let start = std::time::Instant::now();
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(50)))
            .expect("poll failed");

        // Should return after ~50ms with no events
        let elapsed = start.elapsed();
        crate::assert_with_log!(
            elapsed >= Duration::from_millis(40),
            "elapsed lower bound",
            true,
            elapsed >= Duration::from_millis(40)
        );
        crate::assert_with_log!(
            elapsed < Duration::from_millis(200),
            "elapsed upper bound",
            true,
            elapsed < Duration::from_millis(200)
        );
        crate::assert_with_log!(count == 0, "no events", 0usize, count);
        crate::test_complete!("kqueue_poll_timeout");
    }

    #[test]
    fn poll_non_blocking() {
        init_test("kqueue_poll_non_blocking");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let mut events = Events::with_capacity(64);

        let start = std::time::Instant::now();
        let count = reactor
            .poll(&mut events, Some(Duration::ZERO))
            .expect("poll failed");

        // Should return immediately
        let elapsed = start.elapsed();
        crate::assert_with_log!(
            elapsed < Duration::from_millis(10),
            "poll returns quickly",
            true,
            elapsed < Duration::from_millis(10)
        );
        crate::assert_with_log!(count == 0, "no events", 0usize, count);
        crate::test_complete!("kqueue_poll_non_blocking");
    }

    #[test]
    fn poll_writable() {
        init_test("kqueue_poll_writable");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let (sock1, _sock2) = UnixStream::pair().expect("failed to create unix stream pair");

        let token = Token::new(1);
        reactor
            .register(&sock1, token, Interest::WRITABLE)
            .expect("register failed");

        let mut events = Events::with_capacity(64);
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .expect("poll failed");

        // Socket should be immediately writable
        crate::assert_with_log!(count >= 1, "has events", true, count >= 1);

        let mut found = false;
        for event in events.iter() {
            if event.token == token && event.is_writable() {
                found = true;
                break;
            }
        }
        crate::assert_with_log!(found, "expected writable event for token", true, found);

        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("kqueue_poll_writable");
    }

    #[test]
    fn poll_readable() {
        init_test("kqueue_poll_readable");
        use std::io::Write;

        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let (sock1, mut sock2) = UnixStream::pair().expect("failed to create unix stream pair");

        let token = Token::new(1);
        reactor
            .register(&sock1, token, Interest::READABLE)
            .expect("register failed");

        // Write some data to make sock1 readable
        sock2.write_all(b"hello").expect("write failed");

        let mut events = Events::with_capacity(64);
        let count = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .expect("poll failed");

        // Socket should be readable now
        crate::assert_with_log!(count >= 1, "has events", true, count >= 1);

        let mut found = false;
        for event in events.iter() {
            if event.token == token && event.is_readable() {
                found = true;
                break;
            }
        }
        crate::assert_with_log!(found, "expected readable event for token", true, found);

        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("kqueue_poll_readable");
    }

    #[test]
    fn duplicate_register_fails() {
        init_test("kqueue_duplicate_register_fails");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let (sock1, _sock2) = UnixStream::pair().expect("failed to create unix stream pair");

        let token = Token::new(1);
        reactor
            .register(&sock1, token, Interest::READABLE)
            .expect("first register should succeed");

        // Second registration with same token should fail
        let result = reactor.register(&sock1, token, Interest::WRITABLE);
        crate::assert_with_log!(result.is_err(), "duplicate fails", true, result.is_err());
        let kind = result.unwrap_err().kind();
        crate::assert_with_log!(
            kind == io::ErrorKind::AlreadyExists,
            "already exists kind",
            io::ErrorKind::AlreadyExists,
            kind
        );

        reactor.deregister(token).expect("deregister failed");
        crate::test_complete!("kqueue_duplicate_register_fails");
    }

    #[test]
    fn multiple_registrations() {
        init_test("kqueue_multiple_registrations");
        let reactor = KqueueReactor::new().expect("failed to create reactor");

        let (sock1, _) = UnixStream::pair().expect("failed to create unix stream pair");
        let (sock2, _) = UnixStream::pair().expect("failed to create unix stream pair");
        let (sock3, _) = UnixStream::pair().expect("failed to create unix stream pair");

        reactor
            .register(&sock1, Token::new(1), Interest::READABLE)
            .expect("register 1 failed");
        reactor
            .register(&sock2, Token::new(2), Interest::WRITABLE)
            .expect("register 2 failed");
        reactor
            .register(&sock3, Token::new(3), Interest::both())
            .expect("register 3 failed");

        let count = reactor.registration_count();
        crate::assert_with_log!(count == 3, "registration count", 3usize, count);

        reactor
            .deregister(Token::new(2))
            .expect("deregister failed");
        let count = reactor.registration_count();
        crate::assert_with_log!(count == 2, "after deregister", 2usize, count);

        reactor
            .deregister(Token::new(1))
            .expect("deregister failed");
        reactor
            .deregister(Token::new(3))
            .expect("deregister failed");
        let count = reactor.registration_count();
        crate::assert_with_log!(count == 0, "after deregister all", 0usize, count);
        crate::test_complete!("kqueue_multiple_registrations");
    }

    #[test]
    fn debug_impl() {
        init_test("kqueue_debug_impl");
        let reactor = KqueueReactor::new().expect("failed to create reactor");
        let debug_text = format!("{:?}", reactor);
        crate::assert_with_log!(
            debug_text.contains("KqueueReactor"),
            "debug contains type",
            true,
            debug_text.contains("KqueueReactor")
        );
        crate::assert_with_log!(
            debug_text.contains("registration_count"),
            "debug contains registration_count",
            true,
            debug_text.contains("registration_count")
        );
        crate::test_complete!("kqueue_debug_impl");
    }
}
