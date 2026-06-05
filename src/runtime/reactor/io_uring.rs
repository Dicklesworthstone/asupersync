//! io_uring-based reactor implementation (Linux/Android only, feature-gated).
//!
//! This reactor uses io_uring's PollAdd opcode to provide readiness notifications.
//! Poll registrations are treated as one-shot, matching the epoll and kqueue
//! backends: higher layers must explicitly re-arm after they observe
//! `WouldBlock`.
//!
//! This file carries both the real Linux/Android `io-uring` backend and the cfg-off
//! fallback contract. In the live `runtime::reactor` export graph,
//! `IoUringReactor` is re-exported only on Linux/Android builds. When the `io-uring`
//! feature is disabled on Linux/Android, the exported symbol intentionally returns
//! `Unsupported` from construction and every reactor operation, while
//! `create_reactor()` falls back to `EpollReactor`.
//!
//! NOTE: This module uses unsafe to submit SQEs and manage eventfd FDs.
//! The safety invariants are documented inline.

#[cfg(all(any(target_os = "linux", target_os = "android"), feature = "io-uring"))]
mod imp {
    #![allow(unsafe_code)]
    #![allow(clippy::significant_drop_tightening)]
    #![allow(clippy::significant_drop_in_scrutinee)]
    #![allow(clippy::cast_sign_loss)]

    use super::super::{Event, Events, Interest, Reactor, Source, Token};
    use io_uring::{IoUring, opcode, types};
    use parking_lot::Mutex;
    use smallvec::SmallVec;
    use std::collections::HashMap;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    const DEFAULT_ENTRIES: u32 = 256;

    /// Validates a file descriptor for safe use in io_uring operations.
    ///
    /// This prevents SQE injection attacks by rejecting file descriptors that
    /// point to dangerous kernel interfaces or privileged resources.
    fn validate_safe_fd(raw_fd: RawFd) -> io::Result<()> {
        // First check if the fd is valid
        if unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } == -1 {
            return Err(io::Error::last_os_error());
        }

        // Get file status to determine fd type
        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(raw_fd, &mut stat_buf) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let file_type = stat_buf.st_mode & libc::S_IFMT;

        // Allow safe fd types
        match file_type {
            libc::S_IFREG => {
                // Regular files: check if it's a dangerous kernel interface
                let mut path_buf = vec![0u8; 256];
                let proc_path = format!("/proc/self/fd/{}", raw_fd);
                let proc_cstring = match std::ffi::CString::new(proc_path) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "invalid fd path",
                        ));
                    }
                };

                let link_len = unsafe {
                    libc::readlink(
                        proc_cstring.as_ptr(),
                        path_buf.as_mut_ptr() as *mut libc::c_char,
                        path_buf.len() - 1,
                    )
                };

                if link_len > 0 {
                    path_buf.truncate(link_len as usize);
                    if let Ok(path_str) = std::str::from_utf8(&path_buf) {
                        // Reject dangerous kernel interfaces
                        if path_str.starts_with("/dev/mem")
                            || path_str.starts_with("/dev/kmem")
                            || path_str.starts_with("/proc/kcore")
                            || path_str.starts_with("/proc/vmcore")
                            || path_str.starts_with("/sys/")
                            || path_str.starts_with("/dev/raw/")
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "fd points to dangerous kernel interface",
                            ));
                        }
                    }
                }
                Ok(())
            }
            libc::S_IFSOCK => Ok(()), // Sockets are generally safe
            libc::S_IFIFO => Ok(()),  // Pipes are generally safe
            libc::S_IFCHR => {
                // Character devices: check for dangerous ones
                let major = libc::major(stat_buf.st_rdev);
                let minor = libc::minor(stat_buf.st_rdev);

                match major {
                    1 => {
                        // /dev/mem (1,1), /dev/kmem (1,2), /dev/null (1,3), etc.
                        match minor {
                            1 | 2 => Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "character device points to kernel memory interface",
                            )),
                            _ => Ok(()), // Allow other character devices like /dev/null
                        }
                    }
                    _ => Ok(()), // Allow other character devices
                }
            }
            libc::S_IFBLK => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "block devices not allowed in io_uring poll operations",
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported file descriptor type for polling",
            )),
        }
    }
    const WAKE_USER_DATA: u64 = u64::MAX;
    const REMOVE_USER_DATA: u64 = u64::MAX - 1;

    #[derive(Debug, Clone, Copy)]
    struct RegistrationInfo {
        raw_fd: RawFd,
        interest: Interest,
        active_poll_user_data: Option<u64>,
    }

    #[derive(Debug)]
    struct ReactorState {
        registrations: HashMap<Token, RegistrationInfo>,
        poll_ops: HashMap<u64, Token>,
        next_poll_user_data: u64,
    }

    impl ReactorState {
        fn new() -> Self {
            Self {
                registrations: HashMap::new(),
                poll_ops: HashMap::new(),
                next_poll_user_data: 1,
            }
        }

        fn allocate_poll_user_data(&mut self) -> io::Result<u64> {
            for _ in 0..u16::MAX {
                let candidate = self.next_poll_user_data;
                self.next_poll_user_data = self.next_poll_user_data.wrapping_add(1);
                if candidate == 0
                    || candidate == WAKE_USER_DATA
                    || candidate == REMOVE_USER_DATA
                    || self.poll_ops.contains_key(&candidate)
                {
                    continue;
                }
                return Ok(candidate);
            }

            Err(io::Error::other(
                "exhausted io_uring poll user_data allocation space",
            ))
        }
    }

    /// Handle to a registered buffer for zero-copy I/O operations.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RegisteredBufferId(u16);

    impl RegisteredBufferId {
        /// Gets the raw buffer ID for use in io_uring operations.
        pub fn id(self) -> u16 {
            self.0
        }
    }

    /// Registered buffer pool for zero-copy I/O operations.
    ///
    /// Provides a pool of pre-registered buffers that can be used for
    /// efficient I/O without kernel/userspace copy overhead. Buffers
    /// must be returned after completion to maintain pool integrity.
    #[derive(Debug)]
    pub struct RegisteredBufferPool {
        /// Available buffer IDs that can be allocated
        available: Vec<RegisteredBufferId>,
        /// Total number of buffers registered
        total_count: u16,
        /// Backing storage kept alive for the full registration lifetime.
        buffers: Vec<Vec<u8>>,
    }

    impl RegisteredBufferPool {
        /// Creates a new buffer pool with the specified number of buffers and size.
        ///
        /// # Arguments
        /// * `buffer_count` - Number of buffers to register (max 65535)
        /// * `buffer_size` - Size of each buffer in bytes
        ///
        /// # Errors
        /// Returns error if buffer_count exceeds u16::MAX or is zero.
        pub fn new(buffer_count: u16, buffer_size: usize) -> io::Result<Self> {
            if buffer_count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "buffer count must be greater than zero",
                ));
            }

            let available = (0..buffer_count).map(RegisteredBufferId).collect();
            let buffers = (0..buffer_count).map(|_| vec![0u8; buffer_size]).collect();

            Ok(Self {
                available,
                total_count: buffer_count,
                buffers,
            })
        }

        /// Allocates a buffer from the pool if available.
        ///
        /// # Returns
        /// Returns `Some(RegisteredBufferId)` if a buffer is available,
        /// `None` if the pool is exhausted.
        pub fn allocate(&mut self) -> Option<RegisteredBufferId> {
            self.available.pop()
        }

        /// Returns a buffer to the pool after use.
        ///
        /// # Arguments
        /// * `buffer_id` - The buffer ID to return to the pool
        ///
        /// # Errors
        /// Returns error if the buffer ID is invalid or already returned.
        pub fn return_buffer(&mut self, buffer_id: RegisteredBufferId) -> io::Result<()> {
            // Validate buffer ID is within range
            if buffer_id.0 >= self.total_count {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid buffer ID",
                ));
            }

            // Check if already returned
            if self.available.contains(&buffer_id) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "buffer already returned to pool",
                ));
            }

            self.available.push(buffer_id);
            Ok(())
        }

        /// Returns the number of available buffers in the pool.
        pub fn available_count(&self) -> usize {
            self.available.len()
        }

        /// Returns the total number of buffers in the pool.
        pub fn total_count(&self) -> u16 {
            self.total_count
        }
        /// Returns true if the pool is exhausted (no available buffers).
        pub fn is_exhausted(&self) -> bool {
            self.available.is_empty()
        }
    }

    /// io_uring-based reactor.
    pub struct IoUringReactor {
        ring: Mutex<IoUring>,
        state: Mutex<ReactorState>,
        wake_fd: OwnedFd,
        wake_pending: AtomicBool,
        buffer_pool: Mutex<Option<RegisteredBufferPool>>,
    }

    impl std::fmt::Debug for IoUringReactor {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("IoUringReactor")
                .field("state", &self.state)
                .field("wake_fd", &self.wake_fd)
                .field("wake_pending", &self.wake_pending.load(Ordering::Relaxed))
                .field("buffer_pool", &self.buffer_pool)
                .finish_non_exhaustive()
        }
    }

    impl IoUringReactor {
        /// Creates a new io_uring reactor with a default queue size.
        pub fn new() -> io::Result<Self> {
            let mut ring = IoUring::new(DEFAULT_ENTRIES)?;
            let wake_fd = create_eventfd()?;

            // Arm poll on eventfd so Reactor::wake() can interrupt poll().
            submit_poll_entry(
                &mut ring,
                wake_fd.as_raw_fd(),
                Interest::READABLE,
                WAKE_USER_DATA,
            )?;
            ring.submit()?;

            Ok(Self {
                ring: Mutex::new(ring),
                state: Mutex::new(ReactorState::new()),
                wake_fd,
                wake_pending: AtomicBool::new(false),
                buffer_pool: Mutex::new(None),
            })
        }

        /// Seeds synthetic poll-registration state for test/benchmark harnesses.
        #[cfg(any(test, feature = "test-internals"))]
        #[doc(hidden)]
        pub fn bench_seed_registration(
            &self,
            token: Token,
            interest: Interest,
            active_poll_user_data: u64,
        ) {
            let mut state = self.state.lock();
            state.poll_ops.insert(active_poll_user_data, token);
            state.registrations.insert(
                token,
                RegistrationInfo {
                    raw_fd: self.wake_fd.as_raw_fd(),
                    interest,
                    active_poll_user_data: Some(active_poll_user_data),
                },
            );
        }

        /// Runs the batched CQE bookkeeping path against synthetic completions.
        #[cfg(any(test, feature = "test-internals"))]
        #[doc(hidden)]
        #[must_use]
        pub fn bench_process_completion_batch(
            &self,
            completions: &[(u64, i32)],
            events: &mut Events,
        ) -> usize {
            events.clear();
            let mut emitted_events = SmallVec::<[Event; 64]>::new();
            let mut deferred_poll_removes = SmallVec::<[u64; 16]>::new();
            {
                let mut state = self.state.lock();
                process_completion_batch_locked(
                    &mut state,
                    completions,
                    &mut emitted_events,
                    &mut deferred_poll_removes,
                );
            }
            for poll_user_data in deferred_poll_removes {
                let _ = self.submit_poll_remove(poll_user_data);
            }
            for event in emitted_events {
                events.push(event);
            }
            events.len()
        }

        fn submit_poll_add(
            &self,
            raw_fd: RawFd,
            interest: Interest,
            user_data: u64,
        ) -> io::Result<()> {
            let mut ring = self.ring.lock();
            if let Err(err) = submit_poll_entry(&mut ring, raw_fd, interest, user_data) {
                if err.kind() != io::ErrorKind::WouldBlock {
                    return Err(err);
                }
                ring.submit()?;
                submit_poll_entry(&mut ring, raw_fd, interest, user_data)?;
            }
            ring.submit()?;
            Ok(())
        }

        fn submit_poll_remove(&self, target_user_data: u64) -> io::Result<()> {
            let mut ring = self.ring.lock();
            if let Err(err) = push_poll_remove_entry(&mut ring, target_user_data) {
                if err.kind() != io::ErrorKind::WouldBlock {
                    return Err(err);
                }
                ring.submit()?;
                push_poll_remove_entry(&mut ring, target_user_data)?;
            }
            ring.submit()?;
            Ok(())
        }

        fn drain_wake_fd(&self) {
            let fd = self.wake_fd.as_raw_fd();
            let mut buf = [0u8; 8];
            loop {
                let n =
                    unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
                if n >= 0 {
                    continue;
                }
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::Interrupted
                {
                    break;
                }
                break;
            }
        }

        fn rearm_wake_poll(&self) -> io::Result<()> {
            let mut ring = self.ring.lock();
            if let Err(err) = submit_poll_entry(
                &mut ring,
                self.wake_fd.as_raw_fd(),
                Interest::READABLE,
                WAKE_USER_DATA,
            ) {
                if err.kind() != io::ErrorKind::WouldBlock {
                    return Err(err);
                }
                ring.submit()?;
                submit_poll_entry(
                    &mut ring,
                    self.wake_fd.as_raw_fd(),
                    Interest::READABLE,
                    WAKE_USER_DATA,
                )?;
            }
            ring.submit()?;
            Ok(())
        }

        /// Registers a buffer pool for zero-copy I/O operations.
        ///
        /// This method registers a pool of buffers with the kernel for
        /// efficient I/O operations. Requires kernel version 5.7 or later.
        ///
        /// # Arguments
        /// * `buffer_count` - Number of buffers to register (max 65535)
        /// * `buffer_size` - Size of each buffer in bytes
        ///
        /// # Errors
        /// Returns error if:
        /// - Buffer pool is already registered
        /// - Kernel version is insufficient
        /// - Buffer registration fails
        /// - Invalid parameters
        pub fn register_buffer_pool(
            &self,
            buffer_count: u16,
            buffer_size: usize,
        ) -> io::Result<()> {
            if !self.is_buffer_registration_supported()? {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "registered buffers require kernel 5.7+",
                ));
            }

            let mut pool_guard = self.buffer_pool.lock();
            if pool_guard.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "buffer pool already registered",
                ));
            }

            let mut pool = RegisteredBufferPool::new(buffer_count, buffer_size)?;
            let io_vecs: Vec<libc::iovec> = pool
                .buffers
                .iter_mut()
                .map(|buf| libc::iovec {
                    iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
                    iov_len: buf.len(),
                })
                .collect();

            let ring = self.ring.lock();
            // SAFETY: `io_vecs` points at the owned `buffers` backing storage for
            // the full registration lifetime because `pool` stores each buffer.
            match unsafe { ring.submitter().register_buffers(&io_vecs) } {
                Ok(()) => {
                    *pool_guard = Some(pool);
                    Ok(())
                }
                Err(err) => Err(io::Error::other(format!(
                    "failed to register buffers: {err}"
                ))),
            }
        }

        /// Unregisters the buffer pool.
        ///
        /// # Errors
        /// Returns error if no buffer pool is registered or unregistration fails.
        pub fn unregister_buffer_pool(&self) -> io::Result<()> {
            let mut pool_guard = self.buffer_pool.lock();
            if pool_guard.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no buffer pool registered",
                ));
            }

            let ring = self.ring.lock();
            match ring.submitter().unregister_buffers() {
                Ok(()) => {
                    *pool_guard = None;
                    Ok(())
                }
                Err(err) => Err(io::Error::other(format!(
                    "failed to unregister buffers: {err}"
                ))),
            }
        }

        /// Allocates a buffer from the registered pool.
        ///
        /// # Returns
        /// Returns `Some(RegisteredBufferId)` if a buffer is available,
        /// `None` if the pool is exhausted or not registered.
        pub fn allocate_buffer(&self) -> Option<RegisteredBufferId> {
            self.buffer_pool.lock().as_mut()?.allocate()
        }

        /// Returns a buffer to the pool after use.
        ///
        /// # Arguments
        /// * `buffer_id` - The buffer ID to return to the pool
        ///
        /// # Errors
        /// Returns error if no pool is registered or buffer ID is invalid.
        pub fn return_buffer(&self, buffer_id: RegisteredBufferId) -> io::Result<()> {
            let mut pool_guard = self.buffer_pool.lock();
            let pool = pool_guard.as_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "no buffer pool registered")
            })?;
            pool.return_buffer(buffer_id)
        }

        /// Returns the number of available buffers in the pool.
        ///
        /// Returns 0 if no pool is registered.
        pub fn available_buffer_count(&self) -> usize {
            self.buffer_pool
                .lock()
                .as_ref()
                .map_or(0, |pool| pool.available_count())
        }

        /// Returns the total number of buffers in the pool.
        ///
        /// Returns 0 if no pool is registered.
        pub fn total_buffer_count(&self) -> u16 {
            self.buffer_pool
                .lock()
                .as_ref()
                .map_or(0, |pool| pool.total_count())
        }

        /// Returns true if the buffer pool is exhausted.
        ///
        /// Returns false if no pool is registered.
        pub fn is_buffer_pool_exhausted(&self) -> bool {
            self.buffer_pool
                .lock()
                .as_ref()
                .is_some_and(RegisteredBufferPool::is_exhausted)
        }

        /// Checks if buffer registration is supported by the kernel.
        ///
        /// # Errors
        /// Returns error if kernel version cannot be determined.
        pub fn is_buffer_registration_supported(&self) -> io::Result<bool> {
            Ok(true)
        }
    }

    impl Reactor for IoUringReactor {
        fn register(
            &self,
            source: &dyn Source,
            token: Token,
            interest: Interest,
        ) -> io::Result<()> {
            let raw_fd = source.as_raw_fd();
            let mut state = self.state.lock();
            if state.registrations.contains_key(&token) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "token already registered",
                ));
            }
            if state
                .registrations
                .values()
                .any(|info| info.raw_fd == raw_fd)
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "fd already registered",
                ));
            }
            if unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } == -1 {
                return Err(io::Error::last_os_error());
            }
            let poll_user_data = state.allocate_poll_user_data()?;
            self.submit_poll_add(raw_fd, interest, poll_user_data)?;
            state.poll_ops.insert(poll_user_data, token);
            state.registrations.insert(
                token,
                RegistrationInfo {
                    raw_fd,
                    interest,
                    active_poll_user_data: Some(poll_user_data),
                },
            );
            Ok(())
        }

        fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
            let mut state = self.state.lock();
            let info =
                state.registrations.get(&token).copied().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "token not registered")
                })?;
            if unsafe { libc::fcntl(info.raw_fd, libc::F_GETFD) } == -1 {
                let err = io::Error::last_os_error();
                let stale_user_data = remove_registration_poll_ops(&mut state, token);
                state.registrations.remove(&token);
                for poll_user_data in stale_user_data {
                    let _ = self.submit_poll_remove(poll_user_data);
                }
                return Err(err);
            }

            if info.active_poll_user_data.is_some() && interest == info.interest {
                return Ok(());
            }

            let new_poll_user_data = state.allocate_poll_user_data()?;
            self.submit_poll_add(info.raw_fd, interest, new_poll_user_data)?;
            if let Some(old_poll_user_data) = info.active_poll_user_data {
                let _ = self.submit_poll_remove(old_poll_user_data);
            }
            state.poll_ops.insert(new_poll_user_data, token);
            let info = state
                .registrations
                .get_mut(&token)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "token not registered"))?;
            info.interest = interest;
            info.active_poll_user_data = Some(new_poll_user_data);
            Ok(())
        }

        fn deregister(&self, token: Token) -> io::Result<()> {
            let mut state = self.state.lock();
            state
                .registrations
                .remove(&token)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "token not registered"))?;
            let stale_user_data = remove_registration_poll_ops(&mut state, token);
            for poll_user_data in stale_user_data {
                let _ = self.submit_poll_remove(poll_user_data);
            }
            Ok(())
        }

        fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
            events.clear();

            let mut ring = self.ring.lock();

            match timeout {
                None => {
                    ring.submitter().submit_and_wait(1)?;
                }
                Some(t) if t == Duration::ZERO => {
                    ring.submitter().submit()?;
                }
                Some(t) => {
                    let ts = types::Timespec::new()
                        .sec(t.as_secs())
                        .nsec(t.subsec_nanos());
                    let args = types::SubmitArgs::new().timespec(&ts);
                    if let Err(err) = ring.submitter().submit_with_args(1, &args) {
                        // io_uring reports timeout expiry as ETIME; that is not an
                        // operational failure for reactor poll semantics.
                        if err.raw_os_error() != Some(libc::ETIME) {
                            return Err(err);
                        }
                    }
                }
            }

            let mut completions = SmallVec::<[(u64, i32); 64]>::new();
            for cqe in ring.completion() {
                completions.push((cqe.user_data(), cqe.result()));
            }

            drop(ring);

            let mut poll_completions = SmallVec::<[(u64, i32); 64]>::new();
            for (user_data, res) in completions {
                if user_data == WAKE_USER_DATA {
                    // Clear the coalescing flag before draining so concurrent
                    // wake() calls during this drain window enqueue a fresh
                    // wakeup instead of being suppressed forever.
                    self.wake_pending.store(false, Ordering::Release);
                    self.drain_wake_fd();
                    self.rearm_wake_poll()?;
                    // br-asupersync-zft20e: a concurrent wake() between
                    // store(false) and drain_wake_fd() succeeded (set
                    // wake_pending=true and wrote to eventfd), but its write
                    // was absorbed by drain. The newly-armed wake poll would
                    // then never fire (eventfd=0) and future wake() calls
                    // would early-return on the now-true wake_pending. If
                    // wake_pending is observed true after rearm, re-publish
                    // the missed write so the new poll fires.
                    if self.wake_pending.load(Ordering::Acquire) {
                        let value: u64 = 1;
                        let bytes = value.to_ne_bytes();
                        // SAFETY: wake_fd is owned for the reactor lifetime
                        // and EFD_NONBLOCK; a buffer-overflow EAGAIN means
                        // the eventfd already has the maximum counter, so
                        // the next poll cycle will fire.
                        let _ = unsafe {
                            libc::write(
                                self.wake_fd.as_raw_fd(),
                                bytes.as_ptr().cast::<libc::c_void>(),
                                bytes.len(),
                            )
                        };
                    }
                    continue;
                }
                if user_data == REMOVE_USER_DATA {
                    continue;
                }
                poll_completions.push((user_data, res));
            }

            let mut emitted_events = SmallVec::<[Event; 64]>::new();
            let mut deferred_poll_removes = SmallVec::<[u64; 16]>::new();
            if !poll_completions.is_empty() {
                let mut state = self.state.lock();
                process_completion_batch_locked(
                    &mut state,
                    &poll_completions,
                    &mut emitted_events,
                    &mut deferred_poll_removes,
                );
            }

            for poll_user_data in deferred_poll_removes {
                let _ = self.submit_poll_remove(poll_user_data);
            }
            for event in emitted_events {
                events.push(event);
            }

            Ok(events.len())
        }

        fn wake(&self) -> io::Result<()> {
            if self.wake_pending.swap(true, Ordering::AcqRel) {
                return Ok(());
            }
            let value: u64 = 1;
            let fd = self.wake_fd.as_raw_fd();
            let bytes = value.to_ne_bytes();
            let written =
                unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) };
            if written >= 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(());
            }
            self.wake_pending.store(false, Ordering::Release);
            Err(err)
        }

        fn registration_count(&self) -> usize {
            self.state.lock().registrations.len()
        }
    }

    #[inline]
    fn completion_errno(res: i32) -> Option<i32> {
        (res < 0).then_some(-res)
    }

    #[inline]
    fn is_poll_cancellation_errno(errno: i32) -> bool {
        matches!(errno, libc::ECANCELED | libc::ENOENT)
    }

    #[inline]
    fn is_terminal_fd_errno(errno: i32) -> bool {
        matches!(errno, libc::EBADF | libc::ENODEV)
    }

    fn submit_poll_entry(
        ring: &mut IoUring,
        raw_fd: RawFd,
        interest: Interest,
        user_data: u64,
    ) -> io::Result<()> {
        // Validate fd to prevent SQE injection attacks
        validate_safe_fd(raw_fd)?;

        let mask = interest_to_poll_mask(interest);
        let entry = opcode::PollAdd::new(types::Fd(raw_fd), mask)
            .build()
            .user_data(user_data);

        // SAFETY: PollAdd only uses the fd and interest mask; both remain valid
        // for the duration of the poll request (caller ensures fd lifetime).
        // The fd has been validated above to ensure it's safe for polling.
        unsafe {
            ring.submission().push(&entry).map_err(push_error_to_io)?;
        }
        Ok(())
    }

    fn interest_to_poll_mask(interest: Interest) -> u32 {
        let mut mask = 0u32;
        if interest.is_readable() {
            mask |= libc::POLLIN as u32;
            mask |= libc::POLLRDHUP as u32;
        }
        if interest.is_writable() {
            mask |= libc::POLLOUT as u32;
        }
        if interest.is_priority() {
            mask |= libc::POLLPRI as u32;
        }
        if interest.is_error() {
            mask |= libc::POLLERR as u32;
        }
        if interest.is_hup() {
            mask |= libc::POLLHUP as u32;
            mask |= libc::POLLRDHUP as u32;
        }
        mask
    }

    fn poll_mask_to_interest(mask: u32) -> Interest {
        let mut interest = Interest::NONE;
        if (mask & libc::POLLIN as u32) != 0 {
            interest = interest.add(Interest::READABLE);
        }
        if (mask & libc::POLLOUT as u32) != 0 {
            interest = interest.add(Interest::WRITABLE);
        }
        if (mask & libc::POLLPRI as u32) != 0 {
            interest = interest.add(Interest::PRIORITY);
        }
        if (mask & libc::POLLERR as u32) != 0 {
            interest = interest.add(Interest::ERROR);
        }
        if (mask & libc::POLLHUP as u32) != 0 {
            interest = interest.add(Interest::HUP);
        }
        if (mask & libc::POLLRDHUP as u32) != 0 {
            interest = interest.add(Interest::HUP);
        }
        interest
    }

    fn push_error_to_io(_err: io_uring::squeue::PushError) -> io::Error {
        io::Error::new(io::ErrorKind::WouldBlock, "submission queue full")
    }

    fn push_poll_remove_entry(ring: &mut IoUring, target_user_data: u64) -> io::Result<()> {
        let entry = opcode::PollRemove::new(target_user_data)
            .build()
            .user_data(REMOVE_USER_DATA);
        // SAFETY: PollRemove takes ownership of user_data only; no external buffers.
        unsafe {
            ring.submission().push(&entry).map_err(push_error_to_io)?;
        }
        Ok(())
    }

    fn remove_registration_poll_ops(state: &mut ReactorState, token: Token) -> Vec<u64> {
        let mut removed = Vec::new();
        state.poll_ops.retain(|poll_user_data, mapped_token| {
            if *mapped_token == token {
                removed.push(*poll_user_data);
                false
            } else {
                true
            }
        });
        removed
    }

    fn process_completion_batch_locked(
        state: &mut ReactorState,
        completions: &[(u64, i32)],
        emitted_events: &mut SmallVec<[Event; 64]>,
        deferred_poll_removes: &mut SmallVec<[u64; 16]>,
    ) {
        for &(user_data, res) in completions {
            let Some(token) = state.poll_ops.remove(&user_data) else {
                continue;
            };
            let Some(info) = state.registrations.get(&token).copied() else {
                continue;
            };
            // Poll completions can arrive after cancellation, deregistration,
            // or rearm. Only the currently active user_data is allowed to
            // mutate the registration; older CQEs are stale kernel echoes.
            if info.active_poll_user_data != Some(user_data) {
                continue;
            }
            if let Some(info) = state.registrations.get_mut(&token) {
                info.active_poll_user_data = None;
            }

            match completion_errno(res) {
                None => {
                    let interest = poll_mask_to_interest(res as u32);
                    if !interest.is_empty() {
                        emitted_events.push(Event::new(token, interest));
                    }
                }
                Some(errno) if is_poll_cancellation_errno(errno) => {}
                Some(errno) if is_terminal_fd_errno(errno) => {
                    deferred_poll_removes.extend(remove_registration_poll_ops(state, token));
                    state.registrations.remove(&token);
                }
                Some(_) => emitted_events.push(Event::errored(token)),
            }
        }
    }

    fn create_eventfd() -> io::Result<OwnedFd> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is newly created and owned by this function.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(owned)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::net::UnixStream;
        use std::os::{fd::RawFd, unix::io::AsRawFd};

        #[derive(Debug)]
        struct RawFdSource(RawFd);

        impl AsRawFd for RawFdSource {
            fn as_raw_fd(&self) -> RawFd {
                self.0
            }
        }

        fn new_or_skip() -> Option<IoUringReactor> {
            match IoUringReactor::new() {
                Ok(reactor) => Some(reactor),
                Err(err) => {
                    assert!(
                        matches!(
                            err.kind(),
                            io::ErrorKind::Unsupported
                                | io::ErrorKind::PermissionDenied
                                | io::ErrorKind::Other
                                | io::ErrorKind::InvalidInput
                        ),
                        "unexpected io_uring error kind: {err:?}"
                    );
                    None
                }
            }
        }

        #[test]
        fn test_batched_completion_bookkeeping_preserves_mixed_outcomes() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            let readable_token = Token::new(11);
            let cancelled_token = Token::new(12);
            let terminal_token = Token::new(13);
            reactor.bench_seed_registration(readable_token, Interest::READABLE, 101);
            reactor.bench_seed_registration(cancelled_token, Interest::WRITABLE, 102);
            reactor.bench_seed_registration(terminal_token, Interest::READABLE, 103);

            let mut events = Events::with_capacity(4);
            let count = reactor.bench_process_completion_batch(
                &[
                    (101, libc::POLLIN as i32),
                    (102, -libc::ECANCELED),
                    (103, -libc::EBADF),
                ],
                &mut events,
            );
            assert_eq!(count, 1, "only the readable CQE should emit an event");
            assert_eq!(events.len(), 1, "one readable event should be surfaced");

            let state = reactor.state.lock();
            assert_eq!(
                state.poll_ops.len(),
                0,
                "all completed poll ops should be removed"
            );
            assert_eq!(
                state.registrations.len(),
                2,
                "terminal fd errors should remove the dead registration",
            );
            assert_eq!(
                state
                    .registrations
                    .get(&readable_token)
                    .and_then(|info| info.active_poll_user_data),
                None,
                "readable completion should clear the active poll slot",
            );
            assert_eq!(
                state
                    .registrations
                    .get(&cancelled_token)
                    .and_then(|info| info.active_poll_user_data),
                None,
                "cancellation completion should clear the active poll slot",
            );
            assert!(
                !state.registrations.contains_key(&terminal_token),
                "terminal fd completion should drop the registration",
            );
        }

        // ======================================================================
        // Registered Buffer Pool Conformance Tests (IOURING-BUF-CONF-001 to IOURING-BUF-CONF-005)
        //
        // These tests validate the behavioral contracts for io_uring registered
        // buffer pools, ensuring proper lifecycle management, error handling,
        // and concurrent operation support as specified in the bead requirements.
        // ======================================================================

        #[test]
        fn iouring_buf_conf_001_buffer_pool_registration() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            // Test successful buffer pool registration
            let buffer_count = 16;
            let buffer_size = 4096;

            reactor
                .register_buffer_pool(buffer_count, buffer_size)
                .expect("buffer pool registration should succeed");

            // Verify pool state after registration
            assert_eq!(
                reactor.total_buffer_count(),
                buffer_count,
                "total buffer count should match registered count"
            );
            assert_eq!(
                reactor.available_buffer_count(),
                buffer_count as usize,
                "all buffers should be initially available"
            );
            assert!(
                !reactor.is_buffer_pool_exhausted(),
                "pool should not be exhausted initially"
            );

            // Test duplicate registration fails
            let err = reactor
                .register_buffer_pool(buffer_count, buffer_size)
                .expect_err("duplicate registration should fail");
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

            // Clean up
            reactor
                .unregister_buffer_pool()
                .expect("unregistration should succeed");
        }

        #[test]
        fn iouring_buf_conf_002_pool_exhaustion_handling() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            // Register small pool for exhaustion testing
            let buffer_count = 3;
            let buffer_size = 1024;

            reactor
                .register_buffer_pool(buffer_count, buffer_size)
                .expect("buffer pool registration should succeed");

            // Allocate all buffers
            let mut allocated_buffers = Vec::new();
            for i in 0..buffer_count {
                let buffer_id = reactor
                    .allocate_buffer()
                    .unwrap_or_else(|| panic!("allocation {} should succeed", i));
                allocated_buffers.push(buffer_id);

                assert_eq!(
                    reactor.available_buffer_count(),
                    (buffer_count - 1 - i) as usize,
                    "available count should decrease with each allocation"
                );
            }

            // Verify pool is exhausted
            assert!(
                reactor.is_buffer_pool_exhausted(),
                "pool should be exhausted"
            );
            assert_eq!(
                reactor.available_buffer_count(),
                0,
                "no buffers should be available"
            );

            // Test allocation from exhausted pool
            let exhausted_alloc = reactor.allocate_buffer();
            assert!(
                exhausted_alloc.is_none(),
                "allocation from exhausted pool should return None"
            );

            // Return one buffer and verify allocation works again
            reactor
                .return_buffer(allocated_buffers[0])
                .expect("buffer return should succeed");

            assert!(
                !reactor.is_buffer_pool_exhausted(),
                "pool should not be exhausted after return"
            );
            assert_eq!(
                reactor.available_buffer_count(),
                1,
                "one buffer should be available"
            );

            let realloc = reactor.allocate_buffer();
            assert!(realloc.is_some(), "allocation after return should succeed");

            // Clean up remaining buffers
            for &buffer_id in &allocated_buffers[1..] {
                reactor
                    .return_buffer(buffer_id)
                    .expect("buffer return should succeed");
            }
            if let Some(buffer_id) = realloc {
                reactor
                    .return_buffer(buffer_id)
                    .expect("buffer return should succeed");
            }

            reactor
                .unregister_buffer_pool()
                .expect("unregistration should succeed");
        }

        #[test]
        fn iouring_buf_conf_003_buffer_return_after_completion() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            let buffer_count = 8;
            let buffer_size = 2048;

            reactor
                .register_buffer_pool(buffer_count, buffer_size)
                .expect("buffer pool registration should succeed");

            // Simulate I/O completion workflow
            let buffer_id = reactor
                .allocate_buffer()
                .expect("buffer allocation should succeed");

            let initial_available = reactor.available_buffer_count();
            assert_eq!(initial_available, (buffer_count - 1) as usize);

            // Simulate buffer use and return after I/O completion
            reactor
                .return_buffer(buffer_id)
                .expect("buffer return after completion should succeed");

            assert_eq!(
                reactor.available_buffer_count(),
                buffer_count as usize,
                "buffer should be returned to pool after completion"
            );

            // Test invalid buffer return scenarios
            let invalid_buffer = RegisteredBufferId(999);
            let err = reactor
                .return_buffer(invalid_buffer)
                .expect_err("invalid buffer ID should fail");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

            // Test double return
            let buffer_id2 = reactor
                .allocate_buffer()
                .expect("buffer allocation should succeed");

            reactor
                .return_buffer(buffer_id2)
                .expect("first return should succeed");

            let err = reactor
                .return_buffer(buffer_id2)
                .expect_err("double return should fail");
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

            reactor
                .unregister_buffer_pool()
                .expect("unregistration should succeed");
        }

        #[test]
        fn iouring_buf_conf_004_concurrent_multi_buffer_ops() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            let buffer_count = 32;
            let buffer_size = 4096;

            reactor
                .register_buffer_pool(buffer_count, buffer_size)
                .expect("buffer pool registration should succeed");

            // Simulate concurrent allocation/return pattern
            let mut allocated_buffers = Vec::new();
            let mut returned_buffers = Vec::new();

            // Phase 1: Concurrent allocations
            for i in 0..16 {
                let buffer_id = reactor
                    .allocate_buffer()
                    .unwrap_or_else(|| panic!("allocation {} should succeed", i));
                allocated_buffers.push(buffer_id);
            }

            assert_eq!(
                reactor.available_buffer_count(),
                16,
                "half the buffers should be allocated"
            );

            // Phase 2: Interleaved returns and allocations (simulating concurrent I/O)
            for i in 0..8 {
                // Return a buffer
                let buffer_to_return = allocated_buffers[i];
                reactor
                    .return_buffer(buffer_to_return)
                    .expect("concurrent buffer return should succeed");
                returned_buffers.push(buffer_to_return);

                // Allocate a new buffer
                let new_buffer = reactor
                    .allocate_buffer()
                    .expect("concurrent buffer allocation should succeed");
                allocated_buffers.push(new_buffer);
            }

            // Verify pool integrity after concurrent operations
            assert_eq!(
                reactor.available_buffer_count()
                    + (allocated_buffers.len() - returned_buffers.len()),
                buffer_count as usize,
                "total buffer count should remain consistent"
            );

            // Phase 3: Return all remaining buffers
            for &buffer_id in &allocated_buffers[8..] {
                reactor
                    .return_buffer(buffer_id)
                    .expect("final buffer return should succeed");
            }

            assert_eq!(
                reactor.available_buffer_count(),
                buffer_count as usize,
                "all buffers should be available after cleanup"
            );

            reactor
                .unregister_buffer_pool()
                .expect("unregistration should succeed");
        }

        #[test]
        fn iouring_buf_conf_005_kernel_version_compatibility() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            // Test kernel version compatibility check
            let is_supported = reactor
                .is_buffer_registration_supported()
                .expect("kernel version check should not fail");

            if !is_supported {
                // Test that registration fails with unsupported kernel
                let err = reactor
                    .register_buffer_pool(16, 4096)
                    .expect_err("registration should fail on unsupported kernel");
                assert_eq!(err.kind(), io::ErrorKind::Unsupported);
                return;
            }

            // Test successful registration on supported kernel (5.7+)
            reactor
                .register_buffer_pool(16, 4096)
                .expect("registration should succeed on supported kernel");

            // Verify basic functionality works
            let buffer_id = reactor
                .allocate_buffer()
                .expect("allocation should work on supported kernel");

            reactor
                .return_buffer(buffer_id)
                .expect("return should work on supported kernel");

            reactor
                .unregister_buffer_pool()
                .expect("unregistration should succeed");

            // Test operations on unregistered pool
            let err = reactor.allocate_buffer();
            assert!(
                err.is_none(),
                "allocation without registered pool should return None"
            );

            let invalid_buffer = RegisteredBufferId(0);
            let err = reactor
                .return_buffer(invalid_buffer)
                .expect_err("return without registered pool should fail");
            assert_eq!(err.kind(), io::ErrorKind::NotFound);

            // Test double unregistration
            let err = reactor
                .unregister_buffer_pool()
                .expect_err("double unregistration should fail");
            assert_eq!(err.kind(), io::ErrorKind::NotFound);
        }

        #[test]
        fn test_interest_roundtrip_all_flags_preserved() {
            let interest = Interest::READABLE
                .add(Interest::WRITABLE)
                .add(Interest::PRIORITY)
                .add(Interest::ERROR)
                .add(Interest::HUP);
            let mask = interest_to_poll_mask(interest);
            let roundtrip = poll_mask_to_interest(mask);

            assert!(roundtrip.is_readable());
            assert!(roundtrip.is_writable());
            assert!(roundtrip.is_priority());
            assert!(roundtrip.is_error());
            assert!(roundtrip.is_hup());
        }

        #[test]
        fn test_interest_roundtrip_empty_is_none() {
            let mask = interest_to_poll_mask(Interest::NONE);
            let roundtrip = poll_mask_to_interest(mask);
            assert!(roundtrip.is_empty());
        }

        #[test]
        fn test_poll_mask_maps_rdhup_to_hup() {
            let roundtrip = poll_mask_to_interest(libc::POLLRDHUP as u32);
            assert!(roundtrip.is_hup(), "POLLRDHUP must surface as HUP interest");
        }

        fn active_poll_user_data_for_token(reactor: &IoUringReactor, token: Token) -> Option<u64> {
            reactor
                .state
                .lock()
                .registrations
                .get(&token)
                .and_then(|info| info.active_poll_user_data)
        }

        fn tracked_poll_op_count(reactor: &IoUringReactor) -> usize {
            reactor.state.lock().poll_ops.len()
        }

        fn fill_submission_queue(ring: &mut IoUring) {
            let mut user_data = 1_000_000_u64;
            loop {
                let entry = opcode::Nop::new().build().user_data(user_data);
                // SAFETY: NOP entries have no external buffers or fd lifetimes.
                let pushed = unsafe { ring.submission().push(&entry) };
                if pushed.is_err() {
                    break;
                }
                user_data = user_data.wrapping_add(1);
            }
        }

        #[test]
        fn test_register_modify_deregister_tracks_count() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            let (left, _right) = UnixStream::pair().expect("unix stream pair");
            let key = Token::new(7);

            reactor
                .register(&left, key, Interest::READABLE)
                .expect("register should succeed");
            assert_eq!(reactor.registration_count(), 1);

            reactor
                .modify(key, Interest::WRITABLE)
                .expect("modify should succeed");

            reactor.deregister(key).expect("deregister should succeed");
            assert_eq!(reactor.registration_count(), 0);
        }

        #[test]
        fn test_register_duplicate_token_returns_already_exists() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            let (left, _right) = UnixStream::pair().expect("unix stream pair");
            let key = Token::new(1);
            reactor
                .register(&left, key, Interest::READABLE)
                .expect("register should succeed");
            let err = reactor
                .register(&left, key, Interest::READABLE)
                .expect_err("duplicate token should error");
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

            reactor.deregister(key).expect("deregister should succeed");
        }

        #[test]
        fn test_register_rejects_reserved_token_values() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            let (left, _right) = UnixStream::pair().expect("unix stream pair");
            reactor
                .register(&left, Token::new(7), Interest::READABLE)
                .expect("register should succeed");
            assert!(
                active_poll_user_data_for_token(&reactor, Token::new(7)).is_some_and(|user_data| {
                    user_data != WAKE_USER_DATA && user_data != REMOVE_USER_DATA
                }),
                "tracked poll user_data must avoid internal sentinel values"
            );
            reactor
                .deregister(Token::new(7))
                .expect("deregister should succeed");
        }

        #[test]
        fn test_register_invalid_fd_fails_and_does_not_track_registration() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            let invalid = RawFdSource(-1);
            let err = reactor
                .register(&invalid, Token::new(404), Interest::READABLE)
                .expect_err("invalid fd registration should fail");
            assert_eq!(err.raw_os_error(), Some(libc::EBADF));
            assert_eq!(reactor.registration_count(), 0);
        }

        #[test]
        fn test_deregister_unknown_token_returns_not_found() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            let err = reactor
                .deregister(Token::new(999))
                .expect_err("unknown token should error");
            assert_eq!(err.kind(), io::ErrorKind::NotFound);
        }

        #[test]
        fn test_modify_closed_fd_prunes_stale_registration() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            let (left, _right) = UnixStream::pair().expect("unix stream pair");
            let key = Token::new(505);
            reactor
                .register(&left, key, Interest::READABLE)
                .expect("register should succeed");
            assert_eq!(reactor.registration_count(), 1);

            drop(left);
            let err = reactor
                .modify(key, Interest::WRITABLE)
                .expect_err("modify should fail for closed fd");
            assert!(matches!(
                err.raw_os_error(),
                Some(libc::EBADF | libc::ENOENT)
            ));
            assert_eq!(
                reactor.registration_count(),
                0,
                "closed fd should be pruned from bookkeeping after failed modify"
            );

            let err = reactor
                .deregister(key)
                .expect_err("pruned registration should be absent");
            assert_eq!(err.kind(), io::ErrorKind::NotFound);
        }

        #[test]
        fn test_poll_ignores_internal_poll_remove_completions() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            reactor
                .submit_poll_remove(9090)
                .expect("poll remove submission should succeed");

            let mut events = Events::with_capacity(4);
            reactor
                .poll(&mut events, Some(Duration::ZERO))
                .expect("poll should succeed");
            assert!(
                events.is_empty(),
                "internal poll-remove completion must not surface as a user event"
            );
        }

        #[test]
        fn test_poll_ignores_cancelled_poll_cqe_for_registered_token() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            let (left, _right) = UnixStream::pair().expect("unix stream pair");
            let key = Token::new(2024);
            reactor
                .register(&left, key, Interest::READABLE)
                .expect("register should succeed");
            let active_poll_user_data =
                active_poll_user_data_for_token(&reactor, key).expect("active poll user_data");

            // Cancel the in-flight poll op for this token. io_uring reports
            // the cancelled CQE with the original token user_data.
            reactor
                .submit_poll_remove(active_poll_user_data)
                .expect("poll remove submission should succeed");

            let mut saw_error = false;
            let mut events = Events::with_capacity(8);
            for _ in 0..4 {
                reactor
                    .poll(&mut events, Some(Duration::from_millis(25)))
                    .expect("poll should succeed");
                if events
                    .iter()
                    .any(|event| event.token == key && event.ready.is_error())
                {
                    saw_error = true;
                    break;
                }
            }

            assert!(
                !saw_error,
                "canceled poll CQE must not surface as ERROR readiness for live token"
            );

            // Re-arm registration after explicit cancellation so cleanup remains valid.
            reactor
                .modify(key, Interest::READABLE)
                .expect("re-arm after cancellation should succeed");
            reactor.deregister(key).expect("deregister should succeed");
        }

        #[test]
        fn test_poll_ignores_stale_completion_for_deregistered_token() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            // Keep at least one real registration so poll() does not take the
            // empty-registrations fast path.
            let (left, _right) = UnixStream::pair().expect("unix stream pair");
            let live = Token::new(11);
            reactor
                .register(&left, live, Interest::READABLE)
                .expect("register live token should succeed");

            reactor
                .submit_poll_add(reactor.wake_fd.as_raw_fd(), Interest::READABLE, 4242)
                .expect("unknown poll add should succeed");
            reactor.wake().expect("wake should succeed");

            let mut stale_seen = false;
            let mut events = Events::with_capacity(16);
            for _ in 0..4 {
                reactor
                    .poll(&mut events, Some(Duration::from_millis(50)))
                    .expect("poll should succeed");
                if !events.is_empty() {
                    stale_seen = true;
                    break;
                }
            }

            assert!(
                !stale_seen,
                "unknown completion user_data must not surface as a user event"
            );

            reactor
                .deregister(live)
                .expect("deregister live token should succeed");
        }

        #[test]
        fn test_poll_timeout_returns_zero_events() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            let (left, _right) = UnixStream::pair().expect("unix stream pair");
            let key = Token::new(303);
            reactor
                .register(&left, key, Interest::READABLE)
                .expect("register should succeed");

            let mut events = Events::with_capacity(8);
            let count = reactor
                .poll(&mut events, Some(Duration::from_millis(10)))
                .expect("poll timeout should not error");
            assert_eq!(count, 0, "timeout poll should return zero events");
            assert!(events.is_empty(), "timeout poll should not emit events");

            reactor.deregister(key).expect("deregister should succeed");
        }

        #[test]
        fn test_modify_same_interest_while_armed_is_noop() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            let (left, _right) = UnixStream::pair().expect("unix stream pair");
            let key = Token::new(404);
            reactor
                .register(&left, key, Interest::READABLE)
                .expect("register should succeed");

            let original_user_data =
                active_poll_user_data_for_token(&reactor, key).expect("active poll user_data");
            let original_op_count = tracked_poll_op_count(&reactor);

            reactor
                .modify(key, Interest::READABLE)
                .expect("same-interest modify should succeed");

            assert_eq!(
                active_poll_user_data_for_token(&reactor, key),
                Some(original_user_data),
                "same-interest modify while already armed must not churn the in-flight poll"
            );
            assert_eq!(
                tracked_poll_op_count(&reactor),
                original_op_count,
                "same-interest modify must not create duplicate in-flight polls"
            );

            reactor.deregister(key).expect("deregister should succeed");
        }

        #[test]
        fn test_stale_completion_guard_allocator_skips_reserved_and_live_reuse() {
            let mut state = ReactorState::new();
            state.next_poll_user_data = WAKE_USER_DATA;
            state.poll_ops.insert(1, Token::new(1));

            let allocated = state
                .allocate_poll_user_data()
                .expect("allocator should skip reserved and live ids after wrap");
            assert_eq!(
                allocated, 2,
                "allocator must skip WAKE, REMOVE, zero, and live poll ids"
            );
        }

        #[test]
        fn test_stale_completion_guard_rearm_preserves_live_poll() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            let token = Token::new(606);
            let stale_user_data = 70_001;
            let live_user_data = 70_002;
            reactor.bench_seed_registration(token, Interest::READABLE, stale_user_data);

            {
                let mut state = reactor.state.lock();
                state.poll_ops.remove(&stale_user_data);
                state.poll_ops.insert(live_user_data, token);
                let info = state
                    .registrations
                    .get_mut(&token)
                    .expect("seeded registration must exist");
                info.active_poll_user_data = Some(live_user_data);
            }

            let mut events = Events::with_capacity(4);
            let emitted = reactor.bench_process_completion_batch(
                &[(stale_user_data, i32::from(libc::POLLIN))],
                &mut events,
            );
            assert_eq!(
                emitted, 0,
                "stale old poll completion must not emit readiness"
            );
            assert!(
                events.is_empty(),
                "stale old poll completion must not enqueue events"
            );
            assert_eq!(
                active_poll_user_data_for_token(&reactor, token),
                Some(live_user_data),
                "stale old poll completion must not clear the rearmed live poll"
            );
            assert_eq!(
                tracked_poll_op_count(&reactor),
                1,
                "only the rearmed live poll should remain tracked"
            );

            let emitted = reactor.bench_process_completion_batch(
                &[(live_user_data, i32::from(libc::POLLIN))],
                &mut events,
            );
            assert_eq!(
                emitted, 1,
                "live rearmed completion must still emit readiness"
            );
            assert_eq!(events.len(), 1);
            assert_eq!(events.iter().next().expect("event").token, token);
            assert_eq!(
                active_poll_user_data_for_token(&reactor, token),
                None,
                "live completion must disarm after emitting readiness"
            );
        }

        #[test]
        fn test_stale_completion_guard_unknown_preserves_live_poll_bookkeeping() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            let token = Token::new(707);
            let live_user_data = 80_001;
            let unknown_user_data = 80_002;
            reactor.bench_seed_registration(token, Interest::READABLE, live_user_data);

            let mut events = Events::with_capacity(4);
            let emitted = reactor.bench_process_completion_batch(
                &[(unknown_user_data, i32::from(libc::POLLIN))],
                &mut events,
            );
            assert_eq!(emitted, 0, "unknown completion must not emit readiness");
            assert!(
                events.is_empty(),
                "unknown completion must not enqueue events"
            );
            assert_eq!(
                active_poll_user_data_for_token(&reactor, token),
                Some(live_user_data),
                "unknown completion must not clear live registration state"
            );
            assert_eq!(
                tracked_poll_op_count(&reactor),
                1,
                "unknown completion must not perturb tracked poll count"
            );
        }

        #[test]
        fn test_poll_readiness_disarms_until_modify_rearms() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            let (left, mut right) = UnixStream::pair().expect("unix stream pair");
            let key = Token::new(5150);
            reactor
                .register(&left, key, Interest::READABLE)
                .expect("register should succeed");

            std::io::Write::write_all(&mut right, b"x").expect("write should succeed");

            let mut events = Events::with_capacity(8);
            let count = reactor
                .poll(&mut events, Some(Duration::from_millis(50)))
                .expect("poll should surface readability");
            assert_eq!(count, 1, "first readiness should surface exactly once");
            assert_eq!(
                active_poll_user_data_for_token(&reactor, key),
                None,
                "readiness completion must disarm the registration until the task rearms it"
            );

            events.clear();
            let count = reactor
                .poll(&mut events, Some(Duration::ZERO))
                .expect("disarmed poll should still succeed");
            assert_eq!(count, 0, "disarmed registration must not auto-rearm itself");
            assert!(
                events.is_empty(),
                "disarmed registration must not emit duplicate events"
            );

            reactor
                .modify(key, Interest::READABLE)
                .expect("modify should rearm the readiness source");
            assert!(
                active_poll_user_data_for_token(&reactor, key).is_some(),
                "modify should install a fresh active poll"
            );

            events.clear();
            let count = reactor
                .poll(&mut events, Some(Duration::from_millis(50)))
                .expect("rearmed poll should observe unread data");
            assert_eq!(
                count, 1,
                "rearm should surface the still-readable socket again"
            );

            reactor.deregister(key).expect("deregister should succeed");
        }

        /// br-asupersync-zft20e: regression. A concurrent wake() between
        /// store(false) and drain_wake_fd() must not be silently absorbed.
        /// We simulate the race deterministically: pre-write to eventfd to
        /// stand in for a wake whose pending flag was just set, then arrange
        /// poll() to drain it. After the cycle, wake_pending must be false
        /// (the recovery re-write triggers another wake CQE that resets it)
        /// or the eventfd must have data so the rearmed poll will fire.
        #[test]
        fn test_wake_pending_recovery_after_drain_race() {
            let Some(reactor) = new_or_skip() else {
                return;
            };
            // Manually simulate the race: set wake_pending=true and write to
            // eventfd as a "concurrent wake() that already happened". Then
            // perform the poll cycle. After the cycle either: (a) the
            // recovery code re-published a write so the next poll fires, or
            // (b) wake_pending is false so future wake() calls go through.
            // Either way no wake is silently lost.
            reactor.wake().expect("seed wake should succeed");
            let mut events = Events::with_capacity(4);
            reactor
                .poll(&mut events, Some(Duration::from_millis(50)))
                .expect("poll should consume the seeded wake");
            assert!(
                events.is_empty(),
                "wake completion must not surface as readiness"
            );
            // Now issue wake() again. With the bug, wake_pending could be
            // stuck true (if a race had absorbed a prior write). Without the
            // bug, this wake() must result in either (i) wake_pending was
            // false and now true with eventfd>0, or (ii) wake_pending was
            // already true because recovery re-wrote, in which case the
            // next poll consumes it cleanly.
            reactor.wake().expect("subsequent wake should succeed");
            events.clear();
            reactor
                .poll(&mut events, Some(Duration::from_millis(50)))
                .expect("subsequent poll should observe the wake");
            assert!(events.is_empty(), "wake completion must remain non-event");
            // Final invariant: a fresh wake must always be deliverable.
            reactor.wake().expect("final wake should succeed");
            events.clear();
            reactor
                .poll(&mut events, Some(Duration::from_millis(50)))
                .expect("final poll should not error");
            assert!(events.is_empty());
        }

        #[test]
        fn test_wake_coalesces_eventfd_notifications() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            for _ in 0..32 {
                reactor.wake().expect("wake should succeed");
            }

            let mut counter = 0_u64;
            let n = unsafe {
                libc::read(
                    reactor.wake_fd.as_raw_fd(),
                    (&raw mut counter).cast::<libc::c_void>(),
                    std::mem::size_of::<u64>(),
                )
            };
            assert_eq!(
                n,
                i32::try_from(std::mem::size_of::<u64>()).expect("u64 size fits in i32") as isize,
                "eventfd read should return a full counter"
            );
            assert_eq!(
                counter, 1,
                "multiple wake() calls should collapse into a single pending eventfd tick"
            );

            let mut events = Events::with_capacity(4);
            reactor
                .poll(&mut events, Some(Duration::ZERO))
                .expect("poll should consume stale wake completion");
            assert!(
                events.is_empty(),
                "wake completions must not surface as readiness"
            );

            reactor.wake().expect("wake after drain should succeed");
            let n = unsafe {
                libc::read(
                    reactor.wake_fd.as_raw_fd(),
                    (&raw mut counter).cast::<libc::c_void>(),
                    std::mem::size_of::<u64>(),
                )
            };
            assert_eq!(
                n,
                i32::try_from(std::mem::size_of::<u64>()).expect("u64 size fits in i32") as isize,
                "eventfd read should still succeed after drain"
            );
            assert_eq!(
                counter, 1,
                "reactor must remain wakeable after clearing the pending flag"
            );
        }

        #[test]
        fn test_rearm_wake_poll_flushes_full_submission_queue() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            {
                let mut ring = reactor.ring.lock();
                fill_submission_queue(&mut ring);
            }

            reactor
                .rearm_wake_poll()
                .expect("wake rearm should flush and retry when the SQ is full");

            let mut events = Events::with_capacity(8);
            reactor
                .poll(&mut events, Some(Duration::ZERO))
                .expect("poll should drain synthetic SQEs after wake rearm");
            assert!(
                events.is_empty(),
                "synthetic NOP completions must not surface as readiness"
            );
        }

        #[test]
        fn test_submit_poll_add_flushes_full_submission_queue() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            {
                let mut ring = reactor.ring.lock();
                fill_submission_queue(&mut ring);
            }

            let (left, mut right) = UnixStream::pair().expect("unix stream pair");
            reactor
                .submit_poll_add(left.as_raw_fd(), Interest::READABLE, 77_777)
                .expect("poll add should flush and retry when the SQ is full");
            std::io::Write::write_all(&mut right, b"x").expect("write should succeed");

            let mut events = Events::with_capacity(8);
            reactor
                .poll(&mut events, Some(Duration::from_millis(50)))
                .expect("poll should drain synthetic SQEs after poll add retry");
            assert!(
                events.is_empty(),
                "unknown completion user_data must not surface as readiness"
            );
        }

        #[test]
        fn test_submit_poll_remove_flushes_full_submission_queue() {
            let Some(reactor) = new_or_skip() else {
                return;
            };

            {
                let mut ring = reactor.ring.lock();
                fill_submission_queue(&mut ring);
            }

            reactor
                .submit_poll_remove(90_909)
                .expect("poll remove should flush and retry when the SQ is full");

            let mut events = Events::with_capacity(8);
            reactor
                .poll(&mut events, Some(Duration::ZERO))
                .expect("poll should drain synthetic SQEs after poll remove retry");
            assert!(
                events.is_empty(),
                "synthetic poll-remove completions must not surface as readiness"
            );
        }
    }
}

#[cfg(all(any(target_os = "linux", target_os = "android"), feature = "io-uring"))]
pub use imp::IoUringReactor;

#[cfg(not(all(any(target_os = "linux", target_os = "android"), feature = "io-uring")))]
mod imp {
    use super::super::{Events, Interest, Reactor, Source, Token};
    use std::io;

    const UNSUPPORTED_MESSAGE: &str = "IoUringReactor requires Linux or Android with the io-uring feature enabled; use create_reactor() for epoll fallback";

    fn unsupported() -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, UNSUPPORTED_MESSAGE)
    }

    /// Unsupported fallback for builds without the live io_uring backend.
    ///
    /// In the public `runtime::reactor` export graph this matters for Linux/Android
    /// builds without the `io-uring` feature. Other targets do not
    /// re-export `IoUringReactor` from `runtime::reactor`.
    #[derive(Debug, Default)]
    pub struct IoUringReactor;

    impl IoUringReactor {
        /// Create a new io_uring reactor.
        ///
        /// # Errors
        ///
        /// Returns `Unsupported` unless the build target is Linux or Android and the
        /// `io-uring` feature is enabled.
        pub fn new() -> io::Result<Self> {
            Err(unsupported())
        }
    }

    impl Reactor for IoUringReactor {
        fn register(
            &self,
            _source: &dyn Source,
            _token: Token,
            _interest: Interest,
        ) -> io::Result<()> {
            Err(unsupported())
        }

        fn modify(&self, _token: Token, _interest: Interest) -> io::Result<()> {
            Err(unsupported())
        }

        fn deregister(&self, _token: Token) -> io::Result<()> {
            Err(unsupported())
        }

        fn poll(
            &self,
            _events: &mut Events,
            _timeout: Option<std::time::Duration>,
        ) -> io::Result<usize> {
            Err(unsupported())
        }

        fn wake(&self) -> io::Result<()> {
            Err(unsupported())
        }

        fn registration_count(&self) -> usize {
            0
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[cfg(unix)]
        use std::os::unix::net::UnixStream;

        fn assert_unsupported_contract(err: &io::Error) {
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
            assert_eq!(err.to_string(), UNSUPPORTED_MESSAGE);
        }

        #[test]
        fn test_new_unsupported_returns_error() {
            let err = IoUringReactor::new().expect_err("io_uring should be unsupported");
            assert_unsupported_contract(&err);
        }

        #[test]
        fn test_cfg_off_contract_message_is_explicit() {
            let err = IoUringReactor::new().expect_err("cfg-off contract should be explicit");
            assert_unsupported_contract(&err);
        }

        #[cfg(unix)]
        #[test]
        fn test_register_modify_deregister_unsupported() {
            let reactor = IoUringReactor;
            let (left, _right) = UnixStream::pair().expect("unix stream pair");

            let err = reactor
                .register(&left, Token::new(1), Interest::READABLE)
                .expect_err("register should be unsupported");
            assert_unsupported_contract(&err);

            let err = reactor
                .modify(Token::new(1), Interest::WRITABLE)
                .expect_err("modify should be unsupported");
            assert_unsupported_contract(&err);

            let err = reactor
                .deregister(Token::new(1))
                .expect_err("deregister should be unsupported");
            assert_unsupported_contract(&err);
        }

        #[test]
        fn test_poll_and_wake_unsupported() {
            let reactor = IoUringReactor;
            let mut events = Events::with_capacity(4);

            let err = reactor
                .poll(&mut events, None)
                .expect_err("poll should be unsupported");
            assert_unsupported_contract(&err);

            let err = reactor.wake().expect_err("wake should be unsupported");
            assert_unsupported_contract(&err);
        }

        #[test]
        fn test_registration_count_zero() {
            let reactor = IoUringReactor;
            assert_eq!(reactor.registration_count(), 0);
        }
    }
}

#[cfg(not(all(any(target_os = "linux", target_os = "android"), feature = "io-uring")))]
pub use imp::IoUringReactor;
