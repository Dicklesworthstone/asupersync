//! io_uring-based reactor implementation (Linux only, feature-gated).
//!
//! This reactor uses io_uring's PollAdd opcode to provide readiness notifications.
//! Poll operations are one-shot by default, so we re-arm after each completion
//! unless ONESHOT is requested.
//!
//! NOTE: This module uses unsafe to submit SQEs and manage eventfd FDs.
//! The safety invariants are documented inline.

#[cfg(all(target_os = "linux", feature = "io-uring"))]
mod imp {
    #![allow(unsafe_code)]
    #![allow(clippy::significant_drop_tightening)]
    #![allow(clippy::significant_drop_in_scrutinee)]
    #![allow(clippy::cast_sign_loss)]

    use super::super::{Event, Events, Interest, Reactor, Source, Token};
    use io_uring::{opcode, types, IoUring};
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::time::Duration;

    const DEFAULT_ENTRIES: u32 = 256;
    const WAKE_USER_DATA: u64 = u64::MAX;
    const REMOVE_USER_DATA: u64 = u64::MAX - 1;

    #[derive(Debug, Clone, Copy)]
    struct RegistrationInfo {
        raw_fd: RawFd,
        interest: Interest,
    }

    /// io_uring-based reactor.
    pub struct IoUringReactor {
        ring: Mutex<IoUring>,
        registrations: Mutex<HashMap<Token, RegistrationInfo>>,
        wake_fd: OwnedFd,
    }

    impl std::fmt::Debug for IoUringReactor {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("IoUringReactor")
                .field("registrations", &self.registrations)
                .field("wake_fd", &self.wake_fd)
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
                registrations: Mutex::new(HashMap::new()),
                wake_fd,
            })
        }

        fn submit_poll_add(
            &self,
            token: Token,
            raw_fd: RawFd,
            interest: Interest,
        ) -> io::Result<()> {
            let mut ring = self.ring.lock();
            submit_poll_entry(&mut ring, raw_fd, interest, token.0 as u64)?;
            ring.submit()?;
            Ok(())
        }

        fn submit_poll_remove(&self, token: Token) -> io::Result<()> {
            let mut ring = self.ring.lock();
            let entry = opcode::PollRemove::new(token.0 as u64)
                .build()
                .user_data(REMOVE_USER_DATA);
            // SAFETY: PollRemove takes ownership of user_data only; no external buffers.
            unsafe {
                ring.submission().push(&entry).map_err(push_error_to_io)?;
            }
            ring.submit()?;
            Ok(())
        }

        fn rearm_poll(&self, token: Token, info: RegistrationInfo) -> io::Result<()> {
            if info.interest.is_oneshot() {
                return Ok(());
            }
            self.submit_poll_add(token, info.raw_fd, info.interest)
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
    }

    impl Reactor for IoUringReactor {
        fn register(
            &self,
            source: &dyn Source,
            token: Token,
            interest: Interest,
        ) -> io::Result<()> {
            let raw_fd = source.as_raw_fd();
            let mut regs = self.registrations.lock();
            if regs.contains_key(&token) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "token already registered",
                ));
            }
            regs.insert(token, RegistrationInfo { raw_fd, interest });
            drop(regs);

            self.submit_poll_add(token, raw_fd, interest)
        }

        fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
            {
                let mut regs = self.registrations.lock();
                let info = regs.get_mut(&token).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "token not registered")
                })?;
                info.interest = interest;
            }

            // Best-effort remove existing poll, then re-add with new interest.
            let _ = self.submit_poll_remove(token);
            let raw_fd = {
                let regs = self.registrations.lock();
                regs.get(&token).map(|info| info.raw_fd).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "token not registered")
                })?
            };
            self.submit_poll_add(token, raw_fd, interest)
        }

        fn deregister(&self, token: Token) -> io::Result<()> {
            let existed = {
                let mut regs = self.registrations.lock();
                regs.remove(&token)
            };
            if existed.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "token not registered",
                ));
            }
            let _ = self.submit_poll_remove(token);
            Ok(())
        }

        fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
            events.clear();

            let mut ring = self.ring.lock();

            // If no registrations and no timeout, avoid blocking forever.
            if self.registrations.lock().is_empty() {
                ring.submit()?;
                return Ok(0);
            }

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
                    ring.submitter().submit_with_args(1, &args)?;
                }
            }

            let mut completions = Vec::new();
            for cqe in ring.completion() {
                completions.push((cqe.user_data(), cqe.result()));
            }

            drop(ring);

            for (user_data, res) in completions {
                if user_data == WAKE_USER_DATA {
                    self.drain_wake_fd();
                    let mut ring = self.ring.lock();
                    let _ = submit_poll_entry(
                        &mut ring,
                        self.wake_fd.as_raw_fd(),
                        Interest::READABLE,
                        WAKE_USER_DATA,
                    );
                    let _ = ring.submit();
                    continue;
                }

                let token = Token::new(user_data as usize);
                let interest = if res >= 0 {
                    poll_mask_to_interest(res as u32)
                } else {
                    Interest::ERROR
                };

                if !interest.is_empty() {
                    events.push(Event::new(token, interest));
                }

                if let Some(info) = self.registrations.lock().get(&token).copied() {
                    let _ = self.rearm_poll(token, info);
                }
            }

            Ok(events.len())
        }

        fn wake(&self) -> io::Result<()> {
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
            Err(err)
        }

        fn registration_count(&self) -> usize {
            self.registrations.lock().len()
        }
    }

    fn submit_poll_entry(
        ring: &mut IoUring,
        raw_fd: RawFd,
        interest: Interest,
        user_data: u64,
    ) -> io::Result<()> {
        let mask = interest_to_poll_mask(interest);
        let entry = opcode::PollAdd::new(types::Fd(raw_fd), mask)
            .build()
            .user_data(user_data);

        // SAFETY: PollAdd only uses the fd and interest mask; both remain valid
        // for the duration of the poll request (caller ensures fd lifetime).
        unsafe {
            ring.submission().push(&entry).map_err(push_error_to_io)?;
        }
        Ok(())
    }

    fn interest_to_poll_mask(interest: Interest) -> u32 {
        let mut mask = 0u32;
        if interest.is_readable() {
            mask |= libc::POLLIN as u32;
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
        interest
    }

    fn push_error_to_io(_err: io_uring::squeue::PushError) -> io::Error {
        io::Error::new(io::ErrorKind::WouldBlock, "submission queue full")
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
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub use imp::IoUringReactor;

#[cfg(not(all(target_os = "linux", feature = "io-uring")))]
mod imp {
    use super::super::{Events, Interest, Reactor, Source, Token};
    use std::io;

    /// Stub io_uring reactor for non-Linux or when feature is disabled.
    #[derive(Debug, Default)]
    pub struct IoUringReactor;

    impl IoUringReactor {
        /// Create a new io_uring reactor (unsupported on this platform/config).
        pub fn new() -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IoUringReactor is not available (linux + io-uring feature required)",
            ))
        }
    }

    impl Reactor for IoUringReactor {
        fn register(
            &self,
            _source: &dyn Source,
            _token: Token,
            _interest: Interest,
        ) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IoUringReactor is not available (linux + io-uring feature required)",
            ))
        }

        fn modify(&self, _token: Token, _interest: Interest) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IoUringReactor is not available (linux + io-uring feature required)",
            ))
        }

        fn deregister(&self, _token: Token) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IoUringReactor is not available (linux + io-uring feature required)",
            ))
        }

        fn poll(
            &self,
            _events: &mut Events,
            _timeout: Option<std::time::Duration>,
        ) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IoUringReactor is not available (linux + io-uring feature required)",
            ))
        }

        fn wake(&self) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IoUringReactor is not available (linux + io-uring feature required)",
            ))
        }

        fn registration_count(&self) -> usize {
            0
        }
    }
}

#[cfg(not(all(target_os = "linux", feature = "io-uring")))]
pub use imp::IoUringReactor;
