//! Windows IOCP reactor implementation.
//!
//! On Windows, the reactor uses the `polling` crate's IOCP backend. While IOCP
//! is completion-based rather than readiness-based, the `polling` abstraction
//! exposes readiness-style events that are compatible with the runtime.

// Windows implementation.
#[cfg(target_os = "windows")]
mod iocp_impl {
    use super::{Event, Events, Interest, Reactor, Source, Token};
    use parking_lot::Mutex;
    use polling::{Event as PollEvent, Poller};
    use std::collections::HashMap;
    use std::io;
    use std::os::windows::io::RawSocket;
    use std::time::Duration;

    /// Registration state for a source.
    #[derive(Debug)]
    struct RegistrationInfo {
        raw_socket: RawSocket,
        interest: Interest,
    }

    /// IOCP-based reactor (Windows).
    pub struct IocpReactor {
        poller: Poller,
        registrations: Mutex<HashMap<Token, RegistrationInfo>>,
    }

    impl IocpReactor {
        /// Create a new IOCP reactor.
        pub fn new() -> io::Result<Self> {
            let poller = Poller::new()?;
            Ok(Self {
                poller,
                registrations: Mutex::new(HashMap::new()),
            })
        }

        fn interest_to_poll_event(token: Token, interest: Interest) -> PollEvent {
            let key = token.0;
            let readable = interest.is_readable();
            let writable = interest.is_writable();

            match (readable, writable) {
                (true, true) => PollEvent::all(key),
                (true, false) => PollEvent::readable(key),
                (false, true) => PollEvent::writable(key),
                (false, false) => PollEvent::none(key),
            }
        }

        fn poll_event_to_interest(event: &PollEvent) -> Interest {
            let mut interest = Interest::NONE;

            if event.readable {
                interest = interest.add(Interest::READABLE);
            }
            if event.writable {
                interest = interest.add(Interest::WRITABLE);
            }

            interest
        }
    }

    impl Reactor for IocpReactor {
        fn register(
            &self,
            source: &dyn Source,
            token: Token,
            interest: Interest,
        ) -> io::Result<()> {
            let raw_socket = source.raw_socket();

            let mut regs = self.registrations.lock();
            if regs.contains_key(&token) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "token already registered",
                ));
            }

            let event = Self::interest_to_poll_event(token, interest);
            self.poller.add(raw_socket, event)?;

            regs.insert(
                token,
                RegistrationInfo {
                    raw_socket,
                    interest,
                },
            );

            Ok(())
        }

        fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
            let mut regs = self.registrations.lock();
            let info = regs
                .get_mut(&token)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "token not registered"))?;

            let event = Self::interest_to_poll_event(token, interest);
            self.poller.modify(info.raw_socket, event)?;
            info.interest = interest;

            Ok(())
        }

        fn deregister(&self, token: Token) -> io::Result<()> {
            let mut regs = self.registrations.lock();
            let info = regs
                .remove(&token)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "token not registered"))?;
            self.poller.delete(info.raw_socket)?;
            Ok(())
        }

        fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
            let mut poll_events = Vec::with_capacity(events.capacity());
            self.poller.wait(&mut poll_events, timeout)?;

            let mut count = 0;
            for poll_event in &poll_events {
                let token = Token(poll_event.key);
                let interest = Self::poll_event_to_interest(poll_event);
                events.push(Event::new(token, interest));
                count += 1;
            }

            Ok(count)
        }

        fn wake(&self) -> io::Result<()> {
            self.poller.notify()
        }

        fn registration_count(&self) -> usize {
            self.registrations.lock().len()
        }
    }

    impl std::fmt::Debug for IocpReactor {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let reg_count = self.registrations.lock().len();
            f.debug_struct("IocpReactor")
                .field("registration_count", &reg_count)
                .finish_non_exhaustive()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_interest_to_poll_event_and_back_roundtrip() {
            let token = Token::new(9);
            let interest = Interest::READABLE.add(Interest::WRITABLE);
            let event = IocpReactor::interest_to_poll_event(token, interest);
            let roundtrip = IocpReactor::poll_event_to_interest(&event);
            assert!(roundtrip.is_readable());
            assert!(roundtrip.is_writable());
        }

        #[test]
        fn test_interest_to_poll_event_none_is_empty() {
            let token = Token::new(1);
            let event = IocpReactor::interest_to_poll_event(token, Interest::NONE);
            let roundtrip = IocpReactor::poll_event_to_interest(&event);
            assert!(roundtrip.is_empty());
        }
    }
}

// Stub for non-Windows platforms (keeps docs/builds consistent).
#[cfg(not(target_os = "windows"))]
mod stub {
    use super::{Events, Interest, Reactor, Source, Token};
    use std::io;
    use std::time::Duration;

    /// IOCP-based reactor (Windows-only).
    #[derive(Debug, Default)]
    pub struct IocpReactor;

    impl IocpReactor {
        /// Create a new IOCP reactor.
        ///
        /// # Errors
        ///
        /// Always returns `Unsupported` on non-Windows platforms.
        pub fn new() -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IocpReactor is only available on Windows",
            ))
        }
    }

    impl Reactor for IocpReactor {
        fn register(
            &self,
            _source: &dyn Source,
            _token: Token,
            _interest: Interest,
        ) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IocpReactor is only available on Windows",
            ))
        }

        fn modify(&self, _token: Token, _interest: Interest) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IocpReactor is only available on Windows",
            ))
        }

        fn deregister(&self, _token: Token) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IocpReactor is only available on Windows",
            ))
        }

        fn poll(&self, _events: &mut Events, _timeout: Option<Duration>) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IocpReactor is only available on Windows",
            ))
        }

        fn wake(&self) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IocpReactor is only available on Windows",
            ))
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

        #[test]
        fn test_new_unsupported_returns_error() {
            let err = IocpReactor::new().expect_err("iocp should be unsupported");
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        }

        #[cfg(unix)]
        #[test]
        fn test_register_modify_deregister_unsupported() {
            let reactor = IocpReactor::default();
            let (left, _right) = UnixStream::pair().expect("unix stream pair");

            let err = reactor
                .register(&left, Token::new(1), Interest::READABLE)
                .expect_err("register should be unsupported");
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);

            let err = reactor
                .modify(Token::new(1), Interest::WRITABLE)
                .expect_err("modify should be unsupported");
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);

            let err = reactor
                .deregister(Token::new(1))
                .expect_err("deregister should be unsupported");
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        }

        #[test]
        fn test_poll_and_wake_unsupported() {
            let reactor = IocpReactor::default();
            let mut events = Events::with_capacity(2);

            let err = reactor
                .poll(&mut events, None)
                .expect_err("poll should be unsupported");
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);

            let err = reactor.wake().expect_err("wake should be unsupported");
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        }

        #[test]
        fn test_registration_count_zero() {
            let reactor = IocpReactor::default();
            assert_eq!(reactor.registration_count(), 0);
        }
    }
}

#[cfg(target_os = "windows")]
pub use iocp_impl::IocpReactor;

#[cfg(not(target_os = "windows"))]
pub use stub::IocpReactor;
