//! I/O driver that runs the reactor.

use crate::runtime::reactor::{Events, Reactor};
use slab::Slab;
use std::io;
use std::task::Waker;
use std::time::Duration;

/// Driver for I/O event loop.
pub struct IoDriver {
    reactor: Box<dyn Reactor>,
    registrations: Slab<Waker>,
}

impl IoDriver {
    /// Creates a new I/O driver.
    #[must_use]
    pub fn new(reactor: Box<dyn Reactor>) -> Self {
        Self {
            reactor,
            registrations: Slab::new(),
        }
    }

    /// Registers a waker and returns a token key.
    pub fn register_waker(&mut self, waker: Waker) -> usize {
        self.registrations.insert(waker)
    }

    /// Deregisters a waker.
    pub fn deregister_waker(&mut self, key: usize) {
        if self.registrations.contains(key) {
            self.registrations.remove(key);
        }
    }

    /// Runs one turn of the reactor.
    pub fn turn(&mut self, timeout: Option<Duration>) -> io::Result<usize> {
        let mut events = Events::with_capacity(1024);
        let n = self.reactor.poll(&mut events, timeout)?;

        for event in events {
            // The token value corresponds to the slab index
            if let Some(waker) = self.registrations.get(event.token.0) {
                waker.wake_by_ref();
            }
        }

        Ok(n)
    }
}
