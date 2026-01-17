//! Transport layer abstraction.
//!
//! This module defines the core traits for sending and receiving symbols
//! across different transport mechanisms (TCP, UDP, in-memory, etc.).

pub mod error;
pub mod sink;
pub mod stream;
mod tests;

pub use error::{SinkError, StreamError};
pub use sink::{SymbolSink, SymbolSinkExt};
pub use stream::{SymbolStream, SymbolStreamExt};

use crate::security::authenticated::AuthenticatedSymbol;
use crate::types::Symbol;
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::task::Waker;

/// A set of unique symbols.
pub type SymbolSet = HashSet<Symbol>;

/// Shared state for in-memory channel.
#[derive(Debug)]
pub(crate) struct SharedChannel {
    pub queue: Mutex<VecDeque<AuthenticatedSymbol>>,
    pub capacity: usize,
    pub send_wakers: Mutex<Vec<Waker>>,
    pub recv_wakers: Mutex<Vec<Waker>>,
    pub closed: std::sync::atomic::AtomicBool,
}

impl SharedChannel {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            capacity,
            send_wakers: Mutex::new(Vec::new()),
            recv_wakers: Mutex::new(Vec::new()),
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        // Wake everyone
        {
            let mut wakers = self.send_wakers.lock().unwrap();
            for w in wakers.drain(..) { w.wake(); }
        }
        {
            let mut wakers = self.recv_wakers.lock().unwrap();
            for w in wakers.drain(..) { w.wake(); }
        }
    }
}

/// Create a connected in-memory channel pair.
#[must_use]
pub fn channel(capacity: usize) -> (sink::ChannelSink, stream::ChannelStream) {
    let shared = Arc::new(SharedChannel::new(capacity));
    (
        sink::ChannelSink::new(shared.clone()),
        stream::ChannelStream::new(shared),
    )
}