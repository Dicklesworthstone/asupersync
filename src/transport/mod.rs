//! Transport layer abstraction.
//!
//! This module defines the core traits for sending and receiving symbols
//! across different transport mechanisms (TCP, UDP, in-memory, etc.).

pub mod aggregator;
pub mod error;
pub mod mock;
pub mod router;
pub mod sink;
pub mod stream;
mod tests;

pub use aggregator::{
    AggregatorConfig, AggregatorStats, DeduplicatorConfig, DeduplicatorStats, MultipathAggregator,
    PathCharacteristics, PathId, PathSelectionPolicy, PathSet, PathSetStats, PathState,
    ProcessResult, ReordererConfig, ReordererStats, SymbolDeduplicator, SymbolReorderer,
    TransportPath,
};
pub use error::{SinkError, StreamError};
pub use mock::{
    mock_channel, MockChannelSink, MockChannelStream, MockLink, MockNetwork, MockSymbolSink,
    MockSymbolStream, MockTransportConfig, NodeId,
};
pub use router::{
    DispatchConfig, DispatchError, DispatchResult, DispatchStrategy, Endpoint, EndpointId,
    EndpointState, LoadBalanceStrategy, LoadBalancer, RouteKey, RouteResult, RoutingEntry,
    RoutingError, RoutingTable, SymbolDispatcher, SymbolRouter,
};
pub use sink::{SymbolSink, SymbolSinkExt};
pub use stream::{SymbolStream, SymbolStreamExt};

use crate::security::authenticated::AuthenticatedSymbol;
use crate::types::Symbol;
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Waker;

/// A set of unique symbols.
pub type SymbolSet = HashSet<Symbol>;

/// A waiter entry with tracking flag to prevent unbounded queue growth.
#[derive(Debug)]
pub(crate) struct ChannelWaiter {
    pub waker: Waker,
    /// Flag indicating if this waiter is still queued. When woken, this is set to false.
    pub queued: Arc<AtomicBool>,
}

/// Shared state for in-memory channel.
#[derive(Debug)]
pub(crate) struct SharedChannel {
    pub queue: Mutex<VecDeque<AuthenticatedSymbol>>,
    pub capacity: usize,
    pub send_wakers: Mutex<Vec<ChannelWaiter>>,
    pub recv_wakers: Mutex<Vec<ChannelWaiter>>,
    pub closed: AtomicBool,
}

impl SharedChannel {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            capacity,
            send_wakers: Mutex::new(Vec::new()),
            recv_wakers: Mutex::new(Vec::new()),
            closed: AtomicBool::new(false),
        }
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // Wake everyone (drop locks before waking to avoid deadlocks).
        let send_wakers = {
            let mut wakers = self.send_wakers.lock().unwrap();
            std::mem::take(&mut *wakers)
        };
        let recv_wakers = {
            let mut wakers = self.recv_wakers.lock().unwrap();
            std::mem::take(&mut *wakers)
        };

        for w in send_wakers {
            w.queued.store(false, Ordering::Release);
            w.waker.wake();
        }
        for w in recv_wakers {
            w.queued.store(false, Ordering::Release);
            w.waker.wake();
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
