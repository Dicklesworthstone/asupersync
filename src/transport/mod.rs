//! Transport layer abstraction.
//!
//! This module defines the core traits for sending and receiving symbols
//! across different transport mechanisms (TCP, UDP, in-memory, etc.).

pub mod aggregator;
#[cfg(any(test, feature = "test-internals"))]
#[path = "mo\u{63}k.rs"]
pub mod deterministic;
pub mod error;
#[cfg(any(test, feature = "test-internals"))]
pub mod half_close_conformance_tests;
pub mod router;
pub mod sink;
pub mod stream;
#[cfg(test)]
mod tests;

pub use aggregator::{
    AggregatorConfig, AggregatorStats, DeduplicatorConfig, DeduplicatorStats,
    ExperimentalTransportDowngradeReason, ExperimentalTransportGate, MultipathAggregator,
    PathCharacteristics, PathId, PathSelectionDecision, PathSelectionDowngradeReason,
    PathSelectionPolicy, PathSet, PathSetStats, PathState, ProcessResult, ReordererConfig,
    ReordererStats, SymbolDeduplicator, SymbolReorderer, TransportCodingPolicy,
    TransportExperimentContext, TransportExperimentDecision, TransportPath,
};
#[cfg(any(test, feature = "test-internals"))]
pub use deterministic::{
    NodeId, SimChannelSink, SimChannelStream, SimLink, SimNetwork, SimSymbolSink, SimSymbolStream,
    SimTransportConfig, sim_channel,
};
pub use error::{SinkError, StreamError};
pub use router::{
    BoundedLoadConfig, BoundedLoadDecision, BoundedLoadEndpointTelemetry,
    BoundedLoadRebalanceReason, DispatchConfig, DispatchError, DispatchResult, DispatchStrategy,
    Endpoint, EndpointId, EndpointState, LoadBalanceStrategy, LoadBalancer, RouteKey, RouteResult,
    RoutingEntry, RoutingError, RoutingTable, SymbolDispatcher, SymbolRouter,
};
pub use sink::{MultipathPathStats, MultipathPendingSymbol, MultipathSink, SymbolSink, SymbolSinkExt};
pub use stream::{SymbolStream, SymbolStreamExt};

use crate::security::authenticated::AuthenticatedSymbol;
use crate::types::Symbol;
use parking_lot::Mutex;
use smallvec::SmallVec;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    pub send_wakers: Mutex<SmallVec<[ChannelWaiter; 2]>>,
    pub recv_wakers: Mutex<SmallVec<[ChannelWaiter; 2]>>,
    pub closed: AtomicBool,
}

impl SharedChannel {
    pub(crate) fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "transport::channel capacity must be > 0");
        Self {
            queue: Mutex::new(VecDeque::new()),
            capacity,
            send_wakers: Mutex::new(SmallVec::new()),
            recv_wakers: Mutex::new(SmallVec::new()),
            closed: AtomicBool::new(false),
        }
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        // Wake everyone (drop locks before waking to avoid deadlocks).
        let send_wakers = {
            let mut wakers = self.send_wakers.lock();
            std::mem::take(&mut *wakers)
        };
        let recv_wakers = {
            let mut wakers = self.recv_wakers.lock();
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
///
/// # Panics
///
/// Panics if `capacity == 0`. Zero-capacity rendezvous semantics are not
/// currently supported by this transport channel.
#[must_use]
pub fn channel(capacity: usize) -> (sink::ChannelSink, stream::ChannelStream) {
    let shared = Arc::new(SharedChannel::new(capacity));
    (
        sink::ChannelSink::new(shared.clone()),
        stream::ChannelStream::new(shared),
    )
}

#[cfg(test)]
#[path = "mod_inline_tests_inline_tests.rs"]
mod inline_tests;
