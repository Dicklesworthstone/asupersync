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
    sim_channel, NodeId, SimChannelSink, SimChannelStream, SimLink, SimNetwork, SimSymbolSink,
    SimSymbolStream, SimTransportConfig,
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
use parking_lot::Mutex;
use smallvec::SmallVec;
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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
        self.closed.store(true, Ordering::SeqCst);
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
mod inline_tests {
    use super::*;
    use crate::security::authenticated::AuthenticatedSymbol;
    use crate::security::tag::AuthenticationTag;
    use crate::transport::{SymbolSinkExt, SymbolStreamExt};
    use crate::types::{Symbol, SymbolId, SymbolKind};
    use futures_lite::future;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::task::{Wake, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn create_symbol(esi: u32) -> AuthenticatedSymbol {
        let id = SymbolId::new_for_test(1, 0, esi);
        let symbol = Symbol::new(id, vec![esi as u8], SymbolKind::Source);
        let tag = AuthenticationTag::zero();
        AuthenticatedSymbol::new_verified(symbol, tag)
    }

    struct FlagWake {
        flag: Arc<AtomicBool>,
    }

    impl Wake for FlagWake {
        fn wake(self: Arc<Self>) {
            self.flag.store(true, Ordering::SeqCst);
        }
    }

    fn flagged_waker(flag: Arc<AtomicBool>) -> Waker {
        Waker::from(Arc::new(FlagWake { flag }))
    }

    #[test]
    fn test_channel_round_trip_and_close() {
        init_test("test_channel_round_trip_and_close");
        let (mut sink, mut stream) = channel(2);
        let s1 = create_symbol(1);
        let s2 = create_symbol(2);

        future::block_on(async {
            sink.send(s1.clone()).await.unwrap();
            sink.send(s2.clone()).await.unwrap();
            sink.close().await.unwrap();

            let r1 = stream.next().await.unwrap().unwrap();
            let r2 = stream.next().await.unwrap().unwrap();
            crate::assert_with_log!(r1 == s1, "first symbol", true, r1 == s1);
            crate::assert_with_log!(r2 == s2, "second symbol", true, r2 == s2);
            crate::assert_with_log!(stream.next().await.is_none(), "stream closed", true, true);
        });

        crate::test_complete!("test_channel_round_trip_and_close");
    }

    #[test]
    fn test_shared_channel_close_wakes_waiters() {
        init_test("test_shared_channel_close_wakes_waiters");
        let shared = SharedChannel::new(1);

        let send_flag = Arc::new(AtomicBool::new(false));
        let recv_flag = Arc::new(AtomicBool::new(false));
        let send_queued = Arc::new(AtomicBool::new(true));
        let recv_queued = Arc::new(AtomicBool::new(true));

        {
            let mut send_wakers = shared.send_wakers.lock();
            send_wakers.push(ChannelWaiter {
                waker: flagged_waker(Arc::clone(&send_flag)),
                queued: Arc::clone(&send_queued),
            });
        }

        {
            let mut recv_wakers = shared.recv_wakers.lock();
            recv_wakers.push(ChannelWaiter {
                waker: flagged_waker(Arc::clone(&recv_flag)),
                queued: Arc::clone(&recv_queued),
            });
        }

        shared.close();

        crate::assert_with_log!(
            shared.closed.load(Ordering::SeqCst),
            "closed flag set",
            true,
            shared.closed.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            !send_queued.load(Ordering::Acquire),
            "send queued cleared",
            false,
            send_queued.load(Ordering::Acquire)
        );
        crate::assert_with_log!(
            !recv_queued.load(Ordering::Acquire),
            "recv queued cleared",
            false,
            recv_queued.load(Ordering::Acquire)
        );
        crate::assert_with_log!(
            send_flag.load(Ordering::Acquire),
            "send waker fired",
            true,
            send_flag.load(Ordering::Acquire)
        );
        crate::assert_with_log!(
            recv_flag.load(Ordering::Acquire),
            "recv waker fired",
            true,
            recv_flag.load(Ordering::Acquire)
        );

        crate::test_complete!("test_shared_channel_close_wakes_waiters");
    }

    #[test]
    #[should_panic(expected = "transport::channel capacity must be > 0")]
    fn test_channel_zero_capacity_panics() {
        let _ = channel(0);
    }
}
