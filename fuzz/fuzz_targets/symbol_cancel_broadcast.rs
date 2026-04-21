//! Broadcast cancellation fuzz target.
//!
//! Exercises `CancelBroadcaster` propagation with adversarial subscriber sets to
//! verify that cancellation settles once per subscriber, duplicate deliveries do
//! not replay listeners, and children created before or after cancellation
//! observe the expected terminal state.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::cancel::{CancelBroadcaster, CancelMessage, CancelSink, PeerId, SymbolCancelToken};
use asupersync::types::symbol::ObjectId;
use asupersync::types::{CancelKind, CancelReason, Time};
use asupersync::util::DetRng;
use libfuzzer_sys::fuzz_target;
use std::future::ready;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const MAX_PEERS: usize = 8;
const MAX_CHILDREN: usize = 4;
const MAX_DELIVERIES: usize = 64;

#[derive(Arbitrary, Debug)]
struct SymbolCancelBroadcastInput {
    seed: u64,
    object_value: u64,
    peer_count: u8,
    registered_mask: u8,
    child_count: u8,
    max_hops: u8,
    reason: FuzzReason,
    deliveries: Vec<Delivery>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzReason {
    User,
    Timeout,
    Deadline,
    FailFast,
    ResourceUnavailable,
    Shutdown,
}

impl FuzzReason {
    fn into_reason(self) -> CancelReason {
        match self {
            Self::User => CancelReason::user("fuzz-user"),
            Self::Timeout => CancelReason::timeout(),
            Self::Deadline => CancelReason::deadline(),
            Self::FailFast => CancelReason::fail_fast(),
            Self::ResourceUnavailable => CancelReason::resource_unavailable(),
            Self::Shutdown => CancelReason::shutdown(),
        }
    }

    const fn kind(self) -> CancelKind {
        match self {
            Self::User => CancelKind::User,
            Self::Timeout => CancelKind::Timeout,
            Self::Deadline => CancelKind::Deadline,
            Self::FailFast => CancelKind::FailFast,
            Self::ResourceUnavailable => CancelKind::ResourceUnavailable,
            Self::Shutdown => CancelKind::Shutdown,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum DeliveryMode {
    Direct,
    WireRoundTrip,
    Duplicate,
    Forwarded,
    MaxHops,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct Delivery {
    peer_index: u8,
    mode: DeliveryMode,
    receive_at_ms: u16,
}

#[derive(Default)]
struct NoopSink;

impl CancelSink for NoopSink {
    fn send_to(
        &self,
        _peer: &PeerId,
        _msg: &CancelMessage,
    ) -> impl std::future::Future<Output = asupersync::error::Result<()>> + Send {
        ready(Ok(()))
    }

    fn broadcast(
        &self,
        _msg: &CancelMessage,
    ) -> impl std::future::Future<Output = asupersync::error::Result<usize>> + Send {
        ready(Ok(0))
    }
}

struct PeerState {
    broadcaster: CancelBroadcaster<NoopSink>,
    root: Option<SymbolCancelToken>,
    root_hits: Arc<AtomicUsize>,
    child_tokens: Vec<SymbolCancelToken>,
    child_hits: Vec<Arc<AtomicUsize>>,
    late_seed: u64,
}

fn attach_listener_counter(token: &SymbolCancelToken) -> Arc<AtomicUsize> {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    token.add_listener(move |_reason: &CancelReason, _at: Time| {
        hits_clone.fetch_add(1, Ordering::Relaxed);
    });
    hits
}

fn build_peer(
    object_id: ObjectId,
    registered: bool,
    child_count: usize,
    seed: u64,
) -> PeerState {
    let broadcaster = CancelBroadcaster::new(NoopSink);
    let root_hits = Arc::new(AtomicUsize::new(0));
    let mut child_tokens = Vec::new();
    let mut child_hits = Vec::new();

    let root = if registered {
        let mut rng = DetRng::new(seed);
        let root = SymbolCancelToken::new(object_id, &mut rng);
        let listener_hits = attach_listener_counter(&root);

        for _ in 0..child_count {
            let child = root.child(&mut rng);
            child_hits.push(attach_listener_counter(&child));
            child_tokens.push(child);
        }

        broadcaster.register_token(root.clone());
        Some((root, listener_hits))
    } else {
        None
    };

    match root {
        Some((root, listener_hits)) => PeerState {
            broadcaster,
            root: Some(root),
            root_hits: listener_hits,
            child_tokens,
            child_hits,
            late_seed: seed ^ 0xDEAD_BEEF_F00D_CAFE,
        },
        None => PeerState {
            broadcaster,
            root: None,
            root_hits,
            child_tokens,
            child_hits,
            late_seed: seed ^ 0xDEAD_BEEF_F00D_CAFE,
        },
    }
}

fn delivered_counter(expected: bool) -> usize {
    if expected { 1 } else { 0 }
}

fn receive_once(peer: &PeerState, message: &CancelMessage, now: Time) {
    let _ = peer.broadcaster.receive_message(message, now);
}

fn receive_duplicate(peer: &PeerState, message: &CancelMessage, now: Time) {
    let _ = peer.broadcaster.receive_message(message, now);
    let after_first = peer.broadcaster.metrics();
    let second = peer.broadcaster.receive_message(message, now);
    let after_second = peer.broadcaster.metrics();

    assert!(second.is_none(), "duplicate delivery must not forward");
    assert_eq!(
        after_second.duplicates,
        after_first.duplicates + 1,
        "duplicate delivery must increment duplicate counter exactly once"
    );
    assert_eq!(
        after_second.received, after_first.received,
        "duplicate delivery must not increment received twice"
    );
    assert_eq!(
        after_second.forwarded, after_first.forwarded,
        "duplicate delivery must not forward again"
    );
    assert_eq!(
        after_second.max_hops_reached, after_first.max_hops_reached,
        "duplicate delivery must not re-count max-hop exhaustion"
    );
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = SymbolCancelBroadcastInput::arbitrary(&mut unstructured) else {
        return;
    };

    if input.deliveries.len() > MAX_DELIVERIES {
        return;
    }

    let peer_count = usize::from(input.peer_count).clamp(1, MAX_PEERS);
    let child_count = usize::from(input.child_count).min(MAX_CHILDREN);
    let registered_mask = if input.registered_mask == 0 {
        1
    } else {
        input.registered_mask
    };

    let object_id = ObjectId::new_for_test(input.object_value);
    let reason = input.reason.into_reason();
    let reason_kind = input.reason.kind();

    let origin_seed = input.seed ^ 0xA11C_E5EED;
    let mut origin_rng = DetRng::new(origin_seed);
    let origin_token = SymbolCancelToken::new(object_id, &mut origin_rng);
    let origin_root_hits = attach_listener_counter(&origin_token);
    let mut origin_children = Vec::new();
    let mut origin_child_hits = Vec::new();
    for _ in 0..child_count {
        let child = origin_token.child(&mut origin_rng);
        origin_child_hits.push(attach_listener_counter(&child));
        origin_children.push(child);
    }

    let origin = CancelBroadcaster::new(NoopSink);
    origin.register_token(origin_token.clone());

    let initiated_at = Time::from_millis((input.seed % 10_000) + 1);
    let base_message = origin
        .prepare_cancel(object_id, &reason, initiated_at)
        .with_max_hops(input.max_hops % 5);

    assert!(origin_token.is_cancelled(), "origin token must cancel locally");
    assert_eq!(
        origin_token.reason().map(|stored| stored.kind()),
        Some(reason_kind),
        "origin cancellation reason kind must match input"
    );
    assert_eq!(
        origin_root_hits.load(Ordering::Relaxed),
        1,
        "origin listener must fire exactly once"
    );
    for (child, hits) in origin_children.iter().zip(&origin_child_hits) {
        assert!(child.is_cancelled(), "origin children must be cancelled");
        assert_eq!(
            child.reason().map(|stored| stored.kind()),
            Some(CancelKind::ParentCancelled),
            "origin children must inherit ParentCancelled"
        );
        assert_eq!(
            hits.load(Ordering::Relaxed),
            1,
            "origin child listener must fire exactly once"
        );
    }
    let origin_metrics = origin.metrics();
    assert_eq!(origin_metrics.initiated, 1, "origin should initiate once");
    assert_eq!(origin_metrics.received, 0, "origin should not receive remote messages");

    let mut peers = Vec::with_capacity(peer_count);
    let mut expected_cancelled = vec![false; peer_count];
    for index in 0..peer_count {
        let shift = index.min(u8::BITS as usize - 1);
        let registered = ((registered_mask >> shift) & 1) != 0;
        let seed = input.seed ^ ((index as u64 + 1) << 32) ^ 0x55AA_33CC_11EE_77DD;
        peers.push(build_peer(object_id, registered, child_count, seed));
    }

    for delivery in input.deliveries.iter().take(MAX_DELIVERIES) {
        let peer_index = usize::from(delivery.peer_index) % peers.len();
        let peer = &peers[peer_index];
        let now = Time::from_millis(u64::from(delivery.receive_at_ms) + 2);

        match delivery.mode {
            DeliveryMode::Direct => {
                receive_once(peer, &base_message, now);
                if peer.root.is_some() {
                    expected_cancelled[peer_index] = true;
                }
            }
            DeliveryMode::WireRoundTrip => {
                let wire = base_message.to_bytes();
                if let Some(parsed) = CancelMessage::from_bytes(&wire) {
                    receive_once(peer, &parsed, now);
                    if peer.root.is_some() {
                        expected_cancelled[peer_index] = true;
                    }
                }
            }
            DeliveryMode::Duplicate => {
                receive_duplicate(peer, &base_message, now);
                if peer.root.is_some() {
                    expected_cancelled[peer_index] = true;
                }
            }
            DeliveryMode::Forwarded => {
                if let Some(forwarded) = base_message.forwarded() {
                    receive_once(peer, &forwarded, now);
                    if peer.root.is_some() {
                        expected_cancelled[peer_index] = true;
                    }
                }
            }
            DeliveryMode::MaxHops => {
                let exhausted = base_message.clone().with_max_hops(0);
                receive_once(peer, &exhausted, now);
                if peer.root.is_some() {
                    expected_cancelled[peer_index] = true;
                }
            }
        }
    }

    for (index, peer) in peers.iter().enumerate() {
        let expected = expected_cancelled[index] && peer.root.is_some();
        let expected_hits = delivered_counter(expected);

        assert_eq!(
            peer.root_hits.load(Ordering::Relaxed),
            expected_hits,
            "root listener count must track first cancellation only"
        );

        if let Some(root) = &peer.root {
            assert_eq!(
                root.is_cancelled(),
                expected,
                "registered peer cancellation state must match first delivery outcome"
            );
            if expected {
                assert_eq!(
                    root.reason().map(|stored| stored.kind()),
                    Some(reason_kind),
                    "all subscribers must observe the same cancellation kind"
                );
            } else {
                assert!(
                    root.reason().is_none(),
                    "undelivered peers must not synthesize a cancellation reason"
                );
            }

            for (child, hits) in peer.child_tokens.iter().zip(&peer.child_hits) {
                assert_eq!(
                    child.is_cancelled(),
                    expected,
                    "child cancellation must track parent state"
                );
                assert_eq!(
                    hits.load(Ordering::Relaxed),
                    expected_hits,
                    "child listener count must track parent cancellation once"
                );
                if expected {
                    assert_eq!(
                        child.reason().map(|stored| stored.kind()),
                        Some(CancelKind::ParentCancelled),
                        "children must inherit ParentCancelled after fanout"
                    );
                }
            }

            let mut late_rng = DetRng::new(peer.late_seed);
            let late_child = root.child(&mut late_rng);
            let late_child_hits = attach_listener_counter(&late_child);
            let late_root_hits = attach_listener_counter(root);

            if expected {
                assert!(
                    late_child.is_cancelled(),
                    "late child must observe settled parent cancellation immediately"
                );
                assert_eq!(
                    late_child.reason().map(|stored| stored.kind()),
                    Some(CancelKind::ParentCancelled),
                    "late child must observe ParentCancelled"
                );
                assert_eq!(
                    late_child_hits.load(Ordering::Relaxed),
                    1,
                    "late child listener must fire immediately after settled cancellation"
                );
                assert_eq!(
                    late_root_hits.load(Ordering::Relaxed),
                    1,
                    "late root listener must observe the settled cancellation exactly once"
                );
            } else {
                assert!(
                    !late_child.is_cancelled(),
                    "late child must remain live if the parent never received cancellation"
                );
                assert_eq!(
                    late_child_hits.load(Ordering::Relaxed),
                    0,
                    "late child listener must stay pending before cancellation"
                );
                assert_eq!(
                    late_root_hits.load(Ordering::Relaxed),
                    0,
                    "late root listener must stay pending before cancellation"
                );
            }
        }
    }
});
