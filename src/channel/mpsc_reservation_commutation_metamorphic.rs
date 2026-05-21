//! Metamorphic tests for MPSC reservation commutation.

#![cfg(test)]

use crate::channel::mpsc::{self, RecvError};
use crate::cx::Cx;
use crate::util::DetRng;
use proptest::prelude::*;
use std::collections::BTreeMap;
use std::future::Future;
use std::task::{Context, Poll};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ReservationMessage {
    id: u64,
    sequence: u32,
    payload_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AssociativeSummary {
    count: usize,
    message_counts: BTreeMap<ReservationMessage, usize>,
}

impl AssociativeSummary {
    fn from_messages(messages: &[ReservationMessage]) -> Self {
        messages.iter().fold(
            Self {
                count: 0,
                message_counts: BTreeMap::new(),
            },
            |mut summary, message| {
                summary.count += 1;
                *summary.message_counts.entry(message.clone()).or_default() += 1;
                summary
            },
        )
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut pinned = Box::pin(future);

    loop {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn reservation_messages(seed: u64, count: usize) -> Vec<ReservationMessage> {
    (0..count)
        .map(|index| ReservationMessage {
            id: seed.wrapping_add(index as u64),
            sequence: (seed as u32).wrapping_mul(31).wrapping_add(index as u32),
            payload_len: ((seed as usize) ^ index) % 257,
        })
        .collect()
}

fn reservation_order(count: usize, seed: u64) -> Vec<usize> {
    let mut order: Vec<_> = (0..count).collect();
    DetRng::new(seed).shuffle(&mut order);
    order
}

fn run_reservation_trace(
    cx: &Cx,
    messages: &[ReservationMessage],
    commit_order: &[usize],
) -> Vec<ReservationMessage> {
    assert_eq!(
        messages.len(),
        commit_order.len(),
        "commit order must cover every reservation"
    );

    let (tx, mut rx) = mpsc::channel(messages.len());
    let mut permits = Vec::with_capacity(messages.len());

    for _ in messages {
        permits.push(Some(
            block_on(tx.reserve(cx)).expect("reservation should fit in channel capacity"),
        ));
    }

    for &slot in commit_order {
        let permit = permits[slot]
            .take()
            .expect("commit order must not reuse a reservation slot");
        permit.send(messages[slot].clone()).unwrap(); // ubs:ignore - test oracle
    }

    let mut received = Vec::with_capacity(messages.len());
    for _ in messages {
        match block_on(rx.recv(cx)) {
            Ok(message) => received.push(message),
            Err(RecvError::Disconnected | RecvError::Cancelled | RecvError::Empty) => break,
        }
    }
    received
}

/// MR1: MPSC reservation commits commute for associative consumers.
///
/// Transformation: reserve all slots, then permute the reservation commit
/// order.
///
/// Relation: an associative consumer summary over all received messages is
/// invariant under that permutation.
#[test]
fn mr_mpsc_reservation_permutation_commutes_for_associative_consumer() {
    proptest!(|(
        seed in any::<u64>(),
        count in 2usize..16,
        permutation_seed in any::<u64>(),
    )| {
        let cx = Cx::for_testing();
        let messages = reservation_messages(seed, count);
        let baseline_order: Vec<_> = (0..count).collect();
        let permuted_order = reservation_order(count, permutation_seed);

        let baseline_received = run_reservation_trace(&cx, &messages, &baseline_order);
        let permuted_received = run_reservation_trace(&cx, &messages, &permuted_order);

        prop_assert_eq!(baseline_received.len(), count,
            "baseline reservation trace lost messages");
        prop_assert_eq!(permuted_received.len(), count,
            "permuted reservation trace lost messages");
        prop_assert_eq!(
            AssociativeSummary::from_messages(&baseline_received),
            AssociativeSummary::from_messages(&permuted_received),
            "permuting MPSC reservation commits changed the associative consumer summary"
        );
    });
}
