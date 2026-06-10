// Focused public API smoke runner for MPSC/select integration.
//
// This runner exists as a validation-frontier lane: it exercises the
// channel/MPSC select scenarios through a normal binary target, avoiding the
// crate-root test harness and its unrelated conformance dev-dependency tail.

use asupersync::channel::mpsc::{self, RecvError};
use asupersync::combinator::select::{Either, Select, SelectAll, SelectAllDrain};
use asupersync::cx::{Cx, cap};
use futures_lite::future::block_on;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Message {
    channel: &'static str,
    sequence: u64,
}

fn main() {
    select_recv_keeps_unselected_channel_drained_by_caller();
    select_all_can_mix_bounded_and_unbounded_receivers();
    select_all_drain_returns_pending_mpsc_losers();
    selected_receiver_can_continue_with_recv_many_batching();
}

fn select_recv_keeps_unselected_channel_drained_by_caller() {
    let cx = Cx::<cap::None>::detached_cancel_context();
    let (left_tx, mut left_rx) = mpsc::channel(2);
    let (right_tx, mut right_rx) = mpsc::channel(2);

    left_tx
        .try_send(Message {
            channel: "left",
            sequence: 1,
        })
        .expect("left channel has capacity");
    right_tx
        .try_send(Message {
            channel: "right",
            sequence: 2,
        })
        .expect("right channel has capacity");

    let selected =
        block_on(Select::new(left_rx.recv(&cx), right_rx.recv(&cx))).expect("fresh select future");

    match selected {
        Either::Left(Ok(message)) => {
            assert_eq!(
                message,
                Message {
                    channel: "left",
                    sequence: 1,
                }
            );
        }
        other => panic!("expected left mpsc receiver to win select, got {other:?}"),
    }

    assert_eq!(
        right_rx.try_recv(),
        Ok(Message {
            channel: "right",
            sequence: 2,
        }),
        "raw Select drops the loser future; callers still own draining"
    );
}

fn select_all_can_mix_bounded_and_unbounded_receivers() {
    let cx = Cx::<cap::None>::detached_cancel_context();
    let (_bounded_tx, mut bounded_rx) = mpsc::channel::<Message>(2);
    let (unbounded_tx, mut unbounded_rx) = mpsc::unbounded_channel();

    unbounded_tx
        .send(Message {
            channel: "unbounded",
            sequence: 7,
        })
        .expect("unbounded receiver is live");

    let (selected, index) = block_on(SelectAll::new(vec![
        bounded_rx.recv(&cx),
        unbounded_rx.recv(&cx),
    ]))
    .expect("fresh select_all future");

    assert_eq!(index, 1);
    assert_eq!(
        selected.expect("unbounded recv succeeds"),
        Message {
            channel: "unbounded",
            sequence: 7,
        }
    );
}

fn select_all_drain_returns_pending_mpsc_losers() {
    let cx = Cx::<cap::None>::detached_cancel_context();
    let (_first_tx, mut first_rx) = mpsc::channel::<Message>(1);
    let (second_tx, mut second_rx) = mpsc::channel(1);
    let (_third_tx, mut third_rx) = mpsc::channel::<Message>(1);

    second_tx
        .try_send(Message {
            channel: "second",
            sequence: 11,
        })
        .expect("second channel has capacity");

    {
        let result = block_on(SelectAllDrain::new(vec![
            first_rx.recv(&cx),
            second_rx.recv(&cx),
            third_rx.recv(&cx),
        ]))
        .expect("fresh select_all_drain future");

        assert_eq!(result.winner_index, 1);
        assert_eq!(
            result.value.expect("winning recv succeeds"),
            Message {
                channel: "second",
                sequence: 11,
            }
        );
        assert_eq!(result.losers.len(), 2);
        drop(result.losers);
    }

    assert_eq!(first_rx.try_recv(), Err(RecvError::Empty));
    assert_eq!(third_rx.try_recv(), Err(RecvError::Empty));
}

fn selected_receiver_can_continue_with_recv_many_batching() {
    let cx = Cx::<cap::None>::detached_cancel_context();
    let (batch_tx, mut batch_rx) = mpsc::channel(8);
    let (_idle_tx, mut idle_rx) = mpsc::channel::<Message>(1);

    for sequence in 0..5 {
        batch_tx
            .try_send(Message {
                channel: "batch",
                sequence,
            })
            .expect("batch channel has capacity");
    }

    let selected =
        block_on(Select::new(batch_rx.recv(&cx), idle_rx.recv(&cx))).expect("fresh select future");
    let first = match selected {
        Either::Left(Ok(message)) => message,
        other => panic!("expected populated batch receiver to win select, got {other:?}"),
    };
    assert_eq!(
        first,
        Message {
            channel: "batch",
            sequence: 0,
        }
    );

    let mut batch = Vec::new();
    let drained = block_on(batch_rx.recv_many(&cx, &mut batch, 16)).expect("recv_many succeeds");

    assert_eq!(drained, 4);
    assert_eq!(
        batch,
        vec![
            Message {
                channel: "batch",
                sequence: 1,
            },
            Message {
                channel: "batch",
                sequence: 2,
            },
            Message {
                channel: "batch",
                sequence: 3,
            },
            Message {
                channel: "batch",
                sequence: 4,
            },
        ]
    );
}
