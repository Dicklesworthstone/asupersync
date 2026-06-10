//! br-e2e-226: channel/mpsc ↔ combinator/select integration E2E tests
//!
//! Tests integration between MPSC channels and select combinators for
//! multi-producer coordination, proper selection logic, and resource management.

// Keep this module feature-gated, not only test-gated, so the focused proof
// lane can typecheck it with `cargo check --lib --features channel-mpsc-select-e2e`
// without entering Cargo's dev-dependency test harness path.
#[cfg(feature = "channel-mpsc-select-e2e")]
#[allow(dead_code)]
mod tests {
    use crate::channel::mpsc::{self, RecvError};
    use crate::combinator::select::{Either, Select, SelectAll, SelectAllDrain};
    use crate::cx::{Cx, cap};
    use futures_lite::future::block_on;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Message {
        channel: &'static str,
        sequence: u64,
    }

    #[cfg_attr(test, test)]
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

        let selected = block_on(Select::new(left_rx.recv(&cx), right_rx.recv(&cx)))
            .expect("fresh select future");

        match selected {
            Either::Left(Ok(message)) => {
                assert_eq!(
                    message,
                    Message {
                        channel: "left",
                        sequence: 1
                    }
                );
            }
            other => panic!("expected left mpsc receiver to win select, got {other:?}"),
        }

        assert_eq!(
            right_rx.try_recv(),
            Ok(Message {
                channel: "right",
                sequence: 2
            }),
            "raw Select drops the loser future; callers still own draining"
        );
    }

    #[cfg_attr(test, test)]
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
                sequence: 7
            }
        );
    }

    #[cfg_attr(test, test)]
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

            let winner_index = result.winner_index;
            let value = result.value;
            let losers = result.losers;

            assert_eq!(winner_index, 1);
            assert_eq!(
                value.expect("winning recv succeeds"),
                Message {
                    channel: "second",
                    sequence: 11
                }
            );
            assert_eq!(losers.len(), 2);
            drop(losers);
        }

        assert_eq!(first_rx.try_recv(), Err(RecvError::Empty));
        assert_eq!(third_rx.try_recv(), Err(RecvError::Empty));
    }

    #[cfg_attr(test, test)]
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

        let selected = block_on(Select::new(batch_rx.recv(&cx), idle_rx.recv(&cx)))
            .expect("fresh select future");
        let Either::Left(Ok(first)) = selected else {
            panic!("expected populated batch receiver to win select, got {selected:?}");
        };
        assert_eq!(
            first,
            Message {
                channel: "batch",
                sequence: 0
            }
        );

        let mut batch = Vec::new();
        let drained =
            block_on(batch_rx.recv_many(&cx, &mut batch, 16)).expect("recv_many succeeds");

        assert_eq!(drained, 4);
        assert_eq!(
            batch,
            vec![
                Message {
                    channel: "batch",
                    sequence: 1
                },
                Message {
                    channel: "batch",
                    sequence: 2
                },
                Message {
                    channel: "batch",
                    sequence: 3
                },
                Message {
                    channel: "batch",
                    sequence: 4
                },
            ]
        );
    }
}
