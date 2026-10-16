    use super::TerminationTally;
    use crate::Cx;
    use crate::runtime::{JoinError, RuntimeBuilder, SpawnError};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn termination_tally_rejected_spawn_preserves_native_child_accounting() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            let cx = Cx::current().expect("native parent context");
            let terminated = Arc::new(AtomicUsize::new(0));
            let mut completed = TerminationTally::track_spawn(&terminated, |tally| {
                cx.spawn(move |_| async move {
                    let _tally = tally;
                    17
                })
            })
            .unwrap();
            assert_eq!(completed.join(&cx).await, Ok(17));
            assert_eq!(terminated.load(Ordering::Acquire), 1);

            let entered = Arc::new(AtomicUsize::new(0));
            let child_entered = Arc::clone(&entered);
            let pending = cx.pending_spawn_counter_handle().unwrap();
            let before = pending.count();
            let mut unpolled = TerminationTally::track_spawn(&terminated, |tally| {
                cx.spawn(move |child| async move {
                    let _tally = tally;
                    child_entered.fetch_add(1, Ordering::Release);
                    assert!(
                        child.checkpoint().is_err(),
                        "pre-poll abort must be visible in the child's cleanup poll"
                    );
                    let (_sender, mut receiver) = crate::channel::mpsc::channel::<()>(1);
                    assert_eq!(
                        receiver.recv(&child).await,
                        Err(crate::channel::mpsc::RecvError::Cancelled)
                    );
                })
            })
            .unwrap();
            assert_eq!(pending.count(), before + 1, "child is still queued");
            assert_eq!(entered.load(Ordering::Acquire), 0);

            let unavailable = Cx::for_testing();
            let scope = cx.scope();
            for scoped in [false, true] {
                // Explicit old-boundary control: the rejected spawn captures
                // the guard directly, without compensating its Drop. This
                // exercises the old accounting, not an old-commit binary.
                let uncompensated = Arc::new(AtomicUsize::new(0));
                let tally = TerminationTally(Arc::clone(&uncompensated));
                let factory = move |_| async move {
                    let _tally = tally;
                };
                let old_boundary = if scoped {
                    unavailable.spawn_in_cancellation_dominant(&scope, factory)
                } else {
                    unavailable.spawn(factory)
                };
                assert!(matches!(old_boundary, Err(SpawnError::RuntimeUnavailable)));
                assert_eq!(uncompensated.load(Ordering::Acquire), 1);

                let rejected_entered = Arc::clone(&entered);
                let rejected = TerminationTally::track_spawn(&terminated, |tally| {
                    let factory = move |_| async move {
                        let _tally = tally;
                        rejected_entered.fetch_add(1, Ordering::Release);
                    };
                    if scoped {
                        unavailable.spawn_in_cancellation_dominant(&scope, factory)
                    } else {
                        unavailable.spawn(factory)
                    }
                });
                assert!(matches!(rejected, Err(SpawnError::RuntimeUnavailable)));
                assert_eq!(
                    terminated.load(Ordering::Acquire),
                    1,
                    "rejection must not invent a termination or erase the completed child"
                );
                assert_eq!(pending.count(), before + 1);
                assert_eq!(entered.load(Ordering::Acquire), 0);
                eprintln!(
                    "old-boundary control (scoped={scoped}): rejected spawn counted 1 nonexistent child; corrected accounting retains only the 1 completed native child"
                );
            }

            unpolled.abort();
            assert!(matches!(
                unpolled.join(&cx).await,
                Err(JoinError::Cancelled(ref reason))
                    if reason.kind == crate::types::CancelKind::User
            ));
            assert_eq!(
                entered.load(Ordering::Acquire),
                1,
                "pre-poll abort delivers one cleanup poll while retaining task-level cancellation"
            );
            assert_eq!(terminated.load(Ordering::Acquire), 2);
            assert_eq!(pending.count(), before);
        }));
    }

    #[test]
    fn termination_tally_accepted_drop_before_spawn_returns_still_counts() {
        let terminated = Arc::new(AtomicUsize::new(0));
        let result: Result<(), ()> = TerminationTally::track_spawn(&terminated, |tally| {
            // A native child can terminate before its producer gets the
            // accepted handle. That termination must not be compensated.
            drop(tally);
            Ok(())
        });
        assert_eq!(result, Ok(()));
        assert_eq!(terminated.load(Ordering::Acquire), 1);
    }
