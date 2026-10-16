    use super::*;
    use crate::util::{ArenaIndex, DetEntropy};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn task(index: u32, generation: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(index, generation))
    }

    fn recorder(limits: EntropyCaptureLimits) -> RecordingEntropy {
        RecordingEntropy::new(Arc::new(DetEntropy::new(42)), limits).unwrap()
    }

    #[test]
    fn records_real_values_and_nested_forks_without_global_interleaving_dependency() {
        let capture = recorder(EntropyCaptureLimits::new(20, 128, 4));
        let first = capture.fork(task(1, 3));
        let second = capture.fork(task(2, 4));
        let nested = first.fork(task(3, 5));
        let root_value = capture.next_u64();
        let first_value = first.next_u64();
        let mut bytes = [0; 13];
        second.fill_bytes(&mut bytes);
        let nested_value = nested.next_u64();
        let tape = capture.finish().unwrap();
        assert_eq!((tape.calls(), tape.bytes(), tape.streams()), (7, 37, 4));
        let replay = tape.replay();
        let first = replay.try_fork(task(1, 3)).unwrap();
        let second = replay.try_fork(task(2, 4)).unwrap();
        let mut actual = [0; 13];
        second.try_fill_bytes(&mut actual).unwrap();
        assert_eq!(actual, bytes);
        let nested = first.try_fork(task(3, 5)).unwrap();
        assert_eq!(nested.try_next_u64().unwrap(), nested_value);
        assert_eq!(first.try_next_u64().unwrap(), first_value);
        assert_eq!(replay.try_next_u64().unwrap(), root_value);
        replay.verify_complete().unwrap();
    }

    #[test]
    fn request_kind_and_length_are_not_interchangeable_and_failure_is_sticky() {
        let capture = recorder(EntropyCaptureLimits::new(3, 16, 2));
        let child = capture.fork(task(1, 0));
        capture.next_u64();
        child.next_u64();
        let replay = capture.finish().unwrap().replay();
        let child = replay.try_fork(task(1, 0)).unwrap();
        let mut unchanged = [0xa5; 8];
        let error = replay.try_fill_bytes(&mut unchanged).unwrap_err();
        assert_eq!(error.expected, Some(EntropyRequest::U64));
        assert_eq!(unchanged, [0xa5; 8]);
        assert_eq!(child.try_next_u64().unwrap_err(), error);
        assert_eq!(replay.try_next_u64().unwrap_err(), error);
        assert!(matches!(
            replay.verify_complete(),
            Err(EntropyReplayCompletionError::Diverged(_))
        ));
    }

    #[test]
    fn exhaustion_panics_through_trait_and_cannot_be_hidden_by_catching_it() {
        let replay = recorder(EntropyCaptureLimits::new(1, 8, 1))
            .finish()
            .unwrap()
            .replay();
        replay.verify_complete().unwrap();
        assert!(catch_unwind(AssertUnwindSafe(|| replay.next_u64())).is_err());
        let error = replay.failure().unwrap();
        assert_eq!((error.stream, error.call, error.expected), (0, 0, None));
        assert!(replay.verify_complete().is_err());
    }

    #[test]
    fn unread_child_calls_prevent_a_complete_replay_receipt() {
        let capture = recorder(EntropyCaptureLimits::new(2, 8, 2));
        capture.fork(task(1, 0)).next_u64();
        let replay = capture.finish().unwrap().replay();
        let child = replay.try_fork(task(1, 0)).unwrap();
        assert_eq!(
            replay.verify_complete(),
            Err(EntropyReplayCompletionError::Remaining { calls: 1 })
        );
        child.try_next_u64().unwrap();
        replay.verify_complete().unwrap();
    }

    #[test]
    fn overflow_preserves_provider_behavior_but_never_publishes_a_partial_tape() {
        for limits in [
            EntropyCaptureLimits::new(0, 8, 1),
            EntropyCaptureLimits::new(1, 7, 1),
        ] {
            let capture = recorder(limits);
            let reference = DetEntropy::new(42);
            assert_eq!(capture.next_u64(), reference.next_u64());
            assert_eq!(capture.next_u64(), reference.next_u64());
            assert!(capture.failure().is_some());
            assert!(capture.finish().is_err());
        }
        let capture = recorder(EntropyCaptureLimits::new(10, 80, 1));
        let child = capture.fork(task(2, 0));
        child.next_u64();
        assert_eq!(capture.failure(), Some(EntropyCaptureError::StreamLimit));
        assert!(capture.finish().is_err());
    }

    #[test]
    fn fork_remapping_requires_explicit_opt_in_and_preserves_child_values() {
        for matching in [
            EntropyForkMatching::ExactTaskId,
            EntropyForkMatching::ForkOrder,
        ] {
            let capture = recorder(EntropyCaptureLimits::new(2, 8, 2));
            let expected = capture.fork(task(1, 9)).next_u64();
            let replay = capture.finish().unwrap().replay_with(matching);
            let child = replay.try_fork(task(8, 1));
            if matching == EntropyForkMatching::ExactTaskId {
                assert!(child.is_err());
            } else {
                assert_eq!(child.unwrap().try_next_u64().unwrap(), expected);
                replay.verify_complete().unwrap();
            }
        }
    }

    /// A generous bound costs nothing until used: capacity follows the
    /// recorded calls, and a fork's stream does not reserve the remaining
    /// call budget (br-asupersync-01d60c).
    #[test]
    fn capture_capacity_follows_recorded_calls_not_the_bound() {
        let capture = recorder(EntropyCaptureLimits::new(1_000_000, 8_000_000, 64));
        let children: Vec<_> = (0..63).map(|index| capture.fork(task(index, 0))).collect();
        for child in &children {
            child.next_u64();
        }
        let values: Vec<u64> = (0..10).map(|_| capture.next_u64()).collect();
        {
            let state = capture.shared.state.lock();
            let reserved: usize = state.streams.iter().map(Vec::capacity).sum();
            assert_eq!(state.calls, 136);
            assert!(
                reserved <= 1_000,
                "{reserved} event slots reserved for {} calls",
                state.calls
            );
        }
        let replay = capture.finish().unwrap().replay();
        for index in 0..63 {
            replay.try_fork(task(index, 0)).unwrap();
        }
        let replayed: Vec<u64> = (0..10).map(|_| replay.try_next_u64().unwrap()).collect();
        assert_eq!(replayed, values, "values survive the zeroizing growth");
    }

    #[test]
    fn completed_capture_seals_the_window_without_disabling_the_provider() {
        let capture = recorder(EntropyCaptureLimits::new(1, 8, 1));
        let reference = DetEntropy::new(42);
        let expected = capture.next_u64();
        assert_eq!(expected, reference.next_u64());
        let tape = capture.finish().unwrap();
        assert_eq!(capture.next_u64(), reference.next_u64());
        assert!(matches!(
            capture.finish(),
            Err(EntropyCaptureError::Finished)
        ));
        let replay = tape.replay();
        assert_eq!(replay.next_u64(), expected);
        replay.verify_complete().unwrap();
    }
