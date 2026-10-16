    use super::*;

    /// Capacity follows the recorded polls, not the caller's ceilings, and
    /// growing the I/O tape keeps every recorded step (br-asupersync-01d60c).
    #[test]
    fn capture_capacity_follows_recorded_polls_not_the_limits() {
        let trace = RecordTrace::new(PollCaptureLimits {
            max_polls: 1_000_000,
            max_io_polls: 1_000_000,
            max_write_bytes: 1 << 20,
            max_vectored_slices: 16,
        });
        for effect in 0..20 {
            trace
                .begin(&Request::Write(b"payload"), effect)
                .expect("poll admitted")
                .finish(false);
            trace.boundary(effect + 1, true);
        }
        let state = trace.0.lock();
        assert!(state.failure.is_none());
        assert!(
            state.tape.io.capacity() <= 64,
            "{}",
            state.tape.io.capacity()
        );
        assert!(
            state.tape.frames.capacity() <= 64,
            "{}",
            state.tape.frames.capacity()
        );
        let digest = Request::Write(b"payload").digest();
        assert_eq!(state.tape.io.len(), 20);
        for (index, step) in state.tape.io.iter().enumerate() {
            assert_eq!((step.effect, step.length), (index, 7));
            assert_eq!(step.digest, digest);
        }
    }
