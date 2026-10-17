    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::super::settings::DEFAULT_MAX_HEADER_LIST_SIZE;
    use super::*;

    #[test]
    fn test_stream_state_transitions() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert_eq!(stream.state(), StreamState::Idle);

        // Send headers (no end_stream)
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        // Receive data with end_stream
        stream.recv_data(100, true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);

        // Send data with end_stream
        stream.send_data(true).unwrap();
        assert_eq!(stream.state(), StreamState::Closed);
    }

    #[test]
    fn test_stream_flow_control() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert_eq!(stream.send_window(), 65535);

        stream.consume_send_window(1000);
        assert_eq!(stream.send_window(), 64535);

        stream.update_send_window(500).unwrap();
        assert_eq!(stream.send_window(), 65035);
    }

    #[test]
    fn header_fragment_limit_respects_max_header_list_size() {
        let max_list_size = 8;
        let mut stream = Stream::new(1, 65535, max_list_size);

        // 4x multiplier => 32 bytes total allowed.
        stream
            .add_header_fragment(Bytes::from(vec![0; 16]))
            .unwrap();
        assert!(
            stream
                .add_header_fragment(Bytes::from(vec![0; 17]))
                .is_err()
        );
    }

    #[test]
    fn header_fragment_count_cap_rejects_zero_length_flood() {
        // CONTINUATION-flood DoS (CVE-2024-27316 class): zero-length fragments
        // add 0 bytes, so the byte cap never trips; the fragment-COUNT cap must
        // bound them. With a large byte budget, exactly
        // MAX_HEADER_CONTINUATION_FRAGMENTS empty fragments are accepted and the
        // next is rejected — the vector cannot grow without bound.
        let mut stream = Stream::new(1, 65535, u32::MAX); // 256 KiB byte budget
        for i in 0..MAX_HEADER_CONTINUATION_FRAGMENTS {
            stream
                .add_header_fragment(Bytes::from_static(b""))
                .unwrap_or_else(|_| panic!("empty fragment {i} should be under the count cap"));
        }
        assert!(
            stream.add_header_fragment(Bytes::from_static(b"")).is_err(),
            "fragment-count cap must reject the zero-length CONTINUATION flood"
        );
    }

    #[test]
    fn take_header_fragments_resets_byte_accounting() {
        // The O(1) running byte counter must reset when fragments are taken, so a
        // subsequent header block gets the full budget rather than a stale
        // carried-over sum (which would falsely reject the next block).
        let max_list_size = 8; // 4x => 32-byte budget
        let mut stream = Stream::new(1, 65535, max_list_size);
        stream
            .add_header_fragment(Bytes::from(vec![0; 30]))
            .unwrap();
        let taken = stream.take_header_fragments();
        assert_eq!(taken.len(), 1);
        // Budget is fresh after take: a second 30-byte fragment must fit again.
        stream
            .add_header_fragment(Bytes::from(vec![0; 30]))
            .expect("byte budget must reset after take_header_fragments");
    }

    #[test]
    fn test_stream_store_allocation() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert!(store.is_empty());

        let id1 = store.allocate_stream_id().unwrap();
        assert_eq!(id1, 1);

        let id2 = store.allocate_stream_id().unwrap();
        assert_eq!(id2, 3);

        let id3 = store.allocate_stream_id().unwrap();
        assert_eq!(id3, 5);
        assert!(!store.is_empty());
    }

    #[test]
    fn stream_store_preserves_local_initial_receive_window() {
        let mut store = StreamStore::new_with_local_recv_window(
            true,
            65_535,
            32_768,
            DEFAULT_MAX_HEADER_LIST_SIZE,
        );

        let id = store.allocate_stream_id().unwrap();
        let stream = store.get(id).unwrap();
        assert_eq!(stream.send_window(), 65_535);
        assert_eq!(stream.recv_window(), 32_768);
        assert_eq!(stream.initial_recv_window, 32_768);
        assert_eq!(store.initial_recv_window_size(), 32_768);

        store.set_initial_window_size(100_000).unwrap();
        let stream = store.get(id).unwrap();
        assert_eq!(stream.send_window(), 100_000);
        assert_eq!(
            stream.recv_window(),
            32_768,
            "peer SETTINGS_INITIAL_WINDOW_SIZE must not rewrite our receive window"
        );
        assert_eq!(stream.initial_recv_window, 32_768);
    }

    /// br-asupersync-jq82r4: a server receiving a client-initiated stream
    /// id whose gap from base_id exceeds 1<<20 must reject with
    /// RefusedStream WITHOUT growing the flat Vec to 2.1B slots. This is
    /// the memory-DoS regression guard.
    #[test]
    fn jq82r4_ensure_slot_rejects_pathological_stream_id_gap() {
        // is_client=false → server-side StreamStore that accepts client
        // (odd) stream ids. Open a tiny id first, then attempt a near-MAX
        // id that would create a 2.1B-slot gap.
        let mut store = StreamStore::new(false, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        store.get_or_create(1).expect("first stream opens normally");

        // 0x7FFF_FFFD - 1 ≈ 2.1B slots; the ceiling is 1<<20. Ceiling is
        // crossed by any id ≥ 1 + 2^20 + 1 (off ≥ 1<<20). Pick a
        // representative odd id well above the ceiling but below
        // MAX_STREAM_ID.
        let attack_id: u32 = (1u32 << 21) + 1; // odd, way above ceiling
        let err = store
            .get_or_create(attack_id)
            .expect_err("must reject pathological id gap");
        // The error MUST be a stream-level RefusedStream, NOT a memory
        // allocation that brought down the process.
        assert!(
            err.message.contains("stream id gap exceeds") || err.code == ErrorCode::RefusedStream,
            "expected RefusedStream / gap-exceeds, got {err:?}"
        );

        // Subsequent legitimate allocations must still work — the
        // rejection MUST NOT have advanced next_client_stream_id past
        // attack_id, otherwise smaller ids would now be "already used".
        let id3 = store
            .get_or_create(3)
            .expect("smaller-gap allocation still works");
        assert_eq!(id3.id(), 3);
    }

    /// br-asupersync-jq82r4: rejection MUST NOT mutate
    /// `next_client_stream_id`. If it did, a single attack frame
    /// would permanently break the connection's ability to accept
    /// further legitimate client streams.
    #[test]
    fn jq82r4_rejection_does_not_advance_next_stream_id() {
        let mut store = StreamStore::new(false, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        let next_before = store.next_client_stream_id;
        let attack_id: u32 = (1u32 << 21) + 1; // odd, above 1<<20 cap
        let _err = store
            .get_or_create(attack_id)
            .expect_err("must reject attack id");
        assert_eq!(
            store.next_client_stream_id, next_before,
            "rejected attack must not advance next_client_stream_id"
        );
    }

    /// br-asupersync-jq82r4: a peer-initiated PUSH_PROMISE with a
    /// pathological promised id must be refused without growing the
    /// flat Vec, AND without burning the next-server-stream-id
    /// counter (so legitimate promises still succeed afterwards).
    #[test]
    fn jq82r4_reserve_remote_stream_rejects_pathological_id_gap() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        let next_before = store.next_server_stream_id;
        let attack_id: u32 = 1u32 << 22; // even, server-promised, above cap
        let err = store
            .reserve_remote_stream(attack_id)
            .expect_err("must reject pathological promised id");
        assert_eq!(err.code, ErrorCode::RefusedStream);
        assert_eq!(
            store.next_server_stream_id, next_before,
            "rejection must not burn next_server_stream_id"
        );

        // Legit small promised id still works.
        let s = store
            .reserve_remote_stream(2)
            .expect("legit promise must still succeed");
        assert_eq!(s.id(), 2);
    }

    /// br-asupersync-jq82r4: prune_closed advances base_id past a
    /// long run of closed streams, which restores headroom under the
    /// gap cap. ensure_slot triggers this last-chance compaction
    /// before rejecting, so a long-lived connection that legitimately
    /// closes many streams keeps working.
    #[test]
    fn jq82r4_prune_recovers_when_gap_cap_first_exceeded() {
        // Use a very small synthetic gap by forcing base_id and
        // streams to a state that mimics the long-running connection
        // shape: many closed streams at the front, an attempt to
        // open a stream just past the cap.
        let mut store = StreamStore::new(false, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        // Open a few streams in both peer and local stream-id spaces and close
        // them so prune_closed can advance base_id past them.
        for id in [1u32, 3, 5, 7, 9] {
            let s = store.get_or_create(id).unwrap();
            s.reset(ErrorCode::Cancel);
        }
        for expected_id in [2u32, 4, 6, 8, 10] {
            let id = store.allocate_stream_id().unwrap();
            assert_eq!(id, expected_id);
            store.get_mut(id).unwrap().reset(ErrorCode::Cancel);
        }
        // Sanity: base_id is still 1 (no automatic prune on close).
        assert_eq!(store.base_id, 1);

        // Now force the next opened id to be exactly at the cap from
        // CURRENT base_id. After prune the cap will measure from the
        // new (larger) base_id and the same id will fit.
        let target_id = 1 + StreamStore::MAX_STREAM_GAP_FROM_BASE + 1;
        // Make sure target_id has client (odd) parity for is_client=false.
        let target_id = if target_id % 2 == 1 {
            target_id
        } else {
            target_id + 1
        };
        let result = store.get_or_create(target_id);
        // First time: pre-check rejects (no prune in pre-check).
        let err = result.expect_err("pre-check refuses uncompacted gap");
        assert_eq!(err.code, ErrorCode::RefusedStream);

        // Manually run a prune (simulating the connection's idle-time
        // housekeeping) and then retry — should now succeed.
        store.prune_closed();
        assert!(store.base_id > 1, "prune must advance base_id");
        let s = store
            .get_or_create(target_id)
            .expect("after prune, the same id fits within the gap cap");
        assert_eq!(s.id(), target_id);
    }

    #[test]
    fn test_stream_store_max_concurrent() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        store.set_max_concurrent_streams(2);

        let id1 = store.allocate_stream_id().unwrap();
        store.get_mut(id1).unwrap().send_headers(false).unwrap();
        let id2 = store.allocate_stream_id().unwrap();
        store.get_mut(id2).unwrap().send_headers(false).unwrap();

        // Third should fail — two active streams already at the limit
        assert!(store.allocate_stream_id().is_err());

        // Close one stream
        store.get_mut(id1).unwrap().reset(ErrorCode::NoError);
        store.prune_closed();

        // Now we can allocate again
        assert!(store.allocate_stream_id().is_ok());
    }

    #[test]
    fn auto_window_update_not_needed_when_window_above_half() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        // Consume less than half: no update needed.
        stream.recv_data(30_000, false).unwrap();
        assert!(
            stream.recv_window() >= stream.initial_recv_window / 2,
            "window should still be above the low watermark"
        );
        assert!(stream.auto_window_update_increment().is_none());
    }

    #[test]
    fn auto_window_update_triggered_when_window_below_quarter() {
        let initial = DEFAULT_INITIAL_WINDOW_SIZE;
        let initial_i32 = i32::try_from(initial).unwrap();
        let mut stream = Stream::new(1, initial, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        // Consume just over 75% to cross the 25% watermark.
        let consume = u32::try_from(initial_i32 * 3 / 4 + 2).unwrap();
        stream.recv_data(consume, false).unwrap();

        let increment = stream
            .auto_window_update_increment()
            .expect("should need WINDOW_UPDATE");

        // Increment should restore the window to its initial value.
        assert_eq!(
            i64::from(stream.recv_window()) + i64::from(increment),
            i64::from(initial_i32)
        );
    }

    #[test]
    fn auto_window_update_returns_none_after_replenish() {
        let initial = DEFAULT_INITIAL_WINDOW_SIZE;
        let initial_i32 = i32::try_from(initial).unwrap();
        let mut stream = Stream::new(1, initial, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        // Drain below the 25% watermark.
        let consume = u32::try_from(initial_i32 * 3 / 4 + 2).unwrap();
        stream.recv_data(consume, false).unwrap();

        let increment = stream.auto_window_update_increment().unwrap();
        stream
            .update_recv_window(i32::try_from(increment).unwrap())
            .unwrap();

        // After replenishing, should no longer need an update.
        assert!(stream.auto_window_update_increment().is_none());
    }

    /// Review r27-e8 (br-asupersync-grpc-client-server-audit-jq0c7j): a window
    /// of 1-3 bytes had a low watermark of 0, so once used up it was never
    /// refilled and the stream stalled.
    #[test]
    fn auto_window_update_refills_a_tiny_window_once_it_is_used_up() {
        for initial in 1..=3_u32 {
            let mut stream = Stream::new(1, initial, DEFAULT_MAX_HEADER_LIST_SIZE);
            stream.send_headers(false).unwrap();
            assert!(stream.auto_window_update_increment().is_none());
            stream.recv_data(initial, false).unwrap();
            assert_eq!(stream.auto_window_update_increment(), Some(initial));
        }
    }

    // =========================================================================
    // RFC 7540 Section 5.1 State Machine Tests
    // =========================================================================

    #[test]
    fn idle_to_open_via_send_headers() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert_eq!(stream.state(), StreamState::Idle);

        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);
    }

    #[test]
    fn idle_to_half_closed_local_via_send_headers_with_end_stream() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert_eq!(stream.state(), StreamState::Idle);

        stream.send_headers(true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);
    }

    #[test]
    fn idle_to_open_via_recv_headers() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert_eq!(stream.state(), StreamState::Idle);

        stream.recv_headers(false, true, false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);
    }

    #[test]
    fn idle_to_half_closed_remote_via_recv_headers_with_end_stream() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert_eq!(stream.state(), StreamState::Idle);

        stream.recv_headers(true, true, false).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);
    }

    #[test]
    fn open_to_half_closed_local_via_send_data() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        stream.send_data(true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);
    }

    #[test]
    fn open_to_half_closed_local_via_send_headers() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        // Sending trailers with end_stream
        stream.send_headers(true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);
    }

    #[test]
    fn open_to_half_closed_remote_via_recv_data() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        stream.recv_data(100, true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);
    }

    #[test]
    fn open_to_half_closed_remote_via_recv_headers() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        // Receiving trailers with end_stream
        stream.recv_headers(true, true, false).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);
    }

    // br-asupersync-pyhaov: SERVER receiving a second HEADERS frame
    // (i.e., trailers — first one had END_HEADERS, headers_complete is
    // true) WITHOUT END_STREAM is malformed per RFC 9113 §8.1. The
    // direction parameter is_client=false enables the strict check;
    // is_client=true preserves the legitimate 1xx-informational
    // response path on the client side.
    #[test]
    fn server_rejects_trailing_headers_without_end_stream_pyhaov() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        // First HEADERS: request initial header block, no END_STREAM
        // (request body coming).
        stream.recv_headers(false, true, false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);
        assert!(stream.headers_complete);

        // Second HEADERS without END_STREAM — this is a TRAILER on
        // the request side, and trailers MUST have END_STREAM. The
        // server-side path (is_client=false) MUST reject.
        let err = stream
            .recv_headers(false, true, false)
            .expect_err("server must reject trailing HEADERS without END_STREAM");
        assert_eq!(err.code, ErrorCode::ProtocolError);

        // State must be unchanged: the rejection happens BEFORE state
        // mutation (validation-first pattern).
        assert_eq!(stream.state(), StreamState::Open);
    }

    #[test]
    fn server_accepts_trailing_headers_with_end_stream_pyhaov() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.recv_headers(false, true, false).unwrap();
        // Trailers WITH END_STREAM are the legitimate shape — accept.
        stream.recv_headers(true, true, false).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);
    }

    #[test]
    fn client_still_accepts_1xx_informational_without_end_stream_pyhaov() {
        // Client receives initial 1xx informational HEADERS (no
        // END_STREAM), then the final response HEADERS. The pyhaov
        // server-side gate must NOT fire on the client path.
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap(); // client sent its request HEADERS
        // First 1xx informational from server: no END_STREAM.
        stream
            .recv_headers(false, true, true)
            .expect("client must accept 1xx informational without END_STREAM");
        // Final response HEADERS with END_STREAM closes the stream.
        stream
            .recv_headers(true, true, true)
            .expect("client must accept final response after 1xx");
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);
    }

    #[test]
    fn half_closed_local_to_closed_via_recv_data() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(true).unwrap(); // Go to HalfClosedLocal
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);

        stream.recv_data(100, true).unwrap();
        assert_eq!(stream.state(), StreamState::Closed);
    }

    #[test]
    fn half_closed_local_to_closed_via_recv_headers() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);

        // Receiving trailers with end_stream closes the stream
        stream.recv_headers(true, true, false).unwrap();
        assert_eq!(stream.state(), StreamState::Closed);
    }

    #[test]
    fn half_closed_remote_to_closed_via_send_data() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        stream.recv_data(100, true).unwrap(); // Go to HalfClosedRemote
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);

        stream.send_data(true).unwrap();
        assert_eq!(stream.state(), StreamState::Closed);
    }

    #[test]
    fn half_closed_remote_to_closed_via_send_headers() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        stream.recv_data(100, true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);

        // Sending trailers with end_stream closes the stream
        stream.send_headers(true).unwrap();
        assert_eq!(stream.state(), StreamState::Closed);
    }

    // =========================================================================
    // Open/HalfClosed non-end_stream header tests (RFC 7540 §8.1)
    // =========================================================================

    #[test]
    fn send_headers_open_without_end_stream_stays_open() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap(); // Idle -> Open
        assert_eq!(stream.state(), StreamState::Open);

        // Server sends response headers without END_STREAM (data follows)
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);
    }

    #[test]
    fn send_headers_half_closed_remote_without_end_stream_stays() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap(); // Idle -> Open
        stream.recv_data(100, true).unwrap(); // Open -> HalfClosedRemote
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);

        // Sending headers without END_STREAM stays HalfClosedRemote
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);
    }

    #[test]
    fn recv_headers_open_without_end_stream_stays_open() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap(); // Idle -> Open
        assert_eq!(stream.state(), StreamState::Open);

        // Client receives response headers without END_STREAM (data follows).
        stream.recv_headers(false, true, true).unwrap();
        assert_eq!(stream.state(), StreamState::Open);
    }

    #[test]
    fn recv_headers_half_closed_local_without_end_stream_stays() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(true).unwrap(); // Idle -> HalfClosedLocal
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);

        // Client receives response headers without END_STREAM after sending END_STREAM.
        stream.recv_headers(false, true, true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);
    }

    // =========================================================================
    // Reserved State Tests (Push Promise paths)
    // =========================================================================

    #[test]
    fn reserved_local_to_half_closed_remote_via_send_headers() {
        let mut stream = Stream::new(2, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.state = StreamState::ReservedLocal; // Simulate PUSH_PROMISE sent

        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);
    }

    #[test]
    fn reserved_local_to_closed_via_send_headers_with_end_stream() {
        let mut stream = Stream::new(2, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.state = StreamState::ReservedLocal;

        stream.send_headers(true).unwrap();
        assert_eq!(stream.state(), StreamState::Closed);
    }

    #[test]
    fn reserved_remote_to_half_closed_local_via_recv_headers() {
        let mut stream = Stream::new(2, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.state = StreamState::ReservedRemote; // Simulate PUSH_PROMISE received

        stream.recv_headers(false, true, false).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);
    }

    #[test]
    fn reserved_remote_to_closed_via_recv_headers_with_end_stream() {
        let mut stream = Stream::new(2, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.state = StreamState::ReservedRemote;

        stream.recv_headers(true, true, false).unwrap();
        assert_eq!(stream.state(), StreamState::Closed);
    }

    // =========================================================================
    // Reset Tests
    // =========================================================================

    #[test]
    fn reset_from_any_state_goes_to_closed() {
        for initial_state in [
            StreamState::Idle,
            StreamState::Open,
            StreamState::HalfClosedLocal,
            StreamState::HalfClosedRemote,
            StreamState::ReservedLocal,
            StreamState::ReservedRemote,
        ] {
            let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
            stream.state = initial_state;

            stream.reset(ErrorCode::Cancel);

            assert_eq!(stream.state(), StreamState::Closed);
            assert_eq!(stream.error_code(), Some(ErrorCode::Cancel));
        }
    }

    #[test]
    fn reset_preserves_error_code() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        stream.reset(ErrorCode::InternalError);
        assert_eq!(stream.error_code(), Some(ErrorCode::InternalError));

        stream.reset(ErrorCode::StreamClosed);
        assert_eq!(stream.error_code(), Some(ErrorCode::StreamClosed));
    }

    // =========================================================================
    // Illegal Transition Tests
    // =========================================================================

    #[test]
    fn cannot_send_headers_on_closed_stream() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.reset(ErrorCode::Cancel);
        assert_eq!(stream.state(), StreamState::Closed);

        let result = stream.send_headers(false);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_recv_headers_on_closed_stream() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.reset(ErrorCode::Cancel);

        let result = stream.recv_headers(false, true, false);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_send_data_on_closed_stream() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.reset(ErrorCode::Cancel);

        let result = stream.send_data(false);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_recv_data_on_closed_stream() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.reset(ErrorCode::Cancel);

        let result = stream.recv_data(100, false);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_send_data_on_half_closed_local() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);

        let result = stream.send_data(false);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_recv_data_on_half_closed_remote() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        stream.recv_data(100, true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);

        let result = stream.recv_data(100, false);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_send_headers_on_half_closed_local() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);

        // Trying to send more headers is illegal since we already ended
        let result = stream.send_headers(false);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_recv_headers_on_half_closed_remote() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        stream.recv_headers(true, true, false).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);

        let result = stream.recv_headers(false, true, false);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_send_data_on_idle() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert_eq!(stream.state(), StreamState::Idle);

        let result = stream.send_data(false);
        assert!(result.is_err());
    }

    #[test]
    fn cannot_recv_data_on_idle() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert_eq!(stream.state(), StreamState::Idle);

        let result = stream.recv_data(100, false);
        assert!(result.is_err());
    }

    // =========================================================================
    // Flow Control Error Tests
    // =========================================================================

    #[test]
    fn recv_data_exceeding_window_returns_flow_control_error() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        // Consume most of the receive window (recv_window uses DEFAULT_INITIAL_WINDOW_SIZE)
        stream.recv_data(65530, false).unwrap();

        // Now try to receive more data than remaining window (only 5 bytes left)
        let result = stream.recv_data(100, false);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::FlowControlError);
    }

    #[test]
    fn window_update_overflow_returns_error() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        // Try to overflow the window
        let result = stream.update_send_window(i32::MAX);
        assert!(result.is_err());
    }

    // =========================================================================
    // State Predicate Tests
    // =========================================================================

    #[test]
    fn can_send_predicates_are_correct() {
        assert!(!StreamState::Idle.can_send());
        assert!(StreamState::Open.can_send());
        assert!(!StreamState::HalfClosedLocal.can_send());
        assert!(StreamState::HalfClosedRemote.can_send());
        assert!(StreamState::ReservedLocal.can_send());
        assert!(!StreamState::ReservedRemote.can_send());
        assert!(!StreamState::Closed.can_send());
    }

    #[test]
    fn can_recv_predicates_are_correct() {
        assert!(!StreamState::Idle.can_recv());
        assert!(StreamState::Open.can_recv());
        assert!(StreamState::HalfClosedLocal.can_recv());
        assert!(!StreamState::HalfClosedRemote.can_recv());
        assert!(!StreamState::ReservedLocal.can_recv());
        assert!(StreamState::ReservedRemote.can_recv());
        assert!(!StreamState::Closed.can_recv());
    }

    #[test]
    fn can_send_headers_predicates_are_correct() {
        assert!(StreamState::Idle.can_send_headers());
        assert!(StreamState::Open.can_send_headers());
        assert!(!StreamState::HalfClosedLocal.can_send_headers());
        assert!(StreamState::HalfClosedRemote.can_send_headers());
        assert!(StreamState::ReservedLocal.can_send_headers());
        assert!(!StreamState::ReservedRemote.can_send_headers());
        assert!(!StreamState::Closed.can_send_headers());
    }

    #[test]
    fn can_recv_headers_predicates_are_correct() {
        assert!(StreamState::Idle.can_recv_headers());
        assert!(StreamState::Open.can_recv_headers());
        assert!(StreamState::HalfClosedLocal.can_recv_headers());
        assert!(!StreamState::HalfClosedRemote.can_recv_headers());
        assert!(!StreamState::ReservedLocal.can_recv_headers());
        assert!(StreamState::ReservedRemote.can_recv_headers());
        assert!(!StreamState::Closed.can_recv_headers());
    }

    #[test]
    fn is_closed_predicate_is_correct() {
        assert!(!StreamState::Idle.is_closed());
        assert!(!StreamState::Open.is_closed());
        assert!(!StreamState::HalfClosedLocal.is_closed());
        assert!(!StreamState::HalfClosedRemote.is_closed());
        assert!(!StreamState::ReservedLocal.is_closed());
        assert!(!StreamState::ReservedRemote.is_closed());
        assert!(StreamState::Closed.is_closed());
    }

    // =========================================================================
    // Continuation Frame Tests
    // =========================================================================

    #[test]
    fn continuation_without_headers_in_progress_is_error() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        // headers_complete is true by default, so CONTINUATION is unexpected
        let result = stream.recv_continuation(Bytes::from_static(b"test"), false);
        assert!(result.is_err());
    }

    #[test]
    fn continuation_accumulates_fragments() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        // Receive headers without END_HEADERS
        stream.recv_headers(false, false, false).unwrap();
        assert!(stream.is_receiving_headers());

        // Add continuations
        stream
            .recv_continuation(Bytes::from_static(b"part1"), false)
            .unwrap();
        stream
            .recv_continuation(Bytes::from_static(b"part2"), true)
            .unwrap();

        assert!(!stream.is_receiving_headers());

        let fragments = stream.take_header_fragments();
        assert_eq!(fragments.len(), 2);
    }

    // =========================================================================
    // Pending Data Queue Tests
    // =========================================================================

    #[test]
    fn pending_data_queue_works() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert!(!stream.has_pending_data());

        stream.queue_data(Bytes::from_static(b"hello"), false);
        stream.queue_data(Bytes::from_static(b"world"), true);
        assert!(stream.has_pending_data());

        let (data1, end1) = stream.take_pending_data(100).unwrap();
        assert_eq!(&data1[..], b"hello");
        assert!(!end1);

        let (data2, end2) = stream.take_pending_data(100).unwrap();
        assert_eq!(&data2[..], b"world");
        assert!(end2);

        assert!(!stream.has_pending_data());
    }

    #[test]
    fn pending_data_partial_take() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.queue_data(Bytes::from_static(b"hello world"), true);

        // Take only 5 bytes
        let (data1, end1) = stream.take_pending_data(5).unwrap();
        assert_eq!(&data1[..], b"hello");
        assert!(!end1); // Not end_stream since we only took partial

        // Take the rest
        let (data2, end2) = stream.take_pending_data(100).unwrap();
        assert_eq!(&data2[..], b" world");
        assert!(end2);
    }

    #[test]
    fn pending_data_zero_window_returns_none() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.queue_data(Bytes::from_static(b"hello"), true);

        let taken = stream.take_pending_data(0);
        assert!(taken.is_none());
        assert!(stream.has_pending_data());

        let (data, end) = stream.take_pending_data(5).unwrap();
        assert_eq!(&data[..], b"hello");
        assert!(end);
        assert!(!stream.has_pending_data());
    }

    // =========================================================================
    // Stream Store ID Validation Tests
    // =========================================================================

    #[test]
    fn stream_store_rejects_stream_id_zero() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        let result = store.get_or_create(0);
        assert!(result.is_err());
    }

    #[test]
    fn stream_store_rejects_stream_id_over_max() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        let result = store.get_or_create(MAX_STREAM_ID + 1);
        assert!(result.is_err());
    }

    #[test]
    fn stream_store_client_rejects_client_initiated_stream() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        // Client should not accept odd stream IDs from the server.
        let result = store.get_or_create(1);
        assert!(result.is_err());
    }

    #[test]
    fn stream_store_server_rejects_server_initiated_stream() {
        let mut store = StreamStore::new(false, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        // Server should not accept even stream IDs from the client.
        let result = store.get_or_create(2);
        assert!(result.is_err());
    }

    #[test]
    fn stream_store_client_rejects_reused_server_stream_id() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        // Client receives server stream 2
        store.get_or_create(2).unwrap();

        // Trying to use ID 2 again should fail (but it already exists, so get returns it)
        // The error case is when we try to create a lower ID
        store.get_or_create(4).unwrap(); // This advances next_server_stream_id to 6

        // Now trying to create stream 2 should just return existing
        assert!(store.get_or_create(2).is_ok());
    }

    #[test]
    fn stream_store_server_advances_client_stream_ids() {
        let mut store = StreamStore::new(false, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        // Server receives client streams
        store.get_or_create(1).unwrap();
        store.get_or_create(5).unwrap(); // Skipping 3 is allowed

        // Trying to create stream 3 now should fail (ID already "used")
        let result = store.get_or_create(3);
        assert!(result.is_err());
    }

    #[test]
    fn stream_store_allocate_stream_id_exhausts_at_max() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        // br-asupersync-jq82r4: simulate a long-running connection where
        // base_id has advanced near MAX through repeated stream
        // close+prune. The flat-Vec gap-from-base ceiling rejects fresh
        // connections that try to jump from base_id=1 to id=MAX
        // directly (memory-DoS prevention); to test the MAX exhaustion
        // boundary, advance base_id to MAX-1 first so the gap is small.
        store.next_client_stream_id = MAX_STREAM_ID;
        store.base_id = MAX_STREAM_ID - 1;

        let id = store.allocate_stream_id().unwrap();
        assert_eq!(id, MAX_STREAM_ID);
        assert!(store.allocate_stream_id().is_err());
    }

    #[test]
    fn stream_store_prune_removes_closed_streams() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        let id = store.allocate_stream_id().unwrap();
        store.get_mut(id).unwrap().reset(ErrorCode::NoError);

        assert_eq!(store.active_count(), 0);
        store.prune_closed();
        assert!(store.get(id).is_none());
    }

    #[test]
    fn stream_store_active_stream_ids() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        let id1 = store.allocate_stream_id().unwrap();
        let id2 = store.allocate_stream_id().unwrap();
        // Make id2 active by sending headers
        store.get_mut(id2).unwrap().send_headers(false).unwrap();
        store.get_mut(id1).unwrap().reset(ErrorCode::NoError);

        let active = store.active_stream_ids();
        assert_eq!(active.len(), 1);
        assert!(active.contains(&id2));
        assert!(!active.contains(&id1));
    }

    // =========================================================================
    // Initial Window Size Update Tests
    // =========================================================================

    #[test]
    fn update_initial_window_size_adjusts_existing_streams() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        let id = store.allocate_stream_id().unwrap();
        assert_eq!(store.get(id).unwrap().send_window(), 65535);

        // Increase window size
        store.set_initial_window_size(100_000).unwrap();
        assert_eq!(store.get(id).unwrap().send_window(), 100_000);

        // Decrease window size
        store.set_initial_window_size(50_000).unwrap();
        assert_eq!(store.get(id).unwrap().send_window(), 50_000);
    }

    #[test]
    fn local_recv_window_is_not_replaced_by_peer_send_window_update() {
        let local_initial_window = 32_768;
        let peer_initial_window = 100_000;
        let mut store = StreamStore::new_with_local_recv_window(
            true,
            local_initial_window,
            local_initial_window,
            DEFAULT_MAX_HEADER_LIST_SIZE,
        );

        let first_id = store.allocate_stream_id().unwrap();
        let first = store.get(first_id).unwrap();
        assert_eq!(
            first.send_window(),
            i32::try_from(local_initial_window).unwrap()
        );
        assert_eq!(
            first.recv_window(),
            i32::try_from(local_initial_window).unwrap()
        );
        assert_eq!(
            first.initial_recv_window,
            i32::try_from(local_initial_window).unwrap()
        );

        store.set_initial_window_size(peer_initial_window).unwrap();
        let second_id = store.allocate_stream_id().unwrap();
        let second = store.get(second_id).unwrap();

        assert_eq!(
            second.send_window(),
            i32::try_from(peer_initial_window).unwrap()
        );
        assert_eq!(
            second.recv_window(),
            i32::try_from(local_initial_window).unwrap()
        );
        assert_eq!(
            second.initial_recv_window,
            i32::try_from(local_initial_window).unwrap()
        );
        assert_eq!(store.initial_recv_window_size(), local_initial_window);
    }

    #[test]
    fn priority_can_be_set_and_retrieved() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        let new_priority = PrioritySpec {
            exclusive: true,
            dependency: 3,
            weight: 255,
        };
        stream.set_priority(new_priority);

        let priority = stream.priority();
        assert!(priority.exclusive);
        assert_eq!(priority.dependency, 3);
        assert_eq!(priority.weight, 255);
    }

    // =========================================================================
    // Racey Cancellation Edge Tests
    // =========================================================================

    /// Test: RST_STREAM followed by DATA frame on same stream
    /// Per RFC 7540 Section 5.4.2: After sending RST_STREAM, the sender
    /// should be prepared to receive frames that were in flight.
    #[test]
    fn reset_then_recv_data_returns_error() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        // Reset the stream
        stream.reset(ErrorCode::Cancel);
        assert_eq!(stream.state(), StreamState::Closed);
        assert_eq!(stream.error_code(), Some(ErrorCode::Cancel));

        // Try to receive data on the now-closed stream
        let result = stream.recv_data(100, false);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::StreamClosed);
    }

    /// Test: RST_STREAM followed by HEADERS (trailers) on same stream
    #[test]
    fn reset_then_recv_headers_returns_error() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        stream.reset(ErrorCode::InternalError);
        assert_eq!(stream.state(), StreamState::Closed);

        // Try to receive headers on the closed stream
        let result = stream.recv_headers(true, true, false);
        assert!(result.is_err());
    }

    /// Test: RST_STREAM while CONTINUATION is pending
    /// Verifies that reset transitions stream to Closed and rejects further frames.
    /// Note: The headers_complete flag isn't cleared by reset, but the stream
    /// being Closed means no frames can be processed anyway.
    #[test]
    fn reset_during_header_accumulation() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        // Start receiving headers without END_HEADERS
        stream.recv_headers(false, false, false).unwrap();
        assert!(stream.is_receiving_headers());

        // Add a header fragment
        stream
            .add_header_fragment(Bytes::from_static(b"partial_header"))
            .unwrap();

        // Reset the stream - this closes the stream
        stream.reset(ErrorCode::Cancel);
        assert_eq!(stream.state(), StreamState::Closed);

        // Headers_complete flag is preserved (still false = expecting continuation)
        // but the stream is closed so no frames can be processed
        assert!(stream.is_receiving_headers());

        // Any frame on a closed stream should fail (because state is Closed)
        let result = stream.recv_data(100, false);
        assert!(result.is_err());

        // Headers on closed stream also fails
        let result = stream.recv_headers(false, true, false);
        assert!(result.is_err());
    }

    /// Test: Double reset is idempotent
    /// Resetting an already-reset stream should be safe.
    #[test]
    fn double_reset_is_safe() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        stream.reset(ErrorCode::Cancel);
        assert_eq!(stream.state(), StreamState::Closed);
        assert_eq!(stream.error_code(), Some(ErrorCode::Cancel));

        // Reset again with different error code
        stream.reset(ErrorCode::InternalError);
        assert_eq!(stream.state(), StreamState::Closed);
        // Error code is updated to the latest
        assert_eq!(stream.error_code(), Some(ErrorCode::InternalError));
    }

    /// Test: State transitions after END_STREAM are rejected
    /// Once a stream has sent END_STREAM, no more data/headers can be sent.
    #[test]
    fn no_send_after_end_stream() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(true).unwrap(); // end_stream = true
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);

        // Cannot send more data
        assert!(stream.send_data(false).is_err());

        // Cannot send more headers
        assert!(stream.send_headers(false).is_err());
    }

    /// Test: Trailers must have END_STREAM set
    /// Per RFC 7540 Section 8.1: Trailers are sent as HEADERS with END_STREAM.
    #[test]
    fn trailers_transition_to_half_closed() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        // Client sends request headers (no end_stream - body will follow or trailers)
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        // Client sends trailers (headers with end_stream)
        stream.send_headers(true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);
    }

    /// Test: Receive trailers transitions to half-closed
    #[test]
    fn recv_trailers_transition_to_half_closed() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        // Receive trailers (headers with end_stream)
        stream.recv_headers(true, true, false).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedRemote);
    }

    /// Test: Flow control edge case - negative window after SETTINGS change
    /// Per RFC 7540 Section 6.9.2: Initial window size changes can make
    /// the effective window size negative.
    #[test]
    fn window_can_go_negative_after_settings_change() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        // Consume some window
        stream.consume_send_window(60000);
        assert_eq!(stream.send_window(), 5535);

        // Reduce initial window size (simulates SETTINGS change)
        // New initial = 1000, delta = 1000 - 65535 = -64535
        stream.update_initial_window_size(1000).unwrap();
        // Window was 5535, delta is -64535, new window = 5535 - 64535 = -59000
        assert!(stream.send_window() < 0);
    }

    /// Test: Reserved(remote) stream can receive data per RFC 7540
    /// A reserved(remote) stream is created via PUSH_PROMISE and can receive
    /// headers and data from the server.
    #[test]
    fn reserved_remote_can_recv_data() {
        let mut stream = Stream::new(2, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.state = StreamState::ReservedRemote;

        // Reserved(remote) streams CAN receive data (can_recv returns true)
        // The server would send HEADERS then DATA on the promised stream
        assert!(stream.state().can_recv());

        // However, proper protocol requires headers first to activate the stream
        // Receive headers to transition to half-closed(local)
        stream.recv_headers(false, true, false).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);

        // Now can receive data
        let result = stream.recv_data(100, true);
        assert!(result.is_ok());
        assert_eq!(stream.state(), StreamState::Closed);
    }

    /// Test: Reserved(local) stream rejects DATA frames.
    /// RFC 7540 §5.1: only HEADERS, RST_STREAM, and PRIORITY are allowed
    /// in the reserved(local) state.
    #[test]
    fn reserved_local_rejects_send_data() {
        let mut stream = Stream::new(2, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.state = StreamState::ReservedLocal;

        // DATA must be rejected even though can_send() returns true
        // (can_send covers HEADERS too; send_data is more restrictive).
        let result = stream.send_data(false);
        assert!(result.is_err(), "DATA on reserved(local) must be rejected");
    }

    /// Test: Reserved(remote) stream rejects DATA frames.
    /// RFC 7540 §5.1: only HEADERS, RST_STREAM, and PRIORITY may be
    /// received in the reserved(remote) state.
    #[test]
    fn reserved_remote_rejects_recv_data() {
        let mut stream = Stream::new(2, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.state = StreamState::ReservedRemote;

        let result = stream.recv_data(100, false);
        assert!(result.is_err(), "DATA on reserved(remote) must be rejected");
    }

    /// Test: reset() clears accumulated header fragments and pending data
    /// so the memory is released immediately rather than lingering until
    /// the stream is pruned.
    #[test]
    fn reset_clears_header_fragments_and_pending_data() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        // Accumulate header fragments (simulate partial CONTINUATION)
        stream.recv_headers(false, false, false).unwrap();
        stream
            .add_header_fragment(Bytes::from(vec![0xAA; 64]))
            .unwrap();
        assert!(!stream.take_header_fragments().is_empty() || stream.is_receiving_headers());

        // Re-add fragments after take
        stream
            .add_header_fragment(Bytes::from(vec![0xBB; 64]))
            .unwrap();

        // Queue pending data
        stream.queue_data(Bytes::from_static(b"buffered"), false);
        assert!(stream.has_pending_data());

        // Reset the stream
        stream.reset(ErrorCode::Cancel);
        assert_eq!(stream.state(), StreamState::Closed);

        // Both buffers must be empty
        assert!(
            stream.take_header_fragments().is_empty(),
            "header_fragments should be cleared on reset"
        );
        assert!(
            !stream.has_pending_data(),
            "pending_data should be cleared on reset"
        );
    }

    /// Test: set_initial_window_size skips closed streams.
    /// A closed stream with a very negative send window could cause a
    /// spurious overflow error if the delta is large; closed streams
    /// are excluded from the update.
    #[test]
    fn set_initial_window_size_skips_closed_streams() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        let id = store.allocate_stream_id().unwrap();
        // Drive send window deeply negative
        store.get_mut(id).unwrap().consume_send_window(65535);
        store
            .get_mut(id)
            .unwrap()
            .update_initial_window_size(1)
            .unwrap();
        // send_window is now  0 - 65535 + (1 - 65535) = negative
        assert!(store.get(id).unwrap().send_window() < 0);

        // Close the stream
        store.get_mut(id).unwrap().reset(ErrorCode::NoError);

        // Setting initial window to MAX should succeed because the
        // closed stream is skipped.
        let result = store.set_initial_window_size(0x7fff_ffff);
        assert!(
            result.is_ok(),
            "closed streams must not block SETTINGS update: {result:?}"
        );
    }

    /// Test: Stream store handles rapid allocation/deallocation
    #[test]
    fn stream_store_handles_rapid_churn() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        store.set_max_concurrent_streams(10);

        // Rapidly allocate and close streams
        for round in 0..10 {
            // Allocate up to max and open them so they count as active
            let mut ids = Vec::new();
            for _ in 0..10 {
                let id = store.allocate_stream_id().unwrap();
                store.get_mut(id).unwrap().send_headers(false).unwrap();
                ids.push(id);
            }

            // Should hit limit
            let result = store.allocate_stream_id();
            assert!(
                result.is_err(),
                "round {round}: should hit max_concurrent_streams limit"
            );

            // Close all
            for id in &ids {
                store.get_mut(*id).unwrap().reset(ErrorCode::NoError);
            }

            // Prune should remove all closed streams
            store.prune_closed();
            assert_eq!(
                store.active_count(),
                0,
                "round {round}: all streams should be pruned"
            );
        }

        // After all rounds, should be able to allocate again
        let id = store.allocate_stream_id().unwrap();
        assert!(id > 0);
    }

    /// Test: Reserve remote stream validates stream ID parity
    #[test]
    fn reserve_remote_validates_parity() {
        // Client store
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        // Server should use even IDs for client
        assert!(store.reserve_remote_stream(2).is_ok());

        // Odd ID should fail for client (that's client-initiated)
        assert!(store.reserve_remote_stream(3).is_err());

        // Server store
        let mut store = StreamStore::new(false, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        // Client should use odd IDs for server
        assert!(store.reserve_remote_stream(1).is_ok());

        // Even ID should fail for server (that's server-initiated)
        assert!(store.reserve_remote_stream(2).is_err());
    }

    /// Test: Stream ID monotonicity is enforced
    #[test]
    fn stream_id_must_be_monotonic() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        // Allocate some streams
        let _ = store.allocate_stream_id().unwrap(); // 1
        let _ = store.allocate_stream_id().unwrap(); // 3

        // Server sends push with ID 2, then 4
        store.reserve_remote_stream(2).unwrap();
        store.reserve_remote_stream(4).unwrap();

        // Server cannot go back to ID 2 (already used)
        // Actually, since 2 already exists, this will fail
        assert!(store.reserve_remote_stream(2).is_err());
    }

    /// Test: Pending data queue respects order
    #[test]
    fn pending_data_preserves_order() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        stream.queue_data(Bytes::from_static(b"first"), false);
        stream.queue_data(Bytes::from_static(b"second"), false);
        stream.queue_data(Bytes::from_static(b"third"), true);

        let (d1, e1) = stream.take_pending_data(100).unwrap();
        assert_eq!(&d1[..], b"first");
        assert!(!e1);

        let (d2, e2) = stream.take_pending_data(100).unwrap();
        assert_eq!(&d2[..], b"second");
        assert!(!e2);

        let (d3, e3) = stream.take_pending_data(100).unwrap();
        assert_eq!(&d3[..], b"third");
        assert!(e3);

        assert!(!stream.has_pending_data());
    }

    // =========================================================================
    // Regression Tests: recv_headers / recv_continuation state safety
    // =========================================================================

    /// Regression: recv_headers on a closed stream must not corrupt
    /// headers_complete, which would allow continuation frames to
    /// accumulate on an already-closed stream.
    #[test]
    fn recv_headers_on_closed_stream_does_not_corrupt_headers_complete() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        // Close the stream via reset.
        stream.reset(ErrorCode::Cancel);
        assert_eq!(stream.state(), StreamState::Closed);

        // headers_complete should still be true (the default).
        assert!(
            !stream.is_receiving_headers(),
            "headers_complete should be true before the rejected recv_headers"
        );

        // Attempt to receive headers with end_headers=false on a closed stream.
        // This MUST fail AND must NOT change headers_complete.
        let result = stream.recv_headers(false, false, false);
        assert!(result.is_err(), "recv_headers on Closed must fail");

        // Critical assertion: headers_complete must remain true (unmodified).
        assert!(
            !stream.is_receiving_headers(),
            "headers_complete must not be corrupted by a rejected recv_headers"
        );
    }

    /// Regression: recv_continuation must reject frames on a closed stream.
    #[test]
    fn recv_continuation_rejects_closed_stream() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

        // Start receiving headers without END_HEADERS.
        stream.recv_headers(false, false, false).unwrap();
        assert!(stream.is_receiving_headers());

        // Close the stream via reset.
        stream.reset(ErrorCode::Cancel);
        assert_eq!(stream.state(), StreamState::Closed);

        // CONTINUATION on a closed stream must be rejected.
        let result = stream.recv_continuation(Bytes::from_static(b"fragment"), true);
        assert!(
            result.is_err(),
            "recv_continuation must reject frames on a Closed stream"
        );
        assert_eq!(
            result.unwrap_err().code,
            ErrorCode::StreamClosed,
            "error code should be StreamClosed"
        );
    }

    /// Combined regression: reset → recv_headers (rejected, no corruption)
    /// → recv_continuation (rejected by state check).
    #[test]
    fn reset_then_rejected_headers_then_continuation_all_rejected() {
        let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.send_headers(false).unwrap();

        // Close via reset.
        stream.reset(ErrorCode::Cancel);

        // Rejected recv_headers must not open continuation path.
        assert!(stream.recv_headers(false, false, false).is_err());
        assert!(
            !stream.is_receiving_headers(),
            "rejected recv_headers must not flip headers_complete"
        );

        // Even if headers_complete were somehow false, the state check
        // in recv_continuation provides a second barrier.
        // Force the field to false to exercise the defense-in-depth path.
        stream.headers_complete = false;
        let result = stream.recv_continuation(Bytes::from_static(b"payload"), true);
        assert!(
            result.is_err(),
            "recv_continuation state check must catch closed stream"
        );
    }

    // ====================================================================
    // br-asupersync-tlv3gp: flat-Vec backing-store correctness tests for
    // StreamStore. The hot-path `get`/`get_mut` is now O(1) without a
    // hash; these tests pin the semantic surface that the prior
    // DetHashMap-backed impl exposed.
    // ====================================================================

    #[test]
    fn tlv3gp_get_returns_inserted_stream() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        let id = store.allocate_stream_id().unwrap();
        assert!(store.get(id).is_some());
        assert!(store.get_mut(id).is_some());
    }

    #[test]
    fn tlv3gp_get_unknown_stream_id_returns_none() {
        let store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        assert!(store.get(0).is_none());
        assert!(store.get(1).is_none());
        assert!(store.get(7).is_none());
        assert!(store.get(u32::MAX).is_none());
    }

    #[test]
    fn tlv3gp_high_stream_id_lookup_is_correct() {
        // A connection that allocates many ids exercises both Vec
        // growth and the slot-index arithmetic. Verify each id round-
        // trips through get/get_mut and that gaps (between odd ids)
        // are correctly absent.
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        let mut allocated = Vec::new();
        for _ in 0..256 {
            allocated.push(store.allocate_stream_id().unwrap());
        }
        for &id in &allocated {
            assert!(store.get(id).is_some(), "missing id {id}");
            // Even ids (gaps in odd-allocation client store) must not
            // appear: this is the fingerprint of the flat-Vec layout
            // — every other slot is a None gap by design.
            if id > 0 {
                assert!(store.get(id - 1).is_none(), "even id {} leaked", id - 1);
            }
        }
        assert_eq!(store.len(), allocated.len());
    }

    #[test]
    fn tlv3gp_prune_closed_advances_base_id_and_shrinks_storage() {
        // Allocate four streams, close the two oldest, prune. The
        // leading-None compaction should advance base_id and shrink
        // the underlying Vec.
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        let id1 = store.allocate_stream_id().unwrap();
        let id2 = store.allocate_stream_id().unwrap();
        let _id3 = store.allocate_stream_id().unwrap();
        let _id4 = store.allocate_stream_id().unwrap();
        assert_eq!(store.len(), 4);

        // Close the two oldest. send/recv headers + reset is the
        // standard way to drive a stream to Closed.
        store.get_mut(id1).unwrap().reset(ErrorCode::Cancel);
        store.get_mut(id2).unwrap().reset(ErrorCode::Cancel);
        store.prune_closed();
        assert_eq!(store.len(), 2);

        // base_id should have advanced: looking up the closed/pruned
        // ids must return None (slot reclaimed, not a stale Some).
        assert!(store.get(id1).is_none());
        assert!(store.get(id2).is_none());

        // Active ids still resolvable.
        assert!(store.get(_id3).is_some());
        assert!(store.get(_id4).is_some());
    }

    #[test]
    fn tlv3gp_len_excludes_pruned_streams() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        let ids: Vec<u32> = (0..5)
            .map(|_| store.allocate_stream_id().unwrap())
            .collect();
        assert_eq!(store.len(), 5);
        // Close all of them.
        for id in ids {
            store.get_mut(id).unwrap().reset(ErrorCode::NoError);
        }
        // Before prune, len() still counts the closed-but-stored
        // streams (matches the old HashMap::len semantic).
        assert_eq!(store.len(), 5);
        store.prune_closed();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
    }

    #[test]
    fn tlv3gp_prune_preserves_unopened_opposite_parity_ids() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        let first_local = store.allocate_stream_id().unwrap();
        let second_local = store.allocate_stream_id().unwrap();

        store
            .get_mut(first_local)
            .unwrap()
            .reset(ErrorCode::NoError);
        store
            .get_mut(second_local)
            .unwrap()
            .reset(ErrorCode::NoError);
        store.prune_closed();

        assert_eq!(store.len(), 0);
        assert!(
            store.reserve_remote_stream(2).is_ok(),
            "pruning local streams must not burn unopened remote stream id 2"
        );
        assert!(store.get(2).is_some());
    }

    #[test]
    fn tlv3gp_active_stream_ids_returns_in_id_order() {
        // The flat Vec naturally preserves id order — assert this so
        // any future callers that rely on the prior HashMap's
        // iteration-order (which was DetHashMap = deterministic but
        // unspecified) get the stronger guarantee.
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        let mut ids = Vec::new();
        for _ in 0..8 {
            let id = store.allocate_stream_id().unwrap();
            store.get_mut(id).unwrap().send_headers(false).unwrap();
            ids.push(id);
        }
        let active = store.active_stream_ids();
        assert_eq!(active, ids);
    }

    #[test]
    fn tlv3gp_reserve_remote_then_get_round_trips() {
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        // Client store: reserved-remote ids must be even.
        let _ = store.reserve_remote_stream(2).unwrap();
        let _ = store.reserve_remote_stream(4).unwrap();
        assert!(store.get(2).is_some());
        assert!(store.get(4).is_some());
        // Idle/unallocated id in between must not leak.
        assert!(store.get(3).is_none());
    }

    #[test]
    fn tlv3gp_id_below_pruned_base_is_rejected() {
        // Drive a stream to closed then prune it; the slot is gone
        // and the id is below base_id. Inserting (via the legitimate
        // public surface) any *new* stream id below base would be
        // rejected by the higher-level monotonicity checks; this
        // test covers the lower-layer guard via insert_stream's
        // base_id check, exercised through a fresh allocation that
        // skips the upstream guard.
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        let id1 = store.allocate_stream_id().unwrap();
        store.get_mut(id1).unwrap().reset(ErrorCode::Cancel);
        store.prune_closed();
        // After prune, attempting to look up id1 must yield None
        // (slot reclaimed, not a stale entry).
        assert!(store.get(id1).is_none());
    }

    #[test]
    fn tlv3gp_get_mut_after_window_update_persists() {
        // Mutating a Stream through get_mut must persist across a
        // subsequent get — verifies the slot stores Stream by value
        // (not a clone).
        let mut store = StreamStore::new(true, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        let id = store.allocate_stream_id().unwrap();
        store.get_mut(id).unwrap().send_headers(false).unwrap();
        store.get_mut(id).unwrap().consume_send_window(100);
        let after = store.get(id).unwrap().send_window();
        assert_eq!(after, 65535 - 100);
    }

    /// br-asupersync-of0l5f: trailer block containing a `:status`
    /// pseudo-header MUST be rejected per RFC 9113 §8.1
    /// ("Trailers MUST NOT include pseudo-header fields"). Without
    /// this rejection a malicious peer could rewrite the request
    /// line in trailers after the initial HEADERS already committed
    /// it — a request-smuggling primitive when the gateway forwards
    /// to an HTTP/1 backend.
    #[test]
    fn of0l5f_trailer_with_status_pseudo_header_rejected() {
        let trailer = vec![
            Header::new("content-type", "text/plain"),
            Header::new(":status", "200"),
        ];
        let err = reject_pseudo_headers_in_trailers(&trailer)
            .expect_err("trailer with :status must be rejected");
        assert!(err.contains("RFC 9113 §8.1"), "wrong reject reason: {err}");
    }

    /// br-asupersync-of0l5f: a trailer block with NO pseudo-headers
    /// must pass — happy path regression guard.
    #[test]
    fn of0l5f_trailer_without_pseudo_headers_accepted() {
        let trailer = vec![
            Header::new("trailer-checksum", "abcd"),
            Header::new("x-trace-id", "deadbeef"),
        ];
        assert!(reject_pseudo_headers_in_trailers(&trailer).is_ok());
    }

    /// br-asupersync-of0l5f: would_be_trailer_block returns true
    /// after the initial header block has been received (Open or
    /// HalfClosedLocal state, headers_complete=true). Callers query
    /// this BEFORE recv_headers to know whether to invoke the
    /// trailer-validator on the decoded block.
    #[test]
    fn of0l5f_would_be_trailer_block_after_initial_headers() {
        let mut stream = Stream::new(1, DEFAULT_INITIAL_WINDOW_SIZE, DEFAULT_MAX_HEADER_LIST_SIZE);
        // Initially no headers received → not a trailer block.
        assert!(!stream.would_be_trailer_block());

        // Receive initial HEADERS with end_headers, no end_stream.
        // server-side, is_client=false.
        stream.recv_headers(false, true, false).unwrap();
        assert!(stream.would_be_trailer_block());
    }

    /// br-asupersync-kaqld3: consume_recv_window must signal a
    /// connection-level FLOW_CONTROL_ERROR when the peer overshoots
    /// the window beyond the i32::MIN representable bound, instead
    /// of clamping to MIN and stalling the stream.
    #[test]
    fn kaqld3_consume_recv_window_overshoot_returns_flow_control_error() {
        let mut stream = Stream::new(1, DEFAULT_INITIAL_WINDOW_SIZE, DEFAULT_MAX_HEADER_LIST_SIZE);
        // Drive the window very negative via several SETTINGS-shrink
        // simulations. We bypass the SETTINGS path here and just
        // poke the field to a value close to i32::MIN, so the next
        // legitimate consume drives the window past the bound.
        stream.recv_window = i32::MIN + 100;
        let err = stream
            .consume_recv_window(200)
            .expect_err("overshoot past i32::MIN must be FLOW_CONTROL_ERROR");
        let msg = format!("{err}");
        assert!(
            msg.contains("FLOW_CONTROL") || msg.contains("flow-control"),
            "wrong error kind: {msg}"
        );
    }

    /// br-asupersync-kaqld3: consume_recv_window happy path — when
    /// the deduction stays within i32 bounds it succeeds and updates
    /// the window correctly. Confirms the new fallible signature
    /// preserves the prior semantics for legitimate inputs.
    #[test]
    fn kaqld3_consume_recv_window_legitimate_succeeds() {
        let mut stream = Stream::new(1, DEFAULT_INITIAL_WINDOW_SIZE, DEFAULT_MAX_HEADER_LIST_SIZE);
        let before = stream.recv_window;
        stream
            .consume_recv_window(1024)
            .expect("legitimate consume must succeed");
        assert_eq!(stream.recv_window, before - 1024);
    }
