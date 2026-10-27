    use super::*;
    use serde_json::{Value, json};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Serves at most `cap` bytes per poll, like `crate::fs::File` does since
    /// its poll path hops to the blocking pool in bounded pieces.
    struct ShortReader {
        data: Vec<u8>,
        pos: usize,
        cap: usize,
    }

    #[test]
    fn streaming_cdc_matches_complete_input_boundaries_under_short_reads() {
        for len in [0, 1, 16_383, 16_384, 65_535, 65_536, 65_537, 131_073, 2_000_003] {
            let mut state = 0x6a09_e667_f3bc_c909u64;
            let data = (0..len).map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            }).collect::<Vec<_>>();
            let expected = cdc::chunk_spans(&data).into_iter()
                .map(|(offset, len)| data[offset..offset + len].to_vec())
                .collect::<Vec<_>>();
            for cap in [1, 997, 128 * 1024] {
                let mut reader = cdc::ChunkReader::new(ShortReader {
                    data: data.clone(), pos: 0, cap,
                });
                let chunks = futures_lite::future::block_on(async {
                    let mut chunks = Vec::new();
                    while let Some(chunk) = reader.next_chunk().await.unwrap() {
                        assert!(chunk.len() <= cdc::MAX_CHUNK_BYTES);
                        chunks.push(chunk);
                    }
                    assert!(reader.next_chunk().await.unwrap().is_none());
                    chunks
                });
                assert_eq!(chunks, expected, "input {len}, read cap {cap}");
                assert_eq!(chunks.concat(), data);
            }
        }
    }

    #[test]
    fn streaming_cdc_merges_short_tail_without_changing_the_last_full_boundary() {
        for byte in [0, 0x37, 0xff] {
            for len in [16_385, 65_537, 81_919, 131_081] {
                let data = vec![byte; len];
                let spans = cdc::chunk_spans(&data);
                let mut reader = cdc::ChunkReader::new(ShortReader {
                    data: data.clone(), pos: 0, cap: 523,
                });
                futures_lite::future::block_on(async {
                    for (offset, size) in spans {
                        let chunk = reader.next_chunk().await.unwrap().unwrap();
                        assert_eq!(chunk, data[offset..offset + size]);
                    }
                    assert!(reader.next_chunk().await.unwrap().is_none());
                });
            }
        }
    }

    impl crate::io::AsyncRead for ShortReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut crate::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let n = buf
                .remaining()
                .min(this.cap)
                .min(this.data.len() - this.pos);
            buf.put_slice(&this.data[this.pos..this.pos + n]);
            this.pos += n;
            Poll::Ready(Ok(()))
        }
    }

    /// asupersync-u4j7sr: a chunk is the whole buffer (or the tail at EOF),
    /// not whatever one bounded read happened to return.
    #[test]
    fn read_full_chunk_fills_the_buffer_across_short_reads() {
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let mut reader = ShortReader {
            data: data.clone(),
            pos: 0,
            cap: 128 * 1024,
        };
        let mut buf = vec![0u8; 256 * 1024];

        let first = futures_lite::future::block_on(read_full_chunk(&mut reader, &mut buf)).unwrap();
        assert_eq!(first, buf.len(), "one 128 KiB read is not a chunk");
        assert_eq!(&buf[..first], &data[..first]);

        let second =
            futures_lite::future::block_on(read_full_chunk(&mut reader, &mut buf)).unwrap();
        assert_eq!(
            second,
            data.len() - 256 * 1024,
            "the final chunk is the tail"
        );
        assert_eq!(&buf[..second], &data[256 * 1024..]);

        let eof = futures_lite::future::block_on(read_full_chunk(&mut reader, &mut buf)).unwrap();
        assert_eq!(eof, 0);
    }

    fn assert_legacy_request_fixture(fixture: Value, expected_mode: DeltaWireMode) {
        let decoded: DeltaObjectRequest =
            serde_json::from_value(fixture.clone()).expect("decode legacy delta request fixture");
        assert_eq!(decoded.mode, expected_mode);
        assert_eq!(
            serde_json::to_value(decoded).expect("encode legacy delta request fixture"),
            fixture
        );
    }

    #[test]
    fn legacy_delta_object_request_json_schema_is_stable() {
        assert_legacy_request_fixture(
            json!({
                "mode": "full_object",
                "fallback_reason": "receiver_delta_state_unavailable",
                "sender_merkle_root_hex": "11".repeat(32),
                "receiver_merkle_root_hex": "22".repeat(32),
                "missing_bytes": 0,
                "shared_chunks": 0,
                "stale_chunks": 0,
                "missing_chunks": []
            }),
            DeltaWireMode::FullObject,
        );
        assert_legacy_request_fixture(
            json!({
                "mode": "delta_chunks",
                "sender_merkle_root_hex": "33".repeat(32),
                "receiver_merkle_root_hex": "44".repeat(32),
                "missing_bytes": 7,
                "shared_chunks": 3,
                "stale_chunks": 1,
                "missing_chunks": [{
                    "index": 4,
                    "entry_index": 2,
                    "rel_path": "tree/leaf.bin",
                    "entry_offset": 9,
                    "stream_offset": 15,
                    "size_bytes": 7,
                    "content_id_hex": "55".repeat(32)
                }]
            }),
            DeltaWireMode::DeltaChunks,
        );
        assert_legacy_request_fixture(
            json!({
                "mode": "already_in_sync",
                "sender_merkle_root_hex": "66".repeat(32),
                "missing_bytes": 0,
                "shared_chunks": 9,
                "stale_chunks": 0,
                "missing_chunks": []
            }),
            DeltaWireMode::AlreadyInSync,
        );
    }

    #[test]
    fn legacy_delta_manifest_json_schema_is_stable() {
        let fixture = json!({
            "schema": "asupersync.atp.tcp.delta-chunk-manifest.v1",
            "tree_id": "tree-a",
            "chunk_size": 65536,
            "total_size_bytes": 7,
            "merkle_root_hex": "77".repeat(32),
            "chunks": [{
                "index": 4,
                "entry_index": 2,
                "rel_path": "tree/leaf.bin",
                "entry_offset": 9,
                "stream_offset": 15,
                "size_bytes": 7,
                "content_id_hex": "88".repeat(32)
            }]
        });
        let decoded: DeltaManifestWire =
            serde_json::from_value(fixture.clone()).expect("decode legacy delta manifest fixture");

        assert_eq!(
            serde_json::to_value(decoded).expect("encode legacy delta manifest fixture"),
            fixture
        );
    }

    // --- br-asupersync-sizeku: content-defined delta chunker (cdc) ---

    fn cdc_fixture(len: usize, seed: u32) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|idx| {
                state = state
                    .wrapping_mul(1_664_525)
                    .wrapping_add(1_013_904_223)
                    .wrapping_add(u32::try_from(idx & 0xffff).expect("masked index fits"));
                (state >> 16) as u8
            })
            .collect()
    }

    fn cdc_chunks(data: &[u8]) -> Vec<Vec<u8>> {
        cdc::chunk_spans(data)
            .into_iter()
            .map(|(offset, len)| data[offset..offset + len].to_vec())
            .collect()
    }

    #[test]
    fn cdc_spans_tile_the_input_and_stay_in_bounds() {
        let data = cdc_fixture(512 * 1024, 0x5eed);
        let chunks = cdc_chunks(&data);
        assert_eq!(chunks.concat(), data, "spans must exactly tile the input");
        assert!(chunks.len() > 2, "256KiB fixed chunks would give only two");
        let nonfinal = chunks.len().saturating_sub(1);
        assert!(
            chunks
                .iter()
                .take(nonfinal)
                .all(|c| c.len() >= cdc::MIN_CHUNK_BYTES && c.len() <= cdc::MAX_CHUNK_BYTES),
            "every non-final chunk must be within [MIN, MAX]"
        );
        assert!(
            chunks.iter().any(|c| c.len() < cdc::MAX_CHUNK_BYTES),
            "gear hash should find a content boundary before the hard cap"
        );
    }

    #[test]
    fn cdc_resynchronizes_after_insert() {
        // The insert win: an inserted region costs ~one new chunk; the shifted
        // tail re-synchronizes and keeps its content (fixed-size chunking would
        // change every later chunk).
        let mut data = cdc_fixture(768 * 1024, 0xfeed);
        let original = cdc_chunks(&data);
        data.splice(96 * 1024..96 * 1024, [0xA5; 257]);
        let shifted = cdc_chunks(&data);

        let original_set: std::collections::BTreeSet<Vec<u8>> = original.iter().cloned().collect();
        let shared = shifted.iter().filter(|c| original_set.contains(*c)).count();
        assert!(
            shared * 2 >= original.len(),
            "CDC must resync after a small insert (shared={shared}, original={})",
            original.len()
        );
    }

    #[test]
    fn cdc_localizes_a_same_length_edit() {
        let original_data = cdc_fixture(2 * 1024 * 1024, 0xabcd);
        let mut edited_data = original_data.clone();
        let (edit_start, edit_len) = (1024 * 1024, 100 * 1024);
        for (offset, byte) in edited_data[edit_start..edit_start + edit_len]
            .iter_mut()
            .enumerate()
        {
            *byte = ((offset * 73 + 19) % 251) as u8;
        }
        let original_set: std::collections::BTreeSet<Vec<u8>> =
            cdc_chunks(&original_data).into_iter().collect();
        let missing_bytes: usize = cdc_chunks(&edited_data)
            .into_iter()
            .filter(|c| !original_set.contains(c))
            .map(|c| c.len())
            .sum();
        assert!(
            missing_bytes <= 192 * 1024,
            "a 100KiB same-length edit dirtied {missing_bytes} bytes of chunks"
        );
    }

    #[test]
    fn cdc_empty_input_yields_no_spans() {
        assert!(cdc::chunk_spans(&[]).is_empty());
    }

    mod chunk_read_progress {
        use super::*;
        use crate::io::{AsyncRead, ReadBuf};
        use std::collections::VecDeque;
        use std::future::{Future, poll_fn};
        use std::io::{self, ErrorKind};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};
        use std::task::{Wake, Waker};

        enum Step {
            Bytes(usize),
            Interrupted,
            Pending,
            Fail(ErrorKind),
        }

        // Explicit AsyncRead double: controls read outcomes, not ATP logic.
        struct ScriptedReader {
            data: Vec<u8>,
            position: usize,
            polls: usize,
            steps: VecDeque<Step>,
        }

        impl ScriptedReader {
            fn new(data: &[u8], steps: impl IntoIterator<Item = Step>) -> Self {
                Self {
                    data: data.to_vec(),
                    position: 0,
                    polls: 0,
                    steps: steps.into_iter().collect(),
                }
            }
        }

        impl AsyncRead for ScriptedReader {
            fn poll_read(
                self: Pin<&mut Self>,
                task: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                this.polls += 1;
                match this.steps.pop_front().unwrap_or(Step::Bytes(usize::MAX)) {
                    Step::Interrupted => Poll::Ready(Err(ErrorKind::Interrupted.into())),
                    Step::Pending => {
                        task.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Step::Fail(kind) => {
                        Poll::Ready(Err(io::Error::new(kind, "scripted read failure")))
                    }
                    Step::Bytes(limit) => {
                        let n = limit.min(buf.remaining()).min(this.data.len() - this.position);
                        buf.put_slice(&this.data[this.position..this.position + n]);
                        this.position += n;
                        Poll::Ready(Ok(()))
                    }
                }
            }
        }

        #[derive(Default)]
        struct WakeCount(AtomicUsize);

        impl Wake for WakeCount {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        #[test]
        fn interruptions_and_pending_reads_preserve_canonical_chunks() {
            let expected = b"abcdefghijk";
            let mut reader = ScriptedReader::new(expected, [
                Step::Interrupted, Step::Bytes(2), Step::Pending,
                Step::Interrupted, Step::Bytes(1), Step::Bytes(1),
                Step::Bytes(1), Step::Interrupted, Step::Pending,
            ]);
            let mut actual = Vec::new();
            let mut lengths = Vec::new();
            loop {
                let mut buf = [0xa5; 4];
                let n = futures_lite::future::block_on(read_full_chunk(&mut reader, &mut buf))
                    .expect("transient interruptions are not transfer failures");
                assert!(buf[n..].iter().all(|byte| *byte == 0xa5));
                if n == 0 {
                    break;
                }
                lengths.push(n);
                actual.extend_from_slice(&buf[..n]);
            }
            assert_eq!(lengths, [4, 4, 3]);
            assert_eq!(actual.as_slice(), expected);
            assert_eq!(reader.position, expected.len());
        }

        #[test]
        fn ready_short_reads_yield_without_returning_a_partial_chunk() {
            let expected = vec![0x3c; 129];
            let mut reader = ScriptedReader::new(&expected, (0..129).map(|_| Step::Bytes(1)));
            let count = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&count));
            let mut task = Context::from_waker(&waker);
            let mut buf = [0xa5; 129];
            let mut wait = Box::pin(read_full_chunk(&mut reader, &mut buf));
            assert!(wait.as_mut().poll(&mut task).is_pending());
            assert_eq!(count.0.load(Ordering::SeqCst), 1);
            assert!(wait.as_mut().poll(&mut task).is_pending());
            assert_eq!(count.0.load(Ordering::SeqCst), 2);
            assert!(matches!(wait.as_mut().poll(&mut task), Poll::Ready(Ok(129))));
            drop(wait);
            assert_eq!(reader.polls, 129, "no read past the requested range");
            assert_eq!(buf.as_slice(), expected.as_slice());
        }

        #[test]
        fn interruption_only_turns_are_bounded_and_do_not_invent_eof() {
            let mut reader = ScriptedReader::new(b"x", (0..129).map(|_| Step::Interrupted));
            let count = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&count));
            let mut task = Context::from_waker(&waker);
            let mut buf = [0xa5; 1];
            let mut wait = Box::pin(read_full_chunk(&mut reader, &mut buf));
            assert!(wait.as_mut().poll(&mut task).is_pending());
            assert!(wait.as_mut().poll(&mut task).is_pending());
            assert_eq!(count.0.load(Ordering::SeqCst), 2);
            assert!(matches!(wait.as_mut().poll(&mut task), Poll::Ready(Ok(1))));
            drop(wait);
            assert_eq!(reader.polls, 130);
            assert_eq!(buf, *b"x");
        }

        #[test]
        fn permanent_errors_keep_their_kind_and_completed_prefix() {
            let mut reader = ScriptedReader::new(b"abcdef", [
                Step::Bytes(2), Step::Interrupted, Step::Fail(ErrorKind::BrokenPipe),
            ]);
            let mut buf = [0xa5; 6];
            let error = futures_lite::future::block_on(read_full_chunk(&mut reader, &mut buf))
                .expect_err("a permanent read failure must not become a partial success");
            assert_eq!(error.kind(), ErrorKind::BrokenPipe);
            assert_eq!(error.to_string(), "scripted read failure");
            assert_eq!(reader.polls, 3);
            assert_eq!(&buf[..2], b"ab");
            assert_eq!(&buf[2..], &[0xa5; 4]);
        }

        #[test]
        fn cancellation_interruptions_are_not_retried_but_masks_are_respected() {
            use crate::cx::Cx;
            use crate::types::CancelKind;

            let cx = Cx::for_testing();
            cx.cancel_fast(CancelKind::User);
            let mut reader = ScriptedReader::new(b"x", [Step::Fail(ErrorKind::Interrupted)]);
            let mut buf = [0xa5; 1];
            let error = futures_lite::future::block_on(
                cx.with_ambient(read_full_chunk(&mut reader, &mut buf)),
            ).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Interrupted);
            assert_eq!(error.to_string(), "scripted read failure");
            assert_eq!(reader.polls, 1);
            assert_eq!(buf, [0xa5]);

            let cx = Cx::for_testing();
            cx.cancel_fast(CancelKind::User);
            let mut reader = ScriptedReader::new(b"x", [Step::Interrupted]);
            let n = cx.masked(|| futures_lite::future::block_on(
                cx.with_ambient(read_full_chunk(&mut reader, &mut buf)),
            )).unwrap();
            assert_eq!(n, 1);
            assert_eq!(reader.polls, 2);
            assert_eq!(buf, *b"x");
            assert!(cx.checkpoint().is_err());
        }

        #[test]
        fn empty_and_exact_budget_reads_do_not_poll_past_their_buffers() {
            let mut reader = ScriptedReader::new(b"", [Step::Fail(ErrorKind::Other)]);
            let n = futures_lite::future::block_on(read_full_chunk(&mut reader, &mut [])).unwrap();
            assert_eq!(n, 0);
            assert_eq!(reader.polls, 0);

            let mut reader = ScriptedReader::new(&[7; 65], (0..64).map(|_| Step::Bytes(1)));
            let count = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&count));
            let mut buf = [0; 64];
            let mut wait = Box::pin(read_full_chunk(&mut reader, &mut buf));
            assert!(matches!(
                wait.as_mut().poll(&mut Context::from_waker(&waker)),
                Poll::Ready(Ok(64))
            ));
            drop(wait);
            assert_eq!(reader.polls, 64);
            assert_eq!(reader.position, 64);
            assert_eq!(count.0.load(Ordering::SeqCst), 0);
            assert_eq!(buf, [7; 64]);
        }

        #[test]
        fn native_ready_chunk_reader_allows_a_woken_peer_to_run() {
            #[derive(Default)]
            struct State {
                parked: bool,
                bytes: usize,
                waker: Option<Waker>,
            }
            struct WakePeerReader(Arc<Mutex<State>>);
            impl AsyncRead for WakePeerReader {
                fn poll_read(
                    self: Pin<&mut Self>,
                    _: &mut Context<'_>,
                    buf: &mut ReadBuf<'_>,
                ) -> Poll<io::Result<()>> {
                    buf.put_slice(&[0x37]);
                    let wake = {
                        let mut state = self.0.lock().unwrap();
                        state.bytes += 1;
                        state.waker.take()
                    };
                    if let Some(wake) = wake {
                        wake.wake();
                    }
                    Poll::Ready(Ok(()))
                }
            }

            let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
            let handle = runtime.handle().clone();
            runtime.block_on(runtime.handle().spawn(async move {
                let state = Arc::new(Mutex::new(State::default()));
                let peer_state = Arc::clone(&state);
                let peer = handle.spawn(async move {
                    poll_fn(|task| {
                        let mut state = peer_state.lock().unwrap();
                        if state.bytes != 0 {
                            return Poll::Ready(state.bytes);
                        }
                        state.parked = true;
                        state.waker = Some(task.waker().clone());
                        Poll::Pending
                    }).await
                });
                // Witness the peer's parked read before waking it; no sleep
                // or assumed spawn order substitutes for this handshake.
                for _ in 0..1024 {
                    if state.lock().unwrap().parked {
                        break;
                    }
                    crate::runtime::yield_now().await;
                }
                assert!(state.lock().unwrap().parked);
                let mut reader = WakePeerReader(state);
                let mut buf = vec![0; 64 * 1024];
                let n = read_full_chunk(&mut reader, &mut buf).await.unwrap();
                let observed = peer.await;
                assert!(observed > 0 && observed < n,
                    "peer must run during chunk assembly, observed {observed} of {n}");
                assert_eq!(n, buf.len());
                assert!(buf.iter().all(|byte| *byte == 0x37));
            }));
        }
    }
