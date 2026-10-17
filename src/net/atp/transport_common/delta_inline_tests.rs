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
