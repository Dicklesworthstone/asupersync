    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn records_round_trip() {
        let offer = CodecOffer::new(WireCodec::Zstd.bit(), 18, 256 * 1024);
        assert_eq!(offer.to_bytes().len(), 8);
        assert_eq!(CodecOffer::from_bytes(&offer.to_bytes()), Some(offer));
        let accept = negotiate(&DecodeCapability::new(1, 20, 1 << 20), &offer).unwrap();
        assert_eq!(CodecAccept::from_bytes(&accept.to_bytes()), Some(accept));
        let chunk = ChunkCodec::new(WireCodec::Zstd, 1234);
        assert_eq!(chunk.to_bytes(), [1, 1, 0xD2, 0x04, 0, 0]);
        assert_eq!(ChunkCodec::from_bytes(&chunk.to_bytes()), Some(chunk));
    }

    #[test]
    fn unknown_versions_codecs_and_lengths_mean_no_compression() {
        let offer = CodecOffer::new(1, 18, 4096).to_bytes();
        let mut future = offer.clone();
        future[0] = 2;
        assert_eq!(CodecOffer::from_bytes(&future), None);
        assert_eq!(CodecOffer::from_bytes(&offer[..7]), None);
        let mut longer = offer;
        longer.push(0);
        assert_eq!(CodecOffer::from_bytes(&longer), None);
        assert_eq!(ChunkCodec::from_bytes(&[1, 9, 0, 0, 0, 0]), None, "codec 9");
        assert_eq!(CodecAccept::from_bytes(&[1, 9, 20, 1, 0, 0, 1, 0]), None);
        assert_eq!(ChunkCodec::from_bytes(&[]), None);
    }

    #[test]
    fn negotiation_takes_the_common_codec_and_the_smaller_limits() {
        let local = DecodeCapability::new(WireCodec::Zstd.bit(), 20, 1 << 20);
        let accept = negotiate(&local, &CodecOffer::new(1, 18, 256 * 1024)).unwrap();
        assert_eq!(accept.codec, WireCodec::Zstd);
        assert_eq!(
            (accept.max_window_log, accept.max_chunk_raw),
            (18, 256 * 1024)
        );
        let accept = negotiate(&local, &CodecOffer::new(1, 27, 8 << 20)).unwrap();
        assert_eq!((accept.max_window_log, accept.max_chunk_raw), (20, 1 << 20));
        assert_eq!(accept.decode_slots, 1);
        // Nothing in common, or a receiver that decodes nothing.
        assert_eq!(negotiate(&local, &CodecOffer::new(0b10, 18, 4096)), None);
        assert_eq!(
            negotiate(
                &DecodeCapability::new(0, 0, 4096),
                &CodecOffer::new(1, 18, 4096)
            ),
            None
        );
        assert_eq!(negotiate(&local, &CodecOffer::new(1, 18, 0)), None);
    }

    #[test]
    fn a_sender_admits_only_accepts_within_its_offer() {
        let offer = CodecOffer::new(WireCodec::Zstd.bit(), 18, 256 * 1024);
        let fitting = negotiate(&DecodeCapability::new(1, 20, 1 << 20), &offer).unwrap();
        assert!(offer.admits(&fitting));
        let mut wider = fitting;
        wider.max_chunk_raw += 1;
        assert!(!offer.admits(&wider), "a larger chunk limit than offered");
        let mut deeper = fitting;
        deeper.max_window_log = 19;
        assert!(!offer.admits(&deeper), "a larger window than offered");
        let mut no_slots = fitting;
        no_slots.decode_slots = 0;
        assert!(!offer.admits(&no_slots));
        assert!(
            !CodecOffer::new(0, 18, 256 * 1024).admits(&fitting),
            "codec not offered"
        );
    }

    #[test]
    fn extension_ids_are_unique() {
        let unique: BTreeSet<u16> = ASSIGNED_EXTENSION_IDS.into_iter().collect();
        assert_eq!(unique.len(), ASSIGNED_EXTENSION_IDS.len());
    }

    #[test]
    fn off_never_offers() {
        assert_eq!(local_offer(CompressionMode::Off, 256 * 1024), None);
        assert_eq!(CompressionMode::default(), CompressionMode::Off);
    }

    /// Auto never tries an entry whose name or first bytes mark a compressed
    /// format; Zstd tries everything and Off nothing.
    #[test]
    fn auto_skips_already_compressed_entries() {
        let text = b"plain text, plain text, plain text".as_slice();
        let tries = |mode, name: &str, offset, chunk: &[u8]| {
            EntryCompression::new(mode, name).should_try(offset, chunk)
        };
        for name in [
            "photo.JPG",
            "dir/backup.tar.gz",
            "dir\\logs.zst",
            "clip.mp4",
            "a.b.flac",
        ] {
            assert!(!tries(CompressionMode::Auto, name, 0, text), "{name}");
            assert!(tries(CompressionMode::Zstd, name, 0, text), "{name}");
        }
        for name in [
            "notes.txt",
            "Makefile",
            ".gz",
            "gz",
            "archive.gz.txt",
            "dir.zip/a.rs",
        ] {
            assert!(tries(CompressionMode::Auto, name, 0, text), "{name}");
        }
        let mut webp = b"RIFF\x10\x00\x00\x00WEBPVP8 ".to_vec();
        webp.extend_from_slice(text);
        let mut mp4 = b"\x00\x00\x00\x18ftypisom".to_vec();
        mp4.extend_from_slice(text);
        let signatures: [&[u8]; 6] = [
            &[0x1F, 0x8B, 0x08, 0x00, 0x00],
            &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00],
            b"PK\x03\x04 a zip entry",
            &[0x28, 0xB5, 0x2F, 0xFD, 0x24],
            &webp,
            &mp4,
        ];
        for head in signatures {
            assert!(
                !tries(CompressionMode::Auto, "data.bin", 0, head),
                "{head:?}"
            );
            // A signature counts only at the start of the entry.
            assert!(
                tries(CompressionMode::Auto, "data.bin", 1, head),
                "{head:?}"
            );
            assert!(
                tries(CompressionMode::Zstd, "data.bin", 0, head),
                "{head:?}"
            );
        }
        let mut gzip = EntryCompression::new(CompressionMode::Auto, "data.bin");
        assert!(!gzip.should_try(0, &[0x1F, 0x8B, 0x08]));
        assert!(!gzip.should_try(4096, text), "the whole entry stays raw");
        assert!(!tries(CompressionMode::Off, "notes.txt", 0, text));
    }

    /// The chunks Auto tries over `outcomes`, where `outcomes(i)` is the
    /// compressed size of a tried 1000-byte chunk `i` (`None`: sent raw).
    fn auto_tries(chunks: u64, outcomes: impl Fn(u64) -> Option<usize>) -> Vec<u64> {
        let mut entry = EntryCompression::new(CompressionMode::Auto, "data.bin");
        let mut tried = Vec::new();
        for index in 0..chunks {
            if entry.should_try(index * 1000, b"chunk") {
                tried.push(index);
                entry.record(1000, outcomes(index));
            }
        }
        tried
    }

    /// Misses double the raw run up to 64 chunks; a chunk that saves a
    /// twentieth ends the backoff, and one that saves less is a miss.
    #[test]
    fn auto_backs_off_from_data_that_does_not_compress() {
        assert_eq!(
            auto_tries(200, |_| None),
            [0, 2, 5, 10, 19, 36, 69, 134, 199]
        );
        // Saving 40 of 1000 bytes is a miss; 50 is not.
        assert_eq!(auto_tries(11, |_| Some(960)), [0, 2, 5, 10]);
        assert_eq!(auto_tries(5, |_| Some(950)), [0, 1, 2, 3, 4]);
        // Compressible data after a miss is tried at once after the next hit.
        assert_eq!(
            auto_tries(12, |index| (index >= 5).then_some(100)),
            [0, 2, 5, 6, 7, 8, 9, 10, 11]
        );
        // Zstd tries every chunk whatever happens.
        let mut zstd = EntryCompression::new(CompressionMode::Zstd, "photo.jpg");
        for index in 0..10 {
            assert!(zstd.should_try(index, &[0xFF, 0xD8, 0xFF]));
            zstd.record(1000, None);
        }
    }

    #[cfg(not(feature = "zstd"))]
    #[test]
    fn without_the_feature_nothing_is_offered_or_accepted() {
        assert_eq!(local_offer(CompressionMode::Zstd, 256 * 1024), None);
        let local = local_decode_capability(1 << 20);
        assert_eq!(negotiate(&local, &CodecOffer::new(1, 18, 4096)), None);
        assert_eq!(
            decompress_chunk(&[1, 1, 4, 0, 0, 0], None, 10, b"x", &mut Vec::new()),
            Err(ChunkCodecError::NotNegotiated)
        );
    }

    #[cfg(feature = "zstd")]
    mod zstd {
        use super::super::*;

        fn session() -> CodecAccept {
            let offer = local_offer(CompressionMode::Zstd, 256 * 1024).unwrap();
            negotiate(&local_decode_capability(1 << 20), &offer).unwrap()
        }

        #[test]
        fn compressible_chunks_round_trip() {
            let accept = session();
            let raw: Vec<u8> = b"asupersync transfer protocol "
                .iter()
                .copied()
                .cycle()
                .take(200_000)
                .collect();
            let (chunk, payload) = compress_chunk(&accept, &raw).unwrap();
            assert!(payload.len() < raw.len() / 10);
            let mut out = Vec::new();
            decompress_chunk(
                &chunk.to_bytes(),
                Some(&accept),
                1 << 30,
                &payload,
                &mut out,
            )
            .unwrap();
            assert_eq!(out, raw);
        }

        /// Auto offers what Zstd offers, compresses text, and stops trying
        /// noise and named or signed compressed formats.
        #[test]
        fn auto_compresses_where_it_pays() {
            assert_eq!(
                local_offer(CompressionMode::Auto, 256 * 1024),
                local_offer(CompressionMode::Zstd, 256 * 1024)
            );
            let accept = session();
            let text: Vec<u8> = b"asupersync transfer protocol "
                .iter()
                .copied()
                .cycle()
                .take(64 * 1024)
                .collect();
            let mut state = 3_u64;
            let noise: Vec<u8> = (0..64 * 1024)
                .map(|_| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    state.to_be_bytes()[0]
                })
                .collect();
            let compressed = |mode, name: &str, data: &[u8]| -> Vec<bool> {
                let mut entry = EntryCompression::new(mode, name);
                (0..8_u64)
                    .map(|index| entry.compress(&accept, index * 65_536, data).is_some())
                    .collect()
            };
            assert_eq!(
                compressed(CompressionMode::Auto, "log.txt", &text),
                [true; 8]
            );
            assert_eq!(
                compressed(CompressionMode::Auto, "log.txt", &noise),
                [false; 8]
            );
            assert_eq!(
                compressed(CompressionMode::Auto, "log.png", &text),
                [false; 8]
            );
            assert_eq!(
                compressed(CompressionMode::Zstd, "log.png", &text),
                [true; 8]
            );
            let mut gzip_head = vec![0x1F, 0x8B];
            gzip_head.extend_from_slice(&text[2..]);
            let mut entry = EntryCompression::new(CompressionMode::Auto, "log.bin");
            assert!(entry.compress(&accept, 0, &gzip_head).is_none());
            assert!(entry.compress(&accept, 65_536, &text).is_none());
        }

        /// Chunks of different kinds and sizes, so pool jobs finish out of
        /// order: text, noise every third chunk.
        fn mixed_chunks() -> Vec<Vec<u8>> {
            let mut state = 5_u64;
            (0..12_usize)
                .map(|index| {
                    let len = 4096 + (index % 4) * 60_000;
                    if index % 3 == 2 {
                        (0..len)
                            .map(|_| {
                                state = state
                                    .wrapping_mul(6_364_136_223_846_793_005)
                                    .wrapping_add(1_442_695_040_888_963_407);
                                state.to_be_bytes()[0]
                            })
                            .collect()
                    } else {
                        b"asupersync transfer protocol "
                            .iter()
                            .copied()
                            .cycle()
                            .take(len)
                            .collect()
                    }
                })
                .collect()
        }

        /// The entry chunk `position` belongs to: entries of four chunks.
        fn entry_of(position: usize) -> u32 {
            u32::try_from(position / 4).unwrap()
        }

        /// Runs `chunks` through a pipeline of `depth`, four chunks per
        /// entry, taking one out whenever it is full. Returns what came out,
        /// in order, and how many chunks went to the blocking pool.
        async fn run_pipeline(
            cx: &crate::cx::Cx,
            accept: CodecAccept,
            depth: usize,
            chunks: Vec<Vec<u8>>,
        ) -> (Vec<PipelinedChunk>, usize) {
            let mut entry = EntryCompression::new(CompressionMode::Zstd, "data.bin");
            let mut pipeline = ChunkPipeline::new(accept, depth);
            let mut out = Vec::new();
            let (mut offset, mut current) = (0_u64, 0_u32);
            for (position, chunk) in chunks.into_iter().enumerate() {
                if pipeline.is_full() {
                    let next = pipeline.next(current, &mut entry).await;
                    out.push(next.expect("a queued chunk").expect("joined"));
                }
                if entry_of(position) != current {
                    current = entry_of(position);
                    offset = 0;
                    entry = EntryCompression::new(CompressionMode::Zstd, "data.bin");
                }
                let len = u64::try_from(chunk.len()).unwrap();
                pipeline.push(cx, &mut entry, current, offset, chunk);
                assert!(pipeline.slots.len() <= depth, "at most {depth} in flight");
                offset += len;
            }
            while let Some(next) = pipeline.next(current, &mut entry).await {
                out.push(next.expect("joined"));
            }
            (out, pipeline.pooled)
        }

        /// Every chunk came back in order, with its entry and offset, and with
        /// the bytes sequential compression gives.
        fn assert_sequential(accept: &CodecAccept, chunks: &[Vec<u8>], out: &[PipelinedChunk]) {
            assert_eq!(out.len(), chunks.len());
            let mut offset = 0_u64;
            for (position, (chunk, got)) in chunks.iter().zip(out).enumerate() {
                if position % 4 == 0 {
                    offset = 0;
                }
                assert_eq!(got.index, entry_of(position), "chunk {position}");
                assert_eq!(got.offset, offset, "chunk {position}");
                assert_eq!(&got.raw, chunk, "chunk {position}");
                assert_eq!(
                    got.compressed,
                    compress_chunk(accept, chunk),
                    "chunk {position}"
                );
                offset += u64::try_from(chunk.len()).unwrap();
            }
            assert!(out.iter().any(|chunk| chunk.compressed.is_some()));
            assert!(out.iter().any(|chunk| chunk.compressed.is_none()));
        }

        /// On a runtime with a blocking pool every chunk compresses there,
        /// at most `depth` at once, and comes back in order and identical to
        /// sequential compression (br-asupersync-t1fblr.25).
        #[test]
        fn the_pipeline_compresses_on_the_blocking_pool_in_order() {
            let accept = session();
            let chunks = mixed_chunks();
            let input = chunks.clone();
            let runtime = crate::runtime::RuntimeBuilder::multi_thread()
                .build()
                .expect("runtime");
            let (out, pooled) = runtime.block_on(runtime.handle().spawn(async move {
                let cx = crate::cx::Cx::current().expect("task cx");
                run_pipeline(&cx, accept, 3, input).await
            }));
            assert_eq!(pooled, chunks.len(), "every chunk went to the pool");
            assert_sequential(&accept, &chunks, &out);
        }

        /// Without spawn authority (a test Cx) the pipeline compresses inline,
        /// with the same result.
        #[test]
        fn without_a_pool_the_pipeline_compresses_inline() {
            let accept = session();
            let chunks = mixed_chunks();
            let cx = crate::cx::Cx::for_testing();
            let (out, pooled) =
                crate::util::future::block_on(run_pipeline(&cx, accept, 3, chunks.clone()));
            assert_eq!(pooled, 0);
            assert_sequential(&accept, &chunks, &out);
        }

        /// Dropping a pipeline with jobs in flight detaches nothing: the
        /// region owns the jobs, so the runtime's teardown finishes within
        /// its bound once they retire.
        #[test]
        fn dropping_a_busy_pipeline_detaches_nothing() {
            let accept = session();
            let runtime = crate::runtime::RuntimeBuilder::multi_thread()
                .build()
                .expect("runtime");
            let pooled = runtime.block_on(runtime.handle().spawn(async move {
                let cx = crate::cx::Cx::current().expect("task cx");
                let mut entry = EntryCompression::new(CompressionMode::Zstd, "data.bin");
                let mut pipeline = ChunkPipeline::new(accept, 4);
                let text: Vec<u8> = b"asupersync transfer protocol "
                    .iter()
                    .copied()
                    .cycle()
                    .take(256 * 1024)
                    .collect();
                for index in 0..4_u64 {
                    pipeline.push(&cx, &mut entry, 0, index * 256 * 1024, text.clone());
                }
                let pooled = pipeline.pooled;
                drop(pipeline);
                pooled
            }));
            assert_eq!(pooled, 4);
            assert!(
                runtime.shutdown_timeout(std::time::Duration::from_secs(60)),
                "teardown waits out the dropped jobs and completes"
            );
        }

        #[test]
        fn incompressible_and_oversized_chunks_stay_raw() {
            let accept = session();
            let mut state = 7_u64;
            let noise: Vec<u8> = (0..4096)
                .map(|_| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    state.to_be_bytes()[0]
                })
                .collect();
            assert!(compress_chunk(&accept, &noise).is_none());
            assert!(compress_chunk(&accept, &vec![0; 256 * 1024 + 1]).is_none());
        }

        #[test]
        fn hostile_chunks_are_refused_before_allocation() {
            let accept = session();
            let (chunk, payload) = compress_chunk(&accept, &[0; 1000]).unwrap();
            let record = chunk.to_bytes();
            let mut out = Vec::new();
            assert_eq!(
                decompress_chunk(&record, None, 1000, &payload, &mut out),
                Err(ChunkCodecError::NotNegotiated)
            );
            assert_eq!(
                decompress_chunk(&[1, 1], Some(&accept), 1000, &payload, &mut out),
                Err(ChunkCodecError::CodecMismatch)
            );
            // The entry has fewer bytes left than the chunk declares.
            assert_eq!(
                decompress_chunk(&record, Some(&accept), 999, &payload, &mut out),
                Err(ChunkCodecError::TooLarge {
                    raw_len: 1000,
                    limit: 999
                })
            );
            // A declared length beyond the negotiated chunk limit.
            let huge = ChunkCodec::new(WireCodec::Zstd, u32::MAX).to_bytes();
            assert!(matches!(
                decompress_chunk(&huge, Some(&accept), u64::MAX, &payload, &mut out),
                Err(ChunkCodecError::TooLarge { .. })
            ));
            // A declared length that does not match the frame.
            let short = ChunkCodec::new(WireCodec::Zstd, 999).to_bytes();
            assert!(matches!(
                decompress_chunk(&short, Some(&accept), 1000, &payload, &mut out),
                Err(ChunkCodecError::Corrupt(_))
            ));
            // A payload that is not a zstd frame.
            let mut damaged = payload.clone();
            damaged[0] ^= 0xFF;
            assert!(matches!(
                decompress_chunk(&record, Some(&accept), 1000, &damaged, &mut out),
                Err(ChunkCodecError::Corrupt(_))
            ));
            // The untouched record still decodes.
            decompress_chunk(&record, Some(&accept), 1000, &payload, &mut out).unwrap();
            assert_eq!(out, vec![0; 1000]);
        }
    }
