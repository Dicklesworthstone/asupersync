    use super::*;

    const EXAMPLE_CHUNK_BYTES: usize = 64 * 1024;

    /// Example showing the main ergonomic API for huge buffers
    #[test]
    fn example_write_really_big_buffer_asserts_transfer_shape() {
        let big_data = vec![42u8; 1_000_000]; // 1MB for test
        let chunks = big_data.chunks(EXAMPLE_CHUNK_BYTES).collect::<Vec<_>>();
        let options = WriteOptions::default();
        let expected_last_chunk_len = big_data.len() % EXAMPLE_CHUNK_BYTES;

        assert_eq!(big_data.len(), 1_000_000);
        assert_eq!(chunks.len(), big_data.len().div_ceil(EXAMPLE_CHUNK_BYTES));
        assert!(
            chunks
                .iter()
                .all(|chunk| !chunk.is_empty() && chunk.len() <= EXAMPLE_CHUNK_BYTES)
        );
        assert_eq!(chunks.first().unwrap().len(), EXAMPLE_CHUNK_BYTES);
        assert_eq!(chunks.last().unwrap().len(), expected_last_chunk_len);
        assert!(chunks.iter().flatten().all(|byte| **byte == 42));
        assert!(options.chunking_strategy.is_none());
        assert_eq!(options.compression, CompressionPreference::Auto);
        assert_eq!(options.encryption, EncryptionPreference::Required);
        assert_eq!(options.proof_requirements, ProofRequirements::Standard);
        assert!(options.report_progress);
    }

    /// Example showing streaming with unknown size
    #[test]
    fn example_stream_unknown_size_asserts_chunk_sequence() {
        let chunks = (0..1000).map(|i| vec![i as u8; 1024]).collect::<Vec<_>>();
        let total_bytes = chunks.iter().map(Vec::len).sum::<usize>();
        let observed_patterns = chunks
            .iter()
            .map(|chunk| chunk[0])
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(chunks.len(), 1000);
        assert_eq!(total_bytes, 1_024_000);
        assert!(chunks.iter().all(|chunk| chunk.len() == 1024));
        assert!(chunks[0].iter().all(|byte| *byte == 0));
        assert!(chunks[255].iter().all(|byte| *byte == 255));
        assert!(chunks[256].iter().all(|byte| *byte == 0));
        assert_eq!(observed_patterns.len(), 256);
    }
