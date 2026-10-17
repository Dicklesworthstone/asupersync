    use super::*;

    #[test]
    fn chunk_sizes_optimize_for_streaming() {
        // Small files should avoid over-chunking
        let (target, min, max) = MediaProfile::compute_chunk_sizes(100_000);
        assert!(target >= min);
        assert!(target <= max);
        assert!(max <= 512 * 1024); // Reasonable for small files

        // Large files should use bigger chunks for efficiency
        let (target, min, max) = MediaProfile::compute_chunk_sizes(100_000_000);
        assert!(min <= target);
        assert!(target >= 256 * 1024); // At least 256KB for large files
        assert!(max <= 2 * 1024 * 1024); // But not too large for streaming
    }

    #[test]
    fn content_type_detection() {
        // Test MP4 detection
        let mp4_header = b"\x00\x00\x00\x18ftypmp4\x00\x00\x00\x00";
        assert_eq!(
            MediaProfile::detect_content_type(mp4_header),
            MediaContentType::Video
        );

        // Test PNG detection
        let png_header = b"\x89PNG\r\n\x1A\n\x00\x00\x00\rIHDR";
        assert_eq!(
            MediaProfile::detect_content_type(png_header),
            MediaContentType::Image
        );

        // Test MP3 detection
        let mp3_header = b"ID3\x03\x00\x00\x00\x00\x00\x00";
        assert_eq!(
            MediaProfile::detect_content_type(mp3_header),
            MediaContentType::Audio
        );

        let pytorch_zip = b"PK\x03\x04metadata/pytorch_model.bin";
        assert_eq!(
            MediaProfile::detect_content_type(pytorch_zip),
            MediaContentType::Model
        );

        let saved_model_zip = b"PK\x03\x04assets/saved_model.pb";
        assert_eq!(
            MediaProfile::detect_content_type(saved_model_zip),
            MediaContentType::Model
        );

        // Test unknown
        let unknown_header = b"unknown format here";
        assert_eq!(
            MediaProfile::detect_content_type(unknown_header),
            MediaContentType::Unknown
        );
    }

    #[test]
    fn video_frame_boundary_detection() {
        let h264_start = b"\x00\x00\x00\x01\x67\x42\x00\x1E";
        assert!(MediaProfile::is_video_frame_boundary(h264_start));

        let not_boundary = b"random video data here";
        assert!(!MediaProfile::is_video_frame_boundary(not_boundary));
    }

    #[test]
    fn keyframe_boundary_detection() {
        // First chunk of video should be keyframe
        let video_data = b"some video chunk data";
        assert!(MediaProfile::is_keyframe_boundary(
            video_data,
            &MediaContentType::Video,
            0
        ));

        // Later chunks with start codes
        let keyframe_data = b"\x00\x00\x00\x01".repeat(50);
        assert!(MediaProfile::is_keyframe_boundary(
            &keyframe_data,
            &MediaContentType::Video,
            5
        ));

        // First chunk of image is keyframe
        assert!(MediaProfile::is_keyframe_boundary(
            b"image data",
            &MediaContentType::Image,
            0
        ));
    }

    #[test]
    fn decoding_priority_computation() {
        // First chunk should have high priority
        let priority = MediaProfile::compute_decoding_priority(
            &vec![0u8; 1000],
            &MediaContentType::Video,
            0,
            10,
        );
        assert!(priority >= 90);

        // Last chunk should have lower priority
        let priority = MediaProfile::compute_decoding_priority(
            &vec![0u8; 1000],
            &MediaContentType::Video,
            9,
            10,
        );
        assert!(priority < 50);

        // Large chunks get size bonus
        let priority_large = MediaProfile::compute_decoding_priority(
            &vec![0u8; 200_000],
            &MediaContentType::Video,
            5,
            10,
        );
        let priority_small = MediaProfile::compute_decoding_priority(
            &vec![0u8; 1000],
            &MediaContentType::Video,
            5,
            10,
        );
        assert!(priority_large > priority_small);
    }

    #[test]
    fn chunking_creates_media_boundaries() {
        let video_data = b"\x00\x00\x00\x18ftypmp4\x00".repeat(1000);
        let boundaries =
            MediaProfile::compute_boundaries(&video_data).expect("media chunking should succeed");

        assert!(!boundaries.is_empty());
        for boundary in &boundaries {
            assert!(matches!(boundary.strategy, ChunkStrategy::ObjectSpecific));
            assert!(matches!(
                boundary.metadata,
                Some(ChunkMetadata::Media { .. })
            ));
        }

        // Validate total coverage
        let total_size: u64 = boundaries.iter().map(|b| b.size_bytes).sum();
        assert_eq!(total_size, video_data.len() as u64);
    }

    #[test]
    fn streaming_order_respects_priority() {
        let boundaries = vec![
            ChunkBoundary {
                index: 0,
                byte_offset: 0,
                size_bytes: 1000,
                content_hash: [1; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::Media {
                    is_keyframe_boundary: true,
                    decoding_priority: 100,
                }),
            },
            ChunkBoundary {
                index: 1,
                byte_offset: 1000,
                size_bytes: 1000,
                content_hash: [2; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::Media {
                    is_keyframe_boundary: false,
                    decoding_priority: 50,
                }),
            },
            ChunkBoundary {
                index: 2,
                byte_offset: 2000,
                size_bytes: 1000,
                content_hash: [3; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::Media {
                    is_keyframe_boundary: false,
                    decoding_priority: 75,
                }),
            },
        ];

        let order = MediaProfile::get_streaming_order(&boundaries);

        // Should be ordered by priority: 100, 75, 50
        assert_eq!(order, vec![0, 2, 1]);
    }

    #[test]
    fn startup_latency_estimation() {
        let boundaries = vec![
            ChunkBoundary {
                index: 0,
                byte_offset: 0,
                size_bytes: 100_000,
                content_hash: [1; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::Media {
                    is_keyframe_boundary: true,
                    decoding_priority: 100,
                }),
            },
            ChunkBoundary {
                index: 1,
                byte_offset: 100_000,
                size_bytes: 200_000,
                content_hash: [2; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::Media {
                    is_keyframe_boundary: false,
                    decoding_priority: 80,
                }),
            },
        ];

        let latency = MediaProfile::estimate_startup_latency(&boundaries, 100, 50);
        assert!(latency > std::time::Duration::from_millis(50)); // At least one RTT
        assert!(latency < std::time::Duration::from_secs(5)); // Reasonable for startup
    }

    #[test]
    fn boundary_validation_enforces_media_requirements() {
        let invalid_boundary = ChunkBoundary {
            index: 0,
            byte_offset: 0,
            size_bytes: 1000,
            content_hash: [1; 32],
            strategy: ChunkStrategy::FixedSize, // Wrong strategy
            metadata: Some(ChunkMetadata::Media {
                is_keyframe_boundary: false,
                decoding_priority: 50,
            }),
        };

        let result = MediaProfile::validate_boundaries(&[invalid_boundary]);
        assert!(result.is_err());

        // Priority out of range
        let invalid_priority_boundary = ChunkBoundary {
            index: 0,
            byte_offset: 0,
            size_bytes: 100_000,
            content_hash: [1; 32],
            strategy: ChunkStrategy::ObjectSpecific,
            metadata: Some(ChunkMetadata::Media {
                is_keyframe_boundary: false,
                decoding_priority: 150, // Invalid priority > 100
            }),
        };

        let result = MediaProfile::validate_boundaries(&[invalid_priority_boundary]);
        assert!(result.is_err());
    }

    #[test]
    fn profile_properties() {
        assert!(MediaProfile::supports_incremental_chunking());
        assert_eq!(MediaProfile::min_chunking_threshold(), 16 * 1024);
        assert_eq!(MediaProfile::max_chunk_size(), 2 * 1024 * 1024);
    }

    #[test]
    fn startup_chunk_set_selection() {
        let boundaries = vec![
            ChunkBoundary {
                index: 0,
                byte_offset: 0,
                size_bytes: 50_000,
                content_hash: [1; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::Media {
                    is_keyframe_boundary: true,
                    decoding_priority: 100,
                }),
            },
            ChunkBoundary {
                index: 1,
                byte_offset: 50_000,
                size_bytes: 100_000,
                content_hash: [2; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::Media {
                    is_keyframe_boundary: false,
                    decoding_priority: 90,
                }),
            },
            ChunkBoundary {
                index: 2,
                byte_offset: 150_000,
                size_bytes: 200_000,
                content_hash: [3; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::Media {
                    is_keyframe_boundary: false,
                    decoding_priority: 80,
                }),
            },
        ];

        let startup_set = MediaProfile::get_startup_chunk_set(&boundaries);

        // Should include enough chunks for 256KB threshold
        let startup_bytes: u64 = startup_set
            .iter()
            .map(|&idx| boundaries[idx].size_bytes)
            .sum();
        assert!(startup_bytes >= 256 * 1024);
    }
