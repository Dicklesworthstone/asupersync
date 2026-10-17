    use super::*;

    #[test]
    fn chunk_sizes_optimize_for_deduplication() {
        // Small artifacts should use fine-grained chunking
        let (target, min, max) = ArtifactProfile::compute_chunk_sizes(32_768);
        assert!(min <= target);
        assert_eq!(target, 4 * 1024);
        assert!(max <= 32 * 1024);

        // Large artifacts should balance dedup and efficiency
        let (target, min, max) = ArtifactProfile::compute_chunk_sizes(50_000_000);
        assert!(min <= target);
        assert_eq!(target, 128 * 1024);
        assert_eq!(max, 512 * 1024);
    }

    #[test]
    fn deterministic_cdc_parameters() {
        let params1 = ArtifactProfile::deterministic_cdc_parameters(16384);
        let params2 = ArtifactProfile::deterministic_cdc_parameters(16384);

        // Should be identical for same input
        assert_eq!(params1.window_size, params2.window_size);
        assert_eq!(params1.average_chunk_size, params2.average_chunk_size);
        assert_eq!(params1.normalization, params2.normalization);

        // Fixed window size for determinism
        assert_eq!(params1.window_size, 32);
    }

    #[test]
    fn deterministic_rolling_hash() {
        let mut hash1 = DeterministicRollingHash::new(16);
        let mut hash2 = DeterministicRollingHash::new(16);

        let data = b"deterministic test data";
        for &byte in data {
            let h1 = hash1.update(byte);
            let h2 = hash2.update(byte);
            assert_eq!(h1, h2);
        }
    }

    #[test]
    fn deterministic_rolling_hash_default_window_does_not_overflow() {
        let data: Vec<u8> = (0..128).map(|value| value as u8).collect();
        let mut hash1 = DeterministicRollingHash::new(32);
        let mut hash2 = DeterministicRollingHash::new(32);

        let mut last_hash = 0;
        for &byte in &data {
            last_hash = hash1.update(byte);
            assert_eq!(last_hash, hash2.update(byte));
        }

        assert_eq!(last_hash, hash1.current_hash());
        assert_ne!(last_hash, 0);
    }

    #[test]
    fn deterministic_rolling_hash_matches_window_recompute_after_wrap() {
        let data: Vec<u8> = (0..96)
            .map(|value| ((value * 37 + 11) % 251) as u8)
            .collect();
        let window_size = 8;
        let polynomial = 0x9e3779b9_u64;
        let mut rolling = DeterministicRollingHash::new(window_size);

        for (index, &byte) in data.iter().enumerate() {
            let actual = rolling.update(byte);
            let end = index + 1;
            let start = end.saturating_sub(window_size);
            let expected = data[start..end].iter().fold(0_u64, |hash, &window_byte| {
                hash.wrapping_mul(polynomial)
                    .wrapping_add(window_byte as u64)
            });
            assert_eq!(actual, expected, "rolling hash drift at byte {index}");
        }
    }

    #[test]
    fn deterministic_boundaries_keep_rolling_hash_state_after_boundary() {
        let data = [1, 2, 3, 1, 71, 5, 6, 7, 8];
        let boundaries =
            ArtifactProfile::find_deterministic_boundaries(&data, 2, 256, 1, 4).unwrap();

        // Resetting the hash at each boundary produces [4, 8, 9] here. A CDC
        // rolling hash must continue across boundaries so position 5 is found.
        assert_eq!(boundaries, vec![4, 5, 9]);
    }

    #[test]
    fn build_system_detection() {
        let rust_data = b"rustc 1.70.0 (90c541806 2023-05-31)";
        assert_eq!(ArtifactProfile::detect_build_system(rust_data), "cargo");

        let elf_data = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(ArtifactProfile::detect_build_system(elf_data), "native");

        let java_data = b"PK\x03\x04\x14\x00\x08\x08\x08\x00";
        assert_eq!(ArtifactProfile::detect_build_system(java_data), "jar");
    }

    #[test]
    fn toolchain_version_detection_covers_recognized_markers() {
        let cases: &[(&[u8], &str)] = &[
            (b"rustc 1.70.0 (90c541806 2023-05-31)", "rustc-1.70.0"),
            (
                b"rustc 1.93.0-nightly (abc123 2026-08-01)",
                "rustc-1.93.0-nightly",
            ),
            (b"rustc-1.70.0", "rustc-1.70.0"),
            (b"gcc (Ubuntu) 13.2.1 release", "gcc-13.2.1"),
            (b"gcc-13.2.1", "gcc-13.2.1"),
            (b"clang version 18.1.8 (release)", "clang-18.1.8"),
            (b"clang-18.1.8", "clang-18.1.8"),
            (b"go version go1.22.5 linux/amd64", "go-1.22.5"),
            (b"go1.23.0 linux/amd64", "go-1.23.0"),
            (b"go-1.23.0 linux/amd64", "go-1.23.0"),
            (b"cargo metadata; go1.23.1 linux/amd64", "go-1.23.1"),
            (b"javac 21.0.2", "java-21.0.2"),
            (b"javac-21.0.2", "java-21.0.2"),
            (b"java version \"21.0.2\"", "java-21.0.2"),
            (b"java-21.0.2", "java-21.0.2"),
            (b"rustc 1.2-java", "rustc-1.2-java"),
            (b"rustc 1.2-javac", "rustc-1.2-javac"),
            (b"rustc 1.2-go1", "rustc-1.2-go1"),
            (b"cargo 1.88.0 metadata", "unknown"),
            (b"golang 1.22.5 metadata", "unknown"),
            (b"artifact without a toolchain marker", "unknown"),
        ];

        for &(input, expected) in cases {
            assert_eq!(
                ArtifactProfile::detect_toolchain_version(input),
                expected,
                "input={}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn toolchain_version_detection_is_stable_in_public_artifact_metadata() {
        let input = b"go build metadata; go version go1.22.5 linux/amd64";
        let first = crate::net::atp::chunk::ChunkingProfile::Artifact
            .compute_boundaries(input)
            .unwrap();
        let second = crate::net::atp::chunk::ChunkingProfile::Artifact
            .compute_boundaries(input)
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(
            first
                .iter()
                .map(|boundary| boundary.size_bytes)
                .sum::<u64>(),
            u64::try_from(input.len()).unwrap()
        );

        let Some(ChunkMetadata::Artifact { build_context, .. }) = first
            .first()
            .and_then(|boundary| boundary.metadata.as_ref())
        else {
            panic!("artifact chunk must contain artifact metadata");
        };
        assert_eq!(build_context.toolchain_version, "go-1.22.5");
    }

    #[test]
    fn toolchain_version_detection_respects_sample_and_utf8_boundaries() {
        let mut beyond_sample = vec![b'x'; 2000];
        beyond_sample.extend_from_slice(b" clang version 18.1.8");
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(&beyond_sample),
            "unknown"
        );

        let mut crossing_sample = vec![b'x'; 1988];
        crossing_sample.extend_from_slice(b" rustc 1.234567890");
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(&crossing_sample),
            "unknown"
        );

        let mut late_rustc_version = b"rustc ".to_vec();
        late_rustc_version.extend(std::iter::repeat_n(b'x', 123));
        late_rustc_version.extend_from_slice(b" 1.70.0");
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(&late_rustc_version),
            "rustc-1.70.0"
        );
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(
                b"rustc marker\nfirst line\nsecond line\nthird line\n1.70.0"
            ),
            "rustc-1.70.0"
        );

        let mut late_gcc_version = b"gcc ".to_vec();
        late_gcc_version.extend(std::iter::repeat_n(b'x', NON_RUST_VERSION_SCAN_BYTES));
        late_gcc_version.extend_from_slice(b" 13.2.1");
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(&late_gcc_version),
            "unknown"
        );

        assert_eq!(
            ArtifactProfile::detect_toolchain_version(b"clang version \xff 18.1.8"),
            "clang-18.1.8"
        );
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(b"clang version \xff18.1.8"),
            "unknown"
        );

        let decoy_then_real = b"go marker without a version\nno token here\nstill no token\ncargo metadata; go1.23.1 linux/amd64";
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(decoy_then_real),
            "go-1.23.1"
        );
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(b"rustc metadata; java version 21.0.2"),
            "java-21.0.2"
        );

        let mut repeated_markers = "rustc ".repeat(100);
        repeated_markers.push_str("rustc 1.70.0");
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(repeated_markers.as_bytes()),
            "rustc-1.70.0"
        );

        let separated_gcc_markers = format!("gcc {} gcc 13.2.1", "x".repeat(60));
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(separated_gcc_markers.as_bytes()),
            "gcc-13.2.1"
        );

        let straddling_gcc_marker = format!("gcc {}-gcc-13.2.1", "x".repeat(43));
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(straddling_gcc_marker.as_bytes()),
            "gcc-13.2.1"
        );

        let straddling_clang_join = format!("clang {}-clang-18.1.8", "x".repeat(37));
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(straddling_clang_join.as_bytes()),
            "clang-18.1.8"
        );

        let straddling_clang_prefix = format!("clang {}-clang-v18.1.8", "x".repeat(36));
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(straddling_clang_prefix.as_bytes()),
            "clang-18.1.8"
        );

        assert_eq!(
            ArtifactProfile::detect_toolchain_version(b"rustc metadata-java-21.0"),
            "java-21.0"
        );

        let oversized_before_java = format!(
            "rustc {}.0-java 21.0",
            "7".repeat(MAX_VERSION_TOKEN_BYTES - 1)
        );
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(oversized_before_java.as_bytes()),
            "java-21.0"
        );

        assert_eq!(
            ArtifactProfile::detect_toolchain_version(b"rustc foo9bar1.2-java 21.0"),
            "java-21.0"
        );
    }

    #[test]
    fn structural_boundary_detection() {
        let elf_data = b"some data before\x7fELF\x02\x01\x01\x00and after";
        assert!(ArtifactProfile::is_artifact_structural_boundary(
            elf_data, 16
        ));

        let zip_data = b"prefix dataPK\x03\x04local file header";
        assert!(ArtifactProfile::is_artifact_structural_boundary(
            zip_data, 11
        ));

        let normal_data = b"just normal data without structure";
        assert!(!ArtifactProfile::is_artifact_structural_boundary(
            normal_data,
            10
        ));
    }

    #[test]
    fn proof_strength_computation() {
        // Large chunk with structure should get high proof strength
        let structured_data = b"\x7fELF".repeat(20000);
        let strength = ArtifactProfile::compute_proof_strength(&structured_data, 0);
        assert_eq!(strength, ProofStrength::Cryptographic);

        // Small chunk should get basic strength
        let small_data = b"small data";
        let strength = ArtifactProfile::compute_proof_strength(small_data, 10);
        assert_eq!(strength, ProofStrength::Basic);
    }

    #[test]
    fn entropy_calculation() {
        // Uniform data should have high entropy
        let uniform_data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let entropy = ArtifactProfile::calculate_entropy(&uniform_data);
        assert!(entropy > 7.0);

        // All same byte should have zero entropy
        let uniform_bytes = vec![0u8; 256];
        let entropy = ArtifactProfile::calculate_entropy(&uniform_bytes);
        assert!(entropy < 0.1);
    }

    #[test]
    fn binary_header_detection() {
        assert!(ArtifactProfile::has_binary_headers(b"\x7fELF binary"));
        assert!(ArtifactProfile::has_binary_headers(b"MZ PE executable"));
        assert!(!ArtifactProfile::has_binary_headers(b"plain text file"));
    }

    #[test]
    fn reproducible_chunking() {
        let artifact_data = b"reproducible artifact data for testing".repeat(1000);

        // Should produce identical results
        let result = ArtifactProfile::verify_reproducibility(&artifact_data);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn artifact_chunking_creates_boundaries() {
        let artifact_data = b"\x7fELF\x02\x01\x01\x00".repeat(5000);
        let boundaries = ArtifactProfile::compute_boundaries(&artifact_data).unwrap();

        assert!(!boundaries.is_empty());
        for boundary in &boundaries {
            assert!(matches!(boundary.strategy, ChunkStrategy::ContentDefined));
            assert!(matches!(
                boundary.metadata,
                Some(ChunkMetadata::Artifact { .. })
            ));

            // Check build context
            if let Some(ChunkMetadata::Artifact { build_context, .. }) = &boundary.metadata {
                assert!(!build_context.build_system.is_empty());
                assert!(!build_context.toolchain_version.is_empty());
            }
        }

        // Validate total coverage
        let total_size: u64 = boundaries.iter().map(|b| b.size_bytes).sum();
        assert_eq!(total_size, artifact_data.len() as u64);
    }

    #[test]
    fn deduplication_metrics_computation() {
        let boundaries = vec![
            ChunkBoundary {
                index: 0,
                byte_offset: 0,
                size_bytes: 10000,
                content_hash: [1; 32],
                strategy: ChunkStrategy::ContentDefined,
                metadata: Some(ChunkMetadata::Artifact {
                    build_context: ArtifactBuildContext {
                        build_system: "cargo".to_string(),
                        build_timestamp: None,
                        environment_hash: [1; 32],
                        toolchain_version: "rustc-1.70.0".to_string(),
                    },
                    proof_strength: ProofStrength::Enhanced,
                }),
            },
            ChunkBoundary {
                index: 1,
                byte_offset: 10000,
                size_bytes: 10000,
                content_hash: [1; 32], // Same hash = potential duplication
                strategy: ChunkStrategy::ContentDefined,
                metadata: Some(ChunkMetadata::Artifact {
                    build_context: ArtifactBuildContext {
                        build_system: "cargo".to_string(),
                        build_timestamp: None,
                        environment_hash: [1; 32],
                        toolchain_version: "rustc-1.70.0".to_string(),
                    },
                    proof_strength: ProofStrength::Basic,
                }),
            },
        ];

        let metrics = ArtifactProfile::compute_deduplication_metrics(&boundaries);
        assert_eq!(metrics.total_chunks, 2);
        assert_eq!(metrics.unique_chunks, 1); // Same hash
        assert_eq!(metrics.total_size, 20000);
        assert!(metrics.deduplication_potential > 0.0);
        assert_eq!(metrics.proof_strength_distribution.len(), 2); // Two different strengths
    }

    #[test]
    fn build_context_validation() {
        let valid_context = ArtifactBuildContext {
            build_system: "cargo".to_string(),
            build_timestamp: None,
            environment_hash: [1; 32],
            toolchain_version: "rustc-1.70.0".to_string(),
        };
        assert!(ArtifactProfile::validate_build_context(&valid_context).is_ok());

        let invalid_context = ArtifactBuildContext {
            build_system: String::new(), // Empty!
            build_timestamp: None,
            environment_hash: [1; 32],
            toolchain_version: "rustc-1.70.0".to_string(),
        };
        assert!(ArtifactProfile::validate_build_context(&invalid_context).is_err());

        let zero_hash_context = ArtifactBuildContext {
            build_system: "cargo".to_string(),
            build_timestamp: None,
            environment_hash: [0; 32], // All zeros!
            toolchain_version: "rustc-1.70.0".to_string(),
        };
        assert!(ArtifactProfile::validate_build_context(&zero_hash_context).is_err());
    }

    #[test]
    fn boundary_validation_enforces_artifact_requirements() {
        let invalid_boundary = ChunkBoundary {
            index: 0,
            byte_offset: 0,
            size_bytes: 10000,
            content_hash: [1; 32],
            strategy: ChunkStrategy::FixedSize, // Wrong strategy!
            metadata: Some(ChunkMetadata::Artifact {
                build_context: ArtifactBuildContext {
                    build_system: "cargo".to_string(),
                    build_timestamp: None,
                    environment_hash: [1; 32],
                    toolchain_version: "rustc-1.70.0".to_string(),
                },
                proof_strength: ProofStrength::Basic,
            }),
        };

        let result = ArtifactProfile::validate_boundaries(&[invalid_boundary]);
        assert!(result.is_err());
    }

    #[test]
    fn profile_properties() {
        assert!(ArtifactProfile::supports_incremental_chunking());
        assert_eq!(ArtifactProfile::min_chunking_threshold(), 8 * 1024);
        assert_eq!(ArtifactProfile::max_chunk_size(), 512 * 1024);
    }

    #[test]
    fn toolchain_version_detection_freezes_token_boundaries() {
        let cases = [
            ("rustc 1.70.0 something", Some("1.70.0")),
            ("version 2.1.3-beta info", Some("2.1.3-beta")),
            ("go version go1.22.5", Some("1.22.5")),
            ("release v01.002.3-rc_1!", Some("01.002.3-rc_1")),
            ("build7.4 finished", Some("7.4")),
            ("tool-7.4 finished", Some("7.4")),
            ("nul\0delimited\x001.2\0token", Some("1.2")),
            ("no version here", None),
            ("1", None),
            (".1.2", None),
            ("1.2.", None),
            ("1..2", None),
            ("1.2-", None),
            ("-1.2", None),
            ("1.2-3.4", None),
            ("1.2-beta-2", None),
            ("1.2+metadata", None),
            ("1.2+metadata3.4", None),
            ("1.2~vendor", None),
            ("1.2suffix", None),
            ("1.2suffix3.4", None),
            ("1.2-beta.more", None),
            ("١.٢.٣", None),
            ("1.2β", None),
        ];

        for (input, expected) in cases {
            assert_eq!(
                ArtifactProfile::extract_version_number(input),
                expected,
                "input={input:?}"
            );
        }
    }

    #[test]
    fn toolchain_version_detection_skips_invalid_candidates_without_truncation() {
        assert_eq!(
            ArtifactProfile::extract_version_number("bad 1.2. then good 3.4.5"),
            Some("3.4.5")
        );

        let maximum = format!("{}.0", "7".repeat(MAX_VERSION_TOKEN_BYTES - 2));
        assert_eq!(maximum.len(), MAX_VERSION_TOKEN_BYTES);
        assert_eq!(
            ArtifactProfile::extract_version_number(&maximum),
            Some(maximum.as_str())
        );

        let oversized = format!("{}.0", "7".repeat(MAX_VERSION_TOKEN_BYTES - 1));
        assert_eq!(oversized.len(), MAX_VERSION_TOKEN_BYTES + 1);
        assert_eq!(ArtifactProfile::extract_version_number(&oversized), None);

        let mut beyond_scan_window = "x".repeat(MAX_VERSION_SCAN_BYTES);
        beyond_scan_window.push_str(" 1.2.3");
        assert_eq!(
            ArtifactProfile::extract_version_number(&beyond_scan_window),
            None
        );

        let mut crossing_scan_window = "x".repeat(MAX_VERSION_SCAN_BYTES - 4);
        crossing_scan_window.push_str(" 1.23456789");
        assert_eq!(
            ArtifactProfile::extract_version_number(&crossing_scan_window),
            None
        );
    }

    #[test]
    fn toolchain_version_detection_generated_tokens_match_independent_grammar() {
        for major in ["0", "1", "01", "999"] {
            for minor in ["0", "2", "002", "88"] {
                for patch in ["0", "3", "0004"] {
                    for suffix in ["", "-alpha", "-RC1", "-rc_1", "-9"] {
                        let token = format!("{major}.{minor}.{patch}{suffix}");
                        assert!(reference_version_token(&token));

                        let input = format!("toolchain=({token}); done");
                        assert_eq!(
                            ArtifactProfile::extract_version_number(&input),
                            Some(token.as_str()),
                            "input={input:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn toolchain_version_detection_short_exact_candidates_match_independent_grammar() {
        const ALPHABET: &[u8] = b"01.-a_+";

        for length in 1..=6 {
            let mut combinations = 1;
            for _ in 1..length {
                combinations *= ALPHABET.len();
            }

            for leading in *b"01" {
                for mut encoded in 0..combinations {
                    let mut bytes = vec![leading; length];
                    for byte in &mut bytes[1..] {
                        *byte = ALPHABET[encoded % ALPHABET.len()];
                        encoded /= ALPHABET.len();
                    }

                    let candidate = String::from_utf8(bytes).unwrap();
                    let expected =
                        reference_version_token(&candidate).then_some(candidate.as_str());
                    assert_eq!(
                        ArtifactProfile::extract_version_number(&candidate),
                        expected,
                        "candidate={candidate:?}"
                    );
                }
            }
        }
    }

    fn reference_version_token(token: &str) -> bool {
        if token.is_empty() || token.len() > MAX_VERSION_TOKEN_BYTES || !token.is_ascii() {
            return false;
        }

        let (components, suffix) = match token.split_once('-') {
            Some((components, suffix)) => (components, Some(suffix)),
            None => (token, None),
        };

        let component_count = components.split('.').count();
        let components_are_numeric = components.split('.').all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        });

        components_are_numeric
            && component_count >= 2
            && suffix.is_none_or(|suffix| {
                !suffix.is_empty()
                    && suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            })
    }
