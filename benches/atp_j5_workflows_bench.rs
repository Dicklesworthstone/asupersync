//! ATP-J5 workflow performance benchmarks.
//!
//! Benchmarks the performance characteristics of ATP logistics workflows:
//! - CI artifact cache throughput and latency
//! - Dataset distribution scalability
//! - Fuzz corpus synchronization efficiency
//! - Release bundle distribution performance
//! - Proof bundle archival compression ratios
//!
//! Includes specialized profiles for artifact/cache and dataset workloads.

use asupersync::cli::output::OutputFormat;
use asupersync::cli::{
    AtpCiAction, AtpCiArgs, AtpCiPushArgs, AtpDatasetAction, AtpDatasetArgs, AtpDatasetSeedArgs,
    AtpFuzzAction, AtpFuzzArgs, AtpFuzzSyncArgs, AtpWorkflowCoordinator,
};
use asupersync::test_utils::run_test_with_cx;
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use std::path::PathBuf;
use tempfile::TempDir;
use tokio::runtime::Runtime;

/// Benchmark CI artifact caching with different file sizes.
fn bench_ci_artifact_cache(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("ci_artifact_cache");

    // Test different artifact sizes
    let sizes = vec![
        (1024, "1KB"),
        (1024 * 1024, "1MB"),
        (10 * 1024 * 1024, "10MB"),
        (100 * 1024 * 1024, "100MB"),
    ];

    for (size, name) in sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("push", name), &size, |b, &size| {
            b.iter(|| {
                rt.block_on(async {
                    run_test_with_cx(|cx| async move {
                        let temp_dir = TempDir::new().unwrap();
                        let artifact_path = temp_dir.path().join("benchmark-artifact");

                        let content = vec![0u8; size];
                        tokio::fs::write(&artifact_path, &content).await.unwrap();

                        let mut coordinator =
                            AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

                        let ci_args = AtpCiArgs {
                            action: AtpCiAction::Push(AtpCiPushArgs {
                                paths: vec![artifact_path],
                                build_id: format!("bench-{}", size),
                                tags: vec!["benchmark".to_string()],
                                retention: "1h".to_string(),
                                compression_level: 6,
                                dedupe: true,
                                scope: Some("bench:artifacts".to_string()),
                            }),
                        };

                        black_box(coordinator.handle_ci_command(&cx, ci_args).await.unwrap());
                    })
                    .await;
                });
            });
        });
    }

    group.finish();
}

/// Benchmark dataset seeding with different dataset characteristics.
fn bench_dataset_seeding(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("dataset_seeding");

    // Test different dataset profiles
    let profiles = vec![
        (100, 1024, "small_files"),           // 100 files, 1KB each
        (10, 1024 * 1024, "medium_files"),    // 10 files, 1MB each
        (1, 100 * 1024 * 1024, "large_file"), // 1 file, 100MB
    ];

    for (file_count, file_size, name) in profiles {
        let total_size = (file_count * file_size) as u64;
        group.throughput(Throughput::Bytes(total_size));

        group.bench_with_input(
            BenchmarkId::new("seed", name),
            &(file_count, file_size),
            |b, &(file_count, file_size)| {
                b.iter(|| {
                    rt.block_on(async {
                        run_test_with_cx(|cx| async move {
                            let temp_dir = TempDir::new().unwrap();
                            let dataset_path = temp_dir.path().to_owned();

                            // Create dataset files
                            for i in 0..file_count {
                                let file_path = dataset_path.join(format!("file_{}.dat", i));
                                let content = vec![i as u8; file_size];
                                tokio::fs::write(&file_path, &content).await.unwrap();
                            }

                            let mut coordinator =
                                AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

                            let dataset_args = AtpDatasetArgs {
                                action: AtpDatasetAction::Seed(AtpDatasetSeedArgs {
                                    path: dataset_path,
                                    dataset_id: format!("bench-dataset-{}", name),
                                    metadata: Some(format!(
                                        r#"{{"profile": "{}", "files": {}, "size": {}}}"#,
                                        name, file_count, file_size
                                    )),
                                    chunk_size: Some(1024 * 1024), // 1MB chunks
                                    version: Some("bench".to_string()),
                                    replication_factor: 2,
                                    access_scope: Some("bench:datasets".to_string()),
                                }),
                            };

                            black_box(
                                coordinator
                                    .handle_dataset_command(&cx, dataset_args)
                                    .await
                                    .unwrap(),
                            );
                        })
                        .await;
                    });
                });
            },
        );
    }

    group.finish();
}

/// Benchmark fuzz corpus synchronization with different corpus sizes.
fn bench_fuzz_corpus_sync(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("fuzz_corpus_sync");

    // Test different corpus characteristics
    let corpus_sizes = vec![
        (100, 64, "small_corpus"),     // 100 test cases, 64 bytes each
        (1000, 256, "medium_corpus"),  // 1000 test cases, 256 bytes each
        (10000, 1024, "large_corpus"), // 10000 test cases, 1KB each
    ];

    for (test_case_count, case_size, name) in corpus_sizes {
        let total_size = (test_case_count * case_size) as u64;
        group.throughput(Throughput::Bytes(total_size));

        group.bench_with_input(
            BenchmarkId::new("sync", name),
            &(test_case_count, case_size),
            |b, &(test_case_count, case_size)| {
                b.iter(|| {
                    rt.block_on(async {
                        run_test_with_cx(|cx| async move {
                            let temp_dir = TempDir::new().unwrap();
                            let corpus_path = temp_dir.path().to_owned();

                            // Create corpus test cases
                            for i in 0..test_case_count {
                                let case_path = corpus_path.join(format!("case_{:06}", i));
                                let content = vec![(i % 256) as u8; case_size];
                                tokio::fs::write(&case_path, &content).await.unwrap();
                            }

                            let mut coordinator =
                                AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

                            let fuzz_args = AtpFuzzArgs {
                                action: AtpFuzzAction::Sync(AtpFuzzSyncArgs {
                                    corpus_path,
                                    target: format!("bench-fuzzer-{}", name),
                                    strategy: "bidirectional".to_string(),
                                    exclude: Vec::new(),
                                    watch: false,
                                }),
                            };

                            black_box(
                                coordinator
                                    .handle_fuzz_command(&cx, fuzz_args)
                                    .await
                                    .unwrap(),
                            );
                        })
                        .await;
                    });
                });
            },
        );
    }

    group.finish();
}

/// Benchmark cache deduplication efficiency.
fn bench_cache_deduplication(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("cache_deduplication");

    // Test deduplication with different content patterns
    let patterns = vec![
        ("identical", 100, true), // 100 identical files
        ("unique", 100, false),   // 100 unique files
        ("mixed", 50, true),      // 50% duplicate content
    ];

    for (pattern_name, file_count, use_duplicates) in patterns {
        group.bench_with_input(
            BenchmarkId::new("dedupe", pattern_name),
            &(file_count, use_duplicates),
            |b, &(file_count, use_duplicates)| {
                b.iter(|| {
                    rt.block_on(async {
                        run_test_with_cx(|cx| async move {
                            let temp_dir = TempDir::new().unwrap();
                            let mut coordinator =
                                AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

                            for i in 0..file_count {
                                let artifact_path =
                                    temp_dir.path().join(format!("artifact_{}.bin", i));

                                // Create content based on deduplication pattern
                                let content = if use_duplicates && i % 2 == 0 {
                                    b"duplicate content for deduplication test"
                                } else {
                                    &format!("unique content for file {}", i).into_bytes()
                                };

                                tokio::fs::write(&artifact_path, content).await.unwrap();

                                let ci_args = AtpCiArgs {
                                    action: AtpCiAction::Push(AtpCiPushArgs {
                                        paths: vec![artifact_path],
                                        build_id: format!("dedupe-bench-{}", i),
                                        tags: vec![pattern_name.to_string()],
                                        retention: "1h".to_string(),
                                        compression_level: 1, // Minimal compression for dedupe focus
                                        dedupe: true,
                                        scope: Some("bench:dedupe".to_string()),
                                    }),
                                };

                                black_box(
                                    coordinator.handle_ci_command(&cx, ci_args).await.unwrap(),
                                );
                            }
                        })
                        .await;
                    });
                });
            },
        );
    }

    group.finish();
}

/// Benchmark artifact cache lookup performance.
fn bench_cache_lookup(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("cache_lookup");

    // Benchmark cache hit rates and lookup latency
    let cache_sizes = vec![10, 100, 1000, 10000];

    for cache_size in cache_sizes {
        group.bench_with_input(
            BenchmarkId::new("lookup", cache_size),
            &cache_size,
            |b, &cache_size| {
                b.iter(|| {
                    rt.block_on(async {
                        run_test_with_cx(|cx| async move {
                            let temp_dir = TempDir::new().unwrap();
                            let mut coordinator =
                                AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

                            // Pre-populate cache with artifacts
                            for i in 0..cache_size {
                                let artifact_path =
                                    temp_dir.path().join(format!("cache_item_{}.dat", i));
                                tokio::fs::write(&artifact_path, format!("cache content {}", i))
                                    .await
                                    .unwrap();

                                let ci_args = AtpCiArgs {
                                    action: AtpCiAction::Push(AtpCiPushArgs {
                                        paths: vec![artifact_path],
                                        build_id: format!("cache-prep-{}", i),
                                        tags: vec!["cache-test".to_string()],
                                        retention: "1h".to_string(),
                                        compression_level: 1,
                                        dedupe: false,
                                        scope: Some("bench:cache".to_string()),
                                    }),
                                };

                                coordinator.handle_ci_command(&cx, ci_args).await.unwrap();
                            }

                            // Benchmark cache lookup
                            let lookup_args = AtpCiArgs {
                                action: AtpCiAction::Pull(crate::cli::AtpCiPullArgs {
                                    build_id: Some(format!("cache-prep-{}", cache_size / 2)),
                                    tags: vec!["cache-test".to_string()],
                                    destination: PathBuf::from("/tmp/bench"),
                                    if_newer: false,
                                    verify: false,
                                }),
                            };

                            black_box(
                                coordinator
                                    .handle_ci_command(&cx, lookup_args)
                                    .await
                                    .unwrap(),
                            );
                        })
                        .await;
                    });
                });
            },
        );
    }

    group.finish();
}

/// Benchmark compression ratios for different content types.
fn bench_compression_ratios(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("compression_ratios");

    // Test different content types that represent real-world artifacts
    let content_types = vec![
        ("text", create_text_content(1024 * 1024)),     // 1MB text
        ("binary", create_binary_content(1024 * 1024)), // 1MB binary
        ("json", create_json_content(1024 * 1024)),     // 1MB JSON
        ("compressed", create_compressed_content(1024 * 1024)), // 1MB pre-compressed
    ];

    for (content_type, content) in content_types {
        group.throughput(Throughput::Bytes(content.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("compress", content_type),
            &content,
            |b, content| {
                b.iter(|| {
                    rt.block_on(async {
                        run_test_with_cx(|cx| async move {
                            let temp_dir = TempDir::new().unwrap();
                            let artifact_path =
                                temp_dir.path().join(format!("{}_artifact", content_type));
                            tokio::fs::write(&artifact_path, content).await.unwrap();

                            let mut coordinator =
                                AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

                            let ci_args = AtpCiArgs {
                                action: AtpCiAction::Push(AtpCiPushArgs {
                                    paths: vec![artifact_path],
                                    build_id: format!("compress-{}", content_type),
                                    tags: vec!["compression".to_string()],
                                    retention: "1h".to_string(),
                                    compression_level: 9, // Maximum compression
                                    dedupe: false,
                                    scope: Some("bench:compression".to_string()),
                                }),
                            };

                            black_box(coordinator.handle_ci_command(&cx, ci_args).await.unwrap());
                        })
                        .await;
                    });
                });
            },
        );
    }

    group.finish();
}

/// Helper function to create text content for compression testing.
fn create_text_content(size: usize) -> Vec<u8> {
    let base_text = "This is sample text content with repeated patterns for compression testing. ";
    let mut content = Vec::with_capacity(size);
    while content.len() < size {
        content.extend_from_slice(base_text.as_bytes());
    }
    content.truncate(size);
    content
}

/// Helper function to create binary content for compression testing.
fn create_binary_content(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Helper function to create JSON content for compression testing.
fn create_json_content(size: usize) -> Vec<u8> {
    let mut json_content = String::new();
    json_content.push_str(r#"{"data":["#);

    let entry = r#""sample_entry_with_repeated_structure","#;
    while json_content.len() < size - 20 {
        json_content.push_str(entry);
    }

    json_content.push_str(r#""final_entry"]}"#);
    json_content.into_bytes()
}

/// Helper function to create pre-compressed content.
fn create_compressed_content(size: usize) -> Vec<u8> {
    // Simulate already compressed content (random-like data)
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    (0..size)
        .map(|i| {
            let mut hasher = DefaultHasher::new();
            i.hash(&mut hasher);
            (hasher.finish() % 256) as u8
        })
        .collect()
}

criterion_group!(
    benches,
    bench_ci_artifact_cache,
    bench_dataset_seeding,
    bench_fuzz_corpus_sync,
    bench_cache_deduplication,
    bench_cache_lookup,
    bench_compression_ratios
);
criterion_main!(benches);
