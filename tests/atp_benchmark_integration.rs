//! ATP Benchmark Adapter Integration Tests
//!
//! Tests the benchmark adapter framework with scp baseline and ATP profile comparison.

use asupersync::atp::benchmark::{
    AtpProfile, BenchmarkConfig, BenchmarkSuite, BenchmarkSuiteBuilder, ScpAdapter, ToolAvailability,
};
use std::time::Duration;

#[tokio::test]
async fn test_scp_adapter_availability_check() {
    let adapter = ScpAdapter::new();
    let availability = adapter.check_availability().await;

    match availability {
        ToolAvailability::Available(version) => {
            println!("✅ SCP is available: {}", version.version_string);
            assert_eq!(adapter.tool_name(), "scp");
        }
        ToolAvailability::NotFound => {
            println!("⚠️  SCP not found in PATH (expected in some environments)");
        }
        ToolAvailability::VersionDetectionFailed(reason) => {
            println!("⚠️  SCP version detection failed: {}", reason);
        }
        ToolAvailability::IncompatibleVersion(version) => {
            println!("⚠️  SCP incompatible version: {}", version.version_string);
        }
    }

    // Test should not fail due to tool availability
    // We're testing the adapter framework, not requiring SCP to be installed
}

#[tokio::test]
async fn test_atp_profile_execution() -> Result<(), Box<dyn std::error::Error>> {
    let config = BenchmarkConfig::smoke_test();
    let profile = AtpProfile::clean_lan();

    // Use temporary files for the test
    let temp_dir = tempfile::TempDir::new()?;
    let source_path = temp_dir.path().join("test_source");
    let dest_path = temp_dir.path().join("test_dest");

    // Execute ATP profile benchmark
    let result = profile.run_benchmark(&config, &source_path, &dest_path).await?;

    // Verify the result structure
    assert_eq!(result.tool_name, "atp-clean-lan");
    assert_eq!(result.iterations.len(), config.iterations as usize);

    // Check that at least some metrics are populated
    if let Some(metrics) = result.iterations.first() {
        assert!(metrics.wall_time > Duration::ZERO);
        assert_eq!(metrics.bytes_transferred, config.data_size);
    }

    println!(
        "✅ ATP profile '{}' executed successfully with {} iterations",
        profile.kind.label(),
        result.iterations.len()
    );

    Ok(())
}

#[tokio::test]
async fn test_benchmark_suite_smoke_test() -> Result<(), Box<dyn std::error::Error>> {
    let mut suite = BenchmarkSuite::smoke_test_suite();
    let config = BenchmarkConfig::smoke_test();

    // Run the benchmark suite
    let report = suite.run_benchmark(&config).await?;

    // Verify report structure
    assert!(!report.atp_results.is_empty(), "Should have ATP results");
    assert_eq!(report.config_summary.data_size, config.data_size);
    assert_eq!(report.config_summary.iterations, config.iterations);

    // Print summary for verification
    println!("Benchmark Report Summary:");
    println!("{}", report.summary());

    // Verify ATP results are present
    assert!(
        report.atp_results.contains_key("atp-clean-lan"),
        "Should have clean-lan ATP profile result"
    );

    // Check if baseline results are present (may be empty if tools not available)
    if !report.baseline_results.is_empty() {
        println!("✅ Baseline tools executed successfully");
    } else {
        println!("⚠️  No baseline tools available (expected in some environments)");
    }

    Ok(())
}

#[tokio::test]
async fn test_benchmark_suite_builder() -> Result<(), Box<dyn std::error::Error>> {
    let mut suite = BenchmarkSuiteBuilder::new("integration-test")
        .with_scp()
        .with_atp_profile(AtpProfile::clean_lan())
        .with_atp_profile(AtpProfile::stream())
        .build();

    let config = BenchmarkConfig {
        data_size: 32 * 1024, // 32KB for fast test
        iterations: 1,
        timeout: Duration::from_secs(30),
        ..BenchmarkConfig::default()
    };

    let report = suite.run_benchmark(&config).await?;

    // Verify builder configuration was applied
    assert_eq!(report.atp_results.len(), 2, "Should have 2 ATP profiles");
    assert!(
        report.atp_results.contains_key("atp-clean-lan"),
        "Should have clean-lan profile"
    );
    assert!(
        report.atp_results.contains_key("atp-stream"),
        "Should have stream profile"
    );

    // Check that ATP profiles have different characteristics
    let clean_lan_stats = report.atp_results["atp-clean-lan"].aggregate_stats();
    let stream_stats = report.atp_results["atp-stream"].aggregate_stats();

    assert!(clean_lan_stats.success_rate > 0.0, "Clean LAN should succeed");
    assert!(stream_stats.success_rate > 0.0, "Stream should succeed");

    println!("✅ Benchmark suite builder worked correctly");
    println!("Clean LAN: {:.2} MB/s", clean_lan_stats.mean_throughput / 1_000_000.0);
    println!("Stream: {:.2} MB/s", stream_stats.mean_throughput / 1_000_000.0);

    Ok(())
}

#[tokio::test]
async fn test_performance_comparison_analysis() -> Result<(), Box<dyn std::error::Error>> {
    let profile = AtpProfile::clean_lan();
    let config = BenchmarkConfig::smoke_test();

    let temp_dir = tempfile::TempDir::new()?;
    let source_path = temp_dir.path().join("comparison_source");
    let dest_path = temp_dir.path().join("comparison_dest");

    // Run ATP benchmark
    let atp_result = profile.run_benchmark(&config, &source_path, &dest_path).await?;
    let atp_stats = atp_result.aggregate_stats();

    // Verify metrics are sensible
    assert!(atp_stats.mean_throughput > 0.0, "Should have positive throughput");
    assert!(atp_stats.success_rate > 0.0, "Should have successful transfers");

    if atp_stats.success_rate >= 1.0 {
        println!("✅ Perfect success rate for ATP profile");
    } else {
        println!(
            "⚠️  Partial success rate: {:.1}%",
            atp_stats.success_rate * 100.0
        );
    }

    // Test that compression ratio calculation works if available
    if let Some(metrics) = atp_result.iterations.first() {
        if let Some(ratio) = metrics.compression_ratio() {
            assert!(ratio >= 0.5 && ratio <= 2.0, "Compression ratio should be reasonable");
            println!("Compression ratio: {:.2}", ratio);
        }
    }

    Ok(())
}

#[test]
fn test_atp_profile_kinds_coverage() {
    use asupersync::atp::benchmark::AtpProfileKind;

    // Verify all profile kinds have proper labels and descriptions
    for kind in AtpProfileKind::all() {
        assert!(!kind.label().is_empty(), "Profile kind should have a label");
        assert!(!kind.description().is_empty(), "Profile kind should have a description");

        // Verify label format (should be kebab-case)
        assert!(
            kind.label().chars().all(|c| c.is_ascii_lowercase() || c == '-'),
            "Profile label should be kebab-case: {}",
            kind.label()
        );
    }

    // Verify smoke test suitable profiles are reasonable
    let smoke_suitable: Vec<_> = AtpProfileKind::all()
        .iter()
        .filter(|k| k.is_smoke_test_suitable())
        .collect();

    assert!(!smoke_suitable.is_empty(), "Should have smoke test suitable profiles");
    assert!(
        smoke_suitable.len() <= 5,
        "Smoke test should not include too many profiles"
    );

    println!("✅ All {} ATP profile kinds are properly configured", AtpProfileKind::all().len());
    println!("Smoke test suitable: {:?}", smoke_suitable.iter().map(|k| k.label()).collect::<Vec<_>>());
}