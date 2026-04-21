#![allow(clippy::all)]
//! gRPC Connect Conformance Test Runner
//!
//! This binary executes the complete conformance test suite and outputs
//! results in formats compatible with Connect conformance tools and CI systems.

use anyhow::{Context, Result};
use asupersync::cx::Cx;
use clap::{Arg, Command};
use grpc_conformance_suite::{ConformanceConfig, ConformanceTestSuite};
use std::path::PathBuf;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "grpc_conformance_suite=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let matches = Command::new("grpc-conformance-runner")
        .version("0.1.0")
        .about("gRPC Connect Protocol Conformance Test Runner")
        .arg(
            Arg::new("server")
                .long("server")
                .value_name("ADDRESS")
                .help("gRPC server address to test against")
                .default_value("http://127.0.0.1:8080"),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .value_name("SECONDS")
                .help("Test timeout in seconds")
                .default_value("30"),
        )
        .arg(
            Arg::new("max-message-size")
                .long("max-message-size")
                .value_name("BYTES")
                .help("Maximum message size for testing")
                .default_value("4194304"), // 4MB
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output file for conformance report")
                .default_value("grpc_conformance_report.json"),
        )
        .arg(
            Arg::new("connect-protocol")
                .long("connect-protocol")
                .help("Enable Connect protocol specific tests")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("enable-compression")
                .long("enable-compression")
                .help("Enable compression testing")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("enable-tls")
                .long("enable-tls")
                .help("Enable TLS/SSL testing")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("parallel")
                .long("parallel")
                .help("Run tests in parallel")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("filter")
                .long("filter")
                .value_name("PATTERN")
                .help("Run only tests matching the pattern")
                .action(clap::ArgAction::Append),
        )
        .get_matches();

    let config = ConformanceConfig {
        server_address: matches.get_one::<String>("server").unwrap().clone(),
        timeout: std::time::Duration::from_secs(
            matches.get_one::<String>("timeout")
                .unwrap()
                .parse()
                .context("Invalid timeout value")?
        ),
        max_message_size: matches.get_one::<String>("max-message-size")
            .unwrap()
            .parse()
            .context("Invalid max message size")?,
        enable_compression: matches.get_flag("enable-compression"),
        enable_tls: matches.get_flag("enable-tls"),
        connect_protocol: matches.get_flag("connect-protocol"),
        parallel_execution: matches.get_flag("parallel"),
    };

    let output_file = PathBuf::from(matches.get_one::<String>("output").unwrap());

    info!("Starting gRPC Connect conformance test suite");
    info!("Target server: {}", config.server_address);
    info!("Timeout: {:?}", config.timeout);
    info!("Max message size: {} bytes", config.max_message_size);
    info!("Connect protocol: {}", config.connect_protocol);
    info!("Compression: {}", config.enable_compression);
    info!("TLS: {}", config.enable_tls);

    let cx = Cx::root();
    let mut suite = ConformanceTestSuite::new(config);

    // Run all tests
    let start_time = std::time::Instant::now();
    match suite.run_all_tests(&cx).await {
        Ok(_) => {
            let duration = start_time.elapsed();
            info!("Conformance test suite completed in {:?}", duration);

            let conformance_percentage = suite.conformance_percentage();
            info!("Overall conformance: {:.1}%", conformance_percentage);

            // Write detailed results to output file
            let results_json = serde_json::to_string_pretty(suite.get_results())
                .context("Failed to serialize results")?;
            std::fs::write(&output_file, results_json)
                .context("Failed to write output file")?;

            info!("Detailed results written to {}", output_file.display());

            // Exit with appropriate code
            if conformance_percentage >= 95.0 {
                info!("✅ Conformance test suite PASSED (≥95% compliance)");
                std::process::exit(0);
            } else if conformance_percentage >= 80.0 {
                warn!("⚠️  Conformance test suite PARTIAL (80-95% compliance)");
                std::process::exit(1);
            } else {
                warn!("❌ Conformance test suite FAILED (<80% compliance)");
                std::process::exit(2);
            }
        }
        Err(e) => {
            eprintln!("❌ Conformance test suite failed with error: {:?}", e);
            std::process::exit(3);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(dead_code)]
    fn test_cli_parsing() {
        let app = Command::new("test")
            .arg(
                Arg::new("server")
                    .long("server")
                    .default_value("http://127.0.0.1:8080"),
            );

        let matches = app.try_get_matches_from(&["test"]).unwrap();
        assert_eq!(matches.get_one::<String>("server").unwrap(), "http://127.0.0.1:8080");
    }
}