//! MySQL conformance test runner binary.
//!
//! This binary runs the MySQL wire protocol conformance tests against
//! real MariaDB server instances using Docker.

use asupersync_conformance::mysql_conformance::{MySqlConformanceConfig, MySqlConformanceRunner};
use clap::{Arg, Command};
use std::process;

#[tokio::main]
async fn main() {
    let matches = Command::new("mysql_conformance_runner")
        .version("0.3.1")
        .about("MySQL wire protocol conformance test runner")
        .arg(
            Arg::new("versions")
                .long("versions")
                .help("MariaDB versions to test (comma-separated)")
                .value_name("VERSIONS")
                .default_value("10.5,10.11,11.2"),
        )
        .arg(
            Arg::new("auth-plugins")
                .long("auth-plugins")
                .help("Authentication plugins to test (comma-separated)")
                .value_name("PLUGINS")
                .default_value("mysql_native_password,caching_sha2_password"),
        )
        .arg(
            Arg::new("ssl-modes")
                .long("ssl-modes")
                .help("SSL modes to test (comma-separated)")
                .value_name("MODES")
                .default_value("PREFERRED,REQUIRED,VERIFY_CA"),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .help("Test timeout in seconds")
                .value_name("SECONDS")
                .default_value("300"),
        )
        .arg(
            Arg::new("report-format")
                .long("report-format")
                .help("Report output format")
                .value_name("FORMAT")
                .value_parser(["markdown", "json"])
                .default_value("markdown"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Output file (defaults to stdout)")
                .value_name("FILE"),
        )
        .get_matches();

    // Parse configuration from CLI arguments
    let versions: Vec<String> = matches
        .get_one::<String>("versions")
        .unwrap()
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let auth_plugins: Vec<String> = matches
        .get_one::<String>("auth-plugins")
        .unwrap()
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let ssl_modes: Vec<String> = matches
        .get_one::<String>("ssl-modes")
        .unwrap()
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let timeout_secs: u64 = matches
        .get_one::<String>("timeout")
        .unwrap()
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("Invalid timeout value");
            process::exit(1);
        });

    let config = MySqlConformanceConfig {
        mariadb_versions: versions,
        auth_plugins,
        ssl_modes,
        test_database: "asupersync_test".to_string(),
        timeout_secs,
    };

    eprintln!("Starting MySQL conformance test suite...");
    eprintln!("Configuration: {:?}", config);

    // Create runner and execute tests
    let runner = match MySqlConformanceRunner::new(config) {
        Ok(runner) => runner,
        Err(e) => {
            eprintln!("Failed to create conformance runner: {}", e);
            process::exit(1);
        }
    };

    let results = match runner.run_suite().await {
        Ok(results) => results,
        Err(e) => {
            eprintln!("Test suite execution failed: {}", e);
            process::exit(1);
        }
    };

    // Generate report
    let report_format = matches.get_one::<String>("report-format").unwrap();
    let output = match report_format.as_str() {
        "markdown" => runner.generate_report(&results),
        "json" => serde_json::to_string_pretty(&results).unwrap_or_else(|e| {
            eprintln!("Failed to serialize results to JSON: {}", e);
            process::exit(1);
        }),
        _ => unreachable!(),
    };

    // Write output
    if let Some(output_file) = matches.get_one::<String>("output") {
        if let Err(e) = std::fs::write(output_file, &output) {
            eprintln!("Failed to write output to {}: {}", output_file, e);
            process::exit(1);
        }
        eprintln!("Report written to {}", output_file);
    } else {
        println!("{}", output);
    }

    // Exit with appropriate code
    let failed_tests = results.iter().filter(|r| !r.passed).count();
    if failed_tests > 0 {
        eprintln!("❌ {} tests failed", failed_tests);
        process::exit(1);
    } else {
        eprintln!("✅ All tests passed");
    }
}
