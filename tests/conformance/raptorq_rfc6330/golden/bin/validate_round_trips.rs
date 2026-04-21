//! Round-Trip Validation CLI
//!
//! Validates RaptorQ round-trip encode/decode cycles against golden files.

use clap::{Arg, Command};
use raptorq_golden_testing::{FormatValidator, RoundTripHarness};
use std::path::PathBuf;

#[allow(dead_code)]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("validate_round_trips")
        .version("1.0.0")
        .author("asupersync contributors")
        .about("Validate RaptorQ round-trip conformance against golden files")
        .arg(
            Arg::new("golden")
                .short('g')
                .long("golden")
                .value_name("DIR")
                .help("Golden files directory")
                .default_value("golden"),
        )
        .arg(
            Arg::new("comprehensive")
                .long("comprehensive")
                .action(clap::ArgAction::SetTrue)
                .help("Run comprehensive validation including all test categories"),
        )
        .arg(
            Arg::new("category")
                .short('c')
                .long("category")
                .value_name("CATEGORY")
                .help("Run tests only for specific category")
                .value_parser(["basic", "edge", "performance", "error", "spec", "interop"]),
        )
        .arg(
            Arg::new("validate-format")
                .long("validate-format")
                .action(clap::ArgAction::SetTrue)
                .help("Also validate golden file format and structure"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(clap::ArgAction::SetTrue)
                .help("Verbose output including test details"),
        )
        .get_matches();

    let golden_dir = PathBuf::from(matches.get_one::<String>("golden").unwrap());
    let comprehensive = matches.get_flag("comprehensive");
    let validate_format = matches.get_flag("validate-format");
    let verbose = matches.get_flag("verbose");
    let category_filter = matches.get_one::<String>("category");

    println!("🧪 RaptorQ Round-Trip Validation");
    println!("   Golden directory: {}", golden_dir.display());

    // Format validation if requested
    if validate_format {
        println!("\n📋 Validating golden file format...");
        let validator = FormatValidator::new();
        let format_results = validator.validate_directory(&golden_dir)?;

        println!("   Total files: {}", format_results.total_files);
        println!("   Valid files: {}", format_results.valid_files);
        println!(
            "   Success rate: {:.1}%",
            format_results.success_rate() * 100.0
        );

        if verbose {
            for (file_path, result) in &format_results.results {
                match result {
                    Ok(validation_result) => {
                        if !validation_result.is_valid || validation_result.has_critical_issues() {
                            println!(
                                "   ⚠️  {}: {} issues",
                                file_path.display(),
                                validation_result.issues.len()
                            );
                            if verbose {
                                for issue in &validation_result.issues {
                                    println!("      - {:?}: {}", issue.severity, issue.description);
                                }
                            }
                        } else if verbose {
                            println!("   ✅ {}: OK", file_path.display());
                        }
                    }
                    Err(e) => {
                        println!("   ❌ {}: {}", file_path.display(), e);
                    }
                }
            }
        }

        if format_results.success_rate() < 0.95 {
            eprintln!("\n❌ Golden file format validation failed (success rate < 95%)");
            std::process::exit(1);
        }
    }

    // Round-trip validation
    println!("\n🔄 Running round-trip validation...");

    let harness = if let Some(category) = category_filter {
        println!("   Category filter: {}", category);

        // Create custom configs based on category
        let configs = match category.as_str() {
            "basic" => get_basic_test_configs(),
            "edge" => get_edge_test_configs(),
            "performance" => get_performance_test_configs(),
            "error" => get_error_test_configs(),
            "spec" => get_spec_compliance_configs(),
            "interop" => get_interop_configs(),
            _ => {
                eprintln!("❌ Unknown category: {}", category);
                std::process::exit(1);
            }
        };

        RoundTripHarness::with_configs(&golden_dir, configs)
    } else if comprehensive {
        println!("   Mode: Comprehensive (all categories)");
        RoundTripHarness::new(&golden_dir)
    } else {
        println!("   Mode: Standard test suite");
        RoundTripHarness::new(&golden_dir)
    };

    let summary = harness.run_all_tests()?;

    println!("\n📊 Round-Trip Test Results:");
    println!("   Total tests: {}", summary.total_tests);
    println!("   Passed: {}", summary.passed_tests);
    println!("   Failed: {}", summary.failed_tests);
    println!("   Pass rate: {:.1}%", summary.pass_rate() * 100.0);

    if verbose || summary.failed_tests > 0 {
        println!("\n{}", summary);
    }

    if summary.failed_tests > 0 {
        eprintln!(
            "\n❌ Round-trip validation failed ({} failures)",
            summary.failed_tests
        );
        std::process::exit(1);
    }

    println!("\n✅ All round-trip validations passed!");
    Ok(())
}

// Helper functions to create test configurations for specific categories

#[allow(dead_code)]

fn get_basic_test_configs() -> Vec<raptorq_golden_testing::RoundTripConfig> {
    use raptorq_golden_testing::RoundTripConfig;

    vec![
        RoundTripConfig {
            source_symbols: 10,
            symbol_size: 64,
            repair_symbols: 5,
            seed: 1,
            test_erasures: false,
            erasure_probability: 0.0,
        },
        RoundTripConfig {
            source_symbols: 100,
            symbol_size: 1024,
            repair_symbols: 50,
            seed: 42,
            test_erasures: true,
            erasure_probability: 0.1,
        },
    ]
}

#[allow(dead_code)]

fn get_edge_test_configs() -> Vec<raptorq_golden_testing::RoundTripConfig> {
    use raptorq_golden_testing::RoundTripConfig;

    vec![
        RoundTripConfig {
            source_symbols: 1,
            symbol_size: 1,
            repair_symbols: 1,
            seed: 999,
            test_erasures: false,
            erasure_probability: 0.0,
        },
        RoundTripConfig {
            source_symbols: 8192,
            symbol_size: 1024,
            repair_symbols: 1000,
            seed: 777,
            test_erasures: false,
            erasure_probability: 0.0,
        },
    ]
}

#[allow(dead_code)]

fn get_performance_test_configs() -> Vec<raptorq_golden_testing::RoundTripConfig> {
    use raptorq_golden_testing::RoundTripConfig;

    vec![RoundTripConfig {
        source_symbols: 1000,
        symbol_size: 1024,
        repair_symbols: 200,
        seed: 123,
        test_erasures: true,
        erasure_probability: 0.15,
    }]
}

#[allow(dead_code)]

fn get_error_test_configs() -> Vec<raptorq_golden_testing::RoundTripConfig> {
    use raptorq_golden_testing::RoundTripConfig;

    vec![RoundTripConfig {
        source_symbols: 50,
        symbol_size: 512,
        repair_symbols: 20,
        seed: 456,
        test_erasures: true,
        erasure_probability: 0.5,
    }]
}

#[allow(dead_code)]

fn get_spec_compliance_configs() -> Vec<raptorq_golden_testing::RoundTripConfig> {
    use raptorq_golden_testing::RoundTripConfig;

    vec![RoundTripConfig {
        source_symbols: 64,
        symbol_size: 256,
        repair_symbols: 32,
        seed: 321,
        test_erasures: false,
        erasure_probability: 0.0,
    }]
}

#[allow(dead_code)]

fn get_interop_configs() -> Vec<raptorq_golden_testing::RoundTripConfig> {
    use raptorq_golden_testing::RoundTripConfig;

    vec![RoundTripConfig {
        source_symbols: 256,
        symbol_size: 1024,
        repair_symbols: 64,
        seed: 0x12345678,
        test_erasures: true,
        erasure_probability: 0.25,
    }]
}
