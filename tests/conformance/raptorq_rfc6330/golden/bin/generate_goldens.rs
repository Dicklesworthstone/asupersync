//! Golden File Generation CLI
//!
//! Generates golden files for RaptorQ RFC 6330 conformance testing.

use clap::{Arg, Command};
use raptorq_golden_testing::{run_complete_test_suite, FixtureGenerator};
use std::env;
use std::path::PathBuf;

#[allow(dead_code)]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("generate_goldens")
        .version("1.0.0")
        .author("asupersync contributors")
        .about("Generate RFC 6330 golden test fixtures")
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("DIR")
                .help("Output directory for golden files")
                .default_value("fixtures"),
        )
        .arg(
            Arg::new("golden")
                .short('g')
                .long("golden")
                .value_name("DIR")
                .help("Golden files directory")
                .default_value("golden"),
        )
        .arg(
            Arg::new("update")
                .short('u')
                .long("update")
                .action(clap::ArgAction::SetTrue)
                .help("Update existing golden files (sets UPDATE_GOLDENS=1)"),
        )
        .arg(
            Arg::new("smoke-only")
                .long("smoke-only")
                .action(clap::ArgAction::SetTrue)
                .help("Only generate high-priority smoke test fixtures"),
        )
        .get_matches();

    let output_dir = PathBuf::from(matches.get_one::<String>("output").unwrap());
    let golden_dir = PathBuf::from(matches.get_one::<String>("golden").unwrap());
    let update_goldens = matches.get_flag("update");
    let smoke_only = matches.get_flag("smoke-only");

    // Set UPDATE_GOLDENS environment variable if requested
    if update_goldens {
        env::set_var("UPDATE_GOLDENS", "1");
        println!("🔄 UPDATE_GOLDENS mode enabled");
    }

    println!("🚀 Generating RaptorQ RFC 6330 golden files...");
    println!("   Fixture directory: {}", output_dir.display());
    println!("   Golden directory: {}", golden_dir.display());

    if smoke_only {
        println!("   Mode: Smoke tests only (high-priority fixtures)");

        // Generate just the smoke test fixtures
        let generator = FixtureGenerator::new(&output_dir);
        let fixture_summary = generator.generate_all_fixtures()?;

        println!("\n📊 Fixture Generation Results:");
        println!("   Generated: {}", fixture_summary.generated_fixtures);
        println!("   Failed: {}", fixture_summary.failed_fixtures);

        if fixture_summary.failed_fixtures > 0 {
            println!("\n❌ Fixture generation errors:");
            for error in &fixture_summary.errors {
                println!("   - {}", error);
            }
        }

        // Run smoke tests only
        println!("\n🧪 Running smoke tests...");
        let smoke_summary = raptorq_golden_testing::run_smoke_tests(&golden_dir)?;
        println!("   Total tests: {}", smoke_summary.total_tests);
        println!("   Passed: {}", smoke_summary.passed_tests);
        println!("   Failed: {}", smoke_summary.failed_tests);

        if smoke_summary.failed_tests > 0 {
            println!("\n❌ Smoke test failures:");
            for failure in &smoke_summary.failures {
                println!("   - {}", failure);
            }
        }
    } else {
        println!("   Mode: Complete test suite");

        // Run complete test suite
        let results = run_complete_test_suite(&golden_dir, &output_dir)?;

        // Print detailed results
        println!("\n{}", results.summary_report());

        if !results.is_success() {
            eprintln!("\n❌ Some tests failed. Check the output above for details.");
            std::process::exit(1);
        }
    }

    println!("\n✅ Golden file generation completed successfully!");

    if update_goldens {
        println!("\n📝 Golden files have been updated. Review changes before committing:");
        println!("   git diff {}", golden_dir.display());
    }

    Ok(())
}
