//! Maintain Fixtures Binary
//!
//! CLI tool for automated maintenance of RaptorQ conformance test fixtures,
//! including cleanup, health analysis, and automated maintenance workflows.

use anyhow::{Context, Result};
use clap::{Arg, Command};
use raptorq_conformance_reporting::maintenance_workflows::{
    MaintenanceActionType, MaintenanceConfig, MaintenanceWorkflow,
};
use std::path::PathBuf;

#[allow(dead_code)]

fn main() -> Result<()> {
    let app = Command::new("maintain_fixtures")
        .about("Automated maintenance for RaptorQ conformance test fixtures")
        .version("1.0.0")
        .arg(
            Arg::new("golden-dir")
                .short('g')
                .long("golden-dir")
                .value_name("DIR")
                .help("Path to golden files directory")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("fixture-dir")
                .short('f')
                .long("fixture-dir")
                .value_name("DIR")
                .help("Path to fixture files directory")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("output-dir")
                .short('o')
                .long("output-dir")
                .value_name("DIR")
                .help("Output directory for maintenance reports and snapshots")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("mode")
                .short('m')
                .long("mode")
                .value_name("MODE")
                .help("Maintenance mode")
                .value_parser(["analyze", "cleanup", "full", "health"])
                .default_value("analyze"),
        )
        .arg(
            Arg::new("max-golden-age")
                .long("max-golden-age")
                .value_name("DAYS")
                .help("Maximum age for golden files in days")
                .default_value("30")
                .value_parser(clap::value_parser!(i64)),
        )
        .arg(
            Arg::new("max-fixture-age")
                .long("max-fixture-age")
                .value_name("DAYS")
                .help("Maximum age for fixture files in days")
                .default_value("7")
                .value_parser(clap::value_parser!(i64)),
        )
        .arg(
            Arg::new("max-snapshots")
                .long("max-snapshots")
                .value_name("COUNT")
                .help("Maximum number of historical snapshots to keep")
                .default_value("50")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("large-file-threshold")
                .long("large-file-threshold")
                .value_name("BYTES")
                .help("Size threshold for large files in bytes")
                .default_value("10485760") // 10MB
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("aggressive")
                .long("aggressive")
                .help("Enable aggressive cleanup (actually delete files)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Show what would be done without making changes")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .value_name("FORMAT")
                .help("Output format for reports")
                .value_parser(["text", "json", "markdown"])
                .default_value("text"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::SetTrue),
        );

    let matches = app.get_matches();

    let golden_dir = matches.get_one::<PathBuf>("golden-dir").unwrap();
    let fixture_dir = matches.get_one::<PathBuf>("fixture-dir").unwrap();
    let output_dir = matches.get_one::<PathBuf>("output-dir").unwrap();
    let mode = matches.get_one::<String>("mode").unwrap();
    let max_golden_age = *matches.get_one::<i64>("max-golden-age").unwrap();
    let max_fixture_age = *matches.get_one::<i64>("max-fixture-age").unwrap();
    let max_snapshots = *matches.get_one::<usize>("max-snapshots").unwrap();
    let large_file_threshold = *matches.get_one::<u64>("large-file-threshold").unwrap();
    let aggressive = matches.get_flag("aggressive");
    let dry_run = matches.get_flag("dry-run");
    let format = matches.get_one::<String>("format").unwrap();
    let verbose = matches.get_flag("verbose");

    if verbose {
        println!("🔧 Starting maintenance workflow...");
        println!("  Mode: {}", mode);
        println!("  Golden directory: {}", golden_dir.display());
        println!("  Fixture directory: {}", fixture_dir.display());
        println!("  Output directory: {}", output_dir.display());
        println!("  Max golden age: {} days", max_golden_age);
        println!("  Max fixture age: {} days", max_fixture_age);
        println!("  Aggressive cleanup: {}", aggressive && !dry_run);
        println!("  Dry run: {}", dry_run);
    }

    // Create maintenance configuration
    let config = MaintenanceConfig {
        max_golden_age_days: max_golden_age,
        max_fixture_age_days: max_fixture_age,
        max_snapshots_to_keep: max_snapshots,
        monitored_paths: vec![golden_dir.clone(), fixture_dir.clone()],
        aggressive_cleanup: aggressive && !dry_run,
        large_file_threshold,
    };

    let workflow = MaintenanceWorkflow::new(config);

    match mode.as_str() {
        "analyze" => run_analyze_mode(
            &workflow,
            golden_dir,
            fixture_dir,
            output_dir,
            format,
            verbose,
        )?,
        "health" => run_health_mode(&workflow, golden_dir, fixture_dir, format, verbose)?,
        "cleanup" => run_cleanup_mode(
            &workflow,
            golden_dir,
            fixture_dir,
            output_dir,
            dry_run,
            verbose,
        )?,
        "full" => run_full_maintenance(
            &workflow,
            golden_dir,
            fixture_dir,
            output_dir,
            dry_run,
            verbose,
        )?,
        _ => anyhow::bail!(
            "Invalid mode: {}. Valid options: analyze, health, cleanup, full",
            mode
        ),
    }

    Ok(())
}

#[allow(dead_code)]

fn run_analyze_mode(
    workflow: &MaintenanceWorkflow,
    golden_dir: &PathBuf,
    fixture_dir: &PathBuf,
    output_dir: &PathBuf,
    format: &str,
    verbose: bool,
) -> Result<()> {
    if verbose {
        println!("📊 Running analysis mode...");
    }

    // Analyze file health
    let health_statuses = workflow
        .analyze_file_health(golden_dir, fixture_dir)
        .context("Failed to analyze file health")?;

    if verbose {
        println!("  Analyzed {} files", health_statuses.len());
    }

    // Generate recommendations
    let recommendations = workflow.generate_recommendations(&health_statuses);

    // Create output based on format
    match format {
        "json" => {
            let analysis_data = serde_json::json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "total_files": health_statuses.len(),
                "stale_files": health_statuses.iter().filter(|s| s.is_stale).count(),
                "large_files": health_statuses.iter().filter(|s| s.is_large).count(),
                "unhealthy_files": health_statuses.iter().filter(|s| s.health_score < 0.5).count(),
                "average_health_score": health_statuses.iter().map(|s| s.health_score).sum::<f64>() / health_statuses.len() as f64,
                "recommendations": recommendations,
                "file_health": health_statuses,
            });

            let output_path = output_dir.join("file_health_analysis.json");
            std::fs::create_dir_all(output_dir).with_context(|| {
                format!(
                    "Failed to create output directory: {}",
                    output_dir.display()
                )
            })?;

            std::fs::write(&output_path, serde_json::to_string_pretty(&analysis_data)?)
                .with_context(|| {
                    format!("Failed to write analysis to: {}", output_path.display())
                })?;

            println!("📄 Analysis written to: {}", output_path.display());
        }
        "markdown" => {
            let mut markdown = String::new();
            markdown.push_str("# File Health Analysis Report\n\n");
            markdown.push_str(&format!(
                "Generated: {}\n\n",
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
            ));

            markdown.push_str("## Summary\n\n");
            markdown.push_str(&format!("- **Total Files:** {}\n", health_statuses.len()));
            markdown.push_str(&format!(
                "- **Stale Files:** {}\n",
                health_statuses.iter().filter(|s| s.is_stale).count()
            ));
            markdown.push_str(&format!(
                "- **Large Files:** {}\n",
                health_statuses.iter().filter(|s| s.is_large).count()
            ));
            markdown.push_str(&format!(
                "- **Unhealthy Files:** {}\n",
                health_statuses
                    .iter()
                    .filter(|s| s.health_score < 0.5)
                    .count()
            ));

            let avg_health = health_statuses.iter().map(|s| s.health_score).sum::<f64>()
                / health_statuses.len() as f64;
            markdown.push_str(&format!(
                "- **Average Health Score:** {:.2}\n\n",
                avg_health
            ));

            markdown.push_str("## Recommendations\n\n");
            for rec in &recommendations {
                markdown.push_str(&format!("- {}\n", rec));
            }
            markdown.push_str("\n");

            if !health_statuses
                .iter()
                .filter(|s| s.health_score < 0.5)
                .collect::<Vec<_>>()
                .is_empty()
            {
                markdown.push_str("## Unhealthy Files\n\n");
                for status in health_statuses.iter().filter(|s| s.health_score < 0.5) {
                    markdown.push_str(&format!("### {}\n\n", status.path.display()));
                    markdown.push_str(&format!("- **Health Score:** {:.2}\n", status.health_score));
                    markdown.push_str(&format!("- **Age:** {} days\n", status.age_days));
                    markdown.push_str(&format!("- **Size:** {} bytes\n", status.size_bytes));
                    markdown.push_str(&format!("- **Is Stale:** {}\n", status.is_stale));
                    markdown.push_str(&format!("- **Is Large:** {}\n\n", status.is_large));
                }
            }

            let output_path = output_dir.join("file_health_analysis.md");
            std::fs::create_dir_all(output_dir).with_context(|| {
                format!(
                    "Failed to create output directory: {}",
                    output_dir.display()
                )
            })?;

            std::fs::write(&output_path, markdown).with_context(|| {
                format!("Failed to write analysis to: {}", output_path.display())
            })?;

            println!("📄 Analysis written to: {}", output_path.display());
        }
        "text" | _ => {
            println!("\n📊 File Health Analysis Results");
            println!("================================");
            println!("Total files analyzed: {}", health_statuses.len());
            println!(
                "Stale files: {}",
                health_statuses.iter().filter(|s| s.is_stale).count()
            );
            println!(
                "Large files: {}",
                health_statuses.iter().filter(|s| s.is_large).count()
            );
            println!(
                "Unhealthy files: {}",
                health_statuses
                    .iter()
                    .filter(|s| s.health_score < 0.5)
                    .count()
            );

            let avg_health = health_statuses.iter().map(|s| s.health_score).sum::<f64>()
                / health_statuses.len() as f64;
            println!("Average health score: {:.2}", avg_health);

            println!("\n💡 Recommendations:");
            for rec in &recommendations {
                println!("  • {}", rec);
            }

            // Show most unhealthy files
            let mut unhealthy: Vec<_> = health_statuses
                .iter()
                .filter(|s| s.health_score < 0.7)
                .collect();
            unhealthy.sort_by(|a, b| a.health_score.partial_cmp(&b.health_score).unwrap());

            if !unhealthy.is_empty() {
                println!("\n⚠️  Files Needing Attention:");
                for (i, status) in unhealthy.iter().take(10).enumerate() {
                    let health_emoji = if status.health_score < 0.3 {
                        "🔴"
                    } else if status.health_score < 0.6 {
                        "🟡"
                    } else {
                        "🟢"
                    };
                    println!(
                        "  {}. {} {} (health: {:.2}, age: {} days, size: {} bytes)",
                        i + 1,
                        health_emoji,
                        status.path.display(),
                        status.health_score,
                        status.age_days,
                        status.size_bytes
                    );
                }

                if unhealthy.len() > 10 {
                    println!("  ... and {} more files", unhealthy.len() - 10);
                }
            }
        }
    }

    Ok(())
}

#[allow(dead_code)]

fn run_health_mode(
    workflow: &MaintenanceWorkflow,
    golden_dir: &PathBuf,
    fixture_dir: &PathBuf,
    format: &str,
    verbose: bool,
) -> Result<()> {
    if verbose {
        println!("🏥 Running health check mode...");
    }

    let health_statuses = workflow
        .analyze_file_health(golden_dir, fixture_dir)
        .context("Failed to analyze file health")?;

    // Calculate overall health metrics
    let total_files = health_statuses.len();
    let healthy_files = health_statuses
        .iter()
        .filter(|s| s.health_score >= 0.7)
        .count();
    let unhealthy_files = health_statuses
        .iter()
        .filter(|s| s.health_score < 0.5)
        .count();
    let stale_files = health_statuses.iter().filter(|s| s.is_stale).count();
    let large_files = health_statuses.iter().filter(|s| s.is_large).count();

    let overall_health = if total_files > 0 {
        healthy_files as f64 / total_files as f64
    } else {
        1.0
    };

    let health_emoji = if overall_health >= 0.9 {
        "🟢"
    } else if overall_health >= 0.7 {
        "🟡"
    } else {
        "🔴"
    };

    match format {
        "json" => {
            let health_report = serde_json::json!({
                "overall_health": overall_health,
                "total_files": total_files,
                "healthy_files": healthy_files,
                "unhealthy_files": unhealthy_files,
                "stale_files": stale_files,
                "large_files": large_files,
                "health_status": if overall_health >= 0.9 { "EXCELLENT" } else if overall_health >= 0.7 { "GOOD" } else if overall_health >= 0.5 { "FAIR" } else { "POOR" }
            });

            println!("{}", serde_json::to_string_pretty(&health_report)?);
        }
        _ => {
            println!(
                "{} Overall Health: {:.1}%",
                health_emoji,
                overall_health * 100.0
            );
            println!(
                "Files: {} total, {} healthy, {} unhealthy",
                total_files, healthy_files, unhealthy_files
            );

            if stale_files > 0 {
                println!("⏰ {} stale files detected", stale_files);
            }
            if large_files > 0 {
                println!("📦 {} large files detected", large_files);
            }
            if unhealthy_files == 0 {
                println!("✨ No unhealthy files found!");
            }
        }
    }

    // Exit with appropriate code based on health
    let exit_code = if overall_health >= 0.9 {
        0
    } else if overall_health >= 0.7 {
        1
    } else {
        2
    };

    std::process::exit(exit_code);
}

#[allow(dead_code)]

fn run_cleanup_mode(
    workflow: &MaintenanceWorkflow,
    golden_dir: &PathBuf,
    fixture_dir: &PathBuf,
    output_dir: &PathBuf,
    dry_run: bool,
    verbose: bool,
) -> Result<()> {
    if dry_run {
        println!("🧪 Running in DRY RUN mode - no files will be modified");
    } else if verbose {
        println!("🧹 Running cleanup mode...");
    }

    let result = workflow
        .execute_maintenance(golden_dir, fixture_dir, output_dir)
        .context("Failed to execute maintenance workflow")?;

    println!("\n🔧 Maintenance Results");
    println!("=====================");
    println!("Actions performed: {}", result.actions_performed.len());
    println!("Files cleaned: {}", result.cleaned_files.len());
    println!("Files updated: {}", result.updated_files.len());

    if !result.errors.is_empty() {
        println!("Errors encountered: {}", result.errors.len());
        for error in &result.errors {
            println!("  ❌ {}", error);
        }
    }

    println!(
        "Space reclaimed: {} bytes ({:.1} MB)",
        result.statistics.space_reclaimed,
        result.statistics.space_reclaimed as f64 / (1024.0 * 1024.0)
    );
    println!(
        "Duration: {:.1} seconds",
        result.statistics.duration_seconds
    );

    if verbose {
        println!("\n📋 Detailed Actions:");
        for action in &result.actions_performed {
            let status_emoji = if action.successful { "✅" } else { "❌" };
            println!(
                "  {} {:?}: {}",
                status_emoji, action.action_type, action.description
            );

            if let Some(ref error) = action.error_message {
                println!("    Error: {}", error);
            }

            if !action.affected_files.is_empty() {
                println!("    Files affected: {}", action.affected_files.len());
                if verbose && action.affected_files.len() <= 5 {
                    for file in &action.affected_files {
                        println!("      - {}", file.display());
                    }
                }
            }
        }
    }

    // Save detailed results as JSON
    let results_path = output_dir.join("maintenance_results.json");
    std::fs::create_dir_all(output_dir).with_context(|| {
        format!(
            "Failed to create output directory: {}",
            output_dir.display()
        )
    })?;

    std::fs::write(&results_path, serde_json::to_string_pretty(&result)?)
        .with_context(|| format!("Failed to write results to: {}", results_path.display()))?;

    println!("\n📄 Detailed results saved to: {}", results_path.display());

    Ok(())
}

#[allow(dead_code)]

fn run_full_maintenance(
    workflow: &MaintenanceWorkflow,
    golden_dir: &PathBuf,
    fixture_dir: &PathBuf,
    output_dir: &PathBuf,
    dry_run: bool,
    verbose: bool,
) -> Result<()> {
    if dry_run {
        println!("🧪 Running full maintenance in DRY RUN mode");
    } else if verbose {
        println!("🔧 Running full maintenance workflow...");
    }

    // 1. Health analysis
    println!("📊 Step 1: Health Analysis");
    let health_statuses = workflow
        .analyze_file_health(golden_dir, fixture_dir)
        .context("Failed to analyze file health")?;

    let recommendations = workflow.generate_recommendations(&health_statuses);
    println!("  Analyzed {} files", health_statuses.len());
    println!("  Generated {} recommendations", recommendations.len());

    // 2. Maintenance execution
    println!("\n🧹 Step 2: Automated Maintenance");
    let result = workflow
        .execute_maintenance(golden_dir, fixture_dir, output_dir)
        .context("Failed to execute maintenance workflow")?;

    println!("  Performed {} actions", result.actions_performed.len());
    println!("  Cleaned {} files", result.cleaned_files.len());

    // 3. Generate comprehensive report
    println!("\n📄 Step 3: Report Generation");
    let report_path = output_dir.join("full_maintenance_report.md");

    let mut report = String::new();
    report.push_str("# Full Maintenance Report\n\n");
    report.push_str(&format!(
        "Generated: {}\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));

    report.push_str("## Summary\n\n");
    report.push_str(&format!(
        "- **Files Analyzed:** {}\n",
        health_statuses.len()
    ));
    report.push_str(&format!(
        "- **Actions Performed:** {}\n",
        result.actions_performed.len()
    ));
    report.push_str(&format!(
        "- **Files Cleaned:** {}\n",
        result.cleaned_files.len()
    ));
    report.push_str(&format!(
        "- **Space Reclaimed:** {} bytes\n",
        result.statistics.space_reclaimed
    ));
    report.push_str(&format!(
        "- **Duration:** {:.1} seconds\n\n",
        result.statistics.duration_seconds
    ));

    report.push_str("## Recommendations\n\n");
    for rec in &recommendations {
        report.push_str(&format!("- {}\n", rec));
    }
    report.push_str("\n");

    report.push_str("## Actions Performed\n\n");
    for action in &result.actions_performed {
        report.push_str(&format!("### {:?}\n", action.action_type));
        report.push_str(&format!(
            "- **Status:** {}\n",
            if action.successful {
                "✅ Success"
            } else {
                "❌ Failed"
            }
        ));
        report.push_str(&format!("- **Description:** {}\n", action.description));
        report.push_str(&format!(
            "- **Files Affected:** {}\n",
            action.affected_files.len()
        ));

        if let Some(ref error) = action.error_message {
            report.push_str(&format!("- **Error:** {}\n", error));
        }
        report.push_str("\n");
    }

    std::fs::write(&report_path, report)
        .with_context(|| format!("Failed to write report to: {}", report_path.display()))?;

    println!("  Report saved to: {}", report_path.display());

    // Overall status
    let success_rate = result
        .actions_performed
        .iter()
        .filter(|a| a.successful)
        .count() as f64
        / result.actions_performed.len().max(1) as f64;

    let status_emoji = if success_rate >= 0.9 {
        "✅"
    } else if success_rate >= 0.7 {
        "⚠️"
    } else {
        "❌"
    };

    println!("\n{} Maintenance Complete", status_emoji);
    println!("Success rate: {:.1}%", success_rate * 100.0);

    if !result.errors.is_empty() {
        println!(
            "⚠️  {} errors encountered - check the detailed report",
            result.errors.len()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    #[allow(dead_code)]
    fn test_cli_parsing() {
        let app = Command::new("maintain_fixtures")
            .arg(
                Arg::new("golden-dir")
                    .short('g')
                    .long("golden-dir")
                    .required(true)
                    .value_parser(clap::value_parser!(PathBuf)),
            )
            .arg(
                Arg::new("fixture-dir")
                    .short('f')
                    .long("fixture-dir")
                    .required(true)
                    .value_parser(clap::value_parser!(PathBuf)),
            )
            .arg(
                Arg::new("output-dir")
                    .short('o')
                    .long("output-dir")
                    .required(true)
                    .value_parser(clap::value_parser!(PathBuf)),
            );

        let temp_dir = TempDir::new().unwrap();
        let args = vec![
            "maintain_fixtures",
            "--golden-dir",
            temp_dir.path().to_str().unwrap(),
            "--fixture-dir",
            temp_dir.path().to_str().unwrap(),
            "--output-dir",
            temp_dir.path().to_str().unwrap(),
        ];

        let matches = app.try_get_matches_from(args);
        assert!(matches.is_ok());
    }

    #[test]
    #[allow(dead_code)]
    fn test_maintenance_config_creation() {
        let config = MaintenanceConfig {
            max_golden_age_days: 30,
            max_fixture_age_days: 7,
            max_snapshots_to_keep: 50,
            monitored_paths: vec![],
            aggressive_cleanup: false,
            large_file_threshold: 10 * 1024 * 1024,
        };

        assert_eq!(config.max_golden_age_days, 30);
        assert_eq!(config.max_fixture_age_days, 7);
        assert!(!config.aggressive_cleanup);
    }
}
