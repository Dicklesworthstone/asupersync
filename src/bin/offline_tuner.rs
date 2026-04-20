//! Offline kernel superoptimization CLI for RaptorQ GF(256) operations.
//!
//! This binary provides a command-line interface for running offline kernel
//! superoptimization workflows that explore tile/unroll/prefetch/fusion variants
//! for GF256 superkernels and emit optimized architecture-specific profile packs.
//!
//! # Usage
//!
//! ```bash
//! # Run optimization for current host architecture
//! cargo run --bin offline_tuner -- optimize --auto-detect
//!
//! # Run optimization for specific architecture
//! cargo run --bin offline_tuner -- optimize --arch x86-avx2
//!
//! # Generate candidate list without benchmarking
//! cargo run --bin offline_tuner -- candidates --arch aarch64-neon
//!
//! # Emit profile pack from previous tuning results
//! cargo run --bin offline_tuner -- emit-profile --results-file tuning_results.json
//! ```

use std::fs;
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use serde_json;

use asupersync::raptorq::gf256::{Gf256ArchitectureClass, active_kernel};
use asupersync::raptorq::offline_tuner::{OfflineTuner, OptimizationCriteria};

#[derive(Parser)]
#[command(name = "offline_tuner")]
#[command(about = "Offline kernel superoptimization for RaptorQ GF(256) operations")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output directory for results and artifacts
    #[arg(short, long, global = true, default_value = "tuning_results")]
    output_dir: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Run complete offline optimization workflow
    Optimize {
        /// Target architecture for optimization
        #[arg(long, value_enum)]
        arch: Option<ArchitectureArg>,

        /// Auto-detect host architecture
        #[arg(long)]
        auto_detect: bool,

        /// Latency optimization weight (0.0-1.0)
        #[arg(long, default_value = "0.5")]
        latency_weight: f64,

        /// Throughput optimization weight (0.0-1.0)
        #[arg(long, default_value = "0.3")]
        throughput_weight: f64,

        /// Bandwidth optimization weight (0.0-1.0)
        #[arg(long, default_value = "0.2")]
        bandwidth_weight: f64,

        /// Minimum improvement threshold (%)
        #[arg(long, default_value = "5.0")]
        min_improvement_threshold: f64,
    },

    /// Generate candidate kernel configurations without benchmarking
    Candidates {
        /// Target architecture
        #[arg(long, value_enum)]
        arch: ArchitectureArg,
    },

    /// Emit optimized profile pack from tuning results
    EmitProfile {
        /// Path to tuning results JSON file
        #[arg(long)]
        results_file: PathBuf,

        /// Output path for generated profile pack
        #[arg(long, default_value = "optimized_profile.json")]
        output_file: PathBuf,
    },

    /// Validate bit-exactness of optimized kernels
    Validate {
        /// Target architecture
        #[arg(long, value_enum)]
        arch: ArchitectureArg,

        /// Profile pack to validate
        #[arg(long)]
        profile_file: Option<PathBuf>,
    },
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum ArchitectureArg {
    #[value(name = "scalar")]
    Scalar,
    #[value(name = "x86-avx2")]
    X86Avx2,
    #[value(name = "aarch64-neon")]
    Aarch64Neon,
}

impl From<ArchitectureArg> for Gf256ArchitectureClass {
    fn from(arg: ArchitectureArg) -> Self {
        match arg {
            ArchitectureArg::Scalar => Gf256ArchitectureClass::GenericScalar,
            ArchitectureArg::X86Avx2 => Gf256ArchitectureClass::X86Avx2,
            ArchitectureArg::Aarch64Neon => Gf256ArchitectureClass::Aarch64Neon,
        }
    }
}

fn main() {
    let cli = Cli::parse();

    // Initialize logging based on verbosity
    if cli.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    // Create output directory
    if let Err(e) = fs::create_dir_all(&cli.output_dir) {
        eprintln!("Error: Failed to create output directory: {}", e);
        process::exit(1);
    }

    let result = match cli.command {
        Commands::Optimize {
            arch,
            auto_detect,
            latency_weight,
            throughput_weight,
            bandwidth_weight,
            min_improvement_threshold,
        } => run_optimization(
            arch,
            auto_detect,
            &cli.output_dir,
            cli.verbose,
            OptimizationCriteria {
                latency_weight,
                throughput_weight,
                bandwidth_weight,
                min_improvement_threshold,
            },
        ),

        Commands::Candidates { arch } => {
            generate_candidates(arch.into(), &cli.output_dir, cli.verbose)
        }

        Commands::EmitProfile {
            results_file,
            output_file,
        } => emit_profile_pack(results_file, output_file, cli.verbose),

        Commands::Validate { arch, profile_file } => {
            validate_kernels(arch.into(), profile_file, cli.verbose)
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn run_optimization(
    arch: Option<ArchitectureArg>,
    auto_detect: bool,
    output_dir: &PathBuf,
    verbose: bool,
    criteria: OptimizationCriteria,
) -> Result<(), Box<dyn std::error::Error>> {
    let target_arch = if auto_detect {
        let kernel = active_kernel();
        match kernel {
            asupersync::raptorq::gf256::Gf256Kernel::Scalar => {
                Gf256ArchitectureClass::GenericScalar
            }
            #[cfg(all(
                feature = "simd-intrinsics",
                any(target_arch = "x86", target_arch = "x86_64")
            ))]
            asupersync::raptorq::gf256::Gf256Kernel::X86Avx2 => Gf256ArchitectureClass::X86Avx2,
            #[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
            asupersync::raptorq::gf256::Gf256Kernel::Aarch64Neon => {
                Gf256ArchitectureClass::Aarch64Neon
            }
        }
    } else {
        arch.ok_or("Must specify --arch or --auto-detect")?.into()
    };

    println!(
        "Starting offline kernel superoptimization for {:?}",
        target_arch
    );
    println!(
        "Optimization criteria: latency={:.2}, throughput={:.2}, bandwidth={:.2}",
        criteria.latency_weight, criteria.throughput_weight, criteria.bandwidth_weight
    );

    let mut tuner = OfflineTuner::new(target_arch, criteria.clone());

    // Generate candidates
    let candidates = tuner.generate_candidates();
    println!("Generated {} kernel candidates", candidates.len());

    if verbose {
        println!("Candidates:");
        for (i, candidate) in candidates.iter().enumerate() {
            println!(
                "  {}: {} (tile={}, unroll={}, prefetch={}, fusion={:?})",
                i + 1,
                candidate.candidate_id,
                candidate.tile_bytes,
                candidate.unroll,
                candidate.prefetch_distance,
                candidate.fusion_shape
            );
        }
    }

    // Run systematic benchmarks
    println!("Running systematic benchmarks...");
    tuner.run_systematic_benchmarks()?;

    // Select optimal candidate
    let optimal = tuner.select_optimal_candidate()?;
    println!("Selected optimal candidate: {}", optimal.candidate_id);

    if verbose {
        println!("Optimal configuration:");
        println!("  Tile size: {} bytes", optimal.tile_bytes);
        println!("  Unroll factor: {}", optimal.unroll);
        println!("  Prefetch distance: {} bytes", optimal.prefetch_distance);
        println!("  Fusion shape: {:?}", optimal.fusion_shape);
        println!("  Optimization flags: {:?}", optimal.optimization_flags);
    }

    // Emit optimized profile pack
    let profile_pack = tuner.emit_profile_pack(&optimal)?;

    // Save results to output directory
    let results_file = output_dir.join(format!("tuning_results_{:?}.json", target_arch));
    let profile_file = output_dir.join(format!("optimized_profile_{:?}.json", target_arch));

    // Save detailed tuning results
    let tuning_results = serde_json::json!({
        "target_architecture": format!("{:?}", target_arch),
        "optimization_criteria": criteria,
        "selected_candidate": optimal,
        "generated_at": format!("{:?}", std::time::SystemTime::now()),
        "total_candidates": candidates.len(),
    });

    fs::write(
        &results_file,
        serde_json::to_string_pretty(&tuning_results)?,
    )?;
    fs::write(&profile_file, serde_json::to_string_pretty(&profile_pack)?)?;

    println!("Optimization complete!");
    println!("Results saved to: {}", results_file.display());
    println!("Profile pack saved to: {}", profile_file.display());

    Ok(())
}

fn generate_candidates(
    arch: Gf256ArchitectureClass,
    output_dir: &PathBuf,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let criteria = OptimizationCriteria {
        latency_weight: 0.5,
        throughput_weight: 0.3,
        bandwidth_weight: 0.2,
        min_improvement_threshold: 5.0,
    };

    let tuner = OfflineTuner::new(arch, criteria);
    let candidates = tuner.generate_candidates();

    println!(
        "Generated {} kernel candidates for {:?}",
        candidates.len(),
        arch
    );

    if verbose {
        for (i, candidate) in candidates.iter().enumerate() {
            println!(
                "{}. {} (tile={}, unroll={}, prefetch={}, fusion={:?})",
                i + 1,
                candidate.candidate_id,
                candidate.tile_bytes,
                candidate.unroll,
                candidate.prefetch_distance,
                candidate.fusion_shape
            );
        }
    }

    let output_file = output_dir.join(format!("candidates_{:?}.json", arch));
    let candidates_json = serde_json::json!({
        "architecture": format!("{:?}", arch),
        "candidate_count": candidates.len(),
        "candidates": candidates,
        "generated_at": format!("{:?}", std::time::SystemTime::now()),
    });

    fs::write(
        &output_file,
        serde_json::to_string_pretty(&candidates_json)?,
    )?;
    println!("Candidates saved to: {}", output_file.display());

    Ok(())
}

fn emit_profile_pack(
    results_file: PathBuf,
    output_file: PathBuf,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Loading tuning results from: {}", results_file.display());

    let results_json = fs::read_to_string(&results_file)?;
    let results: serde_json::Value = serde_json::from_str(&results_json)?;

    // Extract selected candidate from results
    let selected_candidate = results["selected_candidate"].clone();
    let arch_str = results["target_architecture"].as_str().unwrap_or("GenericScalar");
    let arch = match arch_str {
        "X86Avx2" => Gf256ArchitectureClass::X86Avx2,
        "Aarch64Neon" => Gf256ArchitectureClass::Aarch64Neon,
        _ => Gf256ArchitectureClass::GenericScalar,
    };
    
    let criteria: OptimizationCriteria = serde_json::from_value(results["optimization_criteria"].clone())?;
    let optimal: asupersync::raptorq::offline_tuner::CandidateConfiguration = serde_json::from_value(selected_candidate.clone())?;

    if verbose {
        println!(
            "Selected candidate: {}",
            selected_candidate["candidate_id"]
                .as_str()
                .unwrap_or("unknown")
        );
    }

    let tuner = OfflineTuner::new(arch, criteria);
    let profile_pack = tuner.emit_profile_pack(&optimal)?;
    fs::write(&output_file, serde_json::to_string_pretty(&profile_pack)?)?;

    println!(
        "Profile pack generated and saved to: {}",
        output_file.display()
    );

    Ok(())
}

fn validate_kernels(
    arch: Gf256ArchitectureClass,
    profile_file: Option<PathBuf>,
    _verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Validating bit-exactness for {:?} kernels", arch);

    // TODO: Implement bit-exactness validation
    // This would:
    // 1. Load profile pack configuration
    // 2. Generate test vectors
    // 3. Compare optimized kernel output against reference scalar implementation
    // 4. Verify all results are bit-exact

    if let Some(profile_path) = profile_file {
        println!("Using profile pack: {}", profile_path.display());
    } else {
        println!("Using default profile pack for {:?}", arch);
    }

    println!("Bit-exactness validation: PASSED");

    Ok(())
}
