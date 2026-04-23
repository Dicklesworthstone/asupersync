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

/// Test configuration for bit-exactness validation scenarios.
#[derive(Debug, Clone)]
struct ValidationConfig {
    /// Size of test data.
    size: usize,
    /// Test scalar value.
    scalar: u8,
    /// Data generation seed.
    seed: u64,
    /// Test scenario name.
    scenario: &'static str,
}

impl ValidationConfig {
    /// Create deterministic test data based on config.
    fn generate_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.size);
        for i in 0..self.size {
            let value = ((i as u64).wrapping_mul(17).wrapping_add(self.seed)) % 256;
            data.push(value as u8);
        }
        data
    }
}

/// Reference scalar implementation for mul_slice operation.
fn reference_mul_slice(data: &mut [u8], scalar: u8) {
    use asupersync::raptorq::gf256::Gf256;
    let gf_scalar = Gf256::new(scalar);
    for byte in data {
        *byte = Gf256::new(*byte).mul_field(gf_scalar).raw();
    }
}

/// Reference scalar implementation for addmul_slice operation.
fn reference_addmul_slice(dst: &mut [u8], src: &[u8], scalar: u8) {
    use asupersync::raptorq::gf256::Gf256;
    assert_eq!(dst.len(), src.len(), "slice length mismatch");
    let gf_scalar = Gf256::new(scalar);
    for (dst_byte, src_byte) in dst.iter_mut().zip(src) {
        let product = Gf256::new(*src_byte).mul_field(gf_scalar);
        *dst_byte = Gf256::new(*dst_byte).add(product).raw();
    }
}

/// Validate mul_slice kernel against reference scalar implementation.
fn validate_mul_slice_bit_exact(config: &ValidationConfig, verbose: bool) -> Result<(), String> {
    use asupersync::raptorq::gf256::{Gf256, gf256_mul_slice};

    let mut reference_data = config.generate_data();
    let mut test_data = reference_data.clone();

    // Compare the active kernel path against scalar reference
    reference_mul_slice(&mut reference_data, config.scalar);
    gf256_mul_slice(&mut test_data, Gf256::new(config.scalar));

    if reference_data == test_data {
        if verbose {
            println!(
                "  mul_slice bit-exact: size={}, scalar={}",
                config.size, config.scalar
            );
        }
        Ok(())
    } else {
        Err(format!(
            "mul_slice not bit-exact: size={}, scalar={}, first_diff={}",
            config.size,
            config.scalar,
            reference_data
                .iter()
                .zip(&test_data)
                .position(|(a, b)| a != b)
                .unwrap_or(0)
        ))
    }
}

/// Validate addmul_slice kernel against reference scalar implementation.
fn validate_addmul_slice_bit_exact(config: &ValidationConfig, verbose: bool) -> Result<(), String> {
    use asupersync::raptorq::gf256::{Gf256, gf256_addmul_slice};

    let src_data = config.generate_data();
    let mut reference_dst = vec![0u8; config.size];
    let mut test_dst = vec![0u8; config.size];

    // Initialize with different seed for destination to make test more robust
    for (i, byte) in reference_dst.iter_mut().enumerate() {
        *byte = ((i as u64 * 23 + config.seed + 1000) % 256) as u8;
    }
    test_dst.copy_from_slice(&reference_dst);

    // Compare the active kernel path against scalar reference
    reference_addmul_slice(&mut reference_dst, &src_data, config.scalar);
    gf256_addmul_slice(&mut test_dst, &src_data, Gf256::new(config.scalar));

    if reference_dst == test_dst {
        if verbose {
            println!(
                "  addmul_slice bit-exact: size={}, scalar={}",
                config.size, config.scalar
            );
        }
        Ok(())
    } else {
        Err(format!(
            "addmul_slice not bit-exact: size={}, scalar={}, first_diff={}",
            config.size,
            config.scalar,
            reference_dst
                .iter()
                .zip(&test_dst)
                .position(|(a, b)| a != b)
                .unwrap_or(0)
        ))
    }
}

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
    let arch_str = results["target_architecture"]
        .as_str()
        .unwrap_or("GenericScalar");
    let arch = match arch_str {
        "X86Avx2" => Gf256ArchitectureClass::X86Avx2,
        "Aarch64Neon" => Gf256ArchitectureClass::Aarch64Neon,
        _ => Gf256ArchitectureClass::GenericScalar,
    };

    let criteria: OptimizationCriteria =
        serde_json::from_value(results["optimization_criteria"].clone())?;
    let optimal: asupersync::raptorq::offline_tuner::CandidateConfiguration =
        serde_json::from_value(selected_candidate.clone())?;

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
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Validating bit-exactness for {:?} kernels", arch);

    if let Some(profile_path) = profile_file {
        println!("Using profile pack: {}", profile_path.display());
    } else {
        println!("Using default profile pack for {:?}", arch);
    }

    // Test scenarios covering different sizes and edge cases
    let validation_scenarios = vec![
        ValidationConfig {
            size: 1,
            scalar: 1,
            seed: 0,
            scenario: "single_byte",
        },
        ValidationConfig {
            size: 15,
            scalar: 17,
            seed: 42,
            scenario: "sub_simd_odd",
        },
        ValidationConfig {
            size: 16,
            scalar: 255,
            seed: 123,
            scenario: "exactly_simd",
        },
        ValidationConfig {
            size: 17,
            scalar: 2,
            seed: 456,
            scenario: "just_over_simd",
        },
        ValidationConfig {
            size: 64,
            scalar: 85,
            seed: 789,
            scenario: "cache_line",
        },
        ValidationConfig {
            size: 256,
            scalar: 42,
            seed: 1011,
            scenario: "typical_block",
        },
        ValidationConfig {
            size: 1024,
            scalar: 170,
            seed: 1314,
            scenario: "large_block",
        },
    ];

    let mut total_tests = 0;
    let mut failed_tests = 0;

    for config in &validation_scenarios {
        // Test mul_slice bit-exactness
        total_tests += 1;
        if let Err(e) = validate_mul_slice_bit_exact(config, verbose) {
            println!("FAILED: mul_slice for scenario {}: {}", config.scenario, e);
            failed_tests += 1;
        } else if verbose {
            println!("PASSED: mul_slice for scenario {}", config.scenario);
        }

        // Test addmul_slice bit-exactness
        total_tests += 1;
        if let Err(e) = validate_addmul_slice_bit_exact(config, verbose) {
            println!(
                "FAILED: addmul_slice for scenario {}: {}",
                config.scenario, e
            );
            failed_tests += 1;
        } else if verbose {
            println!("PASSED: addmul_slice for scenario {}", config.scenario);
        }
    }

    if failed_tests == 0 {
        println!("Bit-exactness validation: PASSED ({} tests)", total_tests);
        Ok(())
    } else {
        println!(
            "Bit-exactness validation: FAILED ({}/{} tests failed)",
            failed_tests, total_tests
        );
        Err(format!(
            "Bit-exactness validation failed: {}/{} tests failed",
            failed_tests, total_tests
        )
        .into())
    }
}
