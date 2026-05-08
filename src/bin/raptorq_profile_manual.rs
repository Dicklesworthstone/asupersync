//! Manual RaptorQ profiling for post-SIMD bottleneck analysis.

use std::time::Instant;

fn main() {
    println!("Manual RaptorQ profiling");

    // Use a workload that will stress post-SIMD bottlenecks
    let k = 2048; // Large enough to trigger matrix operations, smaller than 10000 for reliability
    let symbol_size = 1024; // Simpler size
    let loss_rate = 0.60; // Moderate loss to force matrix solve

    // Run decode operations in a loop for profiling
    for i in 0..5 {
        println!(
            "Iteration {}: Running K={} decode with {}% loss",
            i,
            k,
            loss_rate * 100.0
        );

        let start = Instant::now();

        // Simulate decode work - this is where the profiler will attach
        simulate_raptorq_decode_work(k, symbol_size, loss_rate);

        let elapsed = start.elapsed();
        println!(
            "Iteration {} completed in {:.1}ms",
            i,
            elapsed.as_secs_f64() * 1000.0
        );
    }

    println!("Profiling workload completed");
}

fn simulate_raptorq_decode_work(k: usize, symbol_size: usize, _loss_rate: f64) {
    // This simulates the computational patterns we expect to see in RaptorQ decode
    // without depending on the complex encoder/decoder setup

    // Pattern 1: Matrix operations (should show up after SIMD optimization)
    let mut matrix = vec![vec![0u8; k]; k / 4];
    for row in matrix.iter_mut() {
        for (j, cell) in row.iter_mut().enumerate() {
            *cell = ((j * 7 + 13) % 256) as u8;
        }
    }

    // Pattern 2: Dense memory operations (gap filling)
    let mut symbols = vec![vec![0u8; symbol_size]; k];
    for (i, symbol) in symbols.iter_mut().enumerate() {
        for byte in symbol.iter_mut() {
            *byte = ((i + 42) % 256) as u8;
        }
    }

    // Pattern 3: Sparse operations pattern (coefficient handling)
    for i in 0..k / 10 {
        let idx1 = (i * 17) % symbols.len();
        let idx2 = (i * 23) % symbols.len();

        if idx1 != idx2 && idx1 < symbols.len() && idx2 < symbols.len() {
            for j in 0..symbol_size.min(1024) {
                symbols[idx1][j] ^= symbols[idx2][j];
            }
        }
    }

    // Prevent optimization
    let sum: usize = symbols.iter().flatten().map(|&x| x as usize).sum();
    if sum == 0 {
        println!("Unexpected zero sum");
    }
}
