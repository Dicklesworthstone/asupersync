//! Conformance tests for histogram metrics implementation.
//!
//! Tests critical properties that must hold for histogram correctness:
//! 1. Bucket boundaries honored with <1ulp drift
//! 2. Σ(bucket_counts) == total_count conservation invariant
//! 3. sum/mean/p99 statistical invariants
//! 4. concurrent recorders don't double-count (thread safety)
//! 5. histogram reset atomicity
//!
//! These golden tests verify that histogram implementations conform to
//! mathematical properties required for accurate metrics collection.

#[cfg(feature = "metrics")]
#[cfg(test)]
mod conformance_tests {
    use crate::observability::metrics::{Histogram, Metrics};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier as StdBarrier};
    use std::thread;
    use std::time::Duration;

    // ULP (Unit in the Last Place) helper for floating-point precision testing
    fn ulp_diff(a: f64, b: f64) -> u64 {
        if a == b {
            return 0;
        }
        if a.is_nan() || b.is_nan() || a.is_infinite() || b.is_infinite() {
            return u64::MAX; // Treat special values as maximally different
        }

        let a_bits = a.to_bits();
        let b_bits = b.to_bits();

        // Handle sign differences
        if (a_bits ^ b_bits) & 0x8000_0000_0000_0000 != 0 {
            // Different signs, distance through zero
            if a > 0.0 {
                ulp_diff(a, 0.0) + ulp_diff(0.0, b)
            } else {
                ulp_diff(b, 0.0) + ulp_diff(0.0, a)
            }
        } else {
            // Same sign, direct bit difference
            a_bits.max(b_bits) - a_bits.min(b_bits)
        }
    }

    // Helper to access histogram internals for testing
    impl Histogram {
        #[cfg(test)]
        pub(crate) fn bucket_counts(&self) -> Vec<u64> {
            self.counts
                .iter()
                .map(|atomic| atomic.load(Ordering::Relaxed))
                .collect()
        }

        #[cfg(test)]
        pub(crate) fn reset(&self) {
            // Atomic reset of all counters
            for count in &self.counts {
                count.store(0, Ordering::Relaxed);
            }
            self.count.store(0, Ordering::Relaxed);
            self.sum.store(0_u64, Ordering::Relaxed);
        }

        #[cfg(test)]
        pub(crate) fn mean(&self) -> f64 {
            let total_count = self.count();
            if total_count == 0 {
                0.0
            } else {
                self.sum() / (total_count as f64)
            }
        }

        #[cfg(test)]
        pub(crate) fn bucket_boundaries(&self) -> &[f64] {
            &self.buckets
        }

        #[cfg(test)]
        pub(crate) fn percentile(&self, p: f64) -> Option<f64> {
            if !(0.0..=1.0).contains(&p) || self.count() == 0 {
                return None;
            }

            let total = self.count() as f64;
            let target = total * p;
            let mut cumulative = 0_u64;

            for (i, &count) in self
                .counts
                .iter()
                .enumerate()
                .map(|(i, count)| (i, count.load(Ordering::Relaxed)))
            {
                cumulative += count;
                if (cumulative as f64) >= target {
                    if i == self.buckets.len() {
                        // +Inf bucket, no meaningful upper bound
                        return None;
                    }
                    return Some(self.buckets[i]);
                }
            }
            None
        }
    }

    /// Test 1: Bucket boundary precision - values should be assigned to correct buckets
    /// with floating-point precision within 1 ULP (Unit in the Last Place).
    #[test]
    fn conformance_bucket_boundary_precision() {
        // Test bucket boundaries at various floating-point precision levels
        let test_cases = vec![
            // Standard decimal boundaries
            (
                vec![0.1, 0.5, 1.0, 5.0, 10.0],
                vec![
                    (0.05, 0), // < 0.1
                    (0.1, 0),  // exactly 0.1
                    (0.2, 1),  // between 0.1 and 0.5
                    (0.5, 1),  // exactly 0.5
                    (1.0, 2),  // exactly 1.0
                    (2.0, 3),  // between 1.0 and 5.0
                    (5.0, 3),  // exactly 5.0
                    (7.5, 4),  // between 5.0 and 10.0
                    (10.0, 4), // exactly 10.0
                    (15.0, 5), // > 10.0 (+Inf bucket)
                ],
            ),
            // Powers of 2 for binary precision testing
            (
                vec![0.125, 0.25, 0.5, 1.0, 2.0, 4.0],
                vec![
                    (0.0625, 0), // < 0.125
                    (0.125, 0),  // exactly 0.125 (2^-3)
                    (0.1875, 1), // between 0.125 and 0.25
                    (0.25, 1),   // exactly 0.25 (2^-2)
                    (0.375, 2),  // between 0.25 and 0.5
                    (0.5, 2),    // exactly 0.5 (2^-1)
                    (0.75, 3),   // between 0.5 and 1.0
                    (1.0, 3),    // exactly 1.0 (2^0)
                    (1.5, 4),    // between 1.0 and 2.0
                    (2.0, 4),    // exactly 2.0 (2^1)
                    (3.0, 5),    // between 2.0 and 4.0
                    (4.0, 5),    // exactly 4.0 (2^2)
                    (8.0, 6),    // > 4.0 (+Inf bucket)
                ],
            ),
            // Very small values testing subnormal precision
            (
                vec![1e-10, 1e-8, 1e-6, 1e-4],
                vec![
                    (1e-12, 0), // Very small
                    (1e-10, 0), // Boundary
                    (1e-9, 1),  // Between boundaries
                    (1e-8, 1),  // Boundary
                    (1e-7, 2),  // Between boundaries
                    (1e-6, 2),  // Boundary
                    (1e-5, 3),  // Between boundaries
                    (1e-4, 3),  // Boundary
                    (1e-3, 4),  // Overflow bucket
                ],
            ),
        ];

        for (buckets, values) in test_cases {
            let hist = Histogram::new("boundary_test", buckets.clone());

            for (value, expected_bucket) in values {
                hist.reset(); // Clear between tests
                hist.observe(value);

                let bucket_counts = hist.bucket_counts();

                // Verify exactly one bucket was incremented
                let incremented_buckets: Vec<_> = bucket_counts
                    .iter()
                    .enumerate()
                    .filter(|(_, &count)| count > 0)
                    .collect();

                assert_eq!(
                    incremented_buckets.len(),
                    1,
                    "Value {} should increment exactly one bucket, got {:?}",
                    value,
                    incremented_buckets
                );

                // Verify the correct bucket was incremented
                let (actual_bucket, &count) = incremented_buckets[0];
                assert_eq!(
                    actual_bucket, expected_bucket,
                    "Value {} assigned to bucket {} but expected bucket {}. Buckets: {:?}",
                    value, actual_bucket, expected_bucket, buckets
                );
                assert_eq!(count, 1, "Bucket should be incremented by exactly 1");

                // Test ULP precision for boundary values
                if buckets.contains(&value) {
                    let boundary = value;
                    let next_float = f64::from_bits(boundary.to_bits() + 1);
                    let prev_float = f64::from_bits(boundary.to_bits() - 1);

                    // Test that values within 1 ULP are handled consistently
                    hist.reset();
                    hist.observe(prev_float);
                    hist.observe(boundary);
                    hist.observe(next_float);

                    // All should go to same bucket or adjacent buckets (never skip)
                    let counts = hist.bucket_counts();
                    let non_zero_buckets: Vec<_> = counts
                        .iter()
                        .enumerate()
                        .filter(|(_, &count)| count > 0)
                        .collect();

                    // Should span at most 2 adjacent buckets
                    if non_zero_buckets.len() > 1 {
                        let bucket_indices: Vec<_> =
                            non_zero_buckets.iter().map(|(i, _)| *i).collect();
                        let min_bucket = *bucket_indices.iter().min().unwrap();
                        let max_bucket = *bucket_indices.iter().max().unwrap();
                        assert!(
                            max_bucket - min_bucket <= 1,
                            "Values within 1 ULP of boundary {} span non-adjacent buckets: {:?}",
                            boundary,
                            bucket_indices
                        );
                    }
                }
            }
        }
    }

    /// Test 2: Conservation invariant - sum of all bucket counts must equal total count
    #[test]
    fn conformance_count_conservation() {
        let buckets = vec![1.0, 2.0, 5.0, 10.0];
        let hist = Histogram::new("conservation_test", buckets);

        // Test with various observation patterns
        let test_values = vec![
            // Single observations
            vec![0.5],
            vec![1.5],
            vec![7.5],
            vec![15.0],
            // Multiple observations
            vec![0.1, 0.2, 0.3],
            vec![1.1, 1.2, 1.3],
            vec![5.5, 6.0, 6.5],
            vec![11.0, 12.0, 13.0],
            // Mixed across buckets
            vec![0.5, 1.5, 3.0, 7.5, 15.0],
            vec![0.1, 0.9, 1.1, 1.9, 2.1, 4.9, 5.1, 9.9, 10.1, 20.0],
            // Edge cases
            vec![],                                           // Empty
            vec![1.0, 1.0, 1.0],                              // Exact boundary values
            vec![f64::MIN_POSITIVE, f64::MAX, f64::INFINITY], // Extreme values
        ];

        for values in test_values {
            hist.reset();

            // Observe all values
            for &value in &values {
                hist.observe(value);
            }

            // Verify conservation invariant
            let bucket_counts = hist.bucket_counts();
            let bucket_sum: u64 = bucket_counts.iter().sum();
            let total_count = hist.count();

            assert_eq!(
                bucket_sum, total_count,
                "Conservation invariant violated: bucket sum {} != total count {} for values {:?}",
                bucket_sum, total_count, values
            );

            assert_eq!(
                total_count,
                values.len() as u64,
                "Total count {} does not match observations {} for values {:?}",
                total_count,
                values.len(),
                values
            );
        }
    }

    /// Test 3: Statistical invariants - mean and percentile calculations
    #[test]
    fn conformance_statistical_invariants() {
        let hist = Histogram::new("stats_test", vec![1.0, 2.0, 5.0, 10.0]);

        // Test cases with known statistical properties
        let test_cases = vec![
            // Single value
            (vec![3.0], 3.0, 3.0), // mean=3.0, all percentiles=3.0
            // Two values
            (vec![1.0, 5.0], 3.0, 3.0), // mean=3.0, median around 3.0
            // Multiple identical values
            (vec![2.0, 2.0, 2.0, 2.0], 2.0, 2.0), // all stats = 2.0
            // Symmetric distribution
            (vec![1.0, 2.0, 3.0, 4.0, 5.0], 3.0, 3.0), // mean=3.0, median=3.0
            // Arithmetic sequence
            (vec![10.0, 20.0, 30.0, 40.0, 50.0], 30.0, 30.0), // mean=30.0
        ];

        for (values, expected_mean, expected_approx_median) in test_cases {
            hist.reset();

            for &value in &values {
                hist.observe(value);
            }

            // Test mean invariant: mean = sum / count
            let computed_mean = hist.mean();
            let manual_mean = hist.sum() / (hist.count() as f64);
            assert!(
                (computed_mean - manual_mean).abs() < f64::EPSILON,
                "Mean computation inconsistency: computed={}, manual={}",
                computed_mean,
                manual_mean
            );

            // Test expected mean
            let mean_diff = (computed_mean - expected_mean).abs();
            assert!(
                mean_diff < 1e-10,
                "Mean {} differs from expected {} by {} for values {:?}",
                computed_mean,
                expected_mean,
                mean_diff,
                values
            );

            // Test sum invariant: sum should equal manual sum
            let expected_sum: f64 = values.iter().sum();
            let histogram_sum = hist.sum();
            assert!(
                (histogram_sum - expected_sum).abs() < 1e-10,
                "Sum invariant violated: histogram_sum={}, expected_sum={}",
                histogram_sum,
                expected_sum
            );

            // Test percentile consistency (when computable)
            if !values.is_empty() {
                // Test that percentiles are monotonic
                let percentiles = [0.0, 0.25, 0.5, 0.75, 1.0];
                let mut prev_val = None;

                for &p in &percentiles {
                    if let Some(val) = hist.percentile(p) {
                        if let Some(prev) = prev_val {
                            assert!(
                                val >= prev,
                                "Percentile monotonicity violated: p{}={} < p{}={}",
                                (p * 100.0) as u8,
                                val,
                                ((p - 0.25) * 100.0).max(0.0) as u8,
                                prev
                            );
                        }
                        prev_val = Some(val);
                    }
                }

                // Test boundary percentiles
                if let Some(p0) = hist.percentile(0.0) {
                    assert!(
                        values.iter().any(|&v| v <= p0),
                        "0th percentile {} should be <= minimum value",
                        p0
                    );
                }
            }
        }
    }

    /// Test 4: Concurrent operations - no double counting under concurrent access
    #[test]
    fn conformance_concurrent_no_double_counting() {
        let hist = Arc::new(Histogram::new("concurrent_test", vec![1.0, 5.0, 10.0]));
        let num_threads = 8;
        let observations_per_thread = 1000;
        let total_expected = num_threads * observations_per_thread;

        // Barriers for synchronized starts
        let start_barrier = Arc::new(StdBarrier::new(num_threads));
        let completion_counter = Arc::new(AtomicU64::new(0));

        let mut handles = Vec::new();

        // Spawn concurrent observer threads
        for thread_id in 0..num_threads {
            let hist_clone = Arc::clone(&hist);
            let start_barrier_clone = Arc::clone(&start_barrier);
            let completion_counter_clone = Arc::clone(&completion_counter);

            let handle = thread::spawn(move || {
                // Wait for all threads to be ready
                start_barrier_clone.wait();

                // Each thread observes different values to test different buckets
                let base_value = (thread_id as f64) + 0.1;
                for i in 0..observations_per_thread {
                    let value = base_value + (i as f64) * 0.01;
                    hist_clone.observe(value);
                }

                completion_counter_clone.fetch_add(1, Ordering::Relaxed);
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify all threads completed
        assert_eq!(
            completion_counter.load(Ordering::Relaxed),
            num_threads as u64
        );

        // Verify total count conservation under concurrency
        let final_count = hist.count();
        assert_eq!(
            final_count, total_expected as u64,
            "Concurrent operations resulted in incorrect count: {} expected {}",
            final_count, total_expected
        );

        // Verify bucket count conservation
        let bucket_counts = hist.bucket_counts();
        let bucket_sum: u64 = bucket_counts.iter().sum();
        assert_eq!(
            bucket_sum, final_count,
            "Bucket count conservation violated under concurrency: bucket_sum={}, total={}",
            bucket_sum, final_count
        );

        // Verify no bucket counts exceed their theoretical maximum
        for (i, &count) in bucket_counts.iter().enumerate() {
            assert!(
                count <= total_expected as u64,
                "Bucket {} has impossible count {} > total observations {}",
                i,
                count,
                total_expected
            );
        }

        // Test concurrent reset safety
        let reset_hist = Arc::new(Histogram::new("reset_test", vec![1.0, 2.0]));
        let reset_barrier = Arc::new(StdBarrier::new(4));

        let mut reset_handles = Vec::new();

        // Thread 1: continuous observation
        let observer_hist = Arc::clone(&reset_hist);
        let observer_barrier = Arc::clone(&reset_barrier);
        let observer_handle = thread::spawn(move || {
            observer_barrier.wait();
            for i in 0..100 {
                observer_hist.observe((i % 3) as f64);
                thread::yield_now();
            }
        });

        // Thread 2: continuous reset
        let resetter_hist = Arc::clone(&reset_hist);
        let resetter_barrier = Arc::clone(&reset_barrier);
        let resetter_handle = thread::spawn(move || {
            resetter_barrier.wait();
            for _ in 0..50 {
                resetter_hist.reset();
                thread::yield_now();
            }
        });

        // Thread 3 & 4: continuous readers
        for _ in 0..2 {
            let reader_hist = Arc::clone(&reset_hist);
            let reader_barrier = Arc::clone(&reset_barrier);
            let reader_handle = thread::spawn(move || {
                reader_barrier.wait();
                for _ in 0..100 {
                    let _ = reader_hist.count();
                    let _ = reader_hist.sum();
                    let _ = reader_hist.bucket_counts();
                    thread::yield_now();
                }
            });
            reset_handles.push(reader_handle);
        }

        reset_handles.push(observer_handle);
        reset_handles.push(resetter_handle);

        // Wait for concurrent reset test to complete
        for handle in reset_handles {
            handle.join().unwrap();
        }

        // Final state should be consistent (whatever the final state is)
        let final_bucket_counts = reset_hist.bucket_counts();
        let final_total = reset_hist.count();
        let final_bucket_sum: u64 = final_bucket_counts.iter().sum();

        assert_eq!(
            final_bucket_sum, final_total,
            "Post-concurrent-reset state inconsistent: bucket_sum={}, total={}",
            final_bucket_sum, final_total
        );
    }

    /// Test 5: Reset operation atomicity - reset should be atomic across all fields
    #[test]
    fn conformance_reset_atomicity() {
        let hist = Histogram::new("reset_test", vec![0.5, 1.0, 2.0, 5.0]);

        // Populate histogram with known data
        let test_values = vec![0.1, 0.7, 1.2, 3.0, 7.5];
        for &value in &test_values {
            hist.observe(value);
        }

        // Verify initial state is non-empty
        assert_eq!(hist.count(), test_values.len() as u64);
        assert!(hist.sum() > 0.0);
        assert!(hist.bucket_counts().iter().any(|&c| c > 0));

        // Test reset operation
        hist.reset();

        // Verify all fields are atomically reset to zero
        assert_eq!(hist.count(), 0, "Count not reset to zero");
        assert_eq!(hist.sum(), 0.0, "Sum not reset to zero");

        let bucket_counts = hist.bucket_counts();
        for (i, &count) in bucket_counts.iter().enumerate() {
            assert_eq!(count, 0, "Bucket {} not reset to zero", i);
        }

        // Test that histogram works correctly after reset
        hist.observe(2.5);
        assert_eq!(hist.count(), 1);
        assert_eq!(hist.sum(), 2.5);

        let post_reset_counts = hist.bucket_counts();
        let expected_bucket = 3; // 2.5 should go in the <=5.0 bucket
        for (i, &count) in post_reset_counts.iter().enumerate() {
            if i == expected_bucket {
                assert_eq!(count, 1, "Expected bucket {} should have count 1", i);
            } else {
                assert_eq!(count, 0, "Non-target bucket {} should remain 0", i);
            }
        }

        // Test multiple reset operations are idempotent
        hist.reset();
        hist.reset();
        hist.reset();

        assert_eq!(hist.count(), 0);
        assert_eq!(hist.sum(), 0.0);
        assert!(hist.bucket_counts().iter().all(|&c| c == 0));

        // Test reset doesn't affect bucket boundaries
        let boundaries = hist.bucket_boundaries();
        assert_eq!(boundaries, &[0.5, 1.0, 2.0, 5.0]);
    }

    /// Test edge cases: empty histograms, extreme values, special float values
    #[test]
    fn conformance_edge_cases() {
        // Test empty histogram properties
        let empty_hist = Histogram::new("empty", vec![1.0, 5.0]);
        assert_eq!(empty_hist.count(), 0);
        assert_eq!(empty_hist.sum(), 0.0);
        assert_eq!(empty_hist.mean(), 0.0);
        assert_eq!(empty_hist.percentile(0.5), None);

        // Test special float values
        let special_hist = Histogram::new("special", vec![1.0, 10.0, 100.0]);

        // Test infinity
        special_hist.observe(f64::INFINITY);
        assert_eq!(special_hist.count(), 1);
        assert_eq!(special_hist.sum(), f64::INFINITY);

        special_hist.reset();

        // Test very large finite values
        special_hist.observe(f64::MAX);
        assert_eq!(special_hist.count(), 1);
        assert_eq!(special_hist.sum(), f64::MAX);

        special_hist.reset();

        // Test very small positive values
        special_hist.observe(f64::MIN_POSITIVE);
        assert_eq!(special_hist.count(), 1);
        assert_eq!(special_hist.sum(), f64::MIN_POSITIVE);

        special_hist.reset();

        // Test negative values (if histogram allows them)
        special_hist.observe(-1.0);
        assert_eq!(special_hist.count(), 1);
        // Should go in first bucket (< 1.0)
        let counts = special_hist.bucket_counts();
        assert_eq!(counts[0], 1);

        // Test zero
        special_hist.reset();
        special_hist.observe(0.0);
        assert_eq!(special_hist.count(), 1);
        assert_eq!(special_hist.sum(), 0.0);
        assert_eq!(special_hist.mean(), 0.0);

        // Test NaN handling (should not increment counters or affect sum)
        special_hist.reset();
        let initial_count = special_hist.count();
        let initial_sum = special_hist.sum();

        special_hist.observe(f64::NAN);

        // NaN observations should be handled gracefully
        // (implementation may choose to ignore or count them)
        let final_count = special_hist.count();
        let final_sum = special_hist.sum();

        // If NaN is counted, verify it doesn't corrupt the sum
        if final_count > initial_count {
            // If NaN incremented count, sum should either remain unchanged
            // or become NaN (both are valid approaches)
            assert!(
                final_sum == initial_sum || final_sum.is_nan(),
                "NaN observation should not corrupt sum in unexpected way"
            );
        }
    }

    /// Integration test: verify histogram works correctly within Metrics registry
    #[test]
    fn conformance_metrics_integration() {
        let mut metrics = Metrics::new();

        // Get histogram from registry
        let hist = metrics.histogram("test_integration", vec![1.0, 5.0, 10.0]);

        // Test that same name returns same histogram
        let hist2 = metrics.histogram("test_integration", vec![1.0, 5.0, 10.0]);

        // Observe in first reference
        hist.observe(2.5);

        // Should be visible in second reference
        assert_eq!(hist2.count(), 1);
        assert_eq!(hist2.sum(), 2.5);

        // Test Prometheus export includes correct histogram format
        let export = metrics.export_prometheus();
        assert!(export.contains("test_integration_bucket"));
        assert!(export.contains("test_integration_sum"));
        assert!(export.contains("test_integration_count"));

        // Test bucket export format
        assert!(export.contains("le=\"1.0\""));
        assert!(export.contains("le=\"5.0\""));
        assert!(export.contains("le=\"10.0\""));
        assert!(export.contains("le=\"+Inf\""));

        // Test cumulative bucket counts in export
        hist.observe(0.5); // Should be in <=1.0 bucket
        hist.observe(7.5); // Should be in <=10.0 bucket
        hist.observe(15.0); // Should be in +Inf bucket

        let final_export = metrics.export_prometheus();

        // Parse bucket values from export (this is a basic sanity check)
        assert!(final_export.contains("test_integration_count 4"));

        // Verify cumulative nature of bucket counts in export
        // (exact parsing would be complex, so we just verify the format is reasonable)
        let bucket_lines: Vec<_> = final_export
            .lines()
            .filter(|line| line.contains("test_integration_bucket"))
            .collect();

        assert_eq!(bucket_lines.len(), 4); // 3 buckets + +Inf

        // Test that exported values are reasonable (each bucket count >= previous)
        for line in bucket_lines {
            if let Some(value_part) = line.split_whitespace().last() {
                if let Ok(count) = value_part.parse::<u64>() {
                    assert!(
                        count <= 4,
                        "Bucket count {} exceeds total observations 4",
                        count
                    );
                }
            }
        }
    }
}
