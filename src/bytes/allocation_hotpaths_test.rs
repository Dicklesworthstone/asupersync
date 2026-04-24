//! Test demonstrating allocation hot paths in Bytes/BytesMut operations.
//!
//! This test serves as a baseline measurement for profiling byte allocation patterns.

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use crate::bytes::{Bytes, BytesMut};
    use std::time::Instant;

    #[cfg(feature = "test-internals")]
    use crate::bytes::profiling::{get_allocation_metrics, reset_allocation_metrics};

    /// Baseline test for BytesMut incremental growth patterns.
    /// This simulates network buffer growth and measures allocation behavior.
    #[test]
    fn hotpath_bytes_mut_incremental_growth() {
        #[cfg(feature = "test-internals")]
        reset_allocation_metrics();

        let start = Instant::now();

        // Test Case 1: No pre-allocation (causes reallocations)
        let mut buf = BytesMut::new();
        for i in 0..100 {
            let chunk = vec![i as u8; 256]; // 256-byte chunks
            buf.put_slice(&chunk);
        }

        let no_prealloc_duration = start.elapsed();
        println!(
            "BytesMut growth (no prealloc): {:?} for 25,600 bytes",
            no_prealloc_duration
        );

        // Test Case 2: With pre-allocation (should be faster)
        let start = Instant::now();
        let mut buf2 = BytesMut::with_capacity(25600);
        for i in 0..100 {
            let chunk = vec![i as u8; 256];
            buf2.put_slice(&chunk);
        }

        let prealloc_duration = start.elapsed();
        println!(
            "BytesMut growth (with prealloc): {:?} for 25,600 bytes",
            prealloc_duration
        );

        #[cfg(feature = "test-internals")]
        {
            let metrics = get_allocation_metrics();
            println!("Allocation metrics: {metrics:?}");
        }
    }

    /// Baseline test for BytesMut split operations.
    /// This simulates protocol frame splitting and measures copy overhead.
    #[test]
    fn hotpath_bytes_mut_splitting() {
        #[cfg(feature = "test-internals")]
        reset_allocation_metrics();

        let start = Instant::now();

        // Create a large buffer to split
        let mut buf = BytesMut::with_capacity(32768);
        buf.resize(32768, 0x42);

        // Split into 1KB frames using split_to (expensive - requires copy)
        let mut frames = Vec::new();
        while buf.len() >= 1024 {
            let frame = buf.split_to(1024);
            frames.push(frame);
        }

        let split_to_duration = start.elapsed();
        println!(
            "split_to operations: {:?} for {} frames",
            split_to_duration,
            frames.len()
        );

        #[cfg(feature = "test-internals")]
        {
            let metrics = get_allocation_metrics();
            println!("Split allocation metrics: {metrics:?}");
        }
    }

    /// Baseline test for Bytes creation patterns.
    /// This tests different allocation paths for Bytes creation.
    #[test]
    fn hotpath_bytes_creation() {
        #[cfg(feature = "test-internals")]
        reset_allocation_metrics();

        let test_data = vec![0u8; 4096];

        // Path 1: Copy from slice (allocates Arc<Vec<u8>>)
        let start = Instant::now();
        for _ in 0..1000 {
            let _bytes = Bytes::copy_from_slice(&test_data);
        }
        let copy_duration = start.elapsed();
        println!("Bytes::copy_from_slice: {:?} for 1000×4KB", copy_duration);

        // Path 2: From Vec (transfers ownership)
        let start = Instant::now();
        for _ in 0..1000 {
            let vec = test_data.clone();
            let _bytes = Bytes::from(vec);
        }
        let from_vec_duration = start.elapsed();
        println!("Bytes::from(Vec): {:?} for 1000×4KB", from_vec_duration);

        // Path 3: Freeze from BytesMut
        let start = Instant::now();
        for _ in 0..1000 {
            let mut buf = BytesMut::with_capacity(4096);
            buf.extend_from_slice(&test_data);
            let _bytes = buf.freeze();
        }
        let freeze_duration = start.elapsed();
        println!("BytesMut::freeze: {:?} for 1000×4KB", freeze_duration);

        #[cfg(feature = "test-internals")]
        {
            let metrics = get_allocation_metrics();
            println!("Creation allocation metrics: {metrics:?}");
        }
    }

    /// Integrated test simulating realistic usage patterns.
    #[test]
    fn hotpath_realistic_workload() {
        #[cfg(feature = "test-internals")]
        reset_allocation_metrics();

        let start = Instant::now();

        // Simulate HTTP request processing
        for req_num in 0..100 {
            // 1. Receive request data into growing buffer
            let mut request_buf = BytesMut::with_capacity(2048);

            // Simulate headers arriving in chunks
            for chunk_num in 0..10 {
                let chunk = format!("Header-{req_num}-{chunk_num}: value\r\n");
                request_buf.put_slice(chunk.as_bytes());
            }
            request_buf.put_slice(b"\r\n"); // End headers

            // 2. Parse headers by splitting buffer
            let header_end = request_buf[..]
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .unwrap_or(request_buf.len().saturating_sub(4))
                + 4;

            let headers = request_buf.split_to(header_end.min(request_buf.len()));

            // 3. Convert to immutable Bytes for processing
            let header_bytes = headers.freeze();
            assert!(!header_bytes.is_empty());

            // 4. Simulate response generation
            let mut response_buf = BytesMut::with_capacity(1024);
            response_buf.put_slice(b"HTTP/1.1 200 OK\r\n");
            response_buf.put_slice(b"Content-Type: application/json\r\n\r\n");
            response_buf.put_slice(format!(r#"{{"request":{req_num},"status":"ok"}}"#).as_bytes());

            let _response_bytes = response_buf.freeze();
        }

        let workload_duration = start.elapsed();
        println!(
            "Realistic workload: {:?} for 100 requests",
            workload_duration
        );

        #[cfg(feature = "test-internals")]
        {
            let final_metrics = get_allocation_metrics();
            println!("Final allocation metrics: {final_metrics:?}");
        }
    }
}
