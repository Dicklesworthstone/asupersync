//! Hot-path correctness tests for `Bytes` / `BytesMut` operations.
//!
//! Originally a baseline measurement file that printed durations and
//! allocation metrics without asserting anything. br-asupersync-kcb8aw:
//! the println!-only style let any regression slip through — even
//! `get_allocation_metrics()` returning all-zeros (which it currently
//! does, because the `profile!` sentinels in `bytes::profiling` aren't
//! wired up to the hot paths) would have been invisible.
//!
//! These tests now assert deterministic invariants that hold
//! regardless of profiling instrumentation:
//!
//!   - **incremental_growth**: pre-allocated capacity is never
//!     exceeded by the planned writes, so the underlying buffer
//!     pointer is stable; the no-prealloc path must reach the same
//!     final length but takes at least one growth step (capacity
//!     strictly larger than the initial 0).
//!   - **splitting**: `split_to` preserves total bytes (len of all
//!     fragments + remaining buffer == original) and individual
//!     fragments are exactly the requested size.
//!   - **creation**: each construction path yields the expected length
//!     and identical content; freeze→Bytes has the same content as
//!     the source slice.
//!   - **realistic_workload**: every per-request frozen header buffer
//!     contains its iteration's marker, response buffer is non-empty,
//!     and total processing yields the expected number of frozen
//!     responses.
//!
//! The previous duration / metric prints stay under `BYTES_PROFILING`
//! so a developer running with that env var still gets the diagnostic
//! output, while CI gets real assertions.

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

    /// Returns true when the developer asked for diagnostic prints.
    /// Production CI does not set this, so we keep the test output
    /// quiet by default but still emit timings on demand.
    fn diagnostics_enabled() -> bool {
        std::env::var("BYTES_PROFILING").is_ok()
    }

    /// Hot path: `BytesMut` incremental growth, with and without
    /// pre-allocation. Asserts that:
    ///
    /// 1. The pre-allocated path NEVER triggers a buffer move (the
    ///    backing pointer at completion equals the pointer just after
    ///    `with_capacity`), proving zero growth-induced reallocations.
    /// 2. The no-prealloc path ends up at the same content length and
    ///    a strictly-larger-than-zero capacity (i.e. growth happened).
    /// 3. Both paths produce byte-identical buffers.
    #[test]
    fn hotpath_bytes_mut_incremental_growth() {
        const CHUNKS: usize = 100;
        const CHUNK_SIZE: usize = 256;
        const TOTAL: usize = CHUNKS * CHUNK_SIZE;

        #[cfg(feature = "test-internals")]
        reset_allocation_metrics();

        let start = Instant::now();

        // No pre-allocation: starts at capacity 0 and must grow.
        let mut buf = BytesMut::new();
        let initial_capacity = buf.capacity();
        for i in 0..CHUNKS {
            let chunk = vec![i as u8; CHUNK_SIZE];
            buf.put_slice(&chunk);
        }
        let no_prealloc_duration = start.elapsed();
        assert_eq!(buf.len(), TOTAL, "no-prealloc final length mismatch");
        assert!(
            buf.capacity() > initial_capacity,
            "no-prealloc capacity must have grown at least once \
             (initial={initial_capacity}, final={})",
            buf.capacity()
        );

        // Pre-allocated: capacity holds the entire workload, so the
        // backing pointer must be stable across all `put_slice` calls.
        let start = Instant::now();
        let mut buf2 = BytesMut::with_capacity(TOTAL);
        let initial_ptr = buf2.as_ptr();
        let initial_capacity2 = buf2.capacity();
        for i in 0..CHUNKS {
            let chunk = vec![i as u8; CHUNK_SIZE];
            buf2.put_slice(&chunk);
        }
        let prealloc_duration = start.elapsed();
        assert_eq!(buf2.len(), TOTAL, "prealloc final length mismatch");
        assert_eq!(
            buf2.capacity(),
            initial_capacity2,
            "prealloc capacity must not have grown — \
             this is the regression guard against allocator-vs-amortized \
             growth heuristics"
        );
        assert!(
            std::ptr::eq(buf2.as_ptr(), initial_ptr),
            "prealloc backing pointer must be stable (no realloc happened)"
        );

        // Both paths produced byte-identical content.
        assert_eq!(
            &buf[..],
            &buf2[..],
            "no-prealloc and prealloc paths must produce identical bytes"
        );

        if diagnostics_enabled() {
            println!("BytesMut growth (no prealloc): {no_prealloc_duration:?} for {TOTAL} bytes");
            println!("BytesMut growth (with prealloc): {prealloc_duration:?} for {TOTAL} bytes");
        }

        #[cfg(feature = "test-internals")]
        if diagnostics_enabled() {
            let metrics = get_allocation_metrics();
            println!("Allocation metrics: {metrics:?}");
        }
    }

    /// Hot path: `BytesMut::split_to` for protocol-frame extraction.
    /// Asserts that:
    ///
    /// 1. Each split-out frame is exactly the requested size.
    /// 2. The total bytes across frames + remaining buffer equals the
    ///    original buffer length (no bytes are duplicated or lost).
    /// 3. Frame contents match the original payload byte-for-byte.
    #[test]
    fn hotpath_bytes_mut_splitting() {
        const TOTAL: usize = 32_768;
        const FRAME: usize = 1_024;
        const FILL: u8 = 0x42;

        #[cfg(feature = "test-internals")]
        reset_allocation_metrics();

        let start = Instant::now();

        let mut buf = BytesMut::with_capacity(TOTAL);
        buf.resize(TOTAL, FILL);
        assert_eq!(buf.len(), TOTAL);

        let original_len = buf.len();
        let mut frames = Vec::new();
        while buf.len() >= FRAME {
            let frame = buf.split_to(FRAME);
            assert_eq!(
                frame.len(),
                FRAME,
                "split_to must yield exactly the requested frame size"
            );
            assert!(
                frame.iter().all(|&b| b == FILL),
                "frame must preserve original payload byte-for-byte"
            );
            frames.push(frame);
        }

        let split_to_duration = start.elapsed();
        let bytes_in_frames: usize = frames.iter().map(crate::bytes::BytesMut::len).sum();
        assert_eq!(
            bytes_in_frames + buf.len(),
            original_len,
            "split_to must conserve bytes — frames + remaining must \
             equal the original length (no copies, no losses)"
        );
        assert_eq!(
            frames.len(),
            TOTAL / FRAME,
            "expected exactly {} frames, got {}",
            TOTAL / FRAME,
            frames.len()
        );

        if diagnostics_enabled() {
            println!(
                "split_to operations: {split_to_duration:?} for {} frames",
                frames.len()
            );
        }

        #[cfg(feature = "test-internals")]
        if diagnostics_enabled() {
            let metrics = get_allocation_metrics();
            println!("Split allocation metrics: {metrics:?}");
        }
    }

    /// Hot path: three `Bytes` construction routes. Asserts that
    /// each path produces byte-identical content with the expected
    /// length, regardless of which allocation strategy is used.
    #[test]
    fn hotpath_bytes_creation() {
        const PAYLOAD: usize = 4_096;

        #[cfg(feature = "test-internals")]
        reset_allocation_metrics();

        let test_data: Vec<u8> = (0..PAYLOAD).map(|i| (i * 31 + 7) as u8).collect();

        // Path 1: copy_from_slice.
        let start = Instant::now();
        let mut last_copy: Option<Bytes> = None;
        for _ in 0..1_000 {
            last_copy = Some(Bytes::copy_from_slice(&test_data));
        }
        let copy_duration = start.elapsed();
        let copy_sample = last_copy.expect("loop ran");
        assert_eq!(copy_sample.len(), PAYLOAD);
        assert_eq!(&copy_sample[..], &test_data[..]);

        // Path 2: from Vec (transfers ownership).
        let start = Instant::now();
        let mut last_from_vec: Option<Bytes> = None;
        for _ in 0..1_000 {
            let vec = test_data.clone();
            last_from_vec = Some(Bytes::from(vec));
        }
        let from_vec_duration = start.elapsed();
        let from_vec_sample = last_from_vec.expect("loop ran");
        assert_eq!(from_vec_sample.len(), PAYLOAD);
        assert_eq!(&from_vec_sample[..], &test_data[..]);

        // Path 3: BytesMut::freeze.
        let start = Instant::now();
        let mut last_freeze: Option<Bytes> = None;
        for _ in 0..1_000 {
            let mut buf = BytesMut::with_capacity(PAYLOAD);
            buf.extend_from_slice(&test_data);
            last_freeze = Some(buf.freeze());
        }
        let freeze_duration = start.elapsed();
        let freeze_sample = last_freeze.expect("loop ran");
        assert_eq!(freeze_sample.len(), PAYLOAD);
        assert_eq!(&freeze_sample[..], &test_data[..]);

        // All three paths must produce identical observable content.
        assert_eq!(&copy_sample[..], &from_vec_sample[..]);
        assert_eq!(&copy_sample[..], &freeze_sample[..]);

        if diagnostics_enabled() {
            println!("Bytes::copy_from_slice: {copy_duration:?} for 1000x{PAYLOAD}B");
            println!("Bytes::from(Vec): {from_vec_duration:?} for 1000x{PAYLOAD}B");
            println!("BytesMut::freeze: {freeze_duration:?} for 1000x{PAYLOAD}B");
        }

        #[cfg(feature = "test-internals")]
        if diagnostics_enabled() {
            let metrics = get_allocation_metrics();
            println!("Creation allocation metrics: {metrics:?}");
        }
    }

    /// Integrated test: HTTP-shaped request/response loop. Asserts:
    ///
    /// 1. Each iteration's frozen header buffer contains the
    ///    iteration-specific marker (so a regression that broke
    ///    `put_slice` would surface).
    /// 2. The split point lands at exactly the `\r\n\r\n` end-of-
    ///    headers boundary (no off-by-one).
    /// 3. Every iteration produces a non-empty frozen response.
    /// 4. Bytes accounting is consistent: header_bytes.len() ==
    ///    header_end.
    #[test]
    fn hotpath_realistic_workload() {
        const ITERATIONS: usize = 100;

        #[cfg(feature = "test-internals")]
        reset_allocation_metrics();

        let start = Instant::now();
        let mut frozen_responses: Vec<Bytes> = Vec::with_capacity(ITERATIONS);

        for req_num in 0..ITERATIONS {
            let mut request_buf = BytesMut::with_capacity(2_048);

            for chunk_num in 0..10 {
                let chunk = format!("Header-{req_num}-{chunk_num}: value\r\n");
                request_buf.put_slice(chunk.as_bytes());
            }
            request_buf.put_slice(b"\r\n");

            let header_end = request_buf[..]
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|p| p + 4)
                .expect("end-of-headers boundary must be present");

            let headers = request_buf.split_to(header_end);
            assert_eq!(
                headers.len(),
                header_end,
                "split_to must consume exactly the header bytes"
            );

            let header_bytes = headers.freeze();
            assert_eq!(header_bytes.len(), header_end);
            let marker = format!("Header-{req_num}-0:");
            assert!(
                header_bytes
                    .windows(marker.len())
                    .any(|w| w == marker.as_bytes()),
                "frozen header buffer must contain iteration marker {marker:?}"
            );

            let mut response_buf = BytesMut::with_capacity(1_024);
            response_buf.put_slice(b"HTTP/1.1 200 OK\r\n");
            response_buf.put_slice(b"Content-Type: application/json\r\n\r\n");
            response_buf.put_slice(format!(r#"{{"request":{req_num},"status":"ok"}}"#).as_bytes());
            let response_bytes = response_buf.freeze();
            assert!(
                !response_bytes.is_empty(),
                "every response must be non-empty"
            );
            frozen_responses.push(response_bytes);
        }

        assert_eq!(
            frozen_responses.len(),
            ITERATIONS,
            "all {ITERATIONS} iterations must have produced a frozen response"
        );

        let workload_duration = start.elapsed();
        if diagnostics_enabled() {
            println!("Realistic workload: {workload_duration:?} for {ITERATIONS} requests");
        }

        #[cfg(feature = "test-internals")]
        if diagnostics_enabled() {
            let final_metrics = get_allocation_metrics();
            println!("Final allocation metrics: {final_metrics:?}");
        }
    }
}
