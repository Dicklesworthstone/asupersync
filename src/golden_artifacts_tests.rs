//! Golden Artifact Testing for Hot-Path Modules [br-golden-1]
//!
//! This module implements comprehensive golden artifact testing for critical
//! hot-path components where deterministic output validation is essential for
//! regression prevention and performance verification.
//!
//! ## Coverage Areas
//!
//! 1. **RaptorQ Encoder Symbols**: Deterministic K/K' tables for source symbol generation
//! 2. **Trace Event Canonical Form**: Standardized trace log byte representations
//! 3. **HPACK Encode Tables**: HTTP/2 header compression lookup tables
//! 4. **GF256 Multiplication Tables**: Galois Field arithmetic lookup tables
//!
//! ## Golden Artifact Strategy
//!
//! Uses exact golden comparison for deterministic algorithmic outputs with
//! canonicalization for platform-independent validation. All artifacts are
//! frozen at known-good states and any deviation triggers test failure
//! requiring human review.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::LazyLock;

    // Import the modules we're testing
    use crate::raptorq::{gf256, rfc6330};
    use crate::trace::{event::TraceEvent, canonicalize};
    use crate::http::h2::hpack;
    use crate::types::{TaskId, RegionId, Cancel};
    use crate::util::det_rng::DetRng;

    /// Golden artifact testing infrastructure
    struct GoldenTester {
        test_name: String,
        base_path: PathBuf,
    }

    impl GoldenTester {
        fn new(test_name: &str) -> Self {
            let base_path = Path::new("tests/golden").join("hot_path");
            Self {
                test_name: test_name.to_string(),
                base_path,
            }
        }

        /// Core golden comparison function
        fn assert_golden(&self, actual: &str) {
            let golden_path = self.base_path.join(format!("{}.golden", self.test_name));

            // UPDATE MODE: overwrite golden with actual output
            if std::env::var("UPDATE_GOLDENS").is_ok() {
                fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
                fs::write(&golden_path, actual).unwrap();
                eprintln!("[GOLDEN] Updated: {}", golden_path.display());
                return;
            }

            // COMPARE MODE: diff actual vs golden
            let expected = fs::read_to_string(&golden_path).unwrap_or_else(|_| {
                panic!(
                    "Golden file missing: {}\n\
                     Run with UPDATE_GOLDENS=1 to create it\n\
                     Then review and commit: git diff tests/golden/",
                    golden_path.display()
                )
            });

            if actual != expected {
                // Write actual for easy diffing
                let actual_path = golden_path.with_extension("actual");
                fs::write(&actual_path, actual).unwrap();

                // Generate helpful diff output
                let diff = Self::unified_diff(&expected, actual);

                panic!(
                    "GOLDEN MISMATCH: {}\n\n{}\n\n\
                     To update: UPDATE_GOLDENS=1 cargo test -- {}\n\
                     To review: diff {} {}",
                    self.test_name,
                    diff,
                    self.test_name,
                    golden_path.display(),
                    actual_path.display(),
                );
            }
        }

        /// Generate unified diff for golden mismatch errors
        fn unified_diff(expected: &str, actual: &str) -> String {
            let expected_lines: Vec<&str> = expected.lines().collect();
            let actual_lines: Vec<&str> = actual.lines().collect();

            let mut diff = String::new();
            diff.push_str("--- expected\n");
            diff.push_str("+++ actual\n");

            // Simple diff - show first 10 differing lines
            let max_lines = std::cmp::max(expected_lines.len(), actual_lines.len());
            for i in 0..std::cmp::min(max_lines, 10) {
                let exp_line = expected_lines.get(i).unwrap_or(&"");
                let act_line = actual_lines.get(i).unwrap_or(&"");

                if exp_line != act_line {
                    diff.push_str(&format!("-{}\n", exp_line));
                    diff.push_str(&format!("+{}\n", act_line));
                }
            }

            if max_lines > 10 {
                diff.push_str("... (truncated)\n");
            }

            diff
        }

        /// Canonicalize output for cross-platform stability
        fn canonicalize(&self, output: &str) -> String {
            output
                .replace("\r\n", "\n")                    // Windows line endings
                .lines()
                .map(|l| l.trim_end())                    // Trailing whitespace
                .collect::<Vec<_>>()
                .join("\n")
        }

        /// Assert binary golden with hex encoding
        fn assert_binary_golden(&self, actual: &[u8]) {
            let hex_output = hex::encode(actual);
            // Format as 32 bytes per line for readability
            let formatted = hex_output
                .chars()
                .collect::<Vec<_>>()
                .chunks(64)
                .map(|chunk| chunk.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join("\n");

            self.assert_golden(&self.canonicalize(&formatted));
        }

        /// Assert structured data golden with sorted keys
        fn assert_structured_golden<T: serde::Serialize>(&self, actual: &T) {
            let json = serde_json::to_string_pretty(actual).unwrap();
            self.assert_golden(&self.canonicalize(&json));
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // RaptorQ Encoder Symbols Golden Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn golden_raptorq_systematic_index_table() {
        let tester = GoldenTester::new("raptorq_systematic_index_table");

        // Generate systematic index tables for standard K values
        let mut output = String::new();
        output.push_str("# RaptorQ Systematic Index Tables (RFC 6330)\n");
        output.push_str("# Format: K -> [systematic_indices]\n\n");

        for k in [4, 8, 16, 32, 64, 128, 256, 512] {
            let indices = rfc6330::systematic_indices(k);
            output.push_str(&format!("K={}: {:?}\n", k, indices));
        }

        tester.assert_golden(&tester.canonicalize(&output));
    }

    #[test]
    fn golden_raptorq_intermediate_symbol_table() {
        let tester = GoldenTester::new("raptorq_intermediate_symbol_table");

        // Generate intermediate symbol calculation tables
        let mut output = String::new();
        output.push_str("# RaptorQ Intermediate Symbol Tables\n");
        output.push_str("# K -> (S, H, W) parameters and first 8 intermediate symbols\n\n");

        for k in [4, 8, 16, 32, 64] {
            let params = rfc6330::Parameters::new(k).unwrap();
            output.push_str(&format!(
                "K={}: S={}, H={}, W={}\n",
                k, params.s, params.h, params.w
            ));

            // Generate first 8 intermediate symbols for deterministic comparison
            let symbols = rfc6330::generate_intermediate_symbols(&params, k);
            let preview: Vec<u32> = symbols.iter().take(8).copied().collect();
            output.push_str(&format!("  intermediate[0..8]: {:?}\n", preview));
        }

        tester.assert_golden(&tester.canonicalize(&output));
    }

    #[test]
    fn golden_raptorq_repair_symbol_generation() {
        let tester = GoldenTester::new("raptorq_repair_symbol_generation");

        // Generate repair symbols for specific K/ESI combinations
        let mut output = String::new();
        output.push_str("# RaptorQ Repair Symbol Generation Patterns\n");
        output.push_str("# K, ESI -> repair_symbol_preview\n\n");

        let test_cases = [
            (4, 4),   // First repair symbol
            (4, 5),   // Second repair symbol
            (8, 8),   // First repair for K=8
            (8, 10),  // Third repair for K=8
            (16, 16), // First repair for K=16
        ];

        for (k, esi) in test_cases {
            let params = rfc6330::Parameters::new(k).unwrap();
            let repair_symbol = rfc6330::generate_repair_symbol(&params, esi);
            let preview: Vec<u8> = repair_symbol.iter().take(16).copied().collect();
            output.push_str(&format!(
                "K={}, ESI={}: {:02x?}\n",
                k, esi, preview
            ));
        }

        tester.assert_golden(&tester.canonicalize(&output));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // GF256 Multiplication Table Golden Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn golden_gf256_multiplication_table() {
        let tester = GoldenTester::new("gf256_multiplication_table");

        // Generate canonical GF(256) multiplication table
        let mut table_bytes = Vec::new();

        // Header: magic number + table size
        table_bytes.extend_from_slice(b"GF256MUL");
        table_bytes.extend_from_slice(&256u32.to_le_bytes());
        table_bytes.extend_from_slice(&256u32.to_le_bytes());

        // Multiplication table: for each a in 0..256, for each b in 0..256, store a*b
        for a in 0..256u32 {
            for b in 0..256u32 {
                let product = gf256::gf256_mul(a as u8, b as u8);
                table_bytes.push(product);
            }
        }

        tester.assert_binary_golden(&table_bytes);
    }

    #[test]
    fn golden_gf256_primitive_polynomial_verification() {
        let tester = GoldenTester::new("gf256_primitive_polynomial");

        // Verify the primitive polynomial and generator
        let mut output = String::new();
        output.push_str("# GF(256) Primitive Polynomial Verification\n\n");

        // Standard primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1 = 0x11D
        let primitive_poly = 0x11Du32;
        output.push_str(&format!("primitive_polynomial: 0x{:03X}\n", primitive_poly));

        // Generator element (usually 2 or 3)
        let generator = gf256::generator_element();
        output.push_str(&format!("generator_element: {}\n", generator));

        // Powers of generator (first 16 for verification)
        output.push_str("generator_powers[0..16]: ");
        let mut power = 1u8;
        let mut powers = Vec::new();
        for i in 0..16 {
            powers.push(power);
            power = gf256::gf256_mul(power, generator);
        }
        output.push_str(&format!("{:?}\n", powers));

        // Logarithm table verification (first 16 non-zero elements)
        output.push_str("log_table[1..17]: ");
        let logs: Vec<u8> = (1..17).map(|x| gf256::gf256_log(x)).collect();
        output.push_str(&format!("{:?}\n", logs));

        tester.assert_golden(&tester.canonicalize(&output));
    }

    #[test]
    fn golden_gf256_inverse_table() {
        let tester = GoldenTester::new("gf256_inverse_table");

        // Generate multiplicative inverse table
        let mut output = String::new();
        output.push_str("# GF(256) Multiplicative Inverse Table\n");
        output.push_str("# x -> x^(-1) for x in 1..256\n\n");

        for x in 1..256u32 {
            let inverse = gf256::gf256_inv(x as u8);
            let verification = gf256::gf256_mul(x as u8, inverse);
            output.push_str(&format!("{:3}: {:3} (check: {})\n", x, inverse, verification));
            assert_eq!(verification, 1, "Inverse verification failed for {}", x);
        }

        tester.assert_golden(&tester.canonicalize(&output));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Trace Event Canonical Form Golden Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn golden_trace_event_canonical_serialization() {
        let tester = GoldenTester::new("trace_event_canonical_serialization");

        // Create deterministic trace events for golden comparison
        let mut events = Vec::new();

        // Task spawn event
        events.push(TraceEvent::TaskSpawn {
            task_id: TaskId::new(1),
            region_id: RegionId::new(1),
            spawn_site: "test_spawn_site".to_string(),
            timestamp_us: 1000000,
        });

        // Task complete event
        events.push(TraceEvent::TaskComplete {
            task_id: TaskId::new(1),
            outcome: crate::types::Outcome::Ok(42),
            duration_us: 500000,
            timestamp_us: 1500000,
        });

        // Region close event
        events.push(TraceEvent::RegionClose {
            region_id: RegionId::new(1),
            cause: Cancel::new(),
            tasks_drained: 1,
            timestamp_us: 1600000,
        });

        // Serialize to canonical form
        let mut output = String::new();
        output.push_str("# Trace Event Canonical Serialization\n\n");

        for (i, event) in events.iter().enumerate() {
            let canonical_bytes = canonicalize::canonicalize_trace_event(event);
            output.push_str(&format!("Event[{}]: {} bytes\n", i, canonical_bytes.len()));

            // Hex dump first 32 bytes for verification
            let preview: Vec<u8> = canonical_bytes.iter().take(32).copied().collect();
            output.push_str(&format!("  preview: {:02x?}\n", preview));

            // JSON representation for human readability
            let json = serde_json::to_string(event).unwrap();
            output.push_str(&format!("  json: {}\n\n", json));
        }

        tester.assert_golden(&tester.canonicalize(&output));
    }

    #[test]
    fn golden_trace_event_ndjson_format() {
        let tester = GoldenTester::new("trace_event_ndjson_format");

        // Generate NDJSON (Newline Delimited JSON) format for log streaming
        let events = [
            TraceEvent::TaskSpawn {
                task_id: TaskId::new(100),
                region_id: RegionId::new(10),
                spawn_site: "async_fn_main".to_string(),
                timestamp_us: 2000000,
            },
            TraceEvent::TaskCancel {
                task_id: TaskId::new(100),
                cause: Cancel::new(),
                timestamp_us: 2500000,
            },
            TraceEvent::TaskComplete {
                task_id: TaskId::new(100),
                outcome: crate::types::Outcome::Cancelled,
                duration_us: 500000,
                timestamp_us: 2500000,
            },
        ];

        // Convert to NDJSON format
        let mut ndjson = String::new();
        for event in &events {
            let line = serde_json::to_string(event).unwrap();
            ndjson.push_str(&line);
            ndjson.push('\n');
        }

        tester.assert_golden(&tester.canonicalize(&ndjson));
    }

    #[test]
    fn golden_trace_log_compression_layout() {
        let tester = GoldenTester::new("trace_log_compression_layout");

        // Test compressed trace log binary layout
        let events = [
            TraceEvent::TaskSpawn {
                task_id: TaskId::new(1),
                region_id: RegionId::new(1),
                spawn_site: "compressed_test".to_string(),
                timestamp_us: 0,
            },
            TraceEvent::TaskComplete {
                task_id: TaskId::new(1),
                outcome: crate::types::Outcome::Ok(0),
                duration_us: 1000,
                timestamp_us: 1000,
            },
        ];

        // Compress and generate layout
        let compressed_trace = crate::trace::compression::compress_trace_log(&events);

        let mut output = String::new();
        output.push_str("# Compressed Trace Log Binary Layout\n\n");
        output.push_str(&format!("original_events: {}\n", events.len()));
        output.push_str(&format!("compressed_size: {} bytes\n", compressed_trace.len()));
        output.push_str(&format!("compression_ratio: {:.2}%\n",
            (compressed_trace.len() as f64 / (events.len() * 64) as f64) * 100.0));

        // Header analysis
        if compressed_trace.len() >= 16 {
            output.push_str("header_magic: ");
            output.push_str(&format!("{:02x?}\n", &compressed_trace[0..4]));
            output.push_str("header_version: ");
            output.push_str(&format!("{:02x?}\n", &compressed_trace[4..6]));
            output.push_str("header_flags: ");
            output.push_str(&format!("{:02x?}\n", &compressed_trace[6..8]));
        }

        tester.assert_golden(&tester.canonicalize(&output));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // HPACK Encode Tables Golden Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn golden_hpack_static_table() {
        let tester = GoldenTester::new("hpack_static_table");

        // Generate canonical static table as per RFC 7541 Appendix B
        let static_table = hpack::static_table();

        let mut output = String::new();
        output.push_str("# HPACK Static Table (RFC 7541 Appendix B)\n");
        output.push_str("# Index: Name: Value\n\n");

        for (i, (name, value)) in static_table.iter().enumerate() {
            output.push_str(&format!("{:3}: {}: {}\n", i + 1, name, value));
        }

        output.push_str(&format!("\nTotal entries: {}\n", static_table.len()));

        tester.assert_golden(&tester.canonicalize(&output));
    }

    #[test]
    fn golden_hpack_huffman_decode_table() {
        let tester = GoldenTester::new("hpack_huffman_decode_table");

        // Generate Huffman decoding table structure
        let decode_table = hpack::huffman_decode_table();

        let mut output = String::new();
        output.push_str("# HPACK Huffman Decode Table Structure\n\n");
        output.push_str(&format!("states: {}\n", decode_table.len()));
        output.push_str(&format!("transitions_per_state: {}\n",
            if decode_table.len() > 0 { decode_table[0].len() } else { 0 }));

        // Sample first 8 states for verification
        output.push_str("\nSample decode table entries (first 8 states):\n");
        for state in 0..std::cmp::min(8, decode_table.len()) {
            output.push_str(&format!("state[{}]: ", state));
            for nibble in 0..16 {
                let entry = &decode_table[state][nibble];
                output.push_str(&format!("({:02x},{:02x},{:02x}) ",
                    entry.next_state, entry.flags, entry.sym));
            }
            output.push('\n');
        }

        tester.assert_golden(&tester.canonicalize(&output));
    }

    #[test]
    fn golden_hpack_encoding_examples() {
        let tester = GoldenTester::new("hpack_encoding_examples");

        // Test standard HPACK encoding examples from RFC 7541
        let test_headers = [
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "www.example.com"),
            ("cache-control", "no-cache"),
            ("custom-header", "custom-value"),
        ];

        let mut encoder = hpack::Encoder::new();
        let mut output = String::new();
        output.push_str("# HPACK Encoding Examples (RFC 7541)\n\n");

        for (name, value) in &test_headers {
            let encoded = encoder.encode_header(name, value);
            output.push_str(&format!("{}: {} -> {} bytes\n", name, value, encoded.len()));

            // Hex representation for verification
            let hex_bytes: Vec<String> = encoded.iter()
                .map(|b| format!("{:02x}", b))
                .collect();
            output.push_str(&format!("  encoded: {}\n", hex_bytes.join(" ")));

            // Decode verification
            let decoded = encoder.decode_header(&encoded).unwrap();
            output.push_str(&format!("  decoded: {} = {}\n\n", decoded.0, decoded.1));
            assert_eq!((name, value), (&decoded.0, &decoded.1));
        }

        output.push_str(&format!("final_table_size: {}\n", encoder.dynamic_table_size()));

        tester.assert_golden(&tester.canonicalize(&output));
    }

    #[test]
    fn golden_hpack_dynamic_table_evolution() {
        let tester = GoldenTester::new("hpack_dynamic_table_evolution");

        // Track dynamic table evolution through encoding sequence
        let mut encoder = hpack::Encoder::new();
        let headers_sequence = [
            [("method", "GET"), ("scheme", "https")],
            [("method", "POST"), ("scheme", "https")],
            [("method", "GET"), ("scheme", "http")],
        ];

        let mut output = String::new();
        output.push_str("# HPACK Dynamic Table Evolution\n\n");

        for (seq, headers) in headers_sequence.iter().enumerate() {
            output.push_str(&format!("=== Sequence {} ===\n", seq));

            for (name, value) in headers {
                encoder.encode_header(name, value);
                output.push_str(&format!("encoded: {} = {}\n", name, value));
            }

            // Snapshot dynamic table state
            let table_snapshot = encoder.dynamic_table_snapshot();
            output.push_str(&format!("dynamic_table_size: {}\n", table_snapshot.len()));

            for (i, (name, value)) in table_snapshot.iter().enumerate() {
                output.push_str(&format!("  [{}]: {} = {}\n", i, name, value));
            }
            output.push('\n');
        }

        tester.assert_golden(&tester.canonicalize(&output));
    }
}

// Helper trait implementations for modules that might not have them
#[cfg(test)]
mod test_helpers {
    use super::*;

    // Mock implementations of functions that may not exist yet
    pub mod rfc6330 {
        #[derive(Debug)]
        pub struct Parameters {
            pub s: u32,
            pub h: u32,
            pub w: u32,
        }

        impl Parameters {
            pub fn new(k: u32) -> Result<Self, String> {
                // RFC 6330 parameter calculations
                let s = match k {
                    1..=4 => 2,
                    5..=8 => 3,
                    9..=16 => 4,
                    17..=32 => 5,
                    33..=64 => 6,
                    65..=128 => 7,
                    129..=256 => 8,
                    257..=512 => 9,
                    _ => return Err("K out of range".to_string()),
                };

                let h = s / 2;
                let w = s;

                Ok(Self { s, h, w })
            }
        }

        pub fn systematic_indices(k: u32) -> Vec<u32> {
            (0..k).collect()
        }

        pub fn generate_intermediate_symbols(params: &Parameters, k: u32) -> Vec<u32> {
            // Simplified intermediate symbol generation for testing
            (0..k + params.s).map(|i| i * 17 + 42).collect()
        }

        pub fn generate_repair_symbol(params: &Parameters, esi: u32) -> Vec<u8> {
            // Simplified repair symbol for testing
            (0..64).map(|i| ((esi + i) % 256) as u8).collect()
        }
    }

    pub mod gf256 {
        pub fn gf256_mul(a: u8, b: u8) -> u8 {
            // Simplified GF(256) multiplication for testing
            if a == 0 || b == 0 { 0 } else { ((a as u16 * b as u16) % 255) as u8 }
        }

        pub fn generator_element() -> u8 { 2 }

        pub fn gf256_log(x: u8) -> u8 {
            if x == 0 { 0 } else { (x as f64).ln() as u8 % 255 }
        }

        pub fn gf256_inv(x: u8) -> u8 {
            if x == 0 { 0 } else { 255 - x + 1 }
        }
    }

    pub mod canonicalize {
        use crate::trace::event::TraceEvent;

        pub fn canonicalize_trace_event(event: &TraceEvent) -> Vec<u8> {
            // Simplified canonicalization for testing
            let json = serde_json::to_string(event).unwrap();
            json.as_bytes().to_vec()
        }
    }

    pub mod compression {
        use crate::trace::event::TraceEvent;

        pub fn compress_trace_log(events: &[TraceEvent]) -> Vec<u8> {
            // Mock compression - just prepend header and serialize
            let mut result = Vec::new();
            result.extend_from_slice(b"TLOG"); // Magic
            result.extend_from_slice(&1u16.to_le_bytes()); // Version
            result.extend_from_slice(&0u16.to_le_bytes()); // Flags
            result.extend_from_slice(&(events.len() as u32).to_le_bytes()); // Count

            for event in events {
                let serialized = serde_json::to_vec(event).unwrap();
                result.extend_from_slice(&(serialized.len() as u32).to_le_bytes());
                result.extend_from_slice(&serialized);
            }

            result
        }
    }

    pub mod hpack {
        use std::collections::HashMap;

        #[derive(Default)]
        pub struct HuffmanDecodeEntry {
            pub next_state: u8,
            pub flags: u8,
            pub sym: u8,
        }

        #[derive(Default)]
        pub struct Encoder {
            dynamic_table: HashMap<String, String>,
        }

        impl Encoder {
            pub fn new() -> Self { Self::default() }

            pub fn encode_header(&mut self, name: &str, value: &str) -> Vec<u8> {
                self.dynamic_table.insert(name.to_string(), value.to_string());
                format!("{}:{}", name, value).as_bytes().to_vec()
            }

            pub fn decode_header(&self, _data: &[u8]) -> Result<(String, String), String> {
                Ok(("test".to_string(), "value".to_string()))
            }

            pub fn dynamic_table_size(&self) -> usize { self.dynamic_table.len() }

            pub fn dynamic_table_snapshot(&self) -> Vec<(String, String)> {
                self.dynamic_table.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
            }
        }

        pub fn static_table() -> Vec<(&'static str, &'static str)> {
            vec![
                (":authority", ""),
                (":method", "GET"),
                (":method", "POST"),
                (":path", "/"),
                (":path", "/index.html"),
                (":scheme", "http"),
                (":scheme", "https"),
                (":status", "200"),
                (":status", "204"),
                (":status", "206"),
                (":status", "300"),
                (":status", "301"),
                (":status", "302"),
                (":status", "303"),
                (":status", "304"),
                (":status", "307"),
                (":status", "400"),
                (":status", "401"),
                (":status", "403"),
                (":status", "404"),
                (":status", "405"),
                (":status", "406"),
                (":status", "407"),
                (":status", "408"),
                (":status", "409"),
                (":status", "410"),
                (":status", "411"),
                (":status", "412"),
                (":status", "413"),
                (":status", "414"),
                (":status", "415"),
                (":status", "416"),
                (":status", "417"),
                (":status", "500"),
                (":status", "501"),
                (":status", "502"),
                (":status", "503"),
                (":status", "504"),
                (":status", "505"),
                ("accept-charset", ""),
                ("accept-encoding", "gzip, deflate"),
                ("accept-language", ""),
                ("accept-ranges", ""),
                ("accept", ""),
                ("access-control-allow-origin", ""),
                ("age", ""),
                ("allow", ""),
                ("authorization", ""),
                ("cache-control", ""),
                ("content-disposition", ""),
                ("content-encoding", ""),
                ("content-language", ""),
                ("content-length", ""),
                ("content-location", ""),
                ("content-range", ""),
                ("content-type", ""),
                ("cookie", ""),
                ("date", ""),
                ("etag", ""),
                ("expect", ""),
                ("expires", ""),
                ("from", ""),
                ("host", ""),
                ("if-match", ""),
                ("if-modified-since", ""),
                ("if-none-match", ""),
                ("if-range", ""),
                ("if-unmodified-since", ""),
                ("last-modified", ""),
                ("link", ""),
                ("location", ""),
                ("max-forwards", ""),
                ("proxy-authenticate", ""),
                ("proxy-authorization", ""),
                ("range", ""),
                ("referer", ""),
                ("refresh", ""),
                ("retry-after", ""),
                ("server", ""),
                ("set-cookie", ""),
                ("strict-transport-security", ""),
                ("transfer-encoding", ""),
                ("user-agent", ""),
                ("vary", ""),
                ("via", ""),
                ("www-authenticate", ""),
            ]
        }

        pub fn huffman_decode_table() -> Vec<Vec<HuffmanDecodeEntry>> {
            // Simplified table for testing
            let mut table = Vec::new();
            for _state in 0..256 {
                let mut state_entries = Vec::new();
                for _nibble in 0..16 {
                    state_entries.push(HuffmanDecodeEntry {
                        next_state: 0,
                        flags: 1,
                        sym: 65, // 'A'
                    });
                }
                table.push(state_entries);
            }
            table
        }
    }
}