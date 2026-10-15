//! RFC 6330 systematic encoder — derived EncodingStats consistency over the
//! emission lifecycle.
//!
//! bd-3uox5 (RAPTORQ-RFC6330) AC2/AC5. `EncodingStats` exposes several derived
//! metrics computed from raw counters: `average_degree`, `overhead_ratio`,
//! `total_bytes_emitted`, `encoding_efficiency`, `repair_overhead`. Three of
//! those (`average_degree`, `total_bytes_emitted`, `encoding_efficiency`) had
//! ZERO test coverage, so nothing pinned that they stay consistent with the
//! raw counters as the encoder moves through construction -> systematic ->
//! repair emission.
//!
//! This harness pins the derived-vs-raw identities at each lifecycle stage,
//! recomputing each metric from the public raw fields with the SAME f64 ops so
//! the comparison is exact (no epsilon fuzz):
//!   - FRESH: no emission -> average_degree == 0, total bytes == 0,
//!     efficiency == 0; overhead_ratio == L/K is already populated at build.
//!   - AFTER emit_systematic: systematic bytes == K*sym, total == K*sym,
//!     efficiency == 1.0, average_degree still 0 (no repair degrees yet).
//!   - AFTER emit_repair(n): repair bytes == n*sym, total == (K+n)*sym,
//!     efficiency == K/(K+n), repair_overhead == n/K, degree_count == n,
//!     average_degree == degree_sum/degree_count and lies in [1, L].
//!   - overhead_ratio depends only on construction and is stable throughout.
//!
//! Repro: `cargo test --test raptorq_encoding_stats_derived_consistency`

use asupersync::raptorq::systematic::{EncodingStats, SystematicEncoder};

const SYMBOL_SIZE: usize = 8;

fn make_source(k: usize) -> Vec<Vec<u8>> {
    (0..k)
        .map(|i| {
            (0..SYMBOL_SIZE)
                .map(|b| ((i * 13 + b * 3 + 1) & 0xFF) as u8)
                .collect()
        })
        .collect()
}

fn new_encoder(k: usize) -> SystematicEncoder {
    SystematicEncoder::new(&make_source(k), SYMBOL_SIZE, 0xFEED_u64)
        .unwrap_or_else(|| panic!("encoder construction failed for K={k}"))
}

/// Recompute every derived metric from the raw fields with identical f64 ops,
/// then assert each accessor returns exactly that.
fn assert_derived_match_raw(s: &EncodingStats) {
    // average_degree
    let expect_avg = if s.degree_count == 0 {
        0.0
    } else {
        s.degree_sum as f64 / s.degree_count as f64
    };
    assert_eq!(
        s.average_degree(),
        expect_avg,
        "average_degree != degree_sum/degree_count"
    );

    // overhead_ratio
    let expect_overhead = if s.source_symbol_count == 0 {
        0.0
    } else {
        s.intermediate_symbol_count as f64 / s.source_symbol_count as f64
    };
    assert_eq!(s.overhead_ratio(), expect_overhead, "overhead_ratio != L/K");

    // total_bytes_emitted
    assert_eq!(
        s.total_bytes_emitted(),
        s.systematic_bytes_emitted + s.repair_bytes_emitted,
        "total_bytes_emitted != sys + repair"
    );

    // encoding_efficiency
    let total = s.systematic_bytes_emitted + s.repair_bytes_emitted;
    let expect_eff = if total == 0 {
        0.0
    } else {
        s.systematic_bytes_emitted as f64 / total as f64
    };
    assert_eq!(
        s.encoding_efficiency(),
        expect_eff,
        "encoding_efficiency != sys/total"
    );

    // repair_overhead
    let expect_repair = if s.systematic_bytes_emitted == 0 {
        0.0
    } else {
        s.repair_bytes_emitted as f64 / s.systematic_bytes_emitted as f64
    };
    assert_eq!(
        s.repair_overhead(),
        expect_repair,
        "repair_overhead != repair/sys"
    );
}

#[test]
fn fresh_encoder_stats_are_zeroed_except_overhead_ratio() {
    for &k in &[1usize, 4, 10, 42] {
        let enc = new_encoder(k);
        let s = enc.stats();
        assert_derived_match_raw(s);

        assert_eq!(s.degree_count, 0, "no repair degrees before emission");
        assert_eq!(s.average_degree(), 0.0, "fresh average_degree must be 0");
        assert_eq!(s.total_bytes_emitted(), 0, "fresh total bytes must be 0");
        assert_eq!(s.encoding_efficiency(), 0.0, "fresh efficiency must be 0");
        assert_eq!(s.repair_overhead(), 0.0, "fresh repair overhead must be 0");

        // overhead_ratio = L/K is populated at construction; L > K so it's > 1.
        assert_eq!(s.source_symbol_count, k, "stats must echo K");
        assert!(
            s.overhead_ratio() > 1.0,
            "L/K must exceed 1 (L={}, K={k})",
            s.intermediate_symbol_count
        );
    }
}

#[test]
fn systematic_emission_marks_all_bytes_as_source() {
    for &k in &[1usize, 4, 10, 42] {
        let mut enc = new_encoder(k);
        let _ = enc.emit_systematic();
        let s = enc.stats();
        assert_derived_match_raw(s);

        let sys_bytes = k * SYMBOL_SIZE;
        assert_eq!(
            s.systematic_bytes_emitted, sys_bytes,
            "systematic bytes = K*sym"
        );
        assert_eq!(s.repair_bytes_emitted, 0, "no repair bytes yet");
        assert_eq!(s.total_bytes_emitted(), sys_bytes, "total = systematic");
        assert_eq!(
            s.encoding_efficiency(),
            1.0,
            "all bytes are systematic -> efficiency 1.0"
        );
        assert_eq!(s.average_degree(), 0.0, "no repair degrees recorded yet");
        assert_eq!(s.repair_overhead(), 0.0, "no repair overhead yet");
    }
}

#[test]
fn repair_emission_updates_derived_metrics_consistently() {
    for &k in &[1usize, 4, 10, 42] {
        let n = 7usize;
        let mut enc = new_encoder(k);
        let _ = enc.emit_systematic();
        let _ = enc.emit_repair(n);

        let s = enc.stats();
        assert_derived_match_raw(s);

        let sys_bytes = k * SYMBOL_SIZE;
        let rep_bytes = n * SYMBOL_SIZE;
        assert_eq!(s.systematic_bytes_emitted, sys_bytes);
        assert_eq!(s.repair_bytes_emitted, rep_bytes);
        assert_eq!(
            s.total_bytes_emitted(),
            sys_bytes + rep_bytes,
            "total = sys + repair"
        );

        // efficiency == sys/(sys+rep) == K/(K+n) since all symbols are sym bytes.
        let expect_eff = sys_bytes as f64 / (sys_bytes + rep_bytes) as f64;
        assert_eq!(s.encoding_efficiency(), expect_eff);
        assert_eq!(
            s.encoding_efficiency(),
            k as f64 / (k + n) as f64,
            "efficiency == K/(K+n)"
        );

        // repair_overhead == rep/sys == n/K.
        assert_eq!(
            s.repair_overhead(),
            n as f64 / k as f64,
            "repair_overhead == n/K"
        );

        // degree bookkeeping: one degree per emitted repair symbol.
        assert_eq!(
            s.degree_count, n,
            "degree_count == number of repair symbols"
        );
        assert_eq!(
            s.repair_symbols_generated, n,
            "repair_symbols_generated == n"
        );
        let avg = s.average_degree();
        assert_eq!(
            avg,
            s.degree_sum as f64 / n as f64,
            "average_degree == degree_sum/n"
        );
        assert!(
            avg >= 1.0,
            "every repair symbol has degree >= 1 (avg={avg})"
        );
        assert!(
            avg <= s.intermediate_symbol_count as f64,
            "average degree cannot exceed L (avg={avg}, L={})",
            s.intermediate_symbol_count
        );
        assert!(s.degree_min >= 1, "min repair degree >= 1");
        assert!(s.degree_max >= s.degree_min, "degree_max >= degree_min");
    }
}

#[test]
fn overhead_ratio_is_stable_across_lifecycle() {
    for &k in &[1usize, 4, 10, 42] {
        let mut enc = new_encoder(k);
        let fresh = enc.stats().overhead_ratio();

        let _ = enc.emit_systematic();
        assert_eq!(
            enc.stats().overhead_ratio(),
            fresh,
            "overhead_ratio moved after systematic"
        );

        let _ = enc.emit_repair(5);
        assert_eq!(
            enc.stats().overhead_ratio(),
            fresh,
            "overhead_ratio moved after repair"
        );
    }
}
