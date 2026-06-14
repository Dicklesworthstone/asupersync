//! Deterministic end-to-end harness for RFC 6330 Track-B encoder parameters
//! and repair-equation construction (bead `bd-erfxv`).
//!
//! # Scope (bd-erfxv Track-B)
//!
//! Children B1/B2/B3 implemented the table-driven `(K', J, S, H, W)` lookup,
//! the RFC degree/tuple generator, and the LT/repair equation construction.
//! This harness closes the epic-level acceptance criteria that the child beads
//! intentionally deferred:
//!
//! - **AC4 (deterministic E2E):** exercises the live encoder seams
//!   ([`SystematicParams::try_for_source_block`], [`SystematicEncoder`],
//!   [`SystematicParams::rfc_repair_equation`]) over a fixed `K` matrix with no
//!   randomness beyond the explicit seed.
//! - **AC5 (structured logging):** every scenario emits a canonical
//!   `raptorq-unit-log-v1` JSON line (scenario_id / seed / parameter_set /
//!   outcome / artifact_path) to stdout and to a JSONL artifact.
//! - **AC6 (reproducibility):** each entry carries the exact rch-backed repro
//!   command and a stable seed/fixture derivation.
//!
//! # The equation-construction proof
//!
//! For a systematic RaptorQ encoder, every repair symbol is the GF(256) sum of
//! the intermediate symbols named by its RFC tuple, with all coefficients equal
//! to one (GF(256) addition is XOR). [`SystematicParams::rfc_repair_equation`]
//! is the single source of truth for that column set, and the encoder's
//! internal synthesis walks the identical LT/PI index path. This harness proves
//! the two agree byte-for-byte:
//!
//! ```text
//! repair_symbol(esi) == XOR over col in rfc_repair_equation(esi).columns
//!                          of intermediate_symbol(col)
//! ```
//!
//! A divergence here would mean the published equation no longer describes the
//! bytes actually on the wire — the exact spec-accuracy hazard Track-B exists to
//! eliminate.
//!
//! # Repro
//!
//! ```text
//! rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_asupersync_test \
//!   cargo test --test raptorq_rfc6330_encoder_params_e2e --features test-internals -- --nocapture
//! ```

#![allow(missing_docs)]

use asupersync::raptorq::rfc6330::next_prime_ge;
use asupersync::raptorq::systematic::{SystematicEncoder, SystematicParams};

/// Fixed symbol size for every scenario (bytes).
const SYMBOL_SIZE: usize = 32;

/// Representative + boundary `K` values. Each maps to a distinct row region of
/// the RFC 6330 systematic index table (K'=10 floor, the 26/30 small rows, and
/// successively larger blocks) so the parameter lookup and equation generator
/// are exercised across degree regimes.
const SCENARIO_K: &[usize] = &[1, 4, 10, 11, 26, 30, 64, 128, 256];

/// Stable rch-backed reproduction command embedded in every structured-log
/// entry (AC6). The `raptorq-unit-log-v1` schema requires an `rch exec --`
/// prefix and forbids shell substitution (`${`/`$(`, br-asupersync-zmzwof
/// anti-injection rule), so the target dir is a literal path.
const REPRO_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_asupersync_test cargo test --test raptorq_rfc6330_encoder_params_e2e --features test-internals -- --nocapture";

/// Stable replay catalog reference for this harness.
const REPLAY_REF: &str = "replay:rq-b-encparam-equation-v1";

/// Deterministic root seed for a given `K` (no wall-clock / RNG input).
fn seed_for(k: usize) -> u64 {
    0xA55A_0000_0000_0000_u64 ^ (k as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// Build deterministic source symbols for a `(k, symbol_size, seed)` fixture.
fn build_source(k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    (0..k)
        .map(|i| {
            (0..symbol_size)
                .map(|j| {
                    let mix = seed
                        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                        .wrapping_add((i as u64) << 17)
                        .wrapping_add(j as u64)
                        .wrapping_mul(0xD1B5_4A32_D192_ED03);
                    (mix >> 33) as u8
                })
                .collect()
        })
        .collect()
}

/// In-place GF(256) addition (XOR) of `src` into `acc`.
fn xor_into(acc: &mut [u8], src: &[u8]) {
    for (a, b) in acc.iter_mut().zip(src.iter()) {
        *a ^= *b;
    }
}

/// Assert the table-driven RFC 6330 parameter invariants for one block.
fn assert_param_invariants(params: &SystematicParams, k: usize) {
    assert!(
        params.k_prime >= k,
        "K' must extend K: K'={} < K={k}",
        params.k_prime
    );
    assert_eq!(params.k, k, "params must echo requested K");
    assert_eq!(
        params.l,
        params.k_prime + params.s + params.h,
        "L = K' + S + H invariant violated for K={k}"
    );
    assert_eq!(
        params.p,
        params.l - params.w,
        "P = L - W invariant violated for K={k}"
    );
    assert_eq!(
        params.b,
        params.w - params.s,
        "B = W - S invariant violated for K={k}"
    );
    assert!(
        params.w > 1,
        "tuple generation requires W > 1, got W={} for K={k}",
        params.w
    );
    assert!(
        params.p > 0,
        "tuple generation requires P > 0, got P={} for K={k}",
        params.p
    );
    assert!(params.s >= 1, "S must be >= 1 for K={k}");
    assert!(params.h >= 1, "H must be >= 1 for K={k}");
    assert!(
        params.w <= params.l,
        "W={} must not exceed L={} for K={k}",
        params.w,
        params.l
    );
    assert_eq!(
        params.symbol_size, SYMBOL_SIZE,
        "params must echo symbol size"
    );
    assert!(
        next_prime_ge(params.p).is_some(),
        "PI modulus next_prime_ge(P={}) must exist for K={k}",
        params.p
    );
}

/// Emit a `raptorq-unit-log-v1` structured log line and return it.
fn emit_log_line(
    scenario_id: &str,
    seed: u64,
    parameter_set: &str,
    outcome: &str,
    artifact_path: &str,
) -> String {
    let entry = serde_json::json!({
        "schema_version": "raptorq-unit-log-v1",
        "scenario_id": scenario_id,
        "seed": seed,
        "parameter_set": parameter_set,
        "replay_ref": REPLAY_REF,
        "repro_command": REPRO_COMMAND,
        "outcome": outcome,
        "artifact_path": artifact_path,
    });
    let line = serde_json::to_string(&entry).expect("serialize unit log entry");
    println!("{line}");
    line
}

/// Directory + file path for the JSONL forensic artifact (AC5/AC6).
fn artifact_path() -> String {
    let dir = format!(
        "{}/target/raptorq_rfc6330_encoder_params_e2e",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::create_dir_all(&dir).expect("create artifact dir");
    format!("{dir}/encoder_params_equation.jsonl")
}

/// AC1/AC2 — RFC 6330 systematic-index parameter table is internally consistent,
/// deterministic, and monotone in K' across a dense K sweep.
#[test]
fn rfc6330_systematic_parameter_table_is_consistent_and_monotone() {
    let mut prev_k_prime = 0usize;
    for k in 1..=400usize {
        let params = SystematicParams::try_for_source_block(k, SYMBOL_SIZE)
            .unwrap_or_else(|err| panic!("parameter lookup must succeed for K={k}: {err:?}"));
        assert_param_invariants(&params, k);

        // Determinism: a second lookup yields identical parameters.
        let again = SystematicParams::try_for_source_block(k, SYMBOL_SIZE)
            .expect("repeat parameter lookup must succeed");
        assert_eq!(
            (
                params.k_prime,
                params.j,
                params.s,
                params.h,
                params.l,
                params.w,
                params.p,
                params.b
            ),
            (
                again.k_prime,
                again.j,
                again.s,
                again.h,
                again.l,
                again.w,
                again.p,
                again.b
            ),
            "parameter lookup must be deterministic for K={k}"
        );

        // K' is non-decreasing in K (the table is a step function).
        assert!(
            params.k_prime >= prev_k_prime,
            "K' must be monotone non-decreasing: K'({k})={} < previous {prev_k_prime}",
            params.k_prime
        );
        prev_k_prime = params.k_prime;
    }
}

/// AC4 — deterministic E2E: parameter lookup → encoder construction → repair
/// equation construction → symbol synthesis, with the equation-construction
/// proof and structured logging (AC5/AC6) for every scenario.
#[test]
fn rfc6330_encoder_repair_equation_matches_synthesized_symbols_e2e() {
    let artifact = artifact_path();
    let mut log_lines: Vec<String> = Vec::new();

    for &k in SCENARIO_K {
        let scenario_id = format!("RQ-B-ENCPARAM-K{k:05}");
        let seed = seed_for(k);

        let params = SystematicParams::try_for_source_block(k, SYMBOL_SIZE)
            .unwrap_or_else(|err| panic!("parameter lookup must succeed for K={k}: {err:?}"));
        assert_param_invariants(&params, k);
        let l = params.l;

        let source = build_source(k, SYMBOL_SIZE, seed);
        let mut enc = SystematicEncoder::new(&source, SYMBOL_SIZE, seed)
            .unwrap_or_else(|| panic!("encoder construction must succeed for K={k}"));

        // Encoder params must match the standalone lookup.
        assert_eq!(enc.params().k_prime, params.k_prime, "encoder K' mismatch");
        assert_eq!(enc.params().l, l, "encoder L mismatch");

        // Systematic identity: source symbols pass through unchanged, ESI 0..K.
        let systematic = enc.emit_systematic();
        assert_eq!(
            systematic.len(),
            k,
            "systematic emission must yield K symbols"
        );
        for (i, sym) in systematic.iter().enumerate() {
            assert_eq!(sym.esi, i as u32, "systematic ESI must equal index");
            assert!(sym.is_source, "systematic symbol must be flagged is_source");
            assert_eq!(sym.degree, 1, "systematic symbol degree must be 1");
            assert_eq!(sym.data, source[i], "systematic symbol must equal source");
        }

        // Equation-construction proof over a contiguous repair block (K..K+8),
        // cross-checking the emitted symbol, repair_symbol(), and the published
        // rfc_repair_equation() column set.
        let repair_block = 8usize;
        let repair = enc.emit_repair(repair_block);
        assert_eq!(repair.len(), repair_block, "repair emission count mismatch");
        for (idx, sym) in repair.iter().enumerate() {
            let esi = k as u32 + idx as u32;
            assert_eq!(sym.esi, esi, "repair ESI must be K+idx, ascending");
            assert!(
                !sym.is_source,
                "repair symbol must not be flagged is_source"
            );

            let (columns, coefficients) = params
                .rfc_repair_equation(esi)
                .unwrap_or_else(|err| panic!("repair equation for ESI {esi} (K={k}): {err:?}"));
            assert_eq!(
                columns.len(),
                coefficients.len(),
                "equation columns/coefficients length mismatch (ESI {esi}, K={k})"
            );
            assert!(
                !columns.is_empty(),
                "repair equation must have degree >= 1 (ESI {esi}, K={k})"
            );
            assert_eq!(
                sym.degree,
                columns.len(),
                "emitted degree must equal equation column count (ESI {esi}, K={k})"
            );

            let mut expected = vec![0u8; SYMBOL_SIZE];
            for &col in &columns {
                assert!(
                    col < l,
                    "equation column {col} out of bounds L={l} (ESI {esi}, K={k})"
                );
                xor_into(&mut expected, enc.intermediate_symbol(col));
            }

            assert_eq!(
                sym.data, expected,
                "emitted repair symbol must equal XOR of equation columns (ESI {esi}, K={k})"
            );
            // The standalone repair_symbol() API must agree with emit_repair().
            assert_eq!(
                enc.repair_symbol(esi),
                sym.data,
                "repair_symbol() must agree with emit_repair() (ESI {esi}, K={k})"
            );
        }

        // Sparser high-ESI probes exercise additional tuples / degree regimes.
        for &esi in &[k as u32 + 50, k as u32 + 200, k as u32 + 999] {
            let (columns, _) = params
                .rfc_repair_equation(esi)
                .unwrap_or_else(|err| panic!("repair equation for ESI {esi} (K={k}): {err:?}"));
            assert!(
                !columns.is_empty(),
                "high-ESI repair equation must be non-empty (ESI {esi}, K={k})"
            );
            let mut expected = vec![0u8; SYMBOL_SIZE];
            for &col in &columns {
                assert!(col < l, "high-ESI column {col} out of bounds L={l}");
                xor_into(&mut expected, enc.intermediate_symbol(col));
            }
            assert_eq!(
                enc.repair_symbol(esi),
                expected,
                "high-ESI repair symbol must equal XOR of equation columns (ESI {esi}, K={k})"
            );
        }

        // Determinism: a fresh encoder over the same fixture reproduces every
        // symbol byte-for-byte.
        let mut enc2 = SystematicEncoder::new(&source, SYMBOL_SIZE, seed)
            .unwrap_or_else(|| panic!("re-encoder construction must succeed for K={k}"));
        let systematic2 = enc2.emit_systematic();
        assert_eq!(
            systematic2
                .iter()
                .map(|s| s.data.clone())
                .collect::<Vec<_>>(),
            source,
            "systematic emission must be deterministic for K={k}"
        );
        for &esi in &[k as u32, k as u32 + 3, k as u32 + 200] {
            assert_eq!(
                enc.repair_symbol(esi),
                enc2.repair_symbol(esi),
                "repair synthesis must be deterministic (ESI {esi}, K={k})"
            );
        }

        let parameter_set = format!(
            "k={k},k_prime={},symbol_size={SYMBOL_SIZE},s={},h={},w={},p={},l={}",
            params.k_prime, params.s, params.h, params.w, params.p, params.l
        );
        log_lines.push(emit_log_line(
            &scenario_id,
            seed,
            &parameter_set,
            "ok",
            &artifact,
        ));
    }

    // AC5/AC6 — persist the structured logs as a JSONL forensic artifact.
    std::fs::write(&artifact, format!("{}\n", log_lines.join("\n"))).expect("write JSONL artifact");

    // When the test-internals schema module is linked, prove every emitted line
    // satisfies the canonical raptorq-unit-log-v1 contract.
    #[cfg(feature = "test-internals")]
    {
        use asupersync::raptorq::test_log_schema::validate_unit_log_json;
        for line in &log_lines {
            let violations = validate_unit_log_json(line);
            assert!(
                violations.is_empty(),
                "structured log must satisfy raptorq-unit-log-v1: {violations:?}\nline={line}"
            );
        }
    }

    assert_eq!(
        log_lines.len(),
        SCENARIO_K.len(),
        "every scenario must emit exactly one structured log line"
    );
}
