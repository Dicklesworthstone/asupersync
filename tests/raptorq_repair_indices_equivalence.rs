//! RFC 6330 encoder/decoder parity-path equivalence for repair-symbol
//! intermediate index expansion.
//!
//! bd-3uox5 (RAPTORQ-RFC6330 conformance, Track-D property verification).
//!
//! `repair_indices_for_esi` is the convenience wrapper the systematic
//! encoder/decoder parity code actually calls (`systematic.rs` builds
//! repair-symbol equation columns through it). It must produce exactly
//! the same intermediate-symbol index set as the canonical two-step
//! path `tuple_with_prime_p1(J,W,P,X).map(|t| tuple_indices(t, W, P, P1))`
//! with `P1 = next_prime_ge(P)`. If the wrapper ever derived `P1`
//! differently or expanded the tuple with different bounds, encoder and
//! decoder would compute mismatched equations and decode would silently
//! corrupt. The canonical side intentionally uses the fallible tuple helper
//! so the legacy zero-sentinel tuple path stays quarantined from this
//! production-adjacent parity test.
//!
//! Also pins the fail-closed contract: invalid FEC-OTI parameters yield
//! an empty schedule (the "invalid encoding" signal) rather than a
//! panic or a bogus index list.
//!
//! Repro: `cargo test --test raptorq_repair_indices_equivalence`

use asupersync::raptorq::rfc6330::{
    next_prime_ge, repair_indices_for_esi, tuple_indices, tuple_with_prime_p1,
};
use asupersync::raptorq::systematic::SystematicParams;

const K_SWEEP: &[usize] = &[
    1, 2, 4, 8, 10, 26, 42, 50, 100, 101, 200, 500, 1000, 2048, 10000,
];

#[test]
fn repair_indices_match_canonical_tuple_expansion() {
    let mut compared: u64 = 0;

    for &k in K_SWEEP {
        let params = SystematicParams::for_source_block(k, 64);
        let (j, w, p) = (params.j, params.w, params.p);
        let p1 = next_prime_ge(p);
        assert!(
            p1.is_some(),
            "K={k}: next_prime_ge(P={p}) must fit in usize"
        );
        let Some(p1) = p1 else {
            continue;
        };

        let esi_max = (params.k_prime as u32).saturating_add(128);
        for esi in 0..esi_max {
            let wrapper = repair_indices_for_esi(j, w, p, esi);
            let canonical = tuple_with_prime_p1(j, w, p, esi)
                .map(|lt_tuple| tuple_indices(lt_tuple, w, p, p1))
                .unwrap_or_default();
            assert_eq!(
                wrapper, canonical,
                "K={k} ESI={esi} W={w} P={p} P1={p1}: \
                 repair_indices_for_esi diverged from canonical \
                 tuple_with_prime_p1 + tuple_indices path — encoder/decoder parity \
                 would break; \
                 repro='cargo test --test raptorq_repair_indices_equivalence'"
            );
            // Real RFC params never produce an empty (invalid) schedule.
            assert!(
                !wrapper.is_empty(),
                "K={k} ESI={esi}: valid params produced empty repair schedule"
            );
            compared += 1;
        }
    }

    assert!(
        compared > 10_000,
        "equivalence sweep too small: only {compared} points compared"
    );
}

#[test]
fn repair_indices_fail_closed_on_invalid_params() {
    // W <= 2 caps the LT degree to zero before tuple expansion; the
    // RFC validity gate rejects it. (try_tuple: `lt_width > 2`.)
    for w in [0usize, 1, 2] {
        assert!(
            repair_indices_for_esi(100, w, 15, 0).is_empty(),
            "W={w} <= 2 must fail closed to an empty schedule"
        );
    }

    // P == 0: next_prime_ge(0)=2 but the `pi_count > 0` gate rejects it.
    assert!(
        repair_indices_for_esi(100, 50, 0, 0).is_empty(),
        "P=0 must fail closed to an empty schedule"
    );

    // A well-formed parameter set still succeeds (guards against a
    // fail-closed gate that is simply always-empty).
    let ok = repair_indices_for_esi(562, 113, 15, 0);
    assert!(
        !ok.is_empty(),
        "valid params (J=562,W=113,P=15) must yield a non-empty schedule"
    );
}
