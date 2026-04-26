#![no_main]

//! br-asupersync-eetrey — fuzz target for `compare_observables` and
//! `check_core_invariants` in `src/lab/dual_run.rs`.
//!
//! ## Contract under test
//!
//! 1. **Panic floor.** `check_core_invariants(&NormalizedObservable)`
//!    and `compare_observables(&NormalizedObservable, &NormalizedObservable)`
//!    accept structures that the caller may have built from disk
//!    artefacts (live-run captures, lab-run captures, replay seeds)
//!    — none of them may panic on adversarial inputs. Specifically:
//!    NaN/Inf in resource_surface counters, swapped/reversed
//!    timestamps in cancellation/loser_drain records, dangling
//!    region IDs in close records, and obligation balances that
//!    would overflow when summed across the two observables.
//!
//! 2. **Reflexivity.** `compare_observables(o, o)` must report no
//!    semantic mismatches. This is the metamorphic invariant the
//!    differential-execution oracle is built on; if it fails, the
//!    comparator has a side that doesn't normalise idempotently.
//!
//! 3. **Format-string safety.** `SemanticMismatch::Display` (and the
//!    Display of any other reported reasons) must not panic when an
//!    adversarial scope/originator/reason string contains `{}`
//!    sequences that a misuse of `format_args!` could mistake for
//!    placeholders.
//!
//! ## Input shape
//!
//! Input is a JSON document of shape
//! `{ "a": NormalizedObservable, "b": NormalizedObservable }`. This
//! routes libFuzzer through every NormalizedObservable subfield via
//! its serde derive, including the entire NormalizedSemantics tree
//! (CancellationRecord, LoserDrainRecord, RegionCloseRecord,
//! ObligationBalanceRecord, ResourceSurfaceRecord, TerminalOutcome).
//!
//! Bounded resources: input clamped to 256 KiB; failed deserialise
//! drops the iteration immediately.

use asupersync::lab::dual_run::{
    NormalizedObservable, SeedLineageRecord, check_core_invariants, compare_observables,
};
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

const MAX_INPUT: usize = 256 * 1024;

#[derive(Deserialize)]
struct ObservableTriple {
    a: NormalizedObservable,
    b: NormalizedObservable,
    lineage: SeedLineageRecord,
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT {
        return;
    }

    let triple: ObservableTriple = match serde_json::from_slice(data) {
        Ok(p) => p,
        Err(_) => return,
    };

    // Contract 1: panic floor on the per-observable invariant
    // checker.
    let _ = check_core_invariants(&triple.a);
    let _ = check_core_invariants(&triple.b);

    // Contract 1: panic floor on the differential comparator. The
    // signature is (lab, live, seed_lineage) -> ComparisonVerdict.
    let verdict = compare_observables(&triple.a, &triple.b, triple.lineage.clone());

    // Contract 3: format-string safety — exercise Display + Debug
    // on every reported mismatch.
    for m in &verdict.mismatches {
        let _ = format!("{m:?}");
        let _ = format!("{m}");
        let _ = format!(
            "field={} desc={} lab={} live={}",
            m.field, m.description, m.lab_value, m.live_value,
        );
    }

    // Contract 2: reflexivity. compare_observables(o, o, _) must
    // report no semantic mismatches.
    let self_a = compare_observables(&triple.a, &triple.a, triple.lineage.clone());
    assert!(
        self_a.mismatches.is_empty(),
        "compare_observables must be reflexive on side A; got {} mismatch(es)",
        self_a.mismatches.len(),
    );
    let self_b = compare_observables(&triple.b, &triple.b, triple.lineage);
    assert!(
        self_b.mismatches.is_empty(),
        "compare_observables must be reflexive on side B; got {} mismatch(es)",
        self_b.mismatches.len(),
    );
});
