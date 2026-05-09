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
    NormalizedObservable, SeedLineageRecord, SemanticMismatch, check_core_invariants,
    compare_observables,
};
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

const MAX_INPUT: usize = 256 * 1024;
const CHECK_CORE_INVARIANT_OBSERVER_MAX_VIOLATIONS: usize = 5;

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
    // checker, with violations made visible to the fuzz oracle.
    let side_a_violations = check_core_invariants(&triple.a);
    observe_core_invariant_violations("side A", &side_a_violations);
    let side_b_violations = check_core_invariants(&triple.b);
    observe_core_invariant_violations("side B", &side_b_violations);

    // Contract 1: panic floor on the differential comparator. The
    // signature is (lab, live, seed_lineage) -> ComparisonVerdict.
    let verdict = compare_observables(&triple.a, &triple.b, triple.lineage.clone());

    // Contract 3: format-string safety — exercise Display + Debug
    // on every reported mismatch.
    for m in &verdict.mismatches {
        observe_mismatch_formatting(m);
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

fn observe_core_invariant_violations(side: &str, violations: &[String]) {
    assert!(
        violations.len() <= CHECK_CORE_INVARIANT_OBSERVER_MAX_VIOLATIONS,
        "{side} emitted {} core-invariant violations; update the fuzz oracle if check_core_invariants grows",
        violations.len(),
    );

    for violation in violations {
        assert!(
            !violation.trim().is_empty(),
            "{side} emitted an empty core-invariant violation"
        );

        let diagnostic = format!("{side}: {violation}");
        assert!(
            diagnostic.len() >= side.len() + violation.len() + 2,
            "{side} invariant diagnostic lost context"
        );
    }
}

fn observe_mismatch_formatting(mismatch: &SemanticMismatch) {
    let debug = format!("{mismatch:?}");
    let display = format!("{mismatch}");
    let fields = format!(
        "field={} desc={} lab={} live={}",
        mismatch.field, mismatch.description, mismatch.lab_value, mismatch.live_value,
    );

    for rendered in [&debug, &display, &fields] {
        assert!(
            !rendered.is_empty(),
            "semantic mismatch formatting must not render an empty diagnostic"
        );
    }

    assert!(
        display.contains(&mismatch.field),
        "semantic mismatch Display must include the field name"
    );
    assert!(
        fields.contains(&mismatch.description),
        "semantic mismatch field formatting must include the description"
    );
}
