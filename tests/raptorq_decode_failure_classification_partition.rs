//! RaptorQ decode-failure classification — recoverable/unrecoverable partition.
//!
//! bd-3uox5 (RAPTORQ-RFC6330). The decoder separates retryable failures from
//! malformed/corruption failures at the API boundary through three public
//! `const fn` predicates on `raptorq::decoder::DecodeError`:
//!   - `failure_class()` -> `DecodeFailureClass::{Recoverable, Unrecoverable}`
//!   - `is_recoverable()` / `is_unrecoverable()`
//!
//! Operators key retry policy off this partition: a `Recoverable` failure means
//! "ask for more symbols / redundancy and try again", while an `Unrecoverable`
//! failure means "the input is malformed or an invariant was violated — fail
//! closed, do not retry". Crucially, the two amplification-DoS guards added by
//! br-asupersync-ju2k01 (`ComputeBudgetExhausted`, `EsiRateLimitExceeded`) must
//! classify `Unrecoverable` so a hostile peer cannot drive an unbounded retry
//! loop by repeatedly tripping the budget/rate limiter.
//!
//! `DecodeFailureClass` had ZERO integration references and `is_unrecoverable`
//! had none either; `is_recoverable` was only consumed incidentally inside
//! retry helpers (`ci_regression_gates`, `atp::raptorq_repair`) — nothing
//! pinned the partition itself or the boolean algebra relating the three
//! predicates. A refactor of `failure_class` could silently move a variant
//! across the boundary (turning a fail-closed corruption error into a
//! retryable one, or vice versa) and every existing test would still pass.
//!
//! This harness pins the partition oracle-free, with a compile-time
//! completeness guard: `expected_class` is an EXHAUSTIVE match (no wildcard)
//! mirroring the documented partition, so adding a new `DecodeError` variant
//! forces a decision here rather than silently inheriting a class.
//!
//! Modeled invariants:
//!   - `err.failure_class() == expected_class(&err)` for one of every variant.
//!   - `is_recoverable()` and `is_unrecoverable()` are exact complements.
//!   - `is_recoverable() <=> class == Recoverable`,
//!     `is_unrecoverable() <=> class == Unrecoverable`.
//!   - the partition is non-trivial: exactly `{InsufficientSymbols,
//!     SingularMatrix}` are recoverable; all eight others are unrecoverable.
//!   - the predicates are deterministic and usable in `const` context.
//!
//! Repro: `cargo test --test raptorq_decode_failure_classification_partition`

use std::collections::HashSet;
use std::mem::discriminant;

use asupersync::raptorq::decoder::{DecodeError, DecodeFailureClass};

use DecodeFailureClass::{Recoverable, Unrecoverable};

/// One representative of every `DecodeError` variant, with distinct field
/// payloads so a classifier that (incorrectly) keyed on field values rather
/// than the variant would be observable.
fn all_decode_errors() -> Vec<DecodeError> {
    vec![
        DecodeError::InsufficientSymbols {
            received: 3,
            required: 8,
        },
        DecodeError::SingularMatrix { row: 5 },
        DecodeError::SymbolSizeMismatch {
            expected: 256,
            actual: 255,
        },
        DecodeError::SymbolEquationArityMismatch {
            esi: 11,
            columns: 4,
            coefficients: 3,
        },
        DecodeError::ColumnIndexOutOfRange {
            esi: 12,
            column: 99,
            max_valid: 64,
        },
        DecodeError::SourceEsiOutOfRange {
            esi: 40,
            max_valid: 26,
        },
        DecodeError::InvalidSourceSymbolEquation {
            esi: 7,
            expected_column: 7,
        },
        DecodeError::CorruptDecodedOutput {
            esi: 9,
            byte_index: 2,
            expected: 0xAB,
            actual: 0xCD,
        },
        DecodeError::ComputeBudgetExhausted {
            used: 1_000,
            requested: 4_096,
            max: 2_048,
        },
        DecodeError::EsiRateLimitExceeded {
            esi: u32::MAX,
            column_count: 1_000_000,
            max_columns: 4_096,
        },
    ]
}

/// Golden recompute of the documented partition. EXHAUSTIVE match (no `_`
/// arm) so a newly added `DecodeError` variant fails to compile here until it
/// is deliberately placed on one side of the recoverable boundary.
const fn expected_class(err: &DecodeError) -> DecodeFailureClass {
    match err {
        // Retry may succeed once more redundancy arrives.
        DecodeError::InsufficientSymbols { .. } | DecodeError::SingularMatrix { .. } => Recoverable,
        // Malformed input / violated invariant / resource guard: fail closed.
        DecodeError::SymbolSizeMismatch { .. }
        | DecodeError::SymbolEquationArityMismatch { .. }
        | DecodeError::ColumnIndexOutOfRange { .. }
        | DecodeError::SourceEsiOutOfRange { .. }
        | DecodeError::InvalidSourceSymbolEquation { .. }
        | DecodeError::CorruptDecodedOutput { .. }
        | DecodeError::ComputeBudgetExhausted { .. }
        | DecodeError::EsiRateLimitExceeded { .. } => Unrecoverable,
    }
}

#[test]
fn sample_covers_every_distinct_variant_exactly_once() {
    let errors = all_decode_errors();
    assert_eq!(
        errors.len(),
        10,
        "DecodeError currently has 10 variants; update the sample + expected_class if this changed"
    );
    let distinct: HashSet<_> = errors.iter().map(discriminant).collect();
    assert_eq!(
        distinct.len(),
        errors.len(),
        "all_decode_errors must hold one of EACH variant — found a duplicate discriminant"
    );
}

#[test]
fn failure_class_matches_documented_partition_for_every_variant() {
    for err in all_decode_errors() {
        assert_eq!(
            err.failure_class(),
            expected_class(&err),
            "failure_class diverged from the documented partition for {err:?}"
        );
    }
}

#[test]
fn predicate_methods_agree_with_failure_class() {
    for err in all_decode_errors() {
        let class = err.failure_class();
        assert_eq!(
            err.is_recoverable(),
            class == Recoverable,
            "is_recoverable must agree with failure_class for {err:?}"
        );
        assert_eq!(
            err.is_unrecoverable(),
            class == Unrecoverable,
            "is_unrecoverable must agree with failure_class for {err:?}"
        );
    }
}

#[test]
fn is_recoverable_is_exact_complement_of_is_unrecoverable() {
    for err in all_decode_errors() {
        assert_ne!(
            err.is_recoverable(),
            err.is_unrecoverable(),
            "exactly one of is_recoverable/is_unrecoverable must hold for {err:?}"
        );
    }
}

#[test]
fn recoverable_set_is_exactly_insufficient_and_singular() {
    let recoverable: Vec<DecodeError> = all_decode_errors()
        .into_iter()
        .filter(DecodeError::is_recoverable)
        .collect();

    assert_eq!(
        recoverable.len(),
        2,
        "only InsufficientSymbols and SingularMatrix are retryable"
    );
    assert!(
        recoverable
            .iter()
            .any(|e| matches!(e, DecodeError::InsufficientSymbols { .. })),
        "InsufficientSymbols must be recoverable"
    );
    assert!(
        recoverable
            .iter()
            .any(|e| matches!(e, DecodeError::SingularMatrix { .. })),
        "SingularMatrix must be recoverable"
    );
}

#[test]
fn partition_is_non_trivial_with_eight_unrecoverable() {
    let unrecoverable = all_decode_errors()
        .into_iter()
        .filter(DecodeError::is_unrecoverable)
        .count();
    assert_eq!(
        unrecoverable, 8,
        "eight DecodeError variants are unrecoverable; the partition must inhabit both classes"
    );
}

/// Security regression guard: the amplification-DoS failures from
/// br-asupersync-ju2k01 must classify Unrecoverable so a hostile peer cannot
/// keep a decode loop retrying by repeatedly tripping the budget/rate limiter.
#[test]
fn dos_guard_failures_are_unrecoverable() {
    let budget = DecodeError::ComputeBudgetExhausted {
        used: 0,
        requested: u64::MAX,
        max: 1,
    };
    let rate = DecodeError::EsiRateLimitExceeded {
        esi: u32::MAX,
        column_count: usize::MAX,
        max_columns: 1,
    };

    for guard in [budget, rate] {
        assert_eq!(guard.failure_class(), Unrecoverable, "{guard:?}");
        assert!(guard.is_unrecoverable(), "{guard:?}");
        assert!(
            !guard.is_recoverable(),
            "a DoS guard must never be retryable: {guard:?}"
        );
    }
}

#[test]
fn corruption_guard_is_unrecoverable() {
    // CorruptDecodedOutput is the last-line integrity guard: a reconstructed
    // output that fails an input equation is unsafe to return AND unsafe to
    // retry blindly, so it must fail closed as Unrecoverable.
    let corrupt = DecodeError::CorruptDecodedOutput {
        esi: 0,
        byte_index: 0,
        expected: 1,
        actual: 2,
    };
    assert_eq!(corrupt.failure_class(), Unrecoverable);
    assert!(corrupt.is_unrecoverable());
}

#[test]
fn failure_class_is_deterministic() {
    for err in all_decode_errors() {
        let first = err.failure_class();
        for _ in 0..4 {
            assert_eq!(err.failure_class(), first, "classification must be pure");
            assert_eq!(err.is_recoverable(), first == Recoverable);
            assert_eq!(err.is_unrecoverable(), first == Unrecoverable);
        }
    }
}

#[test]
fn decode_failure_class_value_semantics() {
    // Copy + Eq with two genuinely distinct inhabitants.
    let a = Recoverable;
    let b = a; // Copy
    assert_eq!(a, b);
    assert_eq!(Recoverable, Recoverable);
    assert_eq!(Unrecoverable, Unrecoverable);
    assert_ne!(Recoverable, Unrecoverable);
}

// `failure_class` is a `const fn`; prove it is usable in const context (the
// classification is fixed at compile time, not merely evaluated at runtime).
const RECOVERABLE_WITNESS: DecodeError = DecodeError::SingularMatrix { row: 0 };
const RECOVERABLE_WITNESS_CLASS: DecodeFailureClass = RECOVERABLE_WITNESS.failure_class();
const _: () = assert!(matches!(RECOVERABLE_WITNESS_CLASS, Recoverable));
const _: () = assert!(RECOVERABLE_WITNESS.is_recoverable());
const _: () = assert!(!RECOVERABLE_WITNESS.is_unrecoverable());

const UNRECOVERABLE_WITNESS: DecodeError = DecodeError::ComputeBudgetExhausted {
    used: 0,
    requested: 1,
    max: 0,
};
const UNRECOVERABLE_WITNESS_CLASS: DecodeFailureClass = UNRECOVERABLE_WITNESS.failure_class();
const _: () = assert!(matches!(UNRECOVERABLE_WITNESS_CLASS, Unrecoverable));
const _: () = assert!(UNRECOVERABLE_WITNESS.is_unrecoverable());
const _: () = assert!(!UNRECOVERABLE_WITNESS.is_recoverable());

#[test]
fn const_witnesses_match_runtime_classification() {
    assert_eq!(RECOVERABLE_WITNESS_CLASS, Recoverable);
    assert_eq!(UNRECOVERABLE_WITNESS_CLASS, Unrecoverable);
}
