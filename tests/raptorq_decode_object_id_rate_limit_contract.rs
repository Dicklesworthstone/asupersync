//! `InactivationDecoder` compute-admission and ObjectId rate-limit contract.
//!
//! Every decode entry point applies the same object-independent structural and
//! per-call compute admission policy. The `Option<&ObjectId>` accepted by
//! `decode_with_object_id` only controls cross-call accounting keyed by
//! `(ESI, ObjectId)`; `decode()` passes `None`, while `decode_with_proof()`
//! supplies its proof ObjectId.
//!
//!   * `decode(s)` is byte-for-byte `decode_with_object_id(s, None)`.
//!   * Valid traffic recovers identically with or without cross-call accounting.
//!   * Every mode rejects a near-`u32::MAX` ESI before tuple expansion.
//!   * The per-call compute ceiling scales with the admitted block dimensions,
//!     so the RFC 6330 maximum K does not spuriously exhaust a fixed budget.
//!   * Per-`(esi, ObjectId)` state accumulates across calls: repeated decoding
//!     under one ObjectId is eventually rate-limited (the >100-access ceiling),
//!     while a fresh ObjectId per call never is.
//!
//! Admission constants pinned implicitly: `MAX_ALLOWED_ESI = 1_000_000`,
//! `MAX_COLUMNS_PER_ESI = 1000`, RFC tuple width `<= 32`, access ceiling
//! `> 100` per window.
//!
//! # Repro
//!
//! ```text
//! rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_asupersync_test \
//!   cargo test --test raptorq_decode_object_id_rate_limit_contract -- --nocapture
//! ```

#![allow(missing_docs)]

use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::proof::ProofOutcome;
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::types::ObjectId;
use asupersync::util::DetRng;

const K: usize = 16;
const SYMBOL_SIZE: usize = 40;
const SEED: u64 = 0x00FE_DCBA_9876_5432;
const RFC6330_MAX_K: usize = 56_403;

/// `MAX_COLUMNS_PER_ESI` reported back by `EsiRateLimitExceeded` (decoder.rs).
const EXPECTED_MAX_COLUMNS: usize = 1000;

/// Deterministic source block of `K` symbols of `SYMBOL_SIZE` bytes.
fn make_source() -> Vec<Vec<u8>> {
    let mut rng = DetRng::new(SEED);
    (0..K)
        .map(|_| {
            (0..SYMBOL_SIZE)
                .map(|_| (rng.next_u64() & 0xFF) as u8)
                .collect()
        })
        .collect()
}

/// A fresh encoder/decoder pair plus the original source for this fixture.
fn build() -> (SystematicEncoder, InactivationDecoder, Vec<Vec<u8>>) {
    let source = make_source();
    let encoder = SystematicEncoder::new(&source, SYMBOL_SIZE, SEED).expect("encoder");
    let decoder = InactivationDecoder::new(K, SYMBOL_SIZE, SEED);
    (encoder, decoder, source)
}

/// An over-determined received set: every constraint row, each source symbol
/// (optionally erasing one), and `repairs` repair symbols starting at ESI `K`.
fn clean_received(
    encoder: &SystematicEncoder,
    decoder: &InactivationDecoder,
    source: &[Vec<u8>],
    repairs: u32,
    drop_source: Option<usize>,
) -> Vec<ReceivedSymbol> {
    let k = source.len();
    let mut received = decoder.constraint_symbols();
    for (esi, data) in source.iter().enumerate() {
        if Some(esi) == drop_source {
            continue;
        }
        received.push(ReceivedSymbol::source(esi as u32, data.clone()));
    }
    for offset in 0..repairs {
        let esi = k as u32 + offset;
        let (columns, coefficients) = decoder
            .repair_equation(esi)
            .unwrap_or_else(|err| panic!("repair_equation esi={esi}: {err:?}"));
        let data = encoder.repair_symbol(esi);
        received.push(ReceivedSymbol::repair(esi, columns, coefficients, data));
    }
    received
}

/// `decode()` MUST be exactly `decode_with_object_id(_, None)` -- same recovered
/// source and intermediate symbols, byte for byte.
#[test]
fn decode_delegates_to_object_id_none() {
    let (encoder, decoder, source) = build();
    let received = clean_received(&encoder, &decoder, &source, 5, None);

    let via_decode = decoder.decode(&received).expect("decode() ok");
    let via_none = decoder
        .decode_with_object_id(&received, None)
        .expect("decode_with_object_id(None) ok");

    assert_eq!(
        via_decode.source, via_none.source,
        "decode() must equal decode_with_object_id(None) on recovered source"
    );
    assert_eq!(
        via_decode.intermediate, via_none.intermediate,
        "decode() must equal decode_with_object_id(None) on intermediate symbols"
    );
    assert_eq!(
        via_decode.source, source,
        "over-determined decode recovers the original source verbatim"
    );
}

/// For well-behaved traffic the ObjectId ledger is transparent: `Some(oid)`
/// recovers exactly what the object-independent admission path does.
#[test]
fn object_id_guard_transparent_for_valid_traffic() {
    let (encoder, decoder, source) = build();
    let received = clean_received(&encoder, &decoder, &source, 5, None);
    let oid = ObjectId::new(0xA1A1_A1A1_A1A1_A1A1, 0x0000_0000_0000_0001);

    let guarded = decoder
        .decode_with_object_id(&received, Some(&oid))
        .expect("guarded decode ok for valid traffic");
    let plain = decoder.decode(&received).expect("plain decode ok");

    assert_eq!(
        guarded.source, plain.source,
        "rate-limit guard must not alter recovered source for valid traffic"
    );
    assert_eq!(
        guarded.intermediate, plain.intermediate,
        "rate-limit guard must not alter intermediate symbols for valid traffic"
    );
    assert_eq!(
        guarded.source, source,
        "guarded decode recovers original source"
    );
}

/// Recovery through an actual erasure (source[0] withheld) is identical across
/// all three decode modes -- the guard does not perturb the linear solve.
#[test]
fn erasure_recovery_identical_across_object_id_modes() {
    let (encoder, decoder, source) = build();
    // Withhold source[0]; the repairs over-determine the system so it is recovered.
    let received = clean_received(&encoder, &decoder, &source, 8, Some(0));
    let oid = ObjectId::new(7, 7);

    let r_decode = decoder
        .decode(&received)
        .expect("decode() recovers erased source");
    let r_none = decoder
        .decode_with_object_id(&received, None)
        .expect("None recovers erased source");
    let r_some = decoder
        .decode_with_object_id(&received, Some(&oid))
        .expect("Some recovers erased source");

    assert_eq!(
        r_decode.source[0], source[0],
        "erased source[0] is reconstructed from repair symbols"
    );
    assert_eq!(
        r_decode.source, source,
        "full source recovered after erasure"
    );
    assert_eq!(
        r_decode.source, r_none.source,
        "decode() vs None recovery match"
    );
    assert_eq!(
        r_decode.source, r_some.source,
        "decode() vs Some recovery match"
    );
    assert_eq!(
        r_decode.intermediate, r_none.intermediate,
        "decode() vs None intermediate match"
    );
    assert_eq!(
        r_decode.intermediate, r_some.intermediate,
        "decode() vs Some intermediate match"
    );
}

/// A near-`u32::MAX` ESI is rejected before tuple expansion in every decode
/// mode. ObjectId controls cross-call accounting, not structural admission.
#[test]
fn near_max_esi_is_rejected_identically_across_decode_modes() {
    let (encoder, decoder, source) = build();
    let mut received = clean_received(&encoder, &decoder, &source, 5, None);
    // A "source" symbol claiming ESI = u32::MAX, well past MAX_ALLOWED_ESI.
    received.push(ReceivedSymbol::source(u32::MAX, vec![0u8; SYMBOL_SIZE]));

    let oid = ObjectId::new(0x0000_0000_0000_DEAD, 0x0000_0000_0000_BEEF);

    let assert_rate_limited = |result: Result<_, DecodeError>, mode: &str| match result {
        Err(DecodeError::EsiRateLimitExceeded {
            esi,
            column_count,
            max_columns,
        }) => {
            assert_eq!(esi, u32::MAX, "{mode} reports the offending ESI verbatim");
            assert_eq!(
                column_count, 0,
                "{mode} rejects the ESI before any columns are generated"
            );
            assert_eq!(
                max_columns, EXPECTED_MAX_COLUMNS,
                "{mode} surfaces MAX_COLUMNS_PER_ESI"
            );
        }
        other => panic!("expected EsiRateLimitExceeded from {mode}, got {other:?}"),
    };

    assert_rate_limited(decoder.decode(&received), "decode");
    assert_rate_limited(
        decoder.decode_with_object_id(&received, None),
        "decode_with_object_id(None)",
    );
    assert_rate_limited(
        decoder.decode_with_object_id(&received, Some(&oid)),
        "decode_with_object_id(Some)",
    );

    match decoder.decode_with_proof(&received, oid, 0) {
        Err((DecodeError::EsiRateLimitExceeded { esi, .. }, proof)) => {
            assert_eq!(esi, u32::MAX);
            assert!(
                matches!(proof.outcome, ProofOutcome::Failure { .. }),
                "proof mode records the shared admission failure"
            );
        }
        other => panic!("expected EsiRateLimitExceeded from decode_with_proof, got {other:?}"),
    }
}

/// The RFC 6330 maximum source-block shape must not trip a fixed compute
/// ceiling in proof mode. Supplying all K systematic rows but omitting the
/// required constraint rows intentionally stops after admission with
/// `InsufficientSymbols`, avoiding an enormous solve while exercising all K
/// tuple-cost charges. Before br-asupersync-v96kw8, the plain path reached
/// `InsufficientSymbols` but proof mode failed earlier with
/// `ComputeBudgetExhausted`.
#[test]
fn maximum_k_compute_admission_is_block_scaled_and_mode_invariant() {
    const MAX_K_SYMBOL_SIZE: usize = 1;
    const MAX_K_SEED: u64 = 0xA55A_5AA5_C33C_3CC3;

    let decoder = InactivationDecoder::new(RFC6330_MAX_K, MAX_K_SYMBOL_SIZE, MAX_K_SEED);
    let received = (0..RFC6330_MAX_K)
        .map(|esi| ReceivedSymbol::source(esi as u32, vec![0u8; MAX_K_SYMBOL_SIZE]))
        .collect::<Vec<_>>();
    let expected_required = decoder.params().l;
    assert!(
        expected_required > received.len(),
        "fixture must omit constraint rows and stop after input admission"
    );

    let assert_insufficient = |result: Result<_, DecodeError>, mode: &str| match result {
        Err(DecodeError::InsufficientSymbols { received, required }) => {
            assert_eq!(received, RFC6330_MAX_K, "{mode} reports all supplied rows");
            assert_eq!(
                required, expected_required,
                "{mode} reports the block-shaped minimum"
            );
        }
        other => panic!("expected InsufficientSymbols from {mode}, got {other:?}"),
    };

    assert_insufficient(decoder.decode(&received), "decode");
    assert_insufficient(
        decoder.decode_with_object_id(&received, None),
        "decode_with_object_id(None)",
    );

    let object_id = ObjectId::new(0x5654_0300_0000_0000, 0x0000_0000_0000_0001);
    match decoder.decode_with_proof(&received, object_id, 0) {
        Err((error, proof)) => {
            match error {
                DecodeError::InsufficientSymbols { received, required } => {
                    assert_eq!(received, RFC6330_MAX_K);
                    assert_eq!(required, expected_required);
                }
                other => panic!("expected InsufficientSymbols from proof decode, got {other:?}"),
            }
            assert!(
                matches!(proof.outcome, ProofOutcome::Failure { .. }),
                "proof records the shared insufficient-symbol failure"
            );
        }
        Ok(_) => panic!("fixture intentionally omits required constraint rows"),
    }
}

/// Per-`(esi, ObjectId)` accounting accumulates across calls: repeatedly decoding
/// the *same* block under one ObjectId is eventually rate-limited. The >100
/// per-window access ceiling guarantees a trip by call 101 at the latest (an
/// earlier per-ESI compute-budget trip is also acceptable -- both are DoS guards).
#[test]
fn repeated_decode_accumulates_per_object_id_until_rate_limited() {
    let (encoder, decoder, source) = build();
    let received = clean_received(&encoder, &decoder, &source, 5, None);
    let oid = ObjectId::new(0x5151_5151_5151_5151, 0x6262_6262_6262_6262);

    decoder
        .decode_with_object_id(&received, Some(&oid))
        .expect("first guarded decode succeeds");

    let mut first_trip = None;
    for call in 2..=140u32 {
        match decoder.decode_with_object_id(&received, Some(&oid)) {
            Ok(_) => {}
            Err(
                DecodeError::EsiRateLimitExceeded { .. }
                | DecodeError::ComputeBudgetExhausted { .. },
            ) => {
                first_trip = Some(call);
                break;
            }
            Err(other) => panic!("unexpected non-DoS error during repeated decode: {other:?}"),
        }
    }

    let trip =
        first_trip.expect("repeated same-ObjectId decode never rate-limited within 140 calls");
    assert!(
        (2..=101).contains(&trip),
        "trip at call {trip} is outside the per-window access ceiling bound [2, 101]"
    );
}

/// The accumulated rate-limit state is keyed by ObjectId: a distinct ObjectId per
/// call never accumulates, so identical traffic decodes indefinitely -- well past
/// the same-ObjectId ceiling.
#[test]
fn rate_limit_state_is_keyed_by_object_id() {
    let (encoder, decoder, source) = build();
    let received = clean_received(&encoder, &decoder, &source, 5, None);

    for i in 0..150u64 {
        let oid = ObjectId::new(0, i);
        decoder
            .decode_with_object_id(&received, Some(&oid))
            .unwrap_or_else(|e| {
                panic!("fresh-ObjectId call {i} was unexpectedly rate-limited: {e:?}")
            });
    }
}
