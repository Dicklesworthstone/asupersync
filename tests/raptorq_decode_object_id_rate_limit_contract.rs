//! `InactivationDecoder::decode_with_object_id` ObjectId rate-limit contract (bead bd-3uox5).
//!
//! `decode_with_object_id` is the only public decode entry point that exposes the
//! `Option<&ObjectId>` choice between *unguarded* decoding (`None`, the path
//! `decode()` delegates to) and *amplification-guarded* decoding (`Some`, the
//! br-asupersync-ju2k01 DoS defense). `decode()` always passes `None`;
//! `decode_with_proof()` always passes `Some` -- so neither pins the switch
//! itself, and a grep of `tests/` for `decode_with_object_id` returns nothing.
//! That leaves the security-critical rate-limiter contract unverified at the
//! integration boundary:
//!
//!   * `decode(s)` is byte-for-byte the unguarded `decode_with_object_id(s, None)`.
//!   * The guard is transparent for well-behaved traffic: `Some(oid)` recovers
//!     the identical payload that `None` does, including through erasure.
//!   * The guard activates ONLY with an ObjectId, and the rate-limit check runs
//!     *before* the source-ESI-range check -- a near-`u32::MAX` ESI yields
//!     `EsiRateLimitExceeded` under `Some` but `SourceEsiOutOfRange` under `None`
//!     (gating + error precedence, the ordering an attacker would probe).
//!   * Per-`(esi, ObjectId)` state accumulates across calls: repeated decoding
//!     under one ObjectId is eventually rate-limited (the >100-access ceiling),
//!     while a fresh ObjectId per call never is (the guard is ObjectId-keyed).
//!
//! Guard constants pinned implicitly: `MAX_ALLOWED_ESI = 1_000_000`,
//! `MAX_COLUMNS_PER_ESI = 1000`, access ceiling `> 100` per window.
//!
//! # Repro
//!
//! ```text
//! rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_asupersync_test \
//!   cargo test --test raptorq_decode_object_id_rate_limit_contract -- --nocapture
//! ```

#![allow(missing_docs)]

use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::types::ObjectId;
use asupersync::util::DetRng;

const K: usize = 16;
const SYMBOL_SIZE: usize = 40;
const SEED: u64 = 0x00FE_DCBA_9876_5432;

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

/// For well-behaved traffic the ObjectId guard is transparent: `Some(oid)`
/// recovers exactly what the unguarded path does.
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

/// A near-`u32::MAX` ESI is rate-limited ONLY when an ObjectId is supplied, and
/// the rate-limit check fires *before* the source-ESI-range check. The same
/// malformed symbol therefore yields different, deterministic errors per mode --
/// pinning both the ObjectId gating and the security-critical check ordering.
#[test]
fn near_max_esi_rate_limited_only_with_object_id() {
    let (encoder, decoder, source) = build();
    let mut received = clean_received(&encoder, &decoder, &source, 5, None);
    // A "source" symbol claiming ESI = u32::MAX, well past MAX_ALLOWED_ESI.
    received.push(ReceivedSymbol::source(u32::MAX, vec![0u8; SYMBOL_SIZE]));

    let oid = ObjectId::new(0x0000_0000_0000_DEAD, 0x0000_0000_0000_BEEF);

    // With ObjectId: amplification guard fires first.
    match decoder.decode_with_object_id(&received, Some(&oid)) {
        Err(DecodeError::EsiRateLimitExceeded {
            esi,
            column_count,
            max_columns,
        }) => {
            assert_eq!(esi, u32::MAX, "guard reports the offending ESI verbatim");
            assert_eq!(
                column_count, 0,
                "over-threshold ESI is rejected before any columns are generated"
            );
            assert_eq!(
                max_columns, EXPECTED_MAX_COLUMNS,
                "MAX_COLUMNS_PER_ESI surfaced"
            );
        }
        other => panic!("expected EsiRateLimitExceeded with ObjectId, got {other:?}"),
    }

    // Without ObjectId: the rate check is skipped, so the same symbol falls
    // through to the source-ESI-range validation.
    match decoder.decode_with_object_id(&received, None) {
        Err(DecodeError::SourceEsiOutOfRange { esi, max_valid }) => {
            assert_eq!(esi, u32::MAX);
            assert_eq!(max_valid, K, "source ESI domain is [0, K)");
        }
        other => panic!("expected SourceEsiOutOfRange without ObjectId, got {other:?}"),
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
