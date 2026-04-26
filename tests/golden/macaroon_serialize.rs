//! Golden artifact tests for `MacaroonToken::to_binary` byte representation.
//!
//! Per /testing-golden-artifacts: freeze the wire-byte output for known
//! (root-key, identifier, location, caveat-chain) inputs so any future
//! refactor that changes serialization is caught at commit time, not at
//! decode-time on a deployed system.
//!
//! All inputs are deterministic:
//!   * `AuthKey::from_seed(N)` is a domain-separated SHA-256 over a fixed
//!     prefix and the seed (see `src/security/key.rs:62`); same seed →
//!     same key bytes across runs and platforms.
//!   * `MacaroonToken::mint` HMACs identifier+location with the root key,
//!     producing a fully deterministic initial signature.
//!   * `add_caveat` appends to the caveat chain and re-HMACs with the
//!     previous signature as the key — pure function of inputs.
//!
//! Timing-sensitive fields: none. The only "time" values are virtual
//! timestamps the test passes IN to `CaveatPredicate::TimeBefore/After`
//! and `RateLimit::window_secs` — they're inputs, not wall-clock reads.
//! No scrubbing required.
//!
//! Snapshots use `insta::assert_snapshot!` with the binary serialization
//! rendered as hex (lowercase, no spaces) so diffs are reviewable.

#![allow(warnings)]
#![allow(clippy::all)]

use asupersync::cx::macaroon::{CaveatPredicate, MacaroonToken};
use asupersync::security::key::AuthKey;

/// Render bytes as a hex string for snapshot comparison.
///
/// One byte per two hex chars, no separator. Length-prefixed in the
/// snapshot label (via the line breaks between labelled sections) so a
/// drift in byte count surfaces clearly.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Render a labelled hex block — wraps the hex at 64 chars/line so insta
/// snapshots are scannable and diffs land on a stable line boundary.
fn labelled_hex(label: &str, bytes: &[u8]) -> String {
    let h = hex(bytes);
    let mut out = String::new();
    out.push_str(label);
    out.push_str(" (");
    out.push_str(&bytes.len().to_string());
    out.push_str(" bytes):\n");
    for chunk in h.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out
}

/// Deterministic root key used by all golden tests in this file.
fn golden_key() -> AuthKey {
    AuthKey::from_seed(0xC0FF_EE15_DEAD_BEEFu64)
}

// ─── Bare mint, no caveats ──────────────────────────────────────────────────

#[test]
fn golden_mint_no_caveats() {
    let key = golden_key();
    let token = MacaroonToken::mint(&key, "spawn:region_42", "asupersync.lab");
    let bytes = token.to_binary();
    insta::assert_snapshot!(
        "macaroon_mint_no_caveats",
        labelled_hex("mint(spawn:region_42, asupersync.lab)", &bytes)
    );
}

// ─── Single time-before caveat ──────────────────────────────────────────────

#[test]
fn golden_single_time_before_caveat() {
    let key = golden_key();
    let token = MacaroonToken::mint(&key, "read:db", "core")
        .add_caveat(CaveatPredicate::TimeBefore(1_700_000_000_000));
    let bytes = token.to_binary();
    insta::assert_snapshot!(
        "macaroon_time_before",
        labelled_hex("mint + TimeBefore(1.7e12)", &bytes)
    );
}

// ─── Multi-caveat attenuation chain ─────────────────────────────────────────

#[test]
fn golden_attenuation_chain_three_caveats() {
    let key = golden_key();
    let token = MacaroonToken::mint(&key, "write:queue", "msgbus")
        .add_caveat(CaveatPredicate::TimeBefore(2_000_000_000_000))
        .add_caveat(CaveatPredicate::MaxUses(7))
        .add_caveat(CaveatPredicate::ResourceScope("queue/billing/**".into()));
    let bytes = token.to_binary();
    insta::assert_snapshot!(
        "macaroon_chain_time_max_resource",
        labelled_hex("mint + TimeBefore + MaxUses + ResourceScope", &bytes)
    );
}

// ─── Region + Task scope ────────────────────────────────────────────────────

#[test]
fn golden_region_task_scope_chain() {
    let key = golden_key();
    let token = MacaroonToken::mint(&key, "spawn:isolated", "lab")
        .add_caveat(CaveatPredicate::RegionScope(0xABCD_1234_5678_DEFE))
        .add_caveat(CaveatPredicate::TaskScope(0x4242_4242_4242_4242));
    let bytes = token.to_binary();
    insta::assert_snapshot!(
        "macaroon_region_task_scope",
        labelled_hex("mint + RegionScope + TaskScope", &bytes)
    );
}

// ─── Rate-limit + custom caveats ────────────────────────────────────────────

#[test]
fn golden_rate_limit_and_custom_caveats() {
    let key = golden_key();
    let token = MacaroonToken::mint(&key, "publish:metrics", "telemetry")
        .add_caveat(CaveatPredicate::RateLimit {
            max_count: 100,
            window_secs: 60,
        })
        .add_caveat(CaveatPredicate::Custom(
            "tenant".into(),
            "acme-corp".into(),
        ));
    let bytes = token.to_binary();
    insta::assert_snapshot!(
        "macaroon_rate_limit_custom",
        labelled_hex("mint + RateLimit + Custom", &bytes)
    );
}

// ─── Signature stability across mint sites ──────────────────────────────────

#[test]
fn golden_signature_isolated() {
    // Just the signature bytes, isolated from the rest of the wire format.
    // If the caveat-chain HMAC algorithm or domain-separation prefix ever
    // changes, this snapshot catches it cleanly.
    let key = golden_key();
    let token = MacaroonToken::mint(&key, "id-only", "loc-only");
    let sig_bytes = token.signature().as_bytes();
    insta::assert_snapshot!("macaroon_initial_signature", hex(sig_bytes));

    let attenuated = token
        .add_caveat(CaveatPredicate::TimeBefore(99))
        .add_caveat(CaveatPredicate::MaxUses(3));
    let sig_after = attenuated.signature().as_bytes();
    insta::assert_snapshot!("macaroon_signature_after_two_caveats", hex(sig_after));
}

// ─── Round-trip: encode → decode → re-encode produces identical bytes ──────

#[test]
fn golden_binary_roundtrip_is_byte_identical() {
    // Not a snapshot test per se — a self-consistency property: the
    // serializer must be a stable function of the in-memory token, so
    // decoding a byte string and re-encoding yields identical bytes. If
    // this ever fails, ANY of the snapshots above could become flaky.
    let key = golden_key();
    let original = MacaroonToken::mint(&key, "rt:test", "lab")
        .add_caveat(CaveatPredicate::TimeBefore(1_700_000_000_000))
        .add_caveat(CaveatPredicate::MaxUses(5))
        .add_caveat(CaveatPredicate::ResourceScope("a/b/*".into()));
    let bytes_a = original.to_binary();
    let decoded = MacaroonToken::from_binary(&bytes_a)
        .expect("from_binary must accept bytes produced by to_binary");
    let bytes_b = decoded.to_binary();
    assert_eq!(
        bytes_a, bytes_b,
        "MacaroonToken serialization MUST be a stable function of the in-memory token"
    );
}
