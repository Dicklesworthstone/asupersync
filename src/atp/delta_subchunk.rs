//! Two-level delta: byte-precise sub-chunk diff (B-8.10, asupersync-v0jeoc).
//!
//! Level 1 of the delta path (FastCDC + CAS + IBLT, see [`crate::atp::delta`])
//! localizes the *changed chunks* with communication proportional to the delta,
//! but ships each changed chunk WHOLE — a 100 KB edit inside a 26 KB-average
//! chunk set wastes the unchanged bytes of every touched chunk (~the entire 1.35×
//! loss vs rsync measured in E-RESYNC-4). This module adds **level 2**: a
//! byte-precise sub-delta of a changed chunk's NEW bytes against the receiver's
//! OLD bytes (which it still holds positionally in its CAS / prior manifest), so
//! the sender transmits only the literal sub-delta plus a tiny op stream.
//!
//! The algorithm is the classic rsync rolling-checksum scheme applied at
//! sub-chunk granularity:
//!   * the receiver signs its OLD chunk into fixed-size sub-blocks, each with a
//!     fast rollable weak checksum + a strong (truncated SHA-256) checksum
//!     ([`signature`]);
//!   * the sender rolls the weak checksum across the NEW chunk, and on a weak hit
//!     confirms with the strong checksum, emitting a `Copy` of the matched old
//!     sub-block or accumulating unmatched bytes into a `Literal` ([`diff`]);
//!   * the receiver reconstructs the new chunk from `old + ops` ([`apply`]).
//!
//! Fail-closed: [`apply`] is exact (byte-identical round trip), and the caller
//! still verifies the whole reconstructed chunk's hash against the manifest, so a
//! (cryptographically negligible) strong-checksum collision can never commit
//! wrong bytes. This module owns only the self-contained codec; wiring it into
//! the [`crate::atp::delta`] negotiation is a follow-up that composes on top.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default sub-block size for the level-2 diff.
///
/// Small enough that sparse scattered edits keep enough blocks copyable, large
/// enough to avoid byte-signature state for every position in a content-defined
/// chunk. MATRIX-56 showed 256-byte blocks let 1% scattered flips dirty almost
/// every signed block, forcing a full-object fallback despite valid sidecar
/// state.
pub const DEFAULT_SUBBLOCK_BYTES: usize = 64;

/// Truncated strong-checksum length (128-bit). Collisions are cryptographically
/// negligible, and the whole-chunk hash verify is the fail-closed backstop.
const STRONG_LEN: usize = 16;

/// Bytes charged per non-literal op when estimating wire size (tag + offset +
/// len, varint-ish). Used only by [`wire_bytes`] for benchmark accounting.
const OP_OVERHEAD_BYTES: usize = 10;

/// One signed sub-block of the OLD buffer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BlockSig {
    weak: u32,
    strong: [u8; STRONG_LEN],
    offset: u64,
    len: u32,
}

/// The receiver's signature of an OLD chunk: enough for the sender to find
/// reusable sub-ranges without ever sending the old bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubBlockSignature {
    block_size: u32,
    total_len: u64,
    blocks: Vec<BlockSig>,
}

impl SubBlockSignature {
    /// Number of signed sub-blocks.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Sub-block size this signature was built with.
    #[must_use]
    pub fn block_size(&self) -> usize {
        self.block_size as usize
    }
}

/// One reconstruction op: copy a range of the OLD buffer, or insert literal bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubDeltaOp {
    /// Copy `len` bytes from the OLD buffer starting at `old_offset`.
    Copy { old_offset: u64, len: u32 },
    /// Insert these new literal bytes (absent from / changed vs the OLD buffer).
    Literal(Vec<u8>),
}

/// Error reconstructing a chunk from `old + ops`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubDeltaError {
    /// A `Copy` op references a range outside the OLD buffer.
    CopyOutOfRange {
        old_offset: u64,
        len: u32,
        old_len: usize,
    },
    /// The reconstructed chunk's SHA-256 did not match the manifest's expected
    /// hash — the fail-closed backstop. The caller must discard and fall back to
    /// a whole-chunk transfer rather than commit the bytes.
    HashMismatch { expected: [u8; 32], got: [u8; 32] },
}

impl std::fmt::Display for SubDeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CopyOutOfRange {
                old_offset,
                len,
                old_len,
            } => write!(
                f,
                "sub-delta copy [{old_offset}..+{len}] out of old buffer (len {old_len})"
            ),
            Self::HashMismatch { expected, got } => write!(
                f,
                "reconstructed chunk sha256 {} != expected {}",
                hex16(got),
                hex16(expected)
            ),
        }
    }
}

impl std::error::Error for SubDeltaError {}

/// Short hex prefix (first 8 bytes) for diagnostics.
fn hex16(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(16);
    for b in &bytes[..8] {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// rsync weak rolling checksum over a window (Mark Adler variant): rollable in
/// O(1) as the window slides one byte.
#[derive(Debug, Clone, Copy)]
struct RollingWeak {
    a: u32,
    b: u32,
    len: u32,
}

impl RollingWeak {
    fn new(window: &[u8]) -> Self {
        let mut a: u32 = 0;
        let mut b: u32 = 0;
        let len = window.len() as u32;
        for (i, &byte) in window.iter().enumerate() {
            a = a.wrapping_add(u32::from(byte));
            // weight = (len - i): the first byte counts the most.
            b = b.wrapping_add((len - i as u32).wrapping_mul(u32::from(byte)));
        }
        Self {
            a: a & 0xffff,
            b: b & 0xffff,
            len,
        }
    }

    fn digest(self) -> u32 {
        (self.a & 0xffff) | ((self.b & 0xffff) << 16)
    }

    /// Slide the window: drop `out` (leftmost), append `in_byte` (new rightmost).
    fn roll(&mut self, out: u8, in_byte: u8) {
        let out = u32::from(out);
        let in_byte = u32::from(in_byte);
        self.a = (self.a.wrapping_sub(out).wrapping_add(in_byte)) & 0xffff;
        // b -= len*out; b += a (post-update a)
        self.b = (self
            .b
            .wrapping_sub(self.len.wrapping_mul(out))
            .wrapping_add(self.a))
            & 0xffff;
    }
}

fn strong_checksum(block: &[u8]) -> [u8; STRONG_LEN] {
    let digest = Sha256::digest(block);
    let mut out = [0u8; STRONG_LEN];
    out.copy_from_slice(&digest[..STRONG_LEN]);
    out
}

/// Build the OLD buffer's signature using fixed-size sub-blocks.
///
/// Only full `block_size` blocks are signed (a shorter tail is left to fall
/// through as literal — correct, marginally less optimal). `block_size` is
/// clamped to >= 1.
#[must_use]
pub fn signature(old: &[u8], block_size: usize) -> SubBlockSignature {
    let block_size = block_size.max(1);
    let mut blocks = Vec::with_capacity(old.len() / block_size + 1);
    let mut offset = 0usize;
    while offset + block_size <= old.len() {
        let window = &old[offset..offset + block_size];
        blocks.push(BlockSig {
            weak: RollingWeak::new(window).digest(),
            strong: strong_checksum(window),
            offset: offset as u64,
            len: block_size as u32,
        });
        offset += block_size;
    }
    SubBlockSignature {
        block_size: block_size as u32,
        total_len: old.len() as u64,
        blocks,
    }
}

/// Compute the byte-precise op stream that reconstructs `new` from the OLD buffer
/// described by `sig`. `apply(old, diff(new, signature(old, b))) == new` exactly.
///
/// Consecutive literal bytes are coalesced into a single [`SubDeltaOp::Literal`].
#[must_use]
pub fn diff(new: &[u8], sig: &SubBlockSignature) -> Vec<SubDeltaOp> {
    let block_size = sig.block_size as usize;
    let mut ops: Vec<SubDeltaOp> = Vec::new();

    // New shorter than a block (or no signed blocks): nothing to match → literal.
    if new.len() < block_size || sig.blocks.is_empty() {
        if !new.is_empty() {
            ops.push(SubDeltaOp::Literal(new.to_vec()));
        }
        return ops;
    }

    // weak → candidate block indices (multiple old blocks can share a weak hash).
    let mut by_weak: HashMap<u32, Vec<usize>> = HashMap::new();
    for (idx, b) in sig.blocks.iter().enumerate() {
        by_weak.entry(b.weak).or_default().push(idx);
    }

    let mut pos = 0usize;
    let mut literal_start = 0usize;
    let mut rolling = RollingWeak::new(&new[0..block_size]);

    loop {
        let mut matched: Option<&BlockSig> = None;
        if let Some(cands) = by_weak.get(&rolling.digest()) {
            let window = &new[pos..pos + block_size];
            let strong = strong_checksum(window);
            for &idx in cands {
                let b = &sig.blocks[idx];
                if b.strong == strong {
                    matched = Some(b);
                    break;
                }
            }
        }

        if let Some(b) = matched {
            if pos > literal_start {
                ops.push(SubDeltaOp::Literal(new[literal_start..pos].to_vec()));
            }
            ops.push(SubDeltaOp::Copy {
                old_offset: b.offset,
                len: b.len,
            });
            pos += block_size;
            literal_start = pos;
            if pos + block_size <= new.len() {
                rolling = RollingWeak::new(&new[pos..pos + block_size]);
                continue;
            }
            break;
        }

        // No match: slide the window one byte (the dropped byte stays pending
        // literal, flushed when the next match / the tail is emitted).
        if pos + block_size < new.len() {
            let out = new[pos];
            let in_byte = new[pos + block_size];
            rolling.roll(out, in_byte);
            pos += 1;
        } else {
            break;
        }
    }

    // Flush the trailing literal (everything after the last match / unmatched tail).
    if literal_start < new.len() {
        ops.push(SubDeltaOp::Literal(new[literal_start..].to_vec()));
    }
    ops
}

/// Reconstruct the NEW buffer from the OLD buffer and the op stream.
///
/// Returns an error if a `Copy` op references outside `old` (a malformed/hostile
/// op stream) — the caller then falls back rather than committing bad bytes.
pub fn apply(old: &[u8], ops: &[SubDeltaOp]) -> Result<Vec<u8>, SubDeltaError> {
    let mut out = Vec::new();
    for op in ops {
        match op {
            SubDeltaOp::Copy { old_offset, len } => {
                let start = usize::try_from(*old_offset).unwrap_or(usize::MAX);
                let end = start.saturating_add(*len as usize);
                if end > old.len() {
                    return Err(SubDeltaError::CopyOutOfRange {
                        old_offset: *old_offset,
                        len: *len,
                        old_len: old.len(),
                    });
                }
                out.extend_from_slice(&old[start..end]);
            }
            SubDeltaOp::Literal(bytes) => out.extend_from_slice(bytes),
        }
    }
    Ok(out)
}

/// Receiver-side fail-closed reconstruction: apply the op stream to the OLD chunk
/// and verify the result's SHA-256 against the manifest's expected chunk hash.
///
/// Returns the reconstructed bytes only if the whole-chunk hash matches; a
/// `Copy`-out-of-range or a hash mismatch is an error so the caller falls back to
/// a whole-chunk transfer rather than committing wrong bytes. This is the
/// integration entry point the delta negotiation calls per changed chunk.
pub fn reconstruct_verified(
    old: &[u8],
    ops: &[SubDeltaOp],
    expected_sha256: &[u8; 32],
) -> Result<Vec<u8>, SubDeltaError> {
    let rebuilt = apply(old, ops)?;
    let got: [u8; 32] = Sha256::digest(&rebuilt).into();
    if &got != expected_sha256 {
        return Err(SubDeltaError::HashMismatch {
            expected: *expected_sha256,
            got,
        });
    }
    Ok(rebuilt)
}

/// Estimated bytes-on-wire for an op stream.
///
/// Literal bytes are the only payload; non-literal ops add fixed overhead. This
/// is what level 2 saves over shipping the whole chunk — for a small edit it is
/// ~proportional to the change.
#[must_use]
pub fn wire_bytes(ops: &[SubDeltaOp]) -> usize {
    ops.iter()
        .map(|op| match op {
            SubDeltaOp::Copy { .. } => OP_OVERHEAD_BYTES,
            SubDeltaOp::Literal(bytes) => OP_OVERHEAD_BYTES + bytes.len(),
        })
        .sum()
}

/// Convenience: full sender-side sub-delta of `new` against `old`.
///
/// Equivalent to `diff(new, &signature(old, block_size))`; the protocol splits
/// these across the wire (receiver signs, sender diffs), but a co-located
/// caller / test can do both.
#[must_use]
pub fn sub_delta(old: &[u8], new: &[u8], block_size: usize) -> Vec<SubDeltaOp> {
    diff(new, &signature(old, block_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(old: &[u8], new: &[u8], block: usize) -> Vec<SubDeltaOp> {
        let ops = sub_delta(old, new, block);
        let rebuilt = apply(old, &ops).expect("apply");
        assert_eq!(rebuilt, new, "round trip must be byte-identical");
        ops
    }

    fn literal_bytes(ops: &[SubDeltaOp]) -> usize {
        ops.iter()
            .map(|op| match op {
                SubDeltaOp::Literal(b) => b.len(),
                SubDeltaOp::Copy { .. } => 0,
            })
            .sum()
    }

    #[test]
    fn identical_buffers_are_all_copy_zero_literal() {
        let old: Vec<u8> = (0..8192u32).map(|i| (i * 31) as u8).collect();
        let ops = roundtrip(&old, &old, 1024);
        assert_eq!(
            literal_bytes(&ops),
            0,
            "identical content sends no literals"
        );
        assert!(ops.iter().all(|o| matches!(o, SubDeltaOp::Copy { .. })));
    }

    #[test]
    fn append_only_copies_old_then_literal_tail() {
        let old: Vec<u8> = (0..8192u32).map(|i| (i * 17 + 3) as u8).collect();
        let mut new = old.clone();
        new.extend_from_slice(&[0xAB; 200]);
        let ops = roundtrip(&old, &new, 1024);
        // The 8192 old bytes (8 full blocks) are copied; only the 200 appended
        // bytes are literal.
        assert_eq!(literal_bytes(&ops), 200);
    }

    #[test]
    fn small_edit_sends_only_a_few_literal_blocks_not_whole_chunk() {
        let old: Vec<u8> = (0..16384u32).map(|i| (i * 7 + 1) as u8).collect();
        let mut new = old.clone();
        // Flip 10 bytes in the middle (within one 1 KiB block).
        for k in 0..10 {
            new[8000 + k] ^= 0xFF;
        }
        let ops = roundtrip(&old, &new, 1024);
        // The change touches ~one block; literal must be far below the whole
        // 16 KiB chunk (the E-RESYNC-4 waste this fix kills).
        assert!(
            literal_bytes(&ops) <= 2 * 1024,
            "literal {} should be ~one block, not the whole chunk",
            literal_bytes(&ops)
        );
        assert!(
            wire_bytes(&ops) < new.len(),
            "wire must beat shipping the whole chunk"
        );
    }

    #[test]
    fn insert_shifts_content_but_stays_byte_identical_and_compact() {
        // Insertion shifts all following bytes — the rolling checksum must re-sync
        // on block boundaries (shift resistance), so most old blocks still copy.
        let old: Vec<u8> = (0..16384u32).map(|i| (i * 13 + 5) as u8).collect();
        let mut new = old[..6000].to_vec();
        new.extend_from_slice(&[0xCD; 137]); // inserted run
        new.extend_from_slice(&old[6000..]);
        let ops = roundtrip(&old, &new, 1024);
        // Far less than the whole new buffer is literal (only the inserted region
        // plus boundary slack).
        assert!(
            literal_bytes(&ops) < new.len() / 2,
            "insert literal {} should be well below half the buffer",
            literal_bytes(&ops)
        );
    }

    #[test]
    fn disjoint_buffers_are_all_literal_and_still_exact() {
        let old: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
        let new: Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(251).wrapping_add(99)) as u8)
            .collect();
        let ops = roundtrip(&old, &new, 1024);
        assert_eq!(
            literal_bytes(&ops),
            new.len(),
            "no shared blocks → all literal"
        );
    }

    #[test]
    fn weak_collision_uses_strong_checksum_to_choose_copy_source() {
        // For len=4, deltas [1, -2, 1, 0] preserve both rsync weak sums:
        // sum(delta)=0 and weighted_sum(delta)=4*1 + 3*(-2) + 2*1 = 0.
        // The blocks therefore collide weakly but differ strongly.
        let weak_a = [10u8, 20, 30, 40];
        let weak_b = [11u8, 18, 31, 40];
        assert_eq!(
            RollingWeak::new(&weak_a).digest(),
            RollingWeak::new(&weak_b).digest(),
            "test fixture must create a weak-checksum collision"
        );
        assert_ne!(
            strong_checksum(&weak_a),
            strong_checksum(&weak_b),
            "strong checksum must disambiguate the collision"
        );

        let old = [weak_a, weak_b].concat();
        let sig = signature(&old, 4);
        let ops = diff(&weak_b, &sig);

        assert_eq!(
            ops,
            vec![SubDeltaOp::Copy {
                old_offset: 4,
                len: 4,
            }],
            "diff must copy the strong-matching second block, not the first weak hit"
        );
        assert_eq!(apply(&old, &ops).expect("apply"), weak_b);
    }

    #[test]
    fn weak_only_match_falls_back_to_literal() {
        let old_block = [10u8, 20, 30, 40];
        let weak_collision_without_strong_match = [12u8, 16, 32, 40];
        assert_eq!(
            RollingWeak::new(&old_block).digest(),
            RollingWeak::new(&weak_collision_without_strong_match).digest(),
            "test fixture must create a weak-checksum collision"
        );
        assert_ne!(
            strong_checksum(&old_block),
            strong_checksum(&weak_collision_without_strong_match),
            "fixture must not be a strong match"
        );

        let sig = signature(&old_block, 4);
        let ops = diff(&weak_collision_without_strong_match, &sig);

        assert_eq!(
            ops,
            vec![SubDeltaOp::Literal(
                weak_collision_without_strong_match.to_vec()
            )],
            "a weak-only hit must not produce a copy op"
        );
        assert_eq!(
            apply(&old_block, &ops).expect("apply"),
            weak_collision_without_strong_match
        );
    }

    #[test]
    fn empty_and_short_buffers_roundtrip() {
        assert_eq!(apply(b"old", &sub_delta(b"old", b"", 1024)).unwrap(), b"");
        assert_eq!(
            apply(b"", &sub_delta(b"", b"new bytes", 1024)).unwrap(),
            b"new bytes"
        );
        // new shorter than block_size → single literal.
        let ops = sub_delta(b"abcdefgh", b"xyz", 1024);
        assert_eq!(apply(b"abcdefgh", &ops).unwrap(), b"xyz");
    }

    #[test]
    fn copy_out_of_range_is_rejected_fail_closed() {
        let ops = vec![SubDeltaOp::Copy {
            old_offset: 100,
            len: 50,
        }];
        assert!(matches!(
            apply(b"short", &ops),
            Err(SubDeltaError::CopyOutOfRange { .. })
        ));
    }

    #[test]
    fn reconstruct_verified_accepts_correct_hash_and_rejects_tampered() {
        let old: Vec<u8> = (0..8192u32).map(|i| (i * 11 + 2) as u8).collect();
        let mut new = old.clone();
        for k in 0..40 {
            new[4000 + k] ^= 0x5A;
        }
        let expected: [u8; 32] = Sha256::digest(&new).into();
        let ops = sub_delta(&old, &new, 1024);

        // Correct hash → reconstructs the new chunk.
        let rebuilt = reconstruct_verified(&old, &ops, &expected).expect("verified reconstruct");
        assert_eq!(rebuilt, new);

        // Tampered op stream (drop the literal that carried the edit) → the
        // whole-chunk hash check catches it: fail-closed, no bytes committed.
        let tampered: Vec<SubDeltaOp> = ops
            .into_iter()
            .filter(|op| !matches!(op, SubDeltaOp::Literal(_)))
            .collect();
        assert!(matches!(
            reconstruct_verified(&old, &tampered, &expected),
            Err(SubDeltaError::HashMismatch { .. })
        ));

        // A wrong expected hash also fails closed even with the right ops.
        let wrong = [0u8; 32];
        assert!(matches!(
            reconstruct_verified(&old, &sub_delta(&old, &new, 1024), &wrong),
            Err(SubDeltaError::HashMismatch { .. })
        ));
    }

    #[test]
    fn signature_and_ops_serde_roundtrip_and_still_reconstruct() {
        // The protocol sends the signature (receiver->sender) and the op stream
        // (sender->receiver), so both must survive serialization unchanged and
        // still reconstruct the new chunk byte-identically.
        let old: Vec<u8> = (0..4096u32).map(|i| (i * 5 + 1) as u8).collect();
        let mut new = old.clone();
        new.extend_from_slice(b"appended-tail");
        let sig = signature(&old, 1024);
        let ops = diff(&new, &sig);

        let sig2: SubBlockSignature =
            serde_json::from_slice(&serde_json::to_vec(&sig).expect("ser sig")).expect("de sig");
        assert_eq!(sig, sig2);

        let ops2: Vec<SubDeltaOp> =
            serde_json::from_slice(&serde_json::to_vec(&ops).expect("ser ops")).expect("de ops");
        assert_eq!(ops, ops2);
        assert_eq!(apply(&old, &ops2).expect("apply"), new);
    }

    #[test]
    fn rolling_weak_matches_fresh_computation() {
        let data: Vec<u8> = (0..2048u32).map(|i| (i * 91 + 7) as u8).collect();
        let block = 512usize;
        let mut rolling = RollingWeak::new(&data[0..block]);
        for start in 0..(data.len() - block) {
            let fresh = RollingWeak::new(&data[start..start + block]).digest();
            assert_eq!(rolling.digest(), fresh, "rolling weak diverged at {start}");
            rolling.roll(data[start], data[start + block]);
        }
    }
}
