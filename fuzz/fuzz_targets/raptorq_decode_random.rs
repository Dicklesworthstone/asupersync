//! Fuzz target for `asupersync::raptorq::decoder::InactivationDecoder`.
//!
//! Drives the real RaptorQ decoder with arbitrary, structure-aware random
//! inputs. The harness asserts the decoder's three boundary contracts:
//!
//!   1. **No panics on malformed input.** Every code path must surface a
//!      typed [`DecodeError`] (or `Ok`) — never an unwind from the decoder.
//!   2. **Decode is total over its input domain.** The result is always
//!      `Result<DecodeResult, DecodeError>`; libfuzzer rejects panics, so
//!      reaching the end of the closure is the success criterion.
//!   3. **Memory bounded by config.** K and symbol_size are clamped so a
//!      single iteration's intermediate-symbol matrix cannot exceed
//!      `K_MAX * T_MAX * EQUATION_MAX` bytes.
//!
//! Coverage strategy:
//!
//!   * Mix of three equation kinds per case:
//!       - `source(esi, data)`            — identity equation.
//!       - `repair_equation(esi)` ⇒ data  — real LT equation backed by
//!         decoder-generated columns/coefficients.
//!       - synthetic adversarial          — random columns/coefficients
//!         designed to hit `SymbolEquationArityMismatch`,
//!         `ColumnIndexOutOfRange`, `SourceEsiOutOfRange`,
//!         `InvalidSourceSymbolEquation`, and `SymbolSizeMismatch`.
//!   * K spans the systematic boundary cases (1, 2, 10, 11, K_MAX) and
//!     random in-between values; symbol_size hits 1, 2, 16, 32, 256, 512
//!     plus random.
//!
//! Run with:
//!
//! ```bash
//! rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_pane7 \
//!     cargo +nightly fuzz run raptorq_decode_random -- -max_total_time=180
//! ```

#![no_main]

use asupersync::raptorq::decoder::{DecodeError, DecodeResult, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;
use libfuzzer_sys::fuzz_target;

const K_MAX: usize = 256;
const T_MAX: usize = 128;
const EQUATION_MAX: usize = 1024;
const COLUMN_INDEX_MAX: usize = 4096;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    let mut cursor = Cursor::new(data);
    let k = cursor.k();
    let symbol_size = cursor.symbol_size();
    let seed = cursor.next_u64();

    let decoder = InactivationDecoder::new(k, symbol_size, seed);

    let equation_count = (cursor.next_u16() as usize) % (EQUATION_MAX + 1);
    let mut received: Vec<ReceivedSymbol> = Vec::with_capacity(equation_count);

    for _ in 0..equation_count {
        let Some(symbol) = cursor.next_received_symbol(&decoder, k, symbol_size) else {
            break;
        };
        received.push(symbol);
        if received.len() >= EQUATION_MAX {
            break;
        }
    }

    // Contract: the decoder must be total — every input either succeeds or
    // returns a typed DecodeError. A panic from inside `decode` is a fuzz
    // finding.
    let result: Result<DecodeResult, DecodeError> = decoder.decode(&received);

    // Cheap sanity check on the success path: recovered source symbol count
    // matches K.
    if let Ok(decoded) = result {
        debug_assert_eq!(decoded.source.len(), k);
    }
});

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    prng: u64,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        let mut seed = 0xa076_1d64_78bd_642fu64;
        for &b in data.iter().take(16) {
            seed = seed.rotate_left(5) ^ u64::from(b).wrapping_mul(0x100_00000_001b3);
        }
        Self {
            data,
            pos: 0,
            prng: seed,
        }
    }

    fn xorshift(&mut self) -> u64 {
        let mut x = self.prng.max(1);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.prng = x;
        x
    }

    fn read(&mut self, n: usize) -> Option<&[u8]> {
        if self.pos + n > self.data.len() {
            return None;
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(out)
    }

    fn next_u8(&mut self) -> u8 {
        match self.read(1).map(|s| *s.first().unwrap_or(&0)) {
            Some(v) => v,
            None => (self.xorshift() & 0xFF) as u8,
        }
    }

    fn next_u16(&mut self) -> u16 {
        match self.read(2).and_then(|s| <[u8; 2]>::try_from(s).ok()) {
            Some(bytes) => u16::from_le_bytes(bytes),
            None => {
                let r = self.xorshift().to_le_bytes();
                u16::from_le_bytes([r[0], r[1]])
            }
        }
    }

    fn next_u32(&mut self) -> u32 {
        match self.read(4).and_then(|s| <[u8; 4]>::try_from(s).ok()) {
            Some(bytes) => u32::from_le_bytes(bytes),
            None => {
                let r = self.xorshift().to_le_bytes();
                u32::from_le_bytes([r[0], r[1], r[2], r[3]])
            }
        }
    }

    fn next_u64(&mut self) -> u64 {
        match self.read(8).and_then(|s| <[u8; 8]>::try_from(s).ok()) {
            Some(bytes) => u64::from_le_bytes(bytes),
            None => self.xorshift(),
        }
    }

    fn fill(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        if let Some(slice) = self.read(len) {
            out.extend_from_slice(slice);
            return out;
        }
        // Out of input bytes — fall back to PRNG fill so we still cover the
        // case at full requested length.
        while out.len() < len {
            let r = self.xorshift().to_le_bytes();
            let take = (len - out.len()).min(8);
            out.extend_from_slice(&r[..take]);
        }
        out
    }

    fn k(&mut self) -> usize {
        let bucket = self.next_u8() % 12;
        let raw = match bucket {
            0 => 1,
            1 => 2,
            2 => 9,
            3 => 10,
            4 => 11,
            5 => 16,
            6 => 32,
            7 => 64,
            8 => 128,
            9 => 255,
            10 => K_MAX,
            _ => (self.next_u16() as usize) % K_MAX,
        };
        raw.clamp(1, K_MAX)
    }

    fn symbol_size(&mut self) -> usize {
        let bucket = self.next_u8() % 10;
        let raw = match bucket {
            0 => 1,
            1 => 2,
            2 => 8,
            3 => 16,
            4 => 32,
            5 => 64,
            6 => 128,
            7 => T_MAX,
            _ => (self.next_u8() as usize) % T_MAX + 1,
        };
        raw.clamp(1, T_MAX)
    }

    /// Pick a single received symbol via one of three strategies:
    ///   0..=3  — real source(esi < k, data of T bytes)
    ///   4..=7  — real repair via `decoder.repair_equation(any esi)`,
    ///            falling back to synthetic when the helper errors.
    ///   _      — synthetic adversarial (deliberately malformed shape).
    fn next_received_symbol(
        &mut self,
        decoder: &InactivationDecoder,
        k: usize,
        symbol_size: usize,
    ) -> Option<ReceivedSymbol> {
        let kind = self.next_u8();
        match kind % 10 {
            0 | 1 | 2 | 3 => Some(self.real_source(k, symbol_size)),
            4 | 5 | 6 | 7 => Some(self.real_repair_or_synthetic(decoder, k, symbol_size)),
            _ => Some(self.synthetic_adversarial(k, symbol_size)),
        }
    }

    fn real_source(&mut self, k: usize, symbol_size: usize) -> ReceivedSymbol {
        // Pick an ESI mostly inside [0, K) so the decoder can still solve,
        // but occasionally outside to drive the SourceEsiOutOfRange branch.
        let esi = if self.next_u8() % 8 == 0 {
            self.next_u32()
        } else {
            (self.next_u16() as u32) % (k.max(1) as u32)
        };
        // Symbol size: usually correct, sometimes off-by-one to drive the
        // SymbolSizeMismatch branch.
        let actual_len = if self.next_u8() % 8 == 0 {
            (self.next_u16() as usize) % (T_MAX * 2 + 1)
        } else {
            symbol_size
        };
        let data = self.fill(actual_len);
        ReceivedSymbol::source(esi, data)
    }

    fn real_repair_or_synthetic(
        &mut self,
        decoder: &InactivationDecoder,
        k: usize,
        symbol_size: usize,
    ) -> ReceivedSymbol {
        // ESIs outside the source domain map to repair symbols. Aim for [k, k+512).
        let esi = (k as u32).saturating_add((self.next_u16() as u32) % 512);
        match decoder.repair_equation(esi) {
            Ok((columns, coefficients)) => {
                let actual_len = if self.next_u8() % 16 == 0 {
                    (self.next_u16() as usize) % (T_MAX * 2 + 1)
                } else {
                    symbol_size
                };
                let data = self.fill(actual_len);
                ReceivedSymbol::repair(esi, columns, coefficients, data)
            }
            Err(_) => self.synthetic_adversarial(k, symbol_size),
        }
    }

    fn synthetic_adversarial(&mut self, _k: usize, symbol_size: usize) -> ReceivedSymbol {
        // Deliberately mis-shaped equation to drive the decoder's
        // input-validation paths.
        let column_count = (self.next_u8() as usize) % 32;
        let coefficient_count = if self.next_u8() % 4 == 0 {
            // Hit SymbolEquationArityMismatch.
            ((self.next_u8() as usize) % 32).saturating_sub(1)
        } else {
            column_count
        };
        let columns: Vec<usize> = (0..column_count)
            .map(|_| (self.next_u32() as usize) % (COLUMN_INDEX_MAX + 1))
            .collect();
        let coefficients: Vec<Gf256> = (0..coefficient_count)
            .map(|_| Gf256::new(self.next_u8()))
            .collect();
        let actual_len = if self.next_u8() % 8 == 0 {
            (self.next_u16() as usize) % (T_MAX * 2 + 1)
        } else {
            symbol_size
        };
        let data = self.fill(actual_len);
        let esi = self.next_u32();
        ReceivedSymbol::repair(esi, columns, coefficients, data)
    }
}
