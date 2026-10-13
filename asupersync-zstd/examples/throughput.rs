//! Encode and decode throughput of `Level::Fast` on deterministic inputs.
//!
//! Run with `cargo run --release -p asupersync-zstd --example throughput`.
//! Each input is encoded and decoded repeatedly for about half a second, and
//! the best pass is reported in MB/s (10^6 bytes per second of input).

#![allow(
    clippy::cast_precision_loss,
    reason = "byte counts become f64 only to print rates"
)]

use std::time::{Duration, Instant};

use asupersync_zstd::{DecodeLimits, EncodeParams, Level, decode_all, encode_all};

const LEN: usize = 8 << 20;

fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state >> 33
}

/// Words from a 64-word vocabulary: repeats at many distances, skewed bytes.
fn text(len: usize) -> Vec<u8> {
    let vocabulary: Vec<String> = (0..64)
        .map(|i| format!("word{i:02x}{} ", "ab".repeat(i % 5)))
        .collect();
    let mut state = 1;
    let mut out = Vec::with_capacity(len + 32);
    while out.len() < len {
        let word = &vocabulary[usize::try_from(lcg(&mut state) % 64).unwrap_or(0)];
        out.extend_from_slice(word.as_bytes());
    }
    out.truncate(len);
    out
}

/// Binary-like data: random runs copied from earlier positions with noise.
fn mixed(len: usize) -> Vec<u8> {
    let mut state = 2;
    let mut out: Vec<u8> = (0..4096)
        .map(|_| lcg(&mut state).to_le_bytes()[0])
        .collect();
    while out.len() < len {
        let back = 1 + usize::try_from(lcg(&mut state) % 65_536)
            .unwrap_or(0)
            .min(out.len() - 1);
        let run = 4 + usize::try_from(lcg(&mut state) % 60).unwrap_or(0);
        let start = out.len() - back;
        for k in 0..run {
            let byte = out[start + k % back];
            out.push(byte);
        }
        out.push(lcg(&mut state).to_le_bytes()[0]);
    }
    out.truncate(len);
    out
}

fn random(len: usize) -> Vec<u8> {
    let mut state = 3;
    (0..len).map(|_| lcg(&mut state).to_le_bytes()[0]).collect()
}

/// The best rate over repeated runs of `work` on `bytes` input bytes.
fn best_rate(bytes: usize, mut work: impl FnMut()) -> f64 {
    let mut best = Duration::MAX;
    let started = Instant::now();
    let mut passes = 0;
    while passes < 3 || started.elapsed() < Duration::from_millis(500) {
        let pass = Instant::now();
        work();
        best = best.min(pass.elapsed());
        passes += 1;
    }
    bytes as f64 / best.as_secs_f64() / 1e6
}

fn main() {
    let params = EncodeParams {
        checksum: false,
        ..EncodeParams::new(Level::Fast)
    };
    println!("input   bytes      compressed  ratio   encode MB/s  decode MB/s");
    for (name, data) in [
        ("text", text(LEN)),
        ("mixed", mixed(LEN)),
        ("random", random(LEN)),
    ] {
        let frame = encode_all(&data, &params);
        let limits = DecodeLimits::new(data.len());
        assert_eq!(
            decode_all(&frame, &limits).as_deref(),
            Ok(&data[..]),
            "{name} round trip"
        );
        let encode = best_rate(data.len(), || {
            std::hint::black_box(encode_all(std::hint::black_box(&data), &params));
        });
        let decode = best_rate(data.len(), || {
            std::hint::black_box(decode_all(std::hint::black_box(&frame), &limits).ok());
        });
        println!(
            "{name:7} {:9}  {:10}  {:5.2}  {encode:11.1}  {decode:11.1}",
            data.len(),
            frame.len(),
            data.len() as f64 / frame.len() as f64,
        );
    }
}
