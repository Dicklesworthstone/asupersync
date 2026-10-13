//! Encode and decode throughput of `Level::Fast` on deterministic inputs,
//! against libzstd at level 1 in the same process (libzstd is a
//! dev-dependency, the differential oracle of br-asupersync-t1fblr.11).
//!
//! Run with `cargo run --release -p asupersync-zstd --example throughput`.
//! Each comparison times this crate and libzstd in alternating passes for
//! about a second and reports the best pass of each in MB/s (10^6 bytes of
//! input per second). The ratio is the median, over adjacent pairs of passes,
//! of this crate's speed over libzstd's: load that changes during the second
//! affects both passes of a pair alike. The whole table is measured twice, to
//! show how much it moves. Neither side writes a content checksum.

#![allow(
    clippy::cast_precision_loss,
    reason = "byte counts become f64 only to print rates"
)]

use std::hint::black_box;
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
/// Short matches with a literal between them: mostly sequence work.
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

/// Random 7-bit bytes: no repeats worth a match, so a frame is almost all
/// Huffman-coded literals, and its timing is literal coding alone.
fn literals(len: usize) -> Vec<u8> {
    let mut state = 4;
    (0..len)
        .map(|_| lcg(&mut state).to_le_bytes()[0] & 0x7F)
        .collect()
}

/// The best rates of `ours` and `theirs` on `bytes` input bytes, timed in
/// alternating passes so that load on the machine affects both alike.
fn best_pair(bytes: usize, mut ours: impl FnMut(), mut theirs: impl FnMut()) -> (f64, f64, f64) {
    let mut best = (Duration::MAX, Duration::MAX);
    // Each pass of ours against the pass of theirs right after it: load
    // that drifts over the second cancels out of the pair's ratio.
    let mut ratios = Vec::new();
    let started = Instant::now();
    while ratios.len() < 7 || started.elapsed() < Duration::from_secs(1) {
        let pass = Instant::now();
        ours();
        let mine = pass.elapsed();
        let pass = Instant::now();
        theirs();
        let other = pass.elapsed();
        best = (best.0.min(mine), best.1.min(other));
        ratios.push(other.as_secs_f64() / mine.as_secs_f64());
    }
    ratios.sort_by(f64::total_cmp);
    let rate = |time: Duration| bytes as f64 / time.as_secs_f64() / 1e6;
    (rate(best.0), rate(best.1), ratios[ratios.len() / 2])
}

fn main() {
    let params = EncodeParams {
        checksum: false,
        ..EncodeParams::new(Level::Fast)
    };
    let inputs = [
        ("text", text(LEN)),
        ("mixed", mixed(LEN)),
        ("random", random(LEN)),
        ("7-bit", literals(LEN)),
    ];
    println!(
        "MB/s of input (best pass); x = median over adjacent pass pairs of this crate's speed \
         / libzstd -1's."
    );
    println!(
        "round input   ratio ours/lib | encode ours     lib     x | decode ours     lib     x \
         | lib frames ours     lib     x"
    );
    for round in 1..=2 {
        for (name, data) in &inputs {
            let limits = DecodeLimits::new(data.len());
            let ours = encode_all(data, &params);
            let theirs = zstd::bulk::compress(data, 1).expect("libzstd compress");
            for frame in [&ours, &theirs] {
                assert_eq!(
                    decode_all(frame, &limits).as_deref(),
                    Ok(&data[..]),
                    "{name} round trip"
                );
            }
            assert_eq!(
                &zstd::bulk::decompress(&ours, data.len()).expect("libzstd decodes ours"),
                data,
                "{name}: libzstd decodes this crate's frame"
            );
            let encode = best_pair(
                data.len(),
                || {
                    black_box(encode_all(black_box(data), &params));
                },
                || {
                    black_box(zstd::bulk::compress(black_box(data), 1).ok());
                },
            );
            let decode = best_pair(
                data.len(),
                || {
                    black_box(decode_all(black_box(&ours), &limits).ok());
                },
                || {
                    black_box(zstd::bulk::decompress(black_box(&theirs), data.len()).ok());
                },
            );
            let cross = best_pair(
                data.len(),
                || {
                    black_box(decode_all(black_box(&theirs), &limits).ok());
                },
                || {
                    black_box(zstd::bulk::decompress(black_box(&theirs), data.len()).ok());
                },
            );
            let size = data.len() as f64;
            println!(
                "{round:5} {name:7} {:5.2} {:5.2} | {:7.1} {:7.1} {:5.2} | {:7.1} {:7.1} {:5.2} \
                 | {:7.1} {:7.1} {:5.2}",
                size / ours.len() as f64,
                size / theirs.len() as f64,
                encode.0,
                encode.1,
                encode.2,
                decode.0,
                decode.1,
                decode.2,
                cross.0,
                cross.1,
                cross.2,
            );
        }
    }
}
