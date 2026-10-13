//! Differential tests against libzstd 1.5.7, a dev-only oracle (owner decision
//! 2026-10-13, br-asupersync-t1fblr.11): libzstd decodes every frame this crate
//! writes, this crate decodes every frame libzstd writes at every level, and on
//! damaged frames the two decoders never disagree about bytes they both accept.

use asupersync_zstd::{DecodeLimits, EncodeParams, Level, decode_all, encode_all};

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next()).unwrap_or(0) % bound.max(1)
    }

    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }
}

/// Words from a vocabulary of `words` entries.
fn text(seed: u64, len: usize, words: usize) -> Vec<u8> {
    let vocabulary: Vec<String> = (0..words)
        .map(|i| format!("w{i}{} ", "xyz".repeat(i % 4)))
        .collect();
    let mut rng = Lcg(seed);
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        out.extend_from_slice(vocabulary[rng.below(words)].as_bytes());
    }
    out.truncate(len);
    out
}

/// Copies of earlier bytes at random distances, with noise between them.
fn copies(seed: u64, len: usize, max_distance: usize) -> Vec<u8> {
    let mut rng = Lcg(seed);
    let mut out: Vec<u8> = (0..64).map(|_| rng.byte()).collect();
    while out.len() < len {
        let back = 1 + rng.below(max_distance.min(out.len()));
        let run = 3 + rng.below(80);
        let start = out.len() - back;
        for k in 0..run {
            let byte = out[start + k % back];
            out.push(byte);
        }
        for _ in 0..rng.below(4) {
            out.push(rng.byte());
        }
    }
    out.truncate(len);
    out
}

fn noise(seed: u64, len: usize, mask: u8) -> Vec<u8> {
    let mut rng = Lcg(seed);
    (0..len).map(|_| rng.byte() & mask).collect()
}

/// Inputs that reach every encoder path: empty and tiny inputs, every
/// literals header size, block boundaries, multi-block frames with distant
/// repeats, skewed and uniform alphabets, runs and incompressible data.
fn inputs() -> Vec<(String, Vec<u8>)> {
    let mut all = vec![
        ("empty".to_string(), Vec::new()),
        ("one".to_string(), vec![42]),
        ("zeros 1000".to_string(), vec![0; 1000]),
        ("zeros 300k".to_string(), vec![0; 300_000]),
        ("every byte".to_string(), (0..=255_u8).collect()),
    ];
    for (index, len) in [
        5, 31, 32, 63, 64, 255, 256, 1023, 1024, 4095, 4096, 16_383, 16_384,
    ]
    .into_iter()
    .enumerate()
    {
        let seed = u64::try_from(index).unwrap_or(0);
        all.push((format!("text {len}"), text(seed, len, 40)));
        all.push((format!("noise {len}"), noise(seed + 100, len, 0xFF)));
    }
    for (name, data) in [
        ("text 128 KiB - 1", text(7, 128 * 1024 - 1, 200)),
        ("text 128 KiB", text(7, 128 * 1024, 200)),
        ("text 128 KiB + 1", text(7, 128 * 1024 + 1, 200)),
        ("text 1 MiB", text(8, 1 << 20, 500)),
        ("copies near", copies(9, 400_000, 2_000)),
        ("copies far", copies(10, 900_000, 600_000)),
        ("7-bit noise", noise(11, 50_000, 0x7F)),
        ("4-bit noise", noise(12, 50_000, 0x0F)),
        ("uniform 128", (0..128_u8).cycle().take(20_000).collect()),
        ("noise 300k", noise(13, 300_000, 0xFF)),
    ] {
        all.push((name.to_string(), data));
    }
    all
}

#[test]
fn libzstd_decodes_every_fast_frame() {
    for (name, data) in inputs() {
        for checksum in [true, false] {
            let params = EncodeParams {
                checksum,
                ..EncodeParams::new(Level::Fast)
            };
            let frame = encode_all(&data, &params);
            let decoded = zstd::bulk::decompress(&frame, data.len().max(1))
                .unwrap_or_else(|error| panic!("{name} (checksum {checksum}): libzstd: {error}"));
            assert!(
                decoded == data,
                "{name} (checksum {checksum}): libzstd decoded other bytes"
            );
            let mut streamed = Vec::new();
            zstd::stream::copy_decode(&frame[..], &mut streamed)
                .unwrap_or_else(|error| panic!("{name}: libzstd streaming: {error}"));
            assert!(
                streamed == data,
                "{name}: libzstd streaming decoded other bytes"
            );
        }
    }
}

#[test]
fn every_libzstd_level_decodes() {
    for (name, data) in inputs() {
        // The high levels (lazy and optimal parsing, larger tables) run only on
        // the smaller inputs: libzstd builds unoptimized in the test profile.
        let levels: &[i32] = if data.len() <= 64 * 1024 {
            &[-5, -1, 1, 3, 9, 19]
        } else {
            &[-5, -1, 1, 3]
        };
        for &level in levels {
            let frame = zstd::bulk::compress(&data, level).expect("libzstd compress");
            let decoded = decode_all(&frame, &DecodeLimits::new(data.len()));
            assert!(
                decoded.as_deref() == Ok(&data[..]),
                "{name} at level {level}: {:?}",
                decoded.err()
            );
        }
        let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3).expect("encoder");
        encoder.include_checksum(true).expect("checksum flag");
        encoder.include_dictid(true).expect("dictid flag");
        std::io::Write::write_all(&mut encoder, &data).expect("write");
        let frame = encoder.finish().expect("finish");
        let decoded = decode_all(&frame, &DecodeLimits::new(data.len()));
        assert!(
            decoded.as_deref() == Ok(&data[..]),
            "{name} streamed with checksum: {:?}",
            decoded.err()
        );
    }
}

/// Damaged frames: this decoder never panics, and when both decoders accept
/// the same bytes they produce the same output.
#[test]
fn damaged_frames_never_disagree() {
    const CAPACITY: usize = 1 << 20;
    let mut rng = Lcg(77);
    let sources: Vec<Vec<u8>> = inputs()
        .into_iter()
        .map(|(_, data)| data)
        .filter(|data| data.len() <= 64 * 1024)
        .collect();
    let mut both = 0;
    for round in 0..2_000 {
        let data = &sources[rng.below(sources.len())];
        let mut frame = if round % 2 == 0 {
            zstd::bulk::compress(data, 1 + i32::try_from(rng.below(3)).unwrap_or(0))
                .expect("libzstd compress")
        } else {
            encode_all(data, &EncodeParams::new(Level::Fast))
        };
        for _ in 0..=rng.below(3) {
            let at = rng.below(frame.len());
            match rng.below(3) {
                0 => frame[at] ^= 1 << rng.below(8),
                1 => frame[at] = rng.byte(),
                _ => frame.truncate(at.max(1)),
            }
        }
        let ours = decode_all(&frame, &DecodeLimits::new(CAPACITY));
        let theirs = zstd::bulk::decompress(&frame, CAPACITY);
        if let (Ok(ours), Ok(theirs)) = (&ours, &theirs) {
            both += 1;
            assert!(
                ours == theirs,
                "round {round}: decoders disagree on a damaged frame"
            );
        }
    }
    assert!(
        both > 0,
        "some damaged frames should still decode on both sides"
    );
}
