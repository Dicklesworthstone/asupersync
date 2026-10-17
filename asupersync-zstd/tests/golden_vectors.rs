//! Golden decoding vectors (br-asupersync-t1fblr.10): facebook/zstd's own
//! golden-decompression tests and frames written by the reference zstd 1.5.7
//! CLI. Provenance, commands and licences are in
//! `tests/vectors/golden/PROVENANCE.md`.
//!
//! Every `ok` vector in `MANIFEST.txt` decodes to its recorded length and
//! XXH64 through `decode_all`, `decode_into` and `StreamDecoder`, and libzstd
//! agrees. Every `error` vector is refused by all of them. The manifest must
//! list exactly the `.zst` files on disk, and their number is fixed, so a
//! vector cannot silently disappear.

use std::path::{Path, PathBuf};

use asupersync_zstd::{
    DecodeError, DecodeLimits, StreamDecoder, StreamStatus, decode_all, decode_into, xxh64,
};

/// The vectors in `MANIFEST.txt`: 4 + 3 from facebook/zstd, 15 from the CLI.
const VECTORS: usize = 22;

/// A generous budget for the error vectors, which are all tiny.
const ERROR_BUDGET: usize = 8 << 20;

enum Expect {
    Output { length: usize, digest: u64 },
    Error,
}

struct Vector {
    path: String,
    frame: Vec<u8>,
    expect: Expect,
}

fn golden() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/golden")
}

fn vectors() -> Vec<Vector> {
    let manifest =
        std::fs::read_to_string(golden().join("MANIFEST.txt")).expect("read MANIFEST.txt");
    manifest
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(fields.len(), 4, "malformed manifest line: {line}");
            let expect = match fields[1] {
                "ok" => Expect::Output {
                    length: fields[2].parse().expect("output length"),
                    digest: u64::from_str_radix(fields[3], 16).expect("xxh64"),
                },
                "error" => Expect::Error,
                other => panic!("unknown expectation {other}: {line}"),
            };
            let frame = std::fs::read(golden().join(fields[0]))
                .unwrap_or_else(|error| panic!("read {}: {error}", fields[0]));
            Vector {
                path: fields[0].to_owned(),
                frame,
                expect,
            }
        })
        .collect()
}

fn zst_files(dir: &Path, prefix: &str, found: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("read a golden directory") {
        let entry = entry.expect("directory entry");
        let name = entry.file_name().into_string().expect("UTF-8 file name");
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if entry.file_type().expect("file type").is_dir() {
            zst_files(&entry.path(), &path, found);
        } else if Path::new(&name).extension() == Some("zst".as_ref()) {
            found.push(path);
        }
    }
}

/// Feeds `frame` to a `StreamDecoder` in `input_chunk`-byte pieces with an
/// `output_chunk`-byte output buffer, then finishes the stream.
fn stream_decode(
    frame: &[u8],
    limits: DecodeLimits,
    input_chunk: usize,
    output_chunk: usize,
) -> Result<Vec<u8>, DecodeError> {
    let mut decoder = StreamDecoder::new(limits);
    let mut produced = Vec::new();
    let mut out = vec![0_u8; output_chunk];
    for chunk in frame.chunks(input_chunk) {
        let mut offset = 0;
        while offset < chunk.len() {
            let step = decoder.decode(&chunk[offset..], &mut out)?;
            assert!(
                step.input_read > 0 || step.output_written > 0,
                "no progress with input pending: {step:?}"
            );
            offset += step.input_read;
            produced.extend_from_slice(&out[..step.output_written]);
        }
    }
    loop {
        let step = decoder.finish(&mut out)?;
        produced.extend_from_slice(&out[..step.output_written]);
        if step.status == StreamStatus::Finished {
            return Ok(produced);
        }
        assert!(step.output_written > 0, "finish made no progress: {step:?}");
    }
}

#[test]
fn the_manifest_lists_exactly_the_golden_files() {
    let all = vectors();
    assert_eq!(
        all.len(),
        VECTORS,
        "MANIFEST.txt must keep all {VECTORS} vectors"
    );
    let mut listed: Vec<String> = all.iter().map(|vector| vector.path.clone()).collect();
    listed.sort();
    let mut on_disk = Vec::new();
    zst_files(&golden(), "", &mut on_disk);
    on_disk.sort();
    assert_eq!(listed, on_disk, "MANIFEST.txt and the .zst files differ");
    let errors = all
        .iter()
        .filter(|vector| matches!(vector.expect, Expect::Error))
        .count();
    assert_eq!(errors, 3, "facebook/zstd's three error vectors");
}

#[test]
fn every_golden_frame_decodes_to_its_recorded_digest() {
    for vector in vectors() {
        let Expect::Output { length, digest } = vector.expect else {
            continue;
        };
        let path = &vector.path;
        let limits = DecodeLimits::new(length);

        let decoded = decode_all(&vector.frame, &limits)
            .unwrap_or_else(|error| panic!("{path}: decode_all: {error}"));
        assert_eq!(decoded.len(), length, "{path}: length");
        assert_eq!(xxh64(&decoded, 0), digest, "{path}: XXH64");

        let mut exact = vec![0_u8; length];
        assert_eq!(
            decode_into(&vector.frame, &mut exact, &limits),
            Ok(length),
            "{path}: decode_into"
        );
        assert!(exact == decoded, "{path}: decode_into decoded other bytes");

        for (input_chunk, output_chunk) in [(13, 4093), (vector.frame.len().max(1), 1 << 20)] {
            let streamed = stream_decode(&vector.frame, limits, input_chunk, output_chunk)
                .unwrap_or_else(|error| {
                    panic!("{path}: StreamDecoder ({input_chunk}, {output_chunk}): {error}")
                });
            assert!(
                streamed == decoded,
                "{path}: StreamDecoder ({input_chunk}, {output_chunk}) decoded other bytes"
            );
        }

        let reference = zstd::bulk::decompress(&vector.frame, length.max(1))
            .unwrap_or_else(|error| panic!("{path}: libzstd: {error}"));
        assert!(reference == decoded, "{path}: libzstd decoded other bytes");
    }
}

#[test]
fn one_byte_less_output_budget_is_refused() {
    for vector in vectors() {
        let Expect::Output { length, .. } = vector.expect else {
            continue;
        };
        if length == 0 {
            continue;
        }
        let path = &vector.path;
        let limits = DecodeLimits::new(length - 1);
        assert_eq!(
            decode_all(&vector.frame, &limits),
            Err(DecodeError::OutputTooLarge),
            "{path}"
        );
        let mut short = vec![0_u8; length - 1];
        assert!(
            decode_into(&vector.frame, &mut short, &DecodeLimits::new(length)).is_err(),
            "{path}: decode_into filled a buffer one byte short"
        );
        assert!(
            stream_decode(&vector.frame, limits, 4096, 65_536).is_err(),
            "{path}: StreamDecoder went past its budget"
        );
    }
}

#[test]
fn every_error_vector_is_refused() {
    for vector in vectors() {
        if !matches!(vector.expect, Expect::Error) {
            continue;
        }
        let path = &vector.path;
        let limits = DecodeLimits::new(ERROR_BUDGET);
        let decoded = decode_all(&vector.frame, &limits);
        assert!(
            decoded.is_err(),
            "{path}: decode_all accepted it: {decoded:?}"
        );
        let mut buffer = vec![0_u8; ERROR_BUDGET];
        assert!(
            decode_into(&vector.frame, &mut buffer, &limits).is_err(),
            "{path}: decode_into accepted it"
        );
        for (input_chunk, output_chunk) in [(1, 1), (vector.frame.len(), ERROR_BUDGET)] {
            assert!(
                stream_decode(&vector.frame, limits, input_chunk, output_chunk).is_err(),
                "{path}: StreamDecoder ({input_chunk}, {output_chunk}) accepted it"
            );
        }
        assert!(
            zstd::bulk::decompress(&vector.frame, ERROR_BUDGET).is_err(),
            "{path}: libzstd accepted it"
        );
    }
}

/// A frame streamed with `--long=23` declares an 8 MiB window: the default
/// limit admits it, and a 4 MiB limit refuses it before decoding anything.
#[test]
fn the_8_mib_window_frame_needs_the_default_window() {
    let vector = vectors()
        .into_iter()
        .find(|vector| vector.path == "cli/tar400k_l19_long23_stream.zst")
        .expect("the --long=23 vector");
    let Expect::Output { length, .. } = vector.expect else {
        panic!("the --long=23 vector decodes");
    };
    assert!(decode_all(&vector.frame, &DecodeLimits::new(length)).is_ok());
    let narrow = DecodeLimits::new(length).with_max_window(4 << 20);
    assert_eq!(
        decode_all(&vector.frame, &narrow),
        Err(DecodeError::WindowTooLarge)
    );
}
