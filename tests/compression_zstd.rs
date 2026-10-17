//! The async Zstandard adapters on the native runtime (br-asupersync-t1fblr.31).
//!
//! These tests cover:
//! - round trips through a small in-memory pipe, in odd-sized pieces;
//! - frames that the codec's one-shot decoder reads;
//! - every frame of the reference zstd CLI corpus, read back through the
//!   decoder;
//! - explicit decode limits, truncation and garbage;
//! - flush delivering a decodable prefix;
//! - read and write futures dropped mid-stream on the same adapters, with
//!   nothing lost.
#![cfg(feature = "zstd")]
#![allow(missing_docs)]

use std::future::{Future, poll_fn};
use std::io;
use std::pin::pin;
use std::task::Poll;

use asupersync::compression::zstd::{
    DecodeError, DecodeLimits, EncodeParams, Level, ZstdDecoder, ZstdEncoder,
};
use asupersync::io::{AsyncReadExt, AsyncWriteExt, duplex};
use asupersync::runtime::{RuntimeBuilder, yield_now};
use futures_lite::future::zip;

/// Text-like bytes: words from a small vocabulary.
fn text(len: usize, seed: u64) -> Vec<u8> {
    const WORDS: [&str; 8] = [
        "region ",
        "obligation ",
        "cancel ",
        "scope ",
        "budget ",
        "trace ",
        "join ",
        "spawn\n",
    ];
    let mut state = seed;
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        out.extend_from_slice(WORDS[usize::try_from(state >> 61).expect("3 bits")].as_bytes());
    }
    out.truncate(len);
    out
}

fn block_on<F: Future>(future: F) -> F::Output {
    RuntimeBuilder::current_thread()
        .build()
        .expect("runtime")
        .block_on(future)
}

/// Compresses `payload` into a `Vec` with frames of `frame_size` bytes.
fn compress(payload: &[u8], frame_size: usize) -> Vec<u8> {
    block_on(async {
        let mut encoder =
            ZstdEncoder::with_params(Vec::new(), EncodeParams::new(Level::Fast), frame_size)
                .expect("frame size");
        encoder.write_all(payload).await.expect("compress");
        encoder.shutdown().await.expect("finish");
        encoder.into_inner()
    })
}

/// Reads `wire` to its end through a decoder with `limits`.
fn decompress(wire: &[u8], limits: DecodeLimits) -> (Vec<u8>, io::Result<usize>) {
    block_on(async {
        let mut decoder = ZstdDecoder::new(wire, limits);
        let mut out = Vec::new();
        let result = decoder.read_to_end(&mut out).await;
        (out, result)
    })
}

fn decode_error(error: &io::Error) -> Option<DecodeError> {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<DecodeError>())
        .copied()
}

#[test]
fn round_trip_through_a_small_pipe_in_odd_pieces() {
    let payload = text(600_000, 1);
    let received = block_on(async {
        let (wire_in, wire_out) = duplex(4096);
        // 64 KiB frames: the payload spans ten of them.
        let mut encoder =
            ZstdEncoder::with_params(wire_in, EncodeParams::new(Level::Fast), 64 * 1024)
                .expect("frame size");
        let mut decoder = ZstdDecoder::new(wire_out, DecodeLimits::new(payload.len()));
        let write = async {
            for piece in payload.chunks(1000) {
                encoder.write_all(piece).await?;
            }
            encoder.shutdown().await
        };
        let read = async {
            let mut received = Vec::new();
            let mut piece = [0_u8; 777];
            loop {
                let n = decoder.read(&mut piece).await?;
                if n == 0 {
                    return Ok::<_, io::Error>(received);
                }
                received.extend_from_slice(&piece[..n]);
            }
        };
        let (written, read) = zip(write, read).await;
        written.expect("compress");
        read.expect("decompress")
    });
    assert!(received == payload, "the round trip changed the bytes");
}

/// The wire is plain concatenated Zstandard frames, which the codec's
/// one-shot decoder reads, and it is much smaller than compressible input.
#[test]
fn the_encoder_writes_standard_frames() {
    let payload = text(300_000, 2);
    let wire = compress(&payload, 100_000);
    assert_eq!(&wire[..4], &[0x28, 0xb5, 0x2f, 0xfd], "a Zstandard frame");
    assert!(wire.len() < payload.len() / 4, "{} bytes", wire.len());
    let decoded = asupersync_zstd::decode_all(&wire, &DecodeLimits::new(payload.len()))
        .expect("one-shot decode");
    assert!(decoded == payload);
}

/// Every frame of the reference zstd 1.5.7 CLI corpus (levels, checksums,
/// long windows, block sizes) reads back to its recorded length and XXH64.
#[test]
fn the_decoder_reads_reference_cli_frames() {
    let corpus = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/asupersync-zstd/tests/vectors/frames_zstd_cli.txt"
    ));
    let mut frames = 0;
    for line in corpus.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let length: usize = fields[1].parse().expect("length");
        let digest = u64::from_str_radix(fields[2], 16).expect("xxh64");
        let wire: Vec<u8> = (0..fields[3].len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&fields[3][at..at + 2], 16).expect("hex"))
            .collect();
        let (out, result) = decompress(&wire, DecodeLimits::new(length));
        assert_eq!(result.ok(), Some(length), "{}", fields[0]);
        assert_eq!(asupersync_zstd::xxh64(&out, 0), digest, "{}", fields[0]);
        frames += 1;
    }
    assert_eq!(frames, 264, "the whole corpus");
}

#[test]
fn an_empty_stream_round_trips_and_no_stream_is_an_error() {
    let wire = compress(b"", 1024);
    assert!(!wire.is_empty(), "an empty stream is still one frame");
    let (out, result) = decompress(&wire, DecodeLimits::new(0));
    assert_eq!(result.ok(), Some(0));
    assert!(out.is_empty());

    let (_, result) = decompress(b"", DecodeLimits::new(1024));
    let error = result.expect_err("no frame at all");
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(decode_error(&error), Some(DecodeError::Truncated));
}

#[test]
fn the_decoder_stops_at_its_limits() {
    let payload = text(100_000, 3);
    let wire = compress(&payload, 1 << 20);

    let (out, result) = decompress(&wire, DecodeLimits::new(50_000));
    let error = result.expect_err("over the output limit");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(decode_error(&error), Some(DecodeError::OutputTooLarge));
    assert!(out.len() <= 50_000, "{} bytes delivered", out.len());

    // The frame declares a window of its content size, over 64 KiB.
    let narrow = DecodeLimits::new(payload.len()).with_max_window(64 * 1024);
    let (out, result) = decompress(&wire, narrow);
    assert_eq!(
        result.map_err(|error| decode_error(&error)).err(),
        Some(Some(DecodeError::WindowTooLarge))
    );
    assert!(out.is_empty(), "nothing is decoded from a refused frame");
}

#[test]
fn truncated_corrupt_and_trailing_garbage_streams_fail() {
    let payload = text(50_000, 4);
    let wire = compress(&payload, 1 << 20);
    let limits = DecodeLimits::new(payload.len());

    let (_, result) = decompress(&wire[..wire.len() / 2], limits);
    let error = result.expect_err("truncated");
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);

    let (_, result) = decompress(b"plainly not a zstd frame", limits);
    let error = result.expect_err("garbage");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(decode_error(&error), Some(DecodeError::BadMagic));

    let mut trailing = wire.clone();
    trailing.extend_from_slice(b"junk");
    let (_, result) = decompress(&trailing, limits);
    let error = result.expect_err("trailing garbage");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);

    let mut flipped = wire;
    let middle = flipped.len() / 2;
    flipped[middle] ^= 0x55;
    let (_, result) = decompress(&flipped, limits);
    assert!(result.is_err(), "a corrupted frame is refused");
}

/// `flush` seals a frame, so the reader gets everything written so far while
/// the writer stays open. Writes after `shutdown` are refused.
#[test]
fn flush_delivers_a_decodable_prefix_and_shutdown_ends_input() {
    block_on(async {
        let (wire_in, wire_out) = duplex(64 * 1024);
        let mut encoder = ZstdEncoder::new(wire_in);
        let mut decoder = ZstdDecoder::new(wire_out, DecodeLimits::new(1024));

        encoder.write_all(b"first ").await.expect("write");
        encoder.flush().await.expect("flush");
        let mut first = [0_u8; 6];
        decoder
            .read_exact(&mut first)
            .await
            .expect("read the flushed frame");
        assert_eq!(&first, b"first ");

        encoder.write_all(b"second").await.expect("write");
        encoder.shutdown().await.expect("shutdown");
        let error = encoder
            .write(b"late")
            .await
            .expect_err("a write after shutdown");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        encoder
            .shutdown()
            .await
            .expect("a second shutdown is harmless");

        let mut rest = Vec::new();
        decoder.read_to_end(&mut rest).await.expect("read the rest");
        assert_eq!(rest, b"second");
    });
}

/// A shutdown dropped while it still drains earlier frames already ends the
/// input: a write after it is refused at once, not queued behind the drain.
#[test]
fn a_write_after_an_interrupted_shutdown_is_refused() {
    block_on(async {
        // Nobody reads the pipe, so the compressed frames cannot drain.
        let (wire_in, _wire_out) = duplex(256);
        let mut encoder = ZstdEncoder::with_params(wire_in, EncodeParams::new(Level::Store), 4096)
            .expect("frame size");
        let payload = text(4096, 6);
        let accepted = {
            let mut write = pin!(encoder.write(&payload));
            poll_fn(|cx| Poll::Ready(write.as_mut().poll(cx))).await
        };
        assert!(
            matches!(accepted, Poll::Ready(Ok(4096))),
            "a full frame is accepted and staged: {accepted:?}"
        );
        let shutdown = {
            let mut shutdown = pin!(encoder.shutdown());
            poll_fn(|cx| Poll::Ready(shutdown.as_mut().poll(cx))).await
        };
        assert!(shutdown.is_pending(), "the staged frame cannot drain");
        let late = {
            let mut write = pin!(encoder.write(b"late"));
            poll_fn(|cx| Poll::Ready(write.as_mut().poll(cx))).await
        };
        match late {
            Poll::Ready(Err(error)) => assert_eq!(error.kind(), io::ErrorKind::InvalidInput),
            other => panic!("a write after shutdown must be refused at once: {other:?}"),
        }
    });
}

/// Every write and read future is polled once and dropped whenever it is
/// still pending, then the operation is retried on the same adapter. The
/// pipe is tiny, so both sides are pending often. Nothing may be lost or
/// repeated.
#[test]
fn dropped_reads_and_writes_lose_nothing() {
    let payload = text(300_000, 5);
    let (received, dropped_writes, dropped_reads) = block_on(async {
        let (wire_in, wire_out) = duplex(256);
        let mut encoder =
            ZstdEncoder::with_params(wire_in, EncodeParams::new(Level::Fast), 32 * 1024)
                .expect("frame size");
        let mut decoder = ZstdDecoder::new(wire_out, DecodeLimits::new(payload.len()));
        let write = async {
            let mut dropped = 0_usize;
            let mut offset = 0;
            while offset < payload.len() {
                let end = (offset + 5000).min(payload.len());
                let step = {
                    let mut write = pin!(encoder.write(&payload[offset..end]));
                    poll_fn(|cx| Poll::Ready(write.as_mut().poll(cx))).await
                };
                match step {
                    Poll::Ready(written) => offset += written.expect("write"),
                    Poll::Pending => {
                        dropped += 1;
                        yield_now().await;
                    }
                }
            }
            loop {
                let step = {
                    let mut shutdown = pin!(encoder.shutdown());
                    poll_fn(|cx| Poll::Ready(shutdown.as_mut().poll(cx))).await
                };
                match step {
                    Poll::Ready(done) => {
                        done.expect("shutdown");
                        return dropped;
                    }
                    Poll::Pending => {
                        dropped += 1;
                        yield_now().await;
                    }
                }
            }
        };
        let read = async {
            let mut dropped = 0_usize;
            let mut received = Vec::new();
            let mut piece = [0_u8; 1000];
            loop {
                let step = {
                    let mut read = pin!(decoder.read(&mut piece));
                    poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx))).await
                };
                match step {
                    Poll::Ready(read) => {
                        let n = read.expect("read");
                        if n == 0 {
                            return (received, dropped);
                        }
                        received.extend_from_slice(&piece[..n]);
                    }
                    Poll::Pending => {
                        dropped += 1;
                        yield_now().await;
                    }
                }
            }
        };
        let (dropped_writes, (received, dropped_reads)) = zip(write, read).await;
        (received, dropped_writes, dropped_reads)
    });
    assert!(
        received == payload,
        "dropped futures lost or repeated bytes"
    );
    assert!(
        dropped_writes > 0,
        "no write future was dropped while pending"
    );
    assert!(
        dropped_reads > 0,
        "no read future was dropped while pending"
    );
}
