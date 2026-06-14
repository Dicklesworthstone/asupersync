#![allow(missing_docs)]
//! Integration coverage for `asupersync::io::copy_with_progress` and
//! `asupersync::io::copy_buf`, neither of which is exercised by any other
//! `tests/*.rs`. Pure in-memory: `&[u8]` readers (which impl `AsyncRead` and
//! `AsyncBufRead`) and `Vec<u8>` writers (which impl `AsyncWrite`), so the
//! futures are always `Ready` and need no runtime or reactor.

use asupersync::io::{copy_buf, copy_with_progress};
use futures_lite::future::block_on;
use std::io;

/// `copy_with_progress` copies every byte, returns the total, and invokes the
/// callback with cumulative byte counts that never decrease and end at the
/// total. The payload is larger than the internal copy buffer so several
/// chunks (and several callbacks) occur.
#[test]
fn copy_with_progress_reports_monotonic_cumulative_totals() {
    let result = block_on(async {
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let mut reader: &[u8] = &data;
        let mut writer: Vec<u8> = Vec::new();

        let mut totals: Vec<u64> = Vec::new();
        let copied =
            copy_with_progress(&mut reader, &mut writer, |total| totals.push(total)).await?;

        assert_eq!(copied, data.len() as u64, "returns the total bytes copied");
        assert_eq!(writer, data, "writer receives an exact copy of the source");
        assert!(!totals.is_empty(), "progress callback fired at least once");
        assert!(
            totals.windows(2).all(|w| w[0] <= w[1]),
            "cumulative totals are monotonically non-decreasing: {totals:?}"
        );
        assert_eq!(
            *totals.last().expect("at least one progress callback"),
            data.len() as u64,
            "final cumulative total equals the bytes copied"
        );

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "copy_with_progress should succeed: {result:?}"
    );
}

/// Copying from an empty source yields zero bytes and leaves the writer empty.
#[test]
fn copy_with_progress_on_empty_source_copies_nothing() {
    let result = block_on(async {
        let mut reader: &[u8] = b"";
        let mut writer: Vec<u8> = Vec::new();

        let copied = copy_with_progress(&mut reader, &mut writer, |_| {}).await?;

        assert_eq!(copied, 0, "no bytes copied from an empty source");
        assert!(writer.is_empty(), "writer stays empty");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "empty-source copy_with_progress should succeed: {result:?}"
    );
}

/// `copy_buf` (buffered copy over an `AsyncBufRead` source) copies every byte.
#[test]
fn copy_buf_copies_all_bytes() {
    let result = block_on(async {
        let data: Vec<u8> = (0..50_000u32).map(|i| (i % 97) as u8).collect();
        let mut reader: &[u8] = &data;
        let mut writer: Vec<u8> = Vec::new();

        let copied = copy_buf(&mut reader, &mut writer).await?;

        assert_eq!(
            copied,
            data.len() as u64,
            "copy_buf returns the total bytes copied"
        );
        assert_eq!(writer, data, "copy_buf produces an exact copy");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "copy_buf should succeed: {result:?}");
}
