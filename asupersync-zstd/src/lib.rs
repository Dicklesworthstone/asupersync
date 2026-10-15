//! Memory-safe Zstandard (RFC 8878) codec for asupersync.
//!
//! Experimental: the API may change in any 0.x release. [`EncodeParams`] and
//! [`DecodeLimits`] are `#[non_exhaustive]`, so later settings can be added;
//! build them with `new` and the `with_*` methods.
//!
//! Work in progress, tracked by `br-asupersync-t1fblr`. The decoder is
//! complete for frames without dictionaries. The encoder stores
//! ([`Level::Store`]) or compresses with a greedy hash match finder,
//! Huffman literals and FSE-coded sequences ([`Level::Fast`]).
//! [`StreamEncoder`] and [`StreamDecoder`] accept fragmented input and output
//! with bounded buffering. [`EncodeTransfer`] and [`DecodeTransfer`] drive
//! nonblocking I/O callbacks while retaining progress across cancelled waits.
//!
//! Every decode takes [`DecodeLimits`]: a cap on total output and on the frame
//! window. Malformed input is refused with a [`DecodeError`], never a panic,
//! and the crate forbids unsafe code.
//!
//! ```
//! use asupersync_zstd::{DecodeLimits, decode_all};
//!
//! // A frame holding "hi" as one raw block, as `zstd --no-check` writes it.
//! let frame = [0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x02, 0x11, 0x00, 0x00, b'h', b'i'];
//! assert_eq!(decode_all(&frame, &DecodeLimits::new(64)).unwrap(), b"hi");
//! ```

#![forbid(unsafe_code)]

mod bitio;
mod encode;
mod frame;
mod fse;
mod huffman;
mod literals;
mod matcher;
mod sequences;
mod stream;
mod stream_decode;
mod transfer;
pub mod xxhash64;

pub use encode::{EncodeParams, Level, encode_all, encode_into};
pub use frame::{DecodeError, DecodeLimits, decode_all, decode_append, decode_into};
pub use stream::{StreamEncodeError, StreamEncoder, StreamProgress, StreamStatus};
pub use stream_decode::StreamDecoder;
pub use transfer::{DecodeTransfer, EncodeTransfer, TransferProgress};
pub use xxhash64::{Xxh64, xxh64};
