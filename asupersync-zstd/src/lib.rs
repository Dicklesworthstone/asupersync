//! Memory-safe Zstandard (RFC 8878) codec for asupersync.
//!
//! Work in progress, tracked by `br-asupersync-t1fblr`. The decoder is
//! complete for frames without dictionaries. The encoder stores
//! ([`Level::Store`]) or compresses with a greedy hash match finder,
//! Huffman literals and FSE-coded sequences ([`Level::Fast`]).
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
pub mod xxhash64;

pub use encode::{EncodeParams, Level, encode_all, encode_into};
pub use frame::{DecodeError, DecodeLimits, decode_all, decode_into};
pub use xxhash64::{Xxh64, xxh64};
