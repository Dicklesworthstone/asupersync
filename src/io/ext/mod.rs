//! Extension traits and future adapters for async I/O.

mod read_ext;

pub use read_ext::{AsyncReadExt, ReadExact, ReadToEnd, ReadToString, ReadU8};
