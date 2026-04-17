//! Codec traits, built-in codecs, and framed transport adapters.
//!
//! This module provides the `Decoder` and `Encoder` traits, common
//! implementations like `LinesCodec` and `LengthDelimitedCodec`, and
//! framed transport types (`FramedRead`, `FramedWrite`, `Framed`) that
//! bridge synchronous codecs with async I/O.

pub mod bytes_codec;
pub mod decoder;
pub mod encoder;
pub mod framed;
pub mod framed_read;
pub mod framed_write;
pub mod length_delimited;
pub mod lines;
pub mod raptorq;

pub use bytes_codec::BytesCodec;
pub use decoder::Decoder;
pub use encoder::Encoder;
pub use framed::{Framed, FramedParts};
pub use framed_read::FramedRead;
pub use framed_write::FramedWrite;
pub use length_delimited::{LengthDelimitedCodec, LengthDelimitedCodecBuilder};
pub use lines::{LinesCodec, LinesCodecError};
pub use raptorq::{EncodedSymbol, EncodingConfig, EncodingError, EncodingPipeline};

#[cfg(test)]
mod tests;
