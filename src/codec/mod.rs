//! Codec traits and built-in codecs for framed transport.
//!
//! This module provides the `Decoder` and `Encoder` traits plus common
//! implementations like `LinesCodec` and `LengthDelimitedCodec`.

pub mod decoder;
pub mod encoder;
pub mod length_delimited;
pub mod lines;
pub mod raptorq;

pub use decoder::Decoder;
pub use encoder::Encoder;
pub use length_delimited::{LengthDelimitedCodec, LengthDelimitedCodecBuilder};
pub use lines::{LinesCodec, LinesCodecError};
pub use raptorq::{EncodedSymbol, EncodingConfig, EncodingError, EncodingPipeline};
