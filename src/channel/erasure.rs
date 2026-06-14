//! Forward-erasure-coded channel: block layout, framing, and configuration.
//!
//! The pure foundation of the erasure-coded channel (bead
//! `asupersync-raptorq-leverage-3bb2pl.1`): a channel whose delivery guarantee
//! comes from forward error correction (RaptorQ symbols) rather than
//! retransmission. A message is split into `K` source symbols and encoded into
//! `N = K + repair` symbols; the receiver reconstructs the message once it has
//! collected enough symbols, tolerating the loss of up to `repair` of them.
//!
//! This module owns the *transport-free, async-free* parts — the pieces that
//! are pure functions of their inputs and therefore exhaustively unit-testable:
//!
//! - [`EcConfig`]: the channel parameters and their validation.
//! - [`BlockLayout`]: the per-message plan derived from the message size — how
//!   many source/repair/total symbols, the symbol size, the padding, and the
//!   resulting loss margin. This is where the "K vs message-size" tradeoff is
//!   decided.
//! - [`MessageHeader`]: the small, fixed-size header that precedes a message's
//!   symbols on the wire so a receiver can plan its decode before any symbol
//!   arrives.
//!
//! The async `EcSender`/`EcReceiver` composition over the RaptorQ pipeline
//! ([`crate::raptorq::pipeline`]), the symbol transport, authenticated symbols,
//! and the obligation ledger is layered on top of this foundation in sibling
//! slices.
//!
//! # Obligation-semantics decision (recorded per the bead)
//!
//! The sender's send obligation resolves at **symbol flush** (handoff of enough
//! symbols to the transport for the configured delivery class), **not** at
//! receiver decode. End-to-end acknowledgement is a layer above (the
//! `messaging` fabric's delivery classes L0–L4), which this channel references
//! rather than reinvents. `recv` ordering is per-sender FIFO by message id;
//! there is no cross-sender ordering.
//!
//! # Scope
//!
//! Single source block per message (small/medium messages — the common case;
//! `MessageTooLarge` rejects anything beyond the configured cap). Multi-block
//! striping for very large messages is a recorded follow-up, as are the QUIC
//! datagram lane and production WAN hardening.

use std::fmt;

/// Configuration for an erasure-coded channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcConfig {
    /// Bytes per RaptorQ symbol.
    pub symbol_size: u16,
    /// Repair symbols added beyond the source symbols (`N = K + repair`). The
    /// channel tolerates losing up to this many symbols per message.
    pub repair_overhead: u16,
    /// Maximum message size (bytes) accepted by a single block.
    pub max_message_size: usize,
}

impl Default for EcConfig {
    fn default() -> Self {
        Self {
            symbol_size: 1024,
            repair_overhead: 4,
            max_message_size: 1 << 20, // 1 MiB
        }
    }
}

impl EcConfig {
    /// Validates the configuration.
    pub fn validate(&self) -> Result<(), EcError> {
        if self.symbol_size == 0 {
            return Err(EcError::ZeroSymbolSize);
        }
        if self.max_message_size == 0 {
            return Err(EcError::ZeroMaxMessage);
        }
        Ok(())
    }

    /// Plans the block layout for a message of `message_size` bytes.
    ///
    /// Derives the number of source symbols needed to hold the message
    /// (`ceil(message_size / symbol_size)`, at least one), appends the
    /// configured repair overhead, and computes the padding in the final
    /// symbol. Returns [`EcError::MessageTooLarge`] beyond the configured cap,
    /// or [`EcError::SymbolCountOverflow`] if the layout would exceed the
    /// 16-bit symbol-count space.
    pub fn plan(&self, message_size: usize) -> Result<BlockLayout, EcError> {
        self.validate()?;
        if message_size > self.max_message_size {
            return Err(EcError::MessageTooLarge {
                size: message_size,
                max: self.max_message_size,
            });
        }
        let symbol_size = self.symbol_size as usize;
        let source_usize = message_size.div_ceil(symbol_size).max(1);
        let source_symbols =
            u16::try_from(source_usize).map_err(|_| EcError::SymbolCountOverflow)?;
        let total_symbols = source_symbols
            .checked_add(self.repair_overhead)
            .ok_or(EcError::SymbolCountOverflow)?;
        let padding = source_usize * symbol_size - message_size;
        Ok(BlockLayout {
            message_size,
            symbol_size: self.symbol_size,
            source_symbols,
            repair_symbols: self.repair_overhead,
            total_symbols,
            padding,
        })
    }
}

/// The per-message erasure-coding plan derived from a message size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockLayout {
    /// Original message length, in bytes.
    pub message_size: usize,
    /// Bytes per symbol.
    pub symbol_size: u16,
    /// Source symbols holding the message (`K`).
    pub source_symbols: u16,
    /// Repair symbols added for loss tolerance.
    pub repair_symbols: u16,
    /// Total symbols transmitted (`N = K + repair`).
    pub total_symbols: u16,
    /// Padding bytes in the final source symbol.
    pub padding: usize,
}

impl BlockLayout {
    /// The fraction of transmitted symbols that may be lost while still (per
    /// RaptorQ theory, ignoring the small decode-overhead epsilon) permitting
    /// reconstruction: `repair / total`.
    #[must_use]
    pub fn loss_margin(&self) -> f64 {
        if self.total_symbols == 0 {
            return 0.0;
        }
        f64::from(self.repair_symbols) / f64::from(self.total_symbols)
    }

    /// The theoretical minimum number of symbols a receiver must collect to
    /// reconstruct the message (`K`). Real RaptorQ decoding may need a few more;
    /// that small overhead is accounted for by the repair budget.
    #[must_use]
    pub const fn min_symbols_to_decode(&self) -> u16 {
        self.source_symbols
    }
}

/// The fixed-size header that precedes a message's symbols on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageHeader {
    /// Per-sender message identifier (drives per-sender FIFO recv ordering).
    pub message_id: u64,
    /// Original message length, in bytes.
    pub message_size: u32,
    /// Bytes per symbol.
    pub symbol_size: u16,
    /// Source symbols (`K`).
    pub source_symbols: u16,
    /// Total symbols (`N`).
    pub total_symbols: u16,
}

impl MessageHeader {
    /// The fixed encoded length of a header, in bytes.
    pub const ENCODED_LEN: usize = 8 + 4 + 2 + 2 + 2;

    /// Builds a header for `message_id` from a planned [`BlockLayout`].
    ///
    /// Returns [`EcError::SymbolCountOverflow`] if the message size does not fit
    /// the 32-bit on-wire size field.
    pub fn from_layout(message_id: u64, layout: &BlockLayout) -> Result<Self, EcError> {
        let message_size =
            u32::try_from(layout.message_size).map_err(|_| EcError::SymbolCountOverflow)?;
        Ok(Self {
            message_id,
            message_size,
            symbol_size: layout.symbol_size,
            source_symbols: layout.source_symbols,
            total_symbols: layout.total_symbols,
        })
    }

    /// Encodes the header to its fixed-size little-endian byte form.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0..8].copy_from_slice(&self.message_id.to_le_bytes());
        out[8..12].copy_from_slice(&self.message_size.to_le_bytes());
        out[12..14].copy_from_slice(&self.symbol_size.to_le_bytes());
        out[14..16].copy_from_slice(&self.source_symbols.to_le_bytes());
        out[16..18].copy_from_slice(&self.total_symbols.to_le_bytes());
        out
    }

    /// Decodes a header from the front of `bytes`.
    pub fn decode(bytes: &[u8]) -> Result<Self, EcError> {
        if bytes.len() < Self::ENCODED_LEN {
            return Err(EcError::ShortHeader {
                got: bytes.len(),
                need: Self::ENCODED_LEN,
            });
        }
        let message_id = u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes"));
        let message_size = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes"));
        let symbol_size = u16::from_le_bytes(bytes[12..14].try_into().expect("2 bytes"));
        let source_symbols = u16::from_le_bytes(bytes[14..16].try_into().expect("2 bytes"));
        let total_symbols = u16::from_le_bytes(bytes[16..18].try_into().expect("2 bytes"));
        Ok(Self {
            message_id,
            message_size,
            symbol_size,
            source_symbols,
            total_symbols,
        })
    }
}

/// Errors from erasure-channel configuration, planning, and framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcError {
    /// `symbol_size` was zero.
    ZeroSymbolSize,
    /// `max_message_size` was zero.
    ZeroMaxMessage,
    /// A message exceeded the configured single-block maximum.
    MessageTooLarge {
        /// The offending message size.
        size: usize,
        /// The configured maximum.
        max: usize,
    },
    /// The plan/header would exceed the 16-/32-bit on-wire count space.
    SymbolCountOverflow,
    /// A buffer was too short to contain a [`MessageHeader`].
    ShortHeader {
        /// Bytes available.
        got: usize,
        /// Bytes required.
        need: usize,
    },
}

impl fmt::Display for EcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSymbolSize => write!(f, "symbol_size must be >= 1"),
            Self::ZeroMaxMessage => write!(f, "max_message_size must be >= 1"),
            Self::MessageTooLarge { size, max } => {
                write!(f, "message of {size} bytes exceeds the {max}-byte block maximum")
            }
            Self::SymbolCountOverflow => {
                write!(f, "erasure block layout exceeds the on-wire symbol-count space")
            }
            Self::ShortHeader { got, need } => {
                write!(f, "message header needs {need} bytes, got {got}")
            }
        }
    }
}

impl std::error::Error for EcError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_validation() {
        assert!(EcConfig::default().validate().is_ok());
        assert_eq!(
            EcConfig {
                symbol_size: 0,
                ..EcConfig::default()
            }
            .validate(),
            Err(EcError::ZeroSymbolSize)
        );
        assert_eq!(
            EcConfig {
                max_message_size: 0,
                ..EcConfig::default()
            }
            .validate(),
            Err(EcError::ZeroMaxMessage)
        );
    }

    #[test]
    fn small_message_is_one_source_symbol() {
        let cfg = EcConfig {
            symbol_size: 1024,
            repair_overhead: 4,
            max_message_size: 1 << 20,
        };
        let layout = cfg.plan(10).expect("plan");
        assert_eq!(layout.source_symbols, 1);
        assert_eq!(layout.repair_symbols, 4);
        assert_eq!(layout.total_symbols, 5);
        assert_eq!(layout.padding, 1014);
    }

    #[test]
    fn exact_multiple_has_no_padding() {
        let cfg = EcConfig {
            symbol_size: 100,
            repair_overhead: 2,
            max_message_size: 1 << 20,
        };
        let layout = cfg.plan(300).expect("plan");
        assert_eq!(layout.source_symbols, 3);
        assert_eq!(layout.total_symbols, 5);
        assert_eq!(layout.padding, 0);
    }

    #[test]
    fn non_multiple_pads_final_symbol() {
        let cfg = EcConfig {
            symbol_size: 100,
            repair_overhead: 1,
            max_message_size: 1 << 20,
        };
        let layout = cfg.plan(250).expect("plan");
        assert_eq!(layout.source_symbols, 3); // ceil(250/100)
        assert_eq!(layout.padding, 50); // 300 - 250
    }

    #[test]
    fn empty_message_still_gets_one_symbol() {
        let layout = EcConfig::default().plan(0).expect("plan");
        assert_eq!(layout.source_symbols, 1);
    }

    #[test]
    fn message_too_large_rejected() {
        let cfg = EcConfig {
            symbol_size: 16,
            repair_overhead: 2,
            max_message_size: 100,
        };
        assert_eq!(
            cfg.plan(101),
            Err(EcError::MessageTooLarge {
                size: 101,
                max: 100
            })
        );
    }

    #[test]
    fn loss_margin_matches_overhead_fraction() {
        let cfg = EcConfig {
            symbol_size: 100,
            repair_overhead: 5,
            max_message_size: 1 << 20,
        };
        let layout = cfg.plan(500).expect("plan"); // K=5, N=10
        assert_eq!(layout.total_symbols, 10);
        assert!((layout.loss_margin() - 0.5).abs() < 1e-9);
        assert_eq!(layout.min_symbols_to_decode(), 5);
    }

    #[test]
    fn header_roundtrips() {
        let cfg = EcConfig::default();
        let layout = cfg.plan(5000).expect("plan");
        let header = MessageHeader::from_layout(7, &layout).expect("header");
        let bytes = header.encode();
        assert_eq!(bytes.len(), MessageHeader::ENCODED_LEN);
        let decoded = MessageHeader::decode(&bytes).expect("decode");
        assert_eq!(decoded, header);
        assert_eq!(decoded.message_id, 7);
        assert_eq!(decoded.message_size, 5000);
    }

    #[test]
    fn header_decode_rejects_short_buffer() {
        let result = MessageHeader::decode(&[0u8; 4]);
        assert_eq!(
            result,
            Err(EcError::ShortHeader {
                got: 4,
                need: MessageHeader::ENCODED_LEN
            })
        );
    }
}
