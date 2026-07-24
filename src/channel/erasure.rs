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
//! - [`SymbolFrame`]: the lightweight per-symbol wire frame (`message_id` +
//!   `esi` + payload) that a lossy transport drops, reorders, or duplicates one
//!   at a time.
//! - [`MessageReassembler`]: the receive-side intake state machine that
//!   deduplicates and reorders incoming symbols and reports decode readiness
//!   against the [`BlockLayout`] — the pure core of the symbol aggregator.
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

use std::collections::{HashMap, VecDeque};
use std::fmt;

use crate::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use crate::config::EncodingConfig;
use crate::cx::Cx;
use crate::decoding::{DecodingConfig, DecodingPipeline, RejectReason, SymbolAcceptResult};
use crate::encoding::EncodingPipeline;
use crate::security::{AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use crate::types::resource::{PoolConfig, SymbolPool};
use crate::types::{ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind};
use crate::util::DetRng;
use sha2::{Digest, Sha256};

const AUTHENTICATED_HEADER_DOMAIN: &[u8] =
    b"asupersync::channel::erasure::authenticated-header::v1";
const TRANSFER_DIGEST_DOMAIN: &[u8] = b"asupersync::channel::erasure::transfer-digest::v1";
const SYMBOL_BINDING_DOMAIN: &[u8] = b"asupersync::channel::erasure::symbol-binding::v1";

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

    /// Erasure-encodes `message` into its symbol frames using the runtime
    /// RaptorQ encoder.
    ///
    /// The message is encoded as a single source block (`message.len()` must be
    /// within [`max_message_size`](Self::max_message_size)) into `source + repair`
    /// symbols, each wrapped as a [`SymbolFrame`] under `message_id`. The
    /// returned [`EncodedMessage`] carries a [`MessageHeader`] whose
    /// `source_symbols`/`total_symbols` reflect the encoder's *actual* output
    /// (the systematic RaptorQ block geometry), so the receiver plans its decode
    /// against ground truth rather than the pre-flight [`plan`](Self::plan)
    /// estimate.
    ///
    /// # Errors
    ///
    /// Returns [`EcError::MessageTooLarge`] / config errors from
    /// [`plan`](Self::plan), [`EcError::SymbolCountOverflow`] if the symbol count
    /// or an ESI exceeds the on-wire space, or [`EcError::Coding`] if the encoder
    /// reports an error or the message spans more than one source block.
    pub fn encode_message(
        &self,
        message_id: u64,
        message: &[u8],
    ) -> Result<EncodedMessage, EcError> {
        let planned = self.plan(message.len())?;
        let enc_config = EncodingConfig {
            symbol_size: self.symbol_size,
            max_block_size: self.max_message_size,
            ..EncodingConfig::default()
        };
        let mut pipeline =
            EncodingPipeline::new(enc_config, SymbolPool::new(PoolConfig::default()));
        let object_id = ObjectId::new(message_id, 0);
        let repair_count = self.repair_overhead as usize;

        let mut frames = Vec::new();
        let mut source_symbols: u16 = 0;
        for result in pipeline.encode_with_repair(object_id, message, repair_count) {
            let symbol = result.map_err(|e| EcError::Coding(e.to_string()))?;
            if symbol.id().sbn() != 0 {
                return Err(EcError::Coding(
                    "message spans more than one source block".to_string(),
                ));
            }
            let esi = u16::try_from(symbol.id().esi()).map_err(|_| EcError::SymbolCountOverflow)?;
            if symbol.kind().is_source() {
                source_symbols = source_symbols
                    .checked_add(1)
                    .ok_or(EcError::SymbolCountOverflow)?;
            }
            frames.push(SymbolFrame::new(
                message_id,
                esi,
                symbol.symbol().data().to_vec(),
            ));
        }

        let total_symbols = if message.is_empty() {
            planned.total_symbols
        } else {
            u16::try_from(frames.len()).map_err(|_| EcError::SymbolCountOverflow)?
        };
        if message.is_empty() {
            source_symbols = planned.source_symbols;
        }
        let message_size =
            u32::try_from(message.len()).map_err(|_| EcError::SymbolCountOverflow)?;
        let header = MessageHeader {
            message_id,
            message_size,
            symbol_size: self.symbol_size,
            source_symbols,
            total_symbols,
        };
        header.validate()?;
        Ok(EncodedMessage { header, frames })
    }

    /// Like [`encode_message`](Self::encode_message) but signs every symbol with
    /// `auth`, returning the header and the signed [`AuthenticatedSymbol`]s for
    /// the per-symbol-authenticated channel path (Byzantine-injection
    /// resistance).
    ///
    /// A receiver holding the same [`SecurityContext`] key
    /// ([`decode_message_authenticated`]) verifies each symbol before decoding;
    /// forged, tampered, or wrong-key symbols fail verification and are rejected,
    /// while the authentic survivors still decode within the repair budget.
    ///
    /// # Errors
    ///
    /// As [`encode_message`](Self::encode_message).
    pub fn encode_message_authenticated(
        &self,
        message_id: u64,
        message: &[u8],
        auth: &SecurityContext,
    ) -> Result<(AuthenticatedMessageHeader, Vec<AuthenticatedSymbol>), EcError> {
        let planned = self.plan(message.len())?;
        let enc_config = EncodingConfig {
            symbol_size: self.symbol_size,
            max_block_size: self.max_message_size,
            ..EncodingConfig::default()
        };
        let mut pipeline =
            EncodingPipeline::new(enc_config, SymbolPool::new(PoolConfig::default()));
        let object_id = ObjectId::new(message_id, 0);
        let repair_count = self.repair_overhead as usize;

        let mut raw_symbols = Vec::new();
        let mut source_symbols: u16 = 0;
        for result in pipeline.encode_with_repair(object_id, message, repair_count) {
            let symbol = result.map_err(|e| EcError::Coding(e.to_string()))?;
            if symbol.id().sbn() != 0 {
                return Err(EcError::Coding(
                    "message spans more than one source block".to_string(),
                ));
            }
            if symbol.kind().is_source() {
                source_symbols = source_symbols
                    .checked_add(1)
                    .ok_or(EcError::SymbolCountOverflow)?;
            }
            raw_symbols.push(symbol.symbol().clone());
        }

        let total_symbols = if message.is_empty() {
            planned.total_symbols
        } else {
            u16::try_from(raw_symbols.len()).map_err(|_| EcError::SymbolCountOverflow)?
        };
        if message.is_empty() {
            source_symbols = planned.source_symbols;
        }
        let message_size =
            u32::try_from(message.len()).map_err(|_| EcError::SymbolCountOverflow)?;
        let header = MessageHeader {
            message_id,
            message_size,
            symbol_size: self.symbol_size,
            source_symbols,
            total_symbols,
        };
        let authenticated_header = AuthenticatedMessageHeader::sign(header, message, auth)?;
        let symbol_context = authenticated_header.symbol_context(auth);
        let symbols = raw_symbols
            .iter()
            .map(|symbol| symbol_context.sign_symbol(symbol))
            .collect();
        Ok((authenticated_header, symbols))
    }
}

/// A message encoded into its erasure symbol frames plus the [`MessageHeader`]
/// a receiver needs to plan and perform the decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedMessage {
    /// The header describing the message geometry (reflects the encoder's actual
    /// `K`/`N`, not the pre-flight estimate).
    pub header: MessageHeader,
    /// The encoded symbol frames (`source + repair`), in emission order.
    pub frames: Vec<SymbolFrame>,
}

/// Reconstructs the original message bytes from a set of collected
/// [`SymbolFrame`]s using the runtime RaptorQ decoder.
///
/// `header` is the message's [`MessageHeader`] (typically delivered alongside or
/// recovered from [`MessageHeader::decode`]); `frames` are the symbols a
/// [`MessageReassembler`] collected. Decoding is erasure-only here (per-symbol
/// authentication is enforced by the layer above); a symbol's source/repair role
/// is recovered from its `esi` relative to `header.source_symbols`. Tolerates up
/// to the repair budget of lost symbols, modulo the small RaptorQ decode-overhead
/// epsilon the budget absorbs.
///
/// # Errors
///
/// Returns [`EcError::IncompleteDecode`] if too few usable symbols survived to
/// reconstruct the block, or [`EcError::Coding`] if the decoder rejects a symbol
/// or fails to finalize.
pub fn decode_message(header: &MessageHeader, frames: &[SymbolFrame]) -> Result<Vec<u8>, EcError> {
    header.validate()?;
    if header.message_size == 0 {
        // A zero-length message carries no data symbols; the empty payload is
        // fully described by the header.
        return Ok(Vec::new());
    }
    let object_id = ObjectId::new(header.message_id, 0);
    let source_symbols = header.source_symbols;

    let mut config = DecodingConfig::without_auth();
    config.symbol_size = header.symbol_size;
    config.max_block_size = usize::from(source_symbols) * usize::from(header.symbol_size);
    // Let `set_object_params` size the per-block accept cap from K. Keeping
    // `DecodingConfig`'s fixed 8192-symbol default here silently rejects every
    // later source symbol for otherwise-valid larger blocks, so a lossless
    // K=8193 message can never complete.
    config.max_buffered_symbols = 0;

    let mut decoder = DecodingPipeline::new(config);
    decoder
        .set_object_params(ObjectParams {
            object_id,
            object_size: u64::from(header.message_size),
            symbol_size: header.symbol_size,
            source_blocks: 1,
            symbols_per_block: source_symbols,
        })
        .map_err(|e| EcError::Coding(e.to_string()))?;

    let block_accept_cap = decoder.block_accept_cap();
    if block_accept_cap != 0 && block_accept_cap < usize::from(source_symbols) {
        return Err(EcError::Coding(format!(
            "decoder block accept cap {block_accept_cap} is below source symbol count {source_symbols}"
        )));
    }

    for frame in frames {
        if decoder.is_complete() {
            break;
        }
        let kind = if frame.esi < source_symbols {
            SymbolKind::Source
        } else {
            SymbolKind::Repair
        };
        let symbol = Symbol::new(
            SymbolId::new(object_id, 0, u32::from(frame.esi)),
            frame.payload.clone(),
            kind,
        );
        let outcome = decoder
            .feed(AuthenticatedSymbol::new_unauthenticated(symbol))
            .map_err(|e| EcError::Coding(e.to_string()))?;
        match outcome {
            // RaptorQ may need a later repair symbol to close an otherwise
            // valid rank deficit, so this rejection is explicitly retryable.
            SymbolAcceptResult::Rejected(RejectReason::InsufficientRank) => {}
            // Defensive only: the completion check above normally prevents an
            // already-decoded block from seeing another frame.
            SymbolAcceptResult::Rejected(RejectReason::BlockAlreadyDecoded) => break,
            SymbolAcceptResult::Rejected(reason) => {
                return Err(EcError::Coding(format!(
                    "decoder rejected symbol {}: {reason:?}",
                    frame.esi
                )));
            }
            _ => {}
        }
    }

    if !decoder.is_complete() {
        return Err(EcError::IncompleteDecode {
            needed: source_symbols,
        });
    }
    decoder
        .into_data()
        .map_err(|e| EcError::Coding(e.to_string()))
}

/// Reconstructs a message from per-symbol-authenticated symbols, verifying every
/// symbol against `auth` before it contributes to the decode (the AC3
/// Byzantine-injection-resistant path).
///
/// Built with a fail-closed [`DecodingPipeline::with_auth`]: a symbol whose tag
/// does not verify under `auth`'s key is rejected and never poisons the decode,
/// so a wrong-key or forged symbol cannot inject data, and an authentic transfer
/// still reconstructs from the symbols that pass.
///
/// # Errors
///
/// [`EcError::IncompleteDecode`] if too few symbols authenticated to reconstruct
/// the block (e.g. the wrong key, so none pass), or [`EcError::Coding`] if the
/// decoder rejects a symbol or fails to finalize.
pub fn decode_message_authenticated(
    authenticated_header: &AuthenticatedMessageHeader,
    symbols: &[AuthenticatedSymbol],
    auth: &SecurityContext,
) -> Result<Vec<u8>, EcError> {
    authenticated_header.verify(auth)?;
    let header = &authenticated_header.header;
    if header.message_size == 0 {
        authenticated_header.verify_decoded_payload(&[])?;
        return Ok(Vec::new());
    }
    let object_id = ObjectId::new(header.message_id, 0);
    let source_symbols = header.source_symbols;

    let config = DecodingConfig {
        symbol_size: header.symbol_size,
        max_block_size: usize::from(source_symbols) * usize::from(header.symbol_size),
        // Size the per-block accept cap to K via `set_object_params` rather than
        // the fixed 8192 default, which would reject legitimately-received
        // symbols (and never decode) for a message with K > 8192 source symbols.
        max_buffered_symbols: 0,
        ..DecodingConfig::default()
    };

    let mut decoder =
        DecodingPipeline::with_auth(config, authenticated_header.symbol_context(auth));
    decoder
        .set_object_params(ObjectParams {
            object_id,
            object_size: u64::from(header.message_size),
            symbol_size: header.symbol_size,
            source_blocks: 1,
            symbols_per_block: source_symbols,
        })
        .map_err(|e| EcError::Coding(e.to_string()))?;

    for symbol in symbols {
        decoder
            .feed(symbol.clone())
            .map_err(|e| EcError::Coding(e.to_string()))?;
    }

    if !decoder.is_complete() {
        return Err(EcError::IncompleteDecode {
            needed: source_symbols,
        });
    }
    let decoded = decoder
        .into_data()
        .map_err(|e| EcError::Coding(e.to_string()))?;
    authenticated_header.verify_decoded_payload(&decoded)?;
    Ok(decoded)
}

/// A unit on the erasure channel's in-memory symbol transport: either a message
/// header (announcing a message's decode geometry) or a single symbol frame of
/// that message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireUnit {
    /// Announces a message and the geometry a receiver decodes it against.
    Header(MessageHeader),
    /// One erasure symbol of a previously-announced message.
    Symbol(SymbolFrame),
}

/// Creates a connected erasure-coded channel: an [`EcSender`] that encodes
/// messages into symbols and an [`EcReceiver`] that reassembles and decodes
/// them.
///
/// The channel endpoints are joined by an in-memory reliable, ordered symbol
/// transport.
///
/// The transport here is loss-free (an unbounded in-memory queue), so this is
/// the channel-shaped *composition* — the substrate a lossy transport (UDP
/// fan-out, datagrams) or a seeded [`LossModel`] plugs into at the symbol-frame
/// boundary. The send obligation resolves at symbol flush (handoff to the
/// transport), per the module's recorded obligation-semantics decision; `recv`
/// is async and yields a message once enough of its symbols have arrived.
#[must_use]
pub fn channel(config: EcConfig) -> (EcSender, EcReceiver) {
    let (tx, rx) = unbounded_channel();
    (
        EcSender {
            config,
            tx,
            next_message_id: 0,
        },
        EcReceiver {
            rx,
            pending: HashMap::new(),
            pending_order: VecDeque::new(),
            max_pending: DEFAULT_MAX_PENDING_MESSAGES,
        },
    )
}

/// The sending half of an erasure-coded channel.
pub struct EcSender {
    config: EcConfig,
    tx: UnboundedSender<WireUnit>,
    next_message_id: u64,
}

impl EcSender {
    /// Encodes `message` and flushes its header and symbol frames to the
    /// transport, returning the per-sender message id assigned to it.
    ///
    /// Cancel-correct: if `cx` is already cancelled the message is neither
    /// encoded nor flushed, so nothing partial ever reaches the transport. The
    /// send obligation resolves once every symbol is handed to the transport —
    /// not at receiver decode.
    ///
    /// # Errors
    ///
    /// [`EcError::Cancelled`] if `cx` is cancelled, [`EcError::TransportClosed`]
    /// if the receiver has been dropped, or an encode error from
    /// [`EcConfig::encode_message`].
    pub fn send(&mut self, cx: &Cx, message: &[u8]) -> Result<u64, EcError> {
        cx.checkpoint().map_err(|_| EcError::Cancelled)?;
        let message_id = self.next_message_id;
        let encoded = self.config.encode_message(message_id, message)?;
        self.tx
            .send(WireUnit::Header(encoded.header))
            .map_err(|_| EcError::TransportClosed)?;
        for frame in encoded.frames {
            self.tx
                .send(WireUnit::Symbol(frame))
                .map_err(|_| EcError::TransportClosed)?;
        }
        self.next_message_id = self.next_message_id.wrapping_add(1);
        Ok(message_id)
    }

    /// Serializes `value` and sends it as one erasure-coded message, returning
    /// its per-sender message id.
    ///
    /// This is the typed convenience over [`send`](Self::send): the value is
    /// serialized to bytes (JSON), then erasure-coded and flushed exactly like a
    /// raw byte message. A receiver recovers it with
    /// [`EcReceiver::recv_value`].
    ///
    /// # Errors
    ///
    /// [`EcError::Serialization`] if `value` cannot be serialized, plus any error
    /// from [`send`](Self::send).
    pub fn send_value<T: serde::Serialize>(&mut self, cx: &Cx, value: &T) -> Result<u64, EcError> {
        let bytes = serde_json::to_vec(value).map_err(|e| EcError::Serialization(e.to_string()))?;
        self.send(cx, &bytes)
    }
}

/// Default upper bound on the number of partially-received (not-yet-decodable)
/// messages an [`EcReceiver`] retains for reassembly at once.
///
/// Incomplete messages — ones that never collect their `K` distinct source
/// symbols because the (intended) lossy transport dropped too many, or because
/// the sender abandoned or was cancelled mid-message — are otherwise never
/// evicted (they never become "ready"). Without a bound, a lossy or hostile
/// sender could grow the reassembly map without limit and exhaust memory. When
/// the bound is reached, admitting a new message evicts the oldest still-pending
/// one (FIFO). Worst-case retained memory is bounded by
/// `max_pending * EcConfig::max_message_size`.
const DEFAULT_MAX_PENDING_MESSAGES: usize = 1024;

/// The receiving half of an erasure-coded channel.
pub struct EcReceiver {
    rx: UnboundedReceiver<WireUnit>,
    pending: HashMap<u64, (MessageHeader, MessageReassembler)>,
    /// Insertion order of the keys currently in `pending`, used to evict the
    /// oldest still-incomplete message once `max_pending` is reached. Kept in
    /// exact sync with `pending`'s key set (push on admit, remove on
    /// decode/evict).
    pending_order: VecDeque<u64>,
    /// Cap on `pending.len()` (see [`DEFAULT_MAX_PENDING_MESSAGES`]).
    max_pending: usize,
}

impl EcReceiver {
    /// Awaits and returns the bytes of the next fully-decoded message.
    ///
    /// Ingests transport units, routing each symbol to its message's
    /// [`MessageReassembler`]; once a message has collected enough distinct
    /// symbols it is decoded and its bytes returned. Per-sender FIFO order
    /// follows the ordered transport.
    ///
    /// # Errors
    ///
    /// [`EcError::TransportClosed`] if the transport closes before a message
    /// completes, or a decode error from [`decode_message`].
    pub async fn recv(&mut self, cx: &Cx) -> Result<Vec<u8>, EcError> {
        loop {
            let unit = self
                .rx
                .recv(cx)
                .await
                .map_err(|_| EcError::TransportClosed)?;
            let message_id = self.ingest_unit(unit);
            // Check readiness after EITHER a header or a symbol: a zero-source
            // (empty) message is decodable the moment its header arrives, with no
            // symbols of its own.
            if let Some(bytes) = self.try_complete(message_id)? {
                return Ok(bytes);
            }
        }
    }

    /// Routes one transport unit into the reassembly map and returns its message
    /// id (so the caller can attempt completion).
    ///
    /// A header for a not-yet-seen message admits a fresh
    /// [`MessageReassembler`]; if `pending` is already at `max_pending`, the
    /// oldest still-incomplete message is evicted first (FIFO) so an
    /// incomplete-message flood — intrinsic to a lossy transport, or producible
    /// by a hostile sender — cannot grow the buffer without bound. A symbol for
    /// an unknown id (no header yet, or already decoded/evicted) is dropped.
    fn ingest_unit(&mut self, unit: WireUnit) -> u64 {
        match unit {
            WireUnit::Header(header) => {
                let id = header.message_id;
                if !self.pending.contains_key(&id) {
                    while self.pending.len() >= self.max_pending {
                        match self.pending_order.pop_front() {
                            Some(oldest) => {
                                self.pending.remove(&oldest);
                            }
                            None => break,
                        }
                    }
                    let reassembler = MessageReassembler::new(&header);
                    self.pending.insert(id, (header, reassembler));
                    self.pending_order.push_back(id);
                }
                id
            }
            WireUnit::Symbol(frame) => {
                if let Some((_, reassembler)) = self.pending.get_mut(&frame.message_id) {
                    let _ = reassembler.accept_frame(&frame);
                }
                frame.message_id
            }
        }
    }

    /// Decodes and removes `message_id` if its reassembler has collected enough
    /// distinct symbols; returns `Ok(None)` if it is not yet decodable or
    /// unknown.
    fn try_complete(&mut self, message_id: u64) -> Result<Option<Vec<u8>>, EcError> {
        let Some((header, reassembler)) = self.pending.get(&message_id) else {
            return Ok(None);
        };
        if !reassembler.is_ready() {
            return Ok(None);
        }
        let header = *header;
        let held: Vec<SymbolFrame> = reassembler
            .symbols()
            .map(|(esi, bytes)| SymbolFrame::new(header.message_id, esi, bytes.to_vec()))
            .collect();
        let bytes = decode_message(&header, &held)?;
        self.pending.remove(&message_id);
        // Keep the eviction index in sync with `pending`'s key set.
        self.pending_order.retain(|&id| id != message_id);
        Ok(Some(bytes))
    }

    /// Awaits the next message and deserializes it into a `T`.
    ///
    /// The typed counterpart to [`recv`](Self::recv) / [`EcSender::send_value`]:
    /// recovers the message bytes through the erasure decode, then deserializes
    /// them (from JSON) into `T`.
    ///
    /// # Errors
    ///
    /// Any error from [`recv`](Self::recv), or [`EcError::Serialization`] if the
    /// recovered bytes do not deserialize into `T`.
    pub async fn recv_value<T: serde::de::DeserializeOwned>(
        &mut self,
        cx: &Cx,
    ) -> Result<T, EcError> {
        let bytes = self.recv(cx).await?;
        serde_json::from_slice(&bytes).map_err(|e| EcError::Serialization(e.to_string()))
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

    /// Whether a receiver holding `distinct_received` distinct symbols may
    /// attempt a decode — true once it has at least `K`
    /// ([`min_symbols_to_decode`](Self::min_symbols_to_decode)).
    ///
    /// This is the theoretical RaptorQ bound; a real decode may need a few more
    /// symbols (the small decode-overhead epsilon the repair budget absorbs),
    /// so the async receiver re-attempts as further symbols arrive.
    #[must_use]
    pub const fn is_decodable(&self, distinct_received: u16) -> bool {
        distinct_received >= self.source_symbols
    }

    /// How many more distinct symbols a receiver holding `distinct_received`
    /// must still collect before a decode can be attempted — `0` once
    /// [`is_decodable`](Self::is_decodable) holds.
    #[must_use]
    pub const fn symbols_until_decodable(&self, distinct_received: u16) -> u16 {
        self.source_symbols.saturating_sub(distinct_received)
    }

    /// Whether `distinct_lost` permanently lost symbols put a decode out of
    /// reach: even collecting every symbol still in flight could not reach the
    /// `K` needed. Equivalent to losing more than the repair budget
    /// (`distinct_lost > repair_symbols`), the count complement of
    /// [`loss_margin`](Self::loss_margin).
    #[must_use]
    pub const fn is_unrecoverable(&self, distinct_lost: u16) -> bool {
        distinct_lost > self.repair_symbols
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
        let header = Self {
            message_id,
            message_size,
            symbol_size: layout.symbol_size,
            source_symbols: layout.source_symbols,
            total_symbols: layout.total_symbols,
        };
        header.validate()?;
        Ok(header)
    }

    /// Validates the exact single-block geometry before it can influence decode
    /// allocation or empty-message shortcuts.
    pub fn validate(&self) -> Result<(), EcError> {
        if self.symbol_size == 0 {
            return Err(EcError::InvalidHeader {
                reason: "symbol_size must be non-zero",
            });
        }
        if self.source_symbols == 0 {
            return Err(EcError::InvalidHeader {
                reason: "source_symbols must be non-zero",
            });
        }
        if self.total_symbols < self.source_symbols {
            return Err(EcError::InvalidHeader {
                reason: "total_symbols must be at least source_symbols",
            });
        }
        let expected_source = usize::try_from(self.message_size)
            .expect("u32 fits usize on supported targets")
            .div_ceil(usize::from(self.symbol_size))
            .max(1);
        if expected_source != usize::from(self.source_symbols) {
            return Err(EcError::InvalidHeader {
                reason: "message_size does not match source-symbol geometry",
            });
        }
        Ok(())
    }

    /// Reconstructs the [`BlockLayout`] a receiver should plan against from
    /// this header — the inverse of [`from_layout`](Self::from_layout): the
    /// layout that produced a header round-trips back to an equal layout.
    ///
    /// Padding is recomputed from the symbol geometry (`source_symbols *
    /// symbol_size - message_size`) and the repair count from `total_symbols -
    /// source_symbols`, so the receiver can reason about loss margin and decode
    /// progress before any symbol arrives, without trusting a padding field on
    /// the wire.
    #[must_use]
    pub fn block_layout(&self) -> BlockLayout {
        let symbol_size = self.symbol_size as usize;
        let source = self.source_symbols as usize;
        let message_size = self.message_size as usize;
        let padding = source
            .saturating_mul(symbol_size)
            .saturating_sub(message_size);
        BlockLayout {
            message_size,
            symbol_size: self.symbol_size,
            source_symbols: self.source_symbols,
            repair_symbols: self.total_symbols.saturating_sub(self.source_symbols),
            total_symbols: self.total_symbols,
            padding,
        }
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
        let header = Self {
            message_id,
            message_size,
            symbol_size,
            source_symbols,
            total_symbols,
        };
        header.validate()?;
        Ok(header)
    }
}

/// Authenticated control envelope for one erasure-coded message.
///
/// The tag covers the exact canonical [`MessageHeader`] bytes plus a digest of
/// those bytes and the complete message payload. The same binding derives the
/// per-symbol authentication subkey, preventing valid symbols from a reused
/// `message_id` from being mixed with another transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedMessageHeader {
    /// Canonical decode geometry.
    pub header: MessageHeader,
    /// SHA-256 over the canonical header and complete message payload.
    pub transfer_digest: [u8; 32],
    /// Domain-separated HMAC over `header || transfer_digest`.
    pub authentication_tag: AuthenticationTag,
}

impl AuthenticatedMessageHeader {
    /// Fixed wire length: canonical header, transfer digest, and HMAC tag.
    pub const ENCODED_LEN: usize = MessageHeader::ENCODED_LEN + 32 + 32;

    fn sign(
        header: MessageHeader,
        message: &[u8],
        auth: &SecurityContext,
    ) -> Result<Self, EcError> {
        header.validate()?;
        let transfer_digest = Self::compute_transfer_digest(&header, message);
        let payload = Self::binding_payload(&header, &transfer_digest);
        let authentication_tag = auth.sign_domain_payload(AUTHENTICATED_HEADER_DOMAIN, &payload);
        Ok(Self {
            header,
            transfer_digest,
            authentication_tag,
        })
    }

    fn compute_transfer_digest(header: &MessageHeader, message: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(TRANSFER_DIGEST_DOMAIN);
        hasher.update(header.encode());
        hasher.update((message.len() as u64).to_le_bytes());
        hasher.update(message);
        hasher.finalize().into()
    }

    fn binding_payload(header: &MessageHeader, transfer_digest: &[u8; 32]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(MessageHeader::ENCODED_LEN + transfer_digest.len());
        payload.extend_from_slice(&header.encode());
        payload.extend_from_slice(transfer_digest);
        payload
    }

    fn symbol_context(&self, auth: &SecurityContext) -> SecurityContext {
        let binding = Self::binding_payload(&self.header, &self.transfer_digest);
        let mut purpose = Vec::with_capacity(SYMBOL_BINDING_DOMAIN.len() + binding.len());
        purpose.extend_from_slice(SYMBOL_BINDING_DOMAIN);
        purpose.extend_from_slice(&binding);
        auth.derive_context(&purpose)
    }

    fn verify(&self, auth: &SecurityContext) -> Result<(), EcError> {
        self.header.validate()?;
        let payload = Self::binding_payload(&self.header, &self.transfer_digest);
        if !auth.verify_domain_payload(
            AUTHENTICATED_HEADER_DOMAIN,
            &payload,
            &self.authentication_tag,
        ) {
            return Err(EcError::AuthenticationFailed);
        }
        Ok(())
    }

    fn verify_decoded_payload(&self, decoded: &[u8]) -> Result<(), EcError> {
        let actual = Self::compute_transfer_digest(&self.header, decoded);
        if actual != self.transfer_digest {
            return Err(EcError::AuthenticationFailed);
        }
        Ok(())
    }

    /// Encodes the authenticated envelope in canonical fixed-width form.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[..MessageHeader::ENCODED_LEN].copy_from_slice(&self.header.encode());
        out[MessageHeader::ENCODED_LEN..MessageHeader::ENCODED_LEN + 32]
            .copy_from_slice(&self.transfer_digest);
        out[MessageHeader::ENCODED_LEN + 32..].copy_from_slice(self.authentication_tag.as_bytes());
        out
    }

    /// Decodes and structurally validates an authenticated header envelope.
    /// Cryptographic verification occurs in [`decode_message_authenticated`].
    pub fn decode(bytes: &[u8]) -> Result<Self, EcError> {
        if bytes.len() < Self::ENCODED_LEN {
            return Err(EcError::ShortHeader {
                got: bytes.len(),
                need: Self::ENCODED_LEN,
            });
        }
        let header = MessageHeader::decode(&bytes[..MessageHeader::ENCODED_LEN])?;
        let transfer_digest = bytes[MessageHeader::ENCODED_LEN..MessageHeader::ENCODED_LEN + 32]
            .try_into()
            .expect("32-byte transfer digest");
        let tag_bytes = bytes[MessageHeader::ENCODED_LEN + 32..Self::ENCODED_LEN]
            .try_into()
            .expect("32-byte authentication tag");
        Ok(Self {
            header,
            transfer_digest,
            authentication_tag: AuthenticationTag::from_bytes(tag_bytes),
        })
    }
}

/// A single erasure symbol as it travels over the wire.
///
/// Each encoded symbol of a message is carried in its own frame so a lossy,
/// reordering, duplicating transport can drop, shuffle, or repeat individual
/// symbols without corrupting the others. A frame carries only what is needed
/// to route and deduplicate the symbol: the per-sender `message_id` (which
/// selects the receive-side [`MessageReassembler`] and drives per-sender FIFO
/// ordering) and the RaptorQ encoding-symbol id (`esi`, which identifies the
/// symbol within its message and is the deduplication key). The message
/// geometry (`K`/`N`/size) travels once in the [`MessageHeader`]; symbol frames
/// stay small.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolFrame {
    /// Per-sender message identifier this symbol belongs to.
    pub message_id: u64,
    /// RaptorQ encoding-symbol id within the message (the dedup key).
    pub esi: u16,
    /// The symbol bytes (`symbol_size` bytes for a well-formed symbol).
    pub payload: Vec<u8>,
}

impl SymbolFrame {
    /// Fixed bytes preceding the payload: `message_id` (8) + `esi` (2).
    pub const HEADER_LEN: usize = 8 + 2;

    /// Builds a frame for symbol `esi` of message `message_id`.
    #[must_use]
    pub const fn new(message_id: u64, esi: u16, payload: Vec<u8>) -> Self {
        Self {
            message_id,
            esi,
            payload,
        }
    }

    /// The total encoded length of this frame (fixed header + payload).
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        Self::HEADER_LEN + self.payload.len()
    }

    /// Encodes the frame to `[message_id LE][esi LE][payload..]`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&self.message_id.to_le_bytes());
        out.extend_from_slice(&self.esi.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decodes a frame from `bytes`; the payload is everything after the fixed
    /// [`HEADER_LEN`](Self::HEADER_LEN) header.
    pub fn decode(bytes: &[u8]) -> Result<Self, EcError> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(EcError::ShortFrame {
                got: bytes.len(),
                need: Self::HEADER_LEN,
            });
        }
        let message_id = u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes"));
        let esi = u16::from_le_bytes(bytes[8..10].try_into().expect("2 bytes"));
        Ok(Self {
            message_id,
            esi,
            payload: bytes[Self::HEADER_LEN..].to_vec(),
        })
    }
}

/// The outcome of offering a symbol to a [`MessageReassembler`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolAccept {
    /// A new, in-range, correctly sized symbol was stored.
    Accepted,
    /// The symbol's `esi` was already held; the reassembler keeps the first
    /// copy (later copies — including a Byzantine re-send under a different
    /// payload — are dropped; per-symbol authentication is enforced by the
    /// layer above).
    Duplicate,
    /// `esi` was not below the message's `total_symbols`, so it cannot be a
    /// symbol of this block.
    OutOfRange {
        /// The rejected encoding-symbol id.
        esi: u16,
        /// The message's symbol count (`N`); valid ids are `0..total`.
        total: u16,
    },
    /// The payload length did not equal the message's `symbol_size`.
    WrongSize {
        /// The encoding-symbol id whose payload was malformed.
        esi: u16,
        /// The payload length actually offered.
        got: usize,
        /// The required per-symbol length (`symbol_size`).
        expected: usize,
    },
    /// The frame's `message_id` did not match this reassembler's message.
    WrongMessage {
        /// The reassembler's message id.
        expected: u64,
        /// The frame's message id.
        got: u64,
    },
}

/// Receive-side intake for one message: deduplicates and reorders symbols and
/// tracks decode readiness against the message's [`BlockLayout`].
///
/// Constructed from the message's [`MessageHeader`], it accepts symbols in any
/// order, drops duplicates and malformed/out-of-range symbols, and reports when
/// enough distinct symbols have arrived to attempt a RaptorQ decode
/// ([`is_ready`](Self::is_ready)). Held symbols are retained in ascending `esi`
/// order so a later decode pass observes a deterministic, replayable symbol
/// sequence regardless of arrival order — the determinism the loss-injection
/// suite relies on. The actual RaptorQ decode is performed by the async
/// receiver layered on top; this type owns only the transport-free, pure intake
/// state machine.
#[derive(Debug, Clone)]
pub struct MessageReassembler {
    message_id: u64,
    layout: BlockLayout,
    symbols: std::collections::BTreeMap<u16, Vec<u8>>,
}

impl MessageReassembler {
    /// Creates a reassembler for the message described by `header`.
    #[must_use]
    pub fn new(header: &MessageHeader) -> Self {
        Self {
            message_id: header.message_id,
            layout: header.block_layout(),
            symbols: std::collections::BTreeMap::new(),
        }
    }

    /// The message id this reassembler collects symbols for.
    #[must_use]
    pub const fn message_id(&self) -> u64 {
        self.message_id
    }

    /// The decode plan ([`BlockLayout`]) this reassembler tracks progress
    /// against.
    #[must_use]
    pub const fn layout(&self) -> &BlockLayout {
        &self.layout
    }

    /// The number of distinct, accepted symbols currently held (never exceeds
    /// the message's `total_symbols`).
    #[must_use]
    pub fn distinct_received(&self) -> u16 {
        u16::try_from(self.symbols.len()).unwrap_or(u16::MAX)
    }

    /// Whether enough distinct symbols have arrived to attempt a decode (the
    /// theoretical `K` bound; a real decode may need the small overhead epsilon
    /// the repair budget absorbs).
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.layout.is_decodable(self.distinct_received())
    }

    /// How many more distinct symbols are needed before a decode can be
    /// attempted — `0` once [`is_ready`](Self::is_ready) holds.
    #[must_use]
    pub fn symbols_until_ready(&self) -> u16 {
        self.layout
            .symbols_until_decodable(self.distinct_received())
    }

    /// Offers a raw `(esi, payload)` symbol, deduplicating by `esi`, rejecting
    /// out-of-range ids and wrong-sized payloads, and keeping the first copy of
    /// any repeated symbol.
    #[must_use]
    pub fn accept(&mut self, esi: u16, payload: &[u8]) -> SymbolAccept {
        if esi >= self.layout.total_symbols {
            return SymbolAccept::OutOfRange {
                esi,
                total: self.layout.total_symbols,
            };
        }
        let expected = self.layout.symbol_size as usize;
        if payload.len() != expected {
            return SymbolAccept::WrongSize {
                esi,
                got: payload.len(),
                expected,
            };
        }
        if self.symbols.contains_key(&esi) {
            return SymbolAccept::Duplicate;
        }
        self.symbols.insert(esi, payload.to_vec());
        SymbolAccept::Accepted
    }

    /// Offers a decoded [`SymbolFrame`], routing it by `message_id` (a frame for
    /// a different message is rejected with [`SymbolAccept::WrongMessage`]).
    #[must_use]
    pub fn accept_frame(&mut self, frame: &SymbolFrame) -> SymbolAccept {
        if frame.message_id != self.message_id {
            return SymbolAccept::WrongMessage {
                expected: self.message_id,
                got: frame.message_id,
            };
        }
        self.accept(frame.esi, &frame.payload)
    }

    /// Iterates the held symbols in ascending `esi` order — a deterministic,
    /// arrival-order-independent sequence suitable for feeding a decode.
    pub fn symbols(&self) -> impl Iterator<Item = (u16, &[u8])> {
        self.symbols
            .iter()
            .map(|(&esi, bytes)| (esi, bytes.as_slice()))
    }
}

/// A deterministic, seeded loss/duplication model for the in-memory transport.
///
/// This drives the seeded adversity the channel's correctness story rests on
/// (AC1 loss tolerance, AC7 deterministic replay): given a fixed seed and rates
/// it decides, for each symbol frame in a stream, whether the frame is dropped
/// (lost in transit) and whether a delivered frame is duplicated (delivered more
/// than once). It is reproducible from the seed alone — the same
/// `(seed, rates, input)` always produces the same delivered sequence — so a
/// failing loss scenario replays exactly.
///
/// Rates are in parts-per-million so the decision stream stays integer and
/// platform-independent (no floating-point rounding divergence). Drop and
/// duplicate rolls are independent. The model composes with
/// [`MessageReassembler`]: feed [`apply`](Self::apply)'s output into a
/// reassembler to exercise dedup (duplicates) and the repair budget (drops).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LossModel {
    /// Probability, in parts-per-million, that a frame is dropped (not
    /// delivered). `0` never drops; `1_000_000` always drops.
    pub drop_ppm: u32,
    /// Probability, in parts-per-million, that a delivered frame is delivered a
    /// second time. `0` never duplicates; `1_000_000` always duplicates once.
    pub duplicate_ppm: u32,
    /// Seed for the deterministic decision stream.
    pub seed: u64,
}

impl LossModel {
    /// One part-per-million denominator for the integer rate rolls.
    pub const PPM_SCALE: u32 = 1_000_000;

    /// A lossless, duplication-free model with the given seed (an identity
    /// transport: [`apply`](Self::apply) returns its input unchanged).
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            drop_ppm: 0,
            duplicate_ppm: 0,
            seed,
        }
    }

    /// Sets the per-frame drop probability (parts-per-million), saturating at
    /// [`PPM_SCALE`](Self::PPM_SCALE).
    #[must_use]
    pub const fn with_drop_ppm(mut self, drop_ppm: u32) -> Self {
        self.drop_ppm = if drop_ppm > Self::PPM_SCALE {
            Self::PPM_SCALE
        } else {
            drop_ppm
        };
        self
    }

    /// Sets the per-frame duplicate probability (parts-per-million), saturating
    /// at [`PPM_SCALE`](Self::PPM_SCALE).
    #[must_use]
    pub const fn with_duplicate_ppm(mut self, duplicate_ppm: u32) -> Self {
        self.duplicate_ppm = if duplicate_ppm > Self::PPM_SCALE {
            Self::PPM_SCALE
        } else {
            duplicate_ppm
        };
        self
    }

    /// Applies the model to `frames`, returning the delivered sequence: dropped
    /// frames are omitted and duplicated frames appear twice (the duplicate
    /// directly after the original, preserving stream order otherwise).
    ///
    /// Deterministic in `(seed, rates, frames.len())`: a fresh decision stream
    /// is seeded each call, so repeated calls with the same model and input
    /// yield byte-identical output.
    #[must_use]
    pub fn apply(&self, frames: &[SymbolFrame]) -> Vec<SymbolFrame> {
        let mut rng = DetRng::new(self.seed);
        let mut delivered = Vec::with_capacity(frames.len());
        for frame in frames {
            let drop_roll = rng.next_u32() % Self::PPM_SCALE;
            if drop_roll < self.drop_ppm {
                continue;
            }
            delivered.push(frame.clone());
            let dup_roll = rng.next_u32() % Self::PPM_SCALE;
            if dup_roll < self.duplicate_ppm {
                delivered.push(frame.clone());
            }
        }
        delivered
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
    /// A decoded or caller-supplied header had impossible single-block geometry.
    InvalidHeader {
        /// Stable diagnostic for the rejected invariant.
        reason: &'static str,
    },
    /// Header, symbol binding, or reconstructed payload authentication failed.
    AuthenticationFailed,
    /// A buffer was too short to contain a [`MessageHeader`].
    ShortHeader {
        /// Bytes available.
        got: usize,
        /// Bytes required.
        need: usize,
    },
    /// A buffer was too short to contain a [`SymbolFrame`] header.
    ShortFrame {
        /// Bytes available.
        got: usize,
        /// Bytes required for the fixed frame header.
        need: usize,
    },
    /// The RaptorQ encoder or decoder reported an error (the wrapped string is
    /// the underlying coder diagnostic).
    Coding(String),
    /// Too few usable symbols survived to reconstruct the message block.
    IncompleteDecode {
        /// Source symbols (`K`) the block needs to decode.
        needed: u16,
    },
    /// The send context was cancelled before the message was flushed; nothing
    /// partial reached the transport.
    Cancelled,
    /// The channel transport was closed (the peer half was dropped).
    TransportClosed,
    /// A typed message could not be serialized or deserialized (the wrapped
    /// string is the underlying serde diagnostic).
    Serialization(String),
}

impl fmt::Display for EcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSymbolSize => write!(f, "symbol_size must be >= 1"),
            Self::ZeroMaxMessage => write!(f, "max_message_size must be >= 1"),
            Self::MessageTooLarge { size, max } => {
                write!(
                    f,
                    "message of {size} bytes exceeds the {max}-byte block maximum"
                )
            }
            Self::SymbolCountOverflow => {
                write!(
                    f,
                    "erasure block layout exceeds the on-wire symbol-count space"
                )
            }
            Self::InvalidHeader { reason } => {
                write!(f, "invalid erasure message header: {reason}")
            }
            Self::AuthenticationFailed => {
                write!(f, "erasure message authentication failed")
            }
            Self::ShortHeader { got, need } => {
                write!(f, "message header needs {need} bytes, got {got}")
            }
            Self::ShortFrame { got, need } => {
                write!(f, "symbol frame header needs {need} bytes, got {got}")
            }
            Self::Coding(detail) => write!(f, "erasure coder error: {detail}"),
            Self::IncompleteDecode { needed } => {
                write!(
                    f,
                    "insufficient symbols to decode (need {needed} source symbols)"
                )
            }
            Self::Cancelled => write!(f, "erasure channel send cancelled before flush"),
            Self::TransportClosed => write!(f, "erasure channel transport closed"),
            Self::Serialization(detail) => {
                write!(f, "erasure channel (de)serialization error: {detail}")
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

    #[test]
    fn decode_progress_predicates_track_the_repair_budget() {
        let cfg = EcConfig {
            symbol_size: 100,
            repair_overhead: 5,
            max_message_size: 1 << 20,
        };
        let layout = cfg.plan(500).expect("plan"); // K=5, N=10, repair=5
        assert_eq!(layout.source_symbols, 5);
        assert_eq!(layout.total_symbols, 10);

        // Not enough below K; decodable from exactly K onward.
        assert!(!layout.is_decodable(4));
        assert!(layout.is_decodable(5));
        assert!(layout.is_decodable(7));

        // Remaining count shrinks to zero at K and stays there.
        assert_eq!(layout.symbols_until_decodable(0), 5);
        assert_eq!(layout.symbols_until_decodable(3), 2);
        assert_eq!(layout.symbols_until_decodable(5), 0);
        assert_eq!(layout.symbols_until_decodable(9), 0);

        // Losing up to the whole repair budget stays recoverable; one more is
        // out of reach (10 - 6 = 4 < K=5).
        assert!(!layout.is_unrecoverable(5));
        assert!(layout.is_unrecoverable(6));
    }

    #[test]
    fn decode_predicates_are_self_consistent_across_the_range() {
        let cfg = EcConfig {
            symbol_size: 64,
            repair_overhead: 3,
            max_message_size: 1 << 20,
        };
        let layout = cfg.plan(400).expect("plan"); // K=ceil(400/64)=7, N=10
        let n = layout.total_symbols;

        // is_decodable iff nothing more is needed, monotone as symbols arrive.
        let mut last_remaining = u16::MAX;
        for received in 0..=n {
            let remaining = layout.symbols_until_decodable(received);
            assert_eq!(layout.is_decodable(received), remaining == 0);
            assert!(remaining <= last_remaining, "remaining must not grow");
            last_remaining = remaining;
        }

        // is_unrecoverable iff losses exceed the repair budget; the boundary is
        // exactly repair_symbols losable.
        for lost in 0..=n {
            assert_eq!(layout.is_unrecoverable(lost), lost > layout.repair_symbols);
        }
        assert!(!layout.is_unrecoverable(layout.repair_symbols));
        assert!(layout.is_unrecoverable(layout.repair_symbols + 1));
    }

    #[test]
    fn block_layout_inverts_from_layout() {
        let cfg = EcConfig::default();
        for size in [0usize, 1, 10, 1023, 1024, 1025, 5000, 65_535, 1 << 20] {
            let layout = cfg.plan(size).expect("plan");
            let header = MessageHeader::from_layout(42, &layout).expect("header");
            assert_eq!(
                header.block_layout(),
                layout,
                "block_layout must invert from_layout at size {size}"
            );
        }
    }

    #[test]
    fn block_layout_recomputes_geometry_from_header_fields() {
        // A header carries no padding/repair fields; block_layout derives both.
        let header = MessageHeader {
            message_id: 9,
            message_size: 250,
            symbol_size: 100,
            source_symbols: 3,
            total_symbols: 7,
        };
        let layout = header.block_layout();
        assert_eq!(layout.repair_symbols, 4); // 7 - 3
        assert_eq!(layout.padding, 50); // 3*100 - 250
        assert_eq!(layout.message_size, 250);
        assert_eq!(layout.min_symbols_to_decode(), 3);
    }

    fn k3_n5_header(message_id: u64) -> MessageHeader {
        // symbol_size=4, K=ceil(9/4)=3, repair=2, N=5.
        let cfg = EcConfig {
            symbol_size: 4,
            repair_overhead: 2,
            max_message_size: 1 << 20,
        };
        let layout = cfg.plan(9).expect("plan");
        assert_eq!(layout.source_symbols, 3);
        assert_eq!(layout.total_symbols, 5);
        MessageHeader::from_layout(message_id, &layout).expect("header")
    }

    #[test]
    fn symbol_frame_roundtrips() {
        let frame = SymbolFrame::new(0x00A1_B2C3_D4E5_F601, 9, vec![1, 2, 3, 4, 5]);
        assert_eq!(frame.encoded_len(), SymbolFrame::HEADER_LEN + 5);
        let bytes = frame.encode();
        assert_eq!(bytes.len(), frame.encoded_len());
        let decoded = SymbolFrame::decode(&bytes).expect("decode");
        assert_eq!(decoded, frame);
        assert_eq!(decoded.message_id, 0x00A1_B2C3_D4E5_F601);
        assert_eq!(decoded.esi, 9);
        assert_eq!(decoded.payload, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn symbol_frame_empty_payload_roundtrips() {
        let frame = SymbolFrame::new(5, 0, Vec::new());
        let bytes = frame.encode();
        assert_eq!(bytes.len(), SymbolFrame::HEADER_LEN);
        let decoded = SymbolFrame::decode(&bytes).expect("decode");
        assert_eq!(decoded, frame);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn symbol_frame_decode_rejects_short_buffer() {
        let result = SymbolFrame::decode(&[0u8; 9]);
        assert_eq!(
            result,
            Err(EcError::ShortFrame {
                got: 9,
                need: SymbolFrame::HEADER_LEN
            })
        );
    }

    #[test]
    fn reassembler_dedups_reorders_and_tracks_readiness() {
        let header = k3_n5_header(11);
        let mut ra = MessageReassembler::new(&header);
        assert_eq!(ra.message_id(), 11);
        assert_eq!(ra.layout().source_symbols, 3);
        assert_eq!(ra.distinct_received(), 0);
        assert!(!ra.is_ready());
        assert_eq!(ra.symbols_until_ready(), 3);

        // Out-of-order arrivals are accepted.
        assert_eq!(ra.accept(3, &[3, 3, 3, 3]), SymbolAccept::Accepted);
        assert_eq!(ra.accept(0, &[0, 0, 0, 0]), SymbolAccept::Accepted);
        assert_eq!(ra.distinct_received(), 2);
        assert!(!ra.is_ready());
        assert_eq!(ra.symbols_until_ready(), 1);

        // A repeated esi (even with different bytes) is a duplicate; the first
        // copy is kept and the count does not advance.
        assert_eq!(ra.accept(3, &[9, 9, 9, 9]), SymbolAccept::Duplicate);
        assert_eq!(ra.distinct_received(), 2);

        // The third distinct symbol reaches K and flips readiness.
        assert_eq!(ra.accept(4, &[4, 4, 4, 4]), SymbolAccept::Accepted);
        assert_eq!(ra.distinct_received(), 3);
        assert!(ra.is_ready());
        assert_eq!(ra.symbols_until_ready(), 0);

        // Extra symbols beyond K are still accepted (decode-overhead headroom).
        assert_eq!(ra.accept(1, &[1, 1, 1, 1]), SymbolAccept::Accepted);
        assert_eq!(ra.distinct_received(), 4);
        assert!(ra.is_ready());

        // Held symbols come back in ascending esi order regardless of arrival
        // order, and esi 3 retained its FIRST payload (not the duplicate).
        let held: Vec<(u16, Vec<u8>)> = ra.symbols().map(|(e, b)| (e, b.to_vec())).collect();
        assert_eq!(
            held,
            vec![
                (0, vec![0, 0, 0, 0]),
                (1, vec![1, 1, 1, 1]),
                (3, vec![3, 3, 3, 3]),
                (4, vec![4, 4, 4, 4]),
            ]
        );
    }

    #[test]
    fn reassembler_rejects_out_of_range_and_wrong_size() {
        let header = k3_n5_header(1);
        let mut ra = MessageReassembler::new(&header);

        // esi == total_symbols (5) is out of range; valid ids are 0..5.
        assert_eq!(
            ra.accept(5, &[0, 0, 0, 0]),
            SymbolAccept::OutOfRange { esi: 5, total: 5 }
        );
        // Payload length must equal symbol_size (4).
        assert_eq!(
            ra.accept(0, &[0, 0, 0]),
            SymbolAccept::WrongSize {
                esi: 0,
                got: 3,
                expected: 4
            }
        );
        // Rejected offers store nothing.
        assert_eq!(ra.distinct_received(), 0);
    }

    #[test]
    fn reassembler_routes_frames_by_message_id() {
        let header = k3_n5_header(100);
        let mut ra = MessageReassembler::new(&header);

        let foreign = SymbolFrame::new(200, 0, vec![0, 0, 0, 0]);
        assert_eq!(
            ra.accept_frame(&foreign),
            SymbolAccept::WrongMessage {
                expected: 100,
                got: 200
            }
        );
        assert_eq!(ra.distinct_received(), 0);

        let ours = SymbolFrame::new(100, 0, vec![7, 7, 7, 7]);
        assert_eq!(ra.accept_frame(&ours), SymbolAccept::Accepted);
        assert_eq!(ra.distinct_received(), 1);
        // Re-offering the same frame deduplicates.
        assert_eq!(ra.accept_frame(&ours), SymbolAccept::Duplicate);
        assert_eq!(ra.distinct_received(), 1);
    }

    #[test]
    fn reassembler_intake_is_arrival_order_independent() {
        // The same symbol set delivered in two different orders yields an
        // identical held sequence and identical readiness — the determinism the
        // seeded loss-injection suite relies on (AC7).
        let header = k3_n5_header(7);
        let payloads: [(u16, [u8; 4]); 3] = [(0, [10; 4]), (1, [11; 4]), (2, [12; 4])];

        let mut forward = MessageReassembler::new(&header);
        for (esi, bytes) in payloads {
            assert_eq!(forward.accept(esi, &bytes), SymbolAccept::Accepted);
        }

        let mut reversed = MessageReassembler::new(&header);
        for (esi, bytes) in payloads.iter().rev() {
            assert_eq!(reversed.accept(*esi, bytes), SymbolAccept::Accepted);
        }

        let fwd: Vec<(u16, Vec<u8>)> = forward.symbols().map(|(e, b)| (e, b.to_vec())).collect();
        let rev: Vec<(u16, Vec<u8>)> = reversed.symbols().map(|(e, b)| (e, b.to_vec())).collect();
        assert_eq!(fwd, rev);
        assert_eq!(forward.is_ready(), reversed.is_ready());
        assert!(forward.is_ready());
    }

    fn k5_n8_header(message_id: u64) -> MessageHeader {
        // symbol_size=4, K=ceil(20/4)=5, repair=3, N=8.
        let cfg = EcConfig {
            symbol_size: 4,
            repair_overhead: 3,
            max_message_size: 1 << 20,
        };
        let layout = cfg.plan(20).expect("plan");
        assert_eq!(layout.source_symbols, 5);
        assert_eq!(layout.total_symbols, 8);
        MessageHeader::from_layout(message_id, &layout).expect("header")
    }

    fn n_frames(message_id: u64, n: u16) -> Vec<SymbolFrame> {
        (0..n)
            .map(|esi| SymbolFrame::new(message_id, esi, vec![esi as u8; 4]))
            .collect()
    }

    #[test]
    fn loss_model_lossless_is_identity() {
        let frames = n_frames(1, 8);
        let delivered = LossModel::new(42).apply(&frames);
        assert_eq!(
            delivered, frames,
            "a lossless model must deliver its input verbatim"
        );
    }

    #[test]
    fn loss_model_total_drop_delivers_nothing() {
        let frames = n_frames(1, 8);
        let model = LossModel::new(42).with_drop_ppm(LossModel::PPM_SCALE);
        assert!(model.apply(&frames).is_empty());
    }

    #[test]
    fn loss_model_total_duplicate_delivers_each_twice() {
        let frames = n_frames(1, 4);
        let model = LossModel::new(42).with_duplicate_ppm(LossModel::PPM_SCALE);
        let delivered = model.apply(&frames);
        let expected: Vec<SymbolFrame> =
            frames.iter().flat_map(|f| [f.clone(), f.clone()]).collect();
        assert_eq!(
            delivered, expected,
            "every frame must be delivered exactly twice"
        );
    }

    #[test]
    fn loss_model_is_deterministic_for_a_seed() {
        let frames = n_frames(1, 8);
        let model = LossModel::new(7)
            .with_drop_ppm(300_000)
            .with_duplicate_ppm(100_000);
        // Same model, repeated application: byte-identical (AC7 replayability).
        assert_eq!(model.apply(&frames), model.apply(&frames));
        // A second model with the same seed/rates is identical to the first.
        let twin = LossModel::new(7)
            .with_drop_ppm(300_000)
            .with_duplicate_ppm(100_000);
        assert_eq!(model, twin);
        assert_eq!(model.apply(&frames), twin.apply(&frames));
    }

    #[test]
    fn loss_model_saturates_out_of_range_rates() {
        let model = LossModel::new(1)
            .with_drop_ppm(2_000_000)
            .with_duplicate_ppm(5_000_000);
        assert_eq!(model.drop_ppm, LossModel::PPM_SCALE);
        assert_eq!(model.duplicate_ppm, LossModel::PPM_SCALE);
    }

    #[test]
    fn loss_model_feeds_reassembler_respecting_repair_budget() {
        // AC1 at the intake layer: after seeded drops, the reassembler reports
        // ready iff the number lost stays within the repair budget — the count
        // complement of the loss margin — exactly tracking BlockLayout.
        let header = k5_n8_header(55);
        let frames = n_frames(55, header.total_symbols);
        let layout = header.block_layout();

        for seed in [1u64, 2, 7, 99, 12_345, 654_321] {
            let model = LossModel::new(seed).with_drop_ppm(300_000);
            let delivered = model.apply(&frames);

            let mut ra = MessageReassembler::new(&header);
            for frame in &delivered {
                let _ = ra.accept_frame(frame);
            }
            let lost = header.total_symbols - ra.distinct_received();
            assert_eq!(
                ra.is_ready(),
                !layout.is_unrecoverable(lost),
                "seed {seed}: readiness must track the repair budget (lost={lost}, repair={})",
                layout.repair_symbols
            );
        }
    }

    #[test]
    fn loss_model_duplicates_never_inflate_distinct_count() {
        // Duplicates are deduplicated by the reassembler: a heavy duplicate rate
        // with zero drops still yields exactly the distinct symbol set.
        let header = k5_n8_header(8);
        let frames = n_frames(8, header.total_symbols);
        let model = LossModel::new(3).with_duplicate_ppm(LossModel::PPM_SCALE);
        let delivered = model.apply(&frames);
        assert_eq!(delivered.len(), 2 * frames.len());

        let mut ra = MessageReassembler::new(&header);
        let mut duplicates = 0u32;
        for frame in &delivered {
            if ra.accept_frame(frame) == SymbolAccept::Duplicate {
                duplicates += 1;
            }
        }
        assert_eq!(ra.distinct_received(), header.total_symbols);
        assert_eq!(duplicates, u32::from(header.total_symbols));
        assert!(ra.is_ready());
    }

    #[test]
    fn pending_reassembly_buffer_is_bounded_with_fifo_eviction() {
        // Regression: a lossy/abandoning sender that emits headers for messages
        // that never collect their K source symbols must not grow the
        // reassembly map without bound. Feed 6 distinct headers (K=3) with NO
        // symbols, so every message stays permanently incomplete.
        let (_tx, mut rx) = channel(EcConfig::default());
        rx.max_pending = 4;
        for id in 0..6u64 {
            let _ = rx.ingest_unit(WireUnit::Header(k3_n5_header(id)));
        }
        // Capped at 4: the two oldest (ids 0,1) are evicted FIFO, the newest
        // four (2..=5) retained, and the eviction index stays in exact sync.
        assert_eq!(rx.pending.len(), 4);
        assert_eq!(rx.pending_order.len(), rx.pending.len());
        assert!(!rx.pending.contains_key(&0));
        assert!(!rx.pending.contains_key(&1));
        for id in 2..6u64 {
            assert!(rx.pending.contains_key(&id), "id {id} should be retained");
        }
    }
}
