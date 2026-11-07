//! Bounded, pull-driven HTTP content encoding.

use crate::bytes::{Buf, Bytes, BytesCursor};
use crate::cx::{CancelWakerToken, Cx};
use crate::types::CancelKind;
use super::body::{Body, Frame, HeaderMap, HeaderValue, SizeHint};
use super::compress::{
    CompressionLimitExceeded, Compressor, ContentCoding, make_compressor_with_output_limit,
};
use std::fmt;
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll};

const DEFAULT_CHUNK: usize = 16 * 1024;
const MAX_CHUNK: usize = 64 * 1024;
const POLL_STEPS: usize = 32;

/// Mandatory source and encoded-output ceilings for [`ContentEncodedBody`].
///
/// Limits count cumulative data, including codec headers, flush markers, and
/// the final footer. Neither bound can be disabled. The chunk size bounds
/// codec input quanta and emitted DATA frames, not the codec's internal
/// workspace or the size of one expansion. Standard compressors can retain
/// output up to the remaining encoded ceiling; zstd retains at most one
/// 1 MiB source frame and its encoded counterpart, plus codec workspace.
/// Allocation capacity can exceed logical byte counts. The source may retain
/// one frame, so configure its frame/queue limits separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentEncodeLimits {
    max_source_bytes: usize,
    max_encoded_bytes: usize,
    chunk_bytes: usize,
}

impl ContentEncodeLimits {
    /// Set independent cumulative source and encoded-output limits.
    #[must_use]
    pub const fn new(max_source_bytes: usize, max_encoded_bytes: usize) -> Self {
        Self { max_source_bytes, max_encoded_bytes, chunk_bytes: DEFAULT_CHUNK }
    }

    /// Set the input quantum and emitted DATA-frame ceiling, capped at 64 KiB.
    #[must_use]
    pub fn with_chunk_size(mut self, bytes: NonZeroUsize) -> Self {
        self.chunk_bytes = bytes.get().min(MAX_CHUNK);
        self
    }

    /// Maximum source data bytes, before this adapter's content coding.
    #[must_use]
    pub const fn max_source_bytes(self) -> usize { self.max_source_bytes }

    /// Maximum encoded data bytes, including framing and the final footer.
    #[must_use]
    pub const fn max_encoded_bytes(self) -> usize { self.max_encoded_bytes }

    /// Maximum codec input quantum and returned DATA-frame size.
    #[must_use]
    pub const fn chunk_size(self) -> usize { self.chunk_bytes }
}

/// Terminal failure while producing an encoded HTTP body.
#[derive(Debug)]
#[non_exhaustive]
pub enum ContentEncodeError<E> {
    /// The source failed; its original error type is preserved.
    Body(E),
    /// Codec or frame-order failure.
    Encode(io::Error),
    /// The source exceeded its cumulative byte ceiling.
    SourceLimit {
        /// Observed total, or `None` on arithmetic overflow.
        actual: Option<usize>,
        /// Configured source limit.
        limit: usize,
    },
    /// The encoded representation exceeded its cumulative byte ceiling.
    EncodedLimit {
        /// Observed total when the codec exposes it.
        actual: Option<usize>,
        /// Configured encoded-output limit.
        limit: usize,
    },
    /// An explicitly attached context was cancelled.
    Cancelled {
        /// The authoritative cancellation category.
        kind: CancelKind,
    },
}

impl<E> ContentEncodeError<E> {
    /// Whether the adapter refused its source or encoded resource ceiling.
    #[must_use]
    pub const fn is_limit_exceeded(&self) -> bool {
        matches!(self, Self::SourceLimit { .. } | Self::EncodedLimit { .. })
    }
}

impl<E: fmt::Display> fmt::Display for ContentEncodeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Body(error) => write!(f, "response body source failed: {error}"),
            Self::Encode(error) => write!(f, "content encoding failed: {error}"),
            Self::SourceLimit { actual, limit } => write!(f, "source body exceeds {limit} bytes (observed {actual:?})"),
            Self::EncodedLimit { actual, limit } => write!(f, "encoded body exceeds {limit} bytes (observed {actual:?})"),
            Self::Cancelled { kind } => write!(f, "content encoding cancelled: {kind:?}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ContentEncodeError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Body(error) => Some(error),
            Self::Encode(error) => Some(error),
            _ => None,
        }
    }
}

/// Encode a body incrementally without creating a task or another queue.
///
/// The source is polled only after pending encoded output drains. Each source
/// DATA frame is flushed without finishing the representation, so a small
/// live frame can reach the peer before source EOF. Flush boundaries trade
/// some compression ratio for latency. Zstd uses independent frames of at
/// most 1 MiB and flushes a partial frame at the same application boundary.
/// Empty input still emits a valid compressed representation.
///
/// Trailers are held until source EOF and codec finalization, then stale
/// payload digests/coding/length are removed and strong ETags are weakened.
/// Identity preserves trailer metadata. Invalid trailer order, source errors,
/// codec failures, and resource refusal never publish a successful footer or
/// terminal trailers. Bytes already delivered cannot be retracted: the
/// transport must fail the produced response rather than send a clean EOF.
///
/// Dropping this adapter immediately drops its source and codec state.
/// Dropping a polling future while retaining the adapter preserves progress.
/// [`Self::with_cx`] also wakes an otherwise parked source on cancellation.
/// See [`ContentEncodeLimits`] for the precise retained-memory contract.
#[pin_project::pin_project]
pub struct ContentEncodedBody<B: Body> {
    #[pin]
    inner: Option<B>,
    state: EncodeState<B::Data>,
    cancellation: Option<BodyCancellation>,
}

impl<B: Body> fmt::Debug for ContentEncodedBody<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContentEncodedBody")
            .field("coding", &self.state.coding)
            .field("limits", &self.state.limits)
            .field("source_bytes", &self.state.source_bytes)
            .field("encoded_bytes", &self.state.encoded_bytes)
            .field("done", &self.state.done)
            .finish_non_exhaustive()
    }
}

impl<B: Body> ContentEncodedBody<B> {
    /// Validate codec availability and construct without polling `inner`.
    pub fn new(inner: B, coding: ContentCoding, limits: ContentEncodeLimits) -> io::Result<Self> {
        let codec = Encoder::new(coding, limits)?;
        Ok(Self {
            inner: Some(inner),
            state: EncodeState {
                coding,
                limits,
                codec: Some(codec),
                source_data: None,
                pending: Bytes::new(),
                trailers: None,
                source_bytes: 0,
                encoded_bytes: 0,
                emitted_bytes: 0,
                flush_pending: false,
                source_ended: false,
                finished: false,
                done: false,
            },
            cancellation: None,
        })
    }

    /// Attach cancellation while retaining source and output progress.
    #[must_use]
    pub fn with_cx(mut self, cx: &Cx) -> Self {
        self.cancellation = Some(BodyCancellation::new(cx));
        self
    }

    /// The coding applied by this adapter.
    #[must_use]
    pub const fn coding(&self) -> ContentCoding { self.state.coding }

    /// The mandatory cumulative and chunk limits.
    #[must_use]
    pub const fn limits(&self) -> ContentEncodeLimits { self.state.limits }
}

/// Shared by the encoder and the Body-to-produced transport bridge. Every
/// owner retires only its own registration; no ambient context is minted.
pub struct BodyCancellation {
    cx: Cx,
    token: Option<CancelWakerToken>,
}

impl BodyCancellation {
    pub(crate) fn new(cx: &Cx) -> Self { Self { cx: cx.clone(), token: None } }

    pub(crate) fn register(&mut self, task: &Context<'_>) {
        self.token = Some(self.cx.refresh_cancel_waker(self.token.take(), task.waker()));
    }

    pub(crate) fn check(&self) -> Result<(), CancelKind> {
        self.cx.checkpoint().map_err(|_| {
            self.cx.cancel_reason().map_or(CancelKind::User, |reason| reason.kind())
        })
    }
}

impl Drop for BodyCancellation {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() { self.cx.clear_cancel_waker(token); }
    }
}

enum Encoder {
    Identity,
    Standard(Box<dyn Compressor>),
    #[cfg(feature = "zstd")]
    Zstd(Box<asupersync_zstd::StreamEncoder>),
}

impl Encoder {
    fn new(coding: ContentCoding, limits: ContentEncodeLimits) -> io::Result<Self> {
        if coding == ContentCoding::Identity { return Ok(Self::Identity); }
        if let Some(encoding) = coding.standard() {
            return make_compressor_with_output_limit(encoding, Some(limits.max_encoded_bytes))
                .map(Self::Standard)
                .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "content codec requires compression feature"));
        }
        #[cfg(feature = "zstd")]
        {
            let frame_size = limits.max_source_bytes.clamp(1, 1024 * 1024);
            let codec = asupersync_zstd::StreamEncoder::new(
                asupersync_zstd::EncodeParams::new(asupersync_zstd::Level::Fast), frame_size,
            ).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            Ok(Self::Zstd(Box::new(codec)))
        }
        #[cfg(not(feature = "zstd"))]
        {
            Err(io::Error::new(io::ErrorKind::Unsupported, "content codec requires zstd feature"))
        }
    }

    fn encode(&mut self, input: &[u8], _quantum: usize) -> io::Result<(usize, Bytes)> {
        match self {
            Self::Identity => unreachable!("identity uses zero-copy Buf advancement"),
            Self::Standard(codec) => {
                let mut output = Vec::new();
                codec.compress(input, &mut output)?;
                Ok((input.len(), output.into()))
            }
            #[cfg(feature = "zstd")]
            Self::Zstd(codec) => {
                let mut output = vec![0; _quantum];
                let step = codec.encode(input, &mut output).map_err(io::Error::other)?;
                output.truncate(step.output_written);
                Ok((step.input_read, output.into()))
            }
        }
    }

    // Returns whether flushing/finalization is complete, plus its output.
    fn flush(&mut self, finish: bool, _quantum: usize) -> io::Result<(bool, Bytes)> {
        let mut output = Vec::new();
        let complete = match self {
            Self::Identity => true,
            Self::Standard(codec) => {
                if finish { codec.finish(&mut output)?; } else { codec.flush(&mut output)?; }
                true
            }
            #[cfg(feature = "zstd")]
            Self::Zstd(codec) => {
                output.resize(_quantum, 0);
                let step = if finish {
                    codec.finish(&mut output)
                } else {
                    codec.flush(&mut output).map_err(io::Error::other)?
                };
                output.truncate(step.output_written);
                step.status != asupersync_zstd::StreamStatus::NeedOutput
            }
        };
        Ok((complete, output.into()))
    }
}

struct EncodeState<D> {
    coding: ContentCoding,
    limits: ContentEncodeLimits,
    codec: Option<Encoder>,
    source_data: Option<D>,
    pending: Bytes,
    trailers: Option<HeaderMap>,
    source_bytes: usize,
    encoded_bytes: usize,
    emitted_bytes: usize,
    flush_pending: bool,
    source_ended: bool,
    finished: bool,
    done: bool,
}

impl<D: Buf> EncodeState<D> {
    fn terminate(&mut self) {
        self.done = true;
        self.codec = None;
        self.source_data = None;
        self.pending = Bytes::new();
        self.trailers = None;
    }

    fn codec_error<E>(&self, error: io::Error) -> ContentEncodeError<E> {
        if error.get_ref().is_some_and(|source| source.is::<CompressionLimitExceeded>()) {
            ContentEncodeError::EncodedLimit { actual: None, limit: self.limits.max_encoded_bytes }
        } else {
            ContentEncodeError::Encode(error)
        }
    }

    fn output<E>(&mut self, output: Bytes) -> Result<(), ContentEncodeError<E>> {
        let actual = self.encoded_bytes.checked_add(output.len());
        let Some(total) = actual.filter(|total| *total <= self.limits.max_encoded_bytes) else {
            return Err(ContentEncodeError::EncodedLimit { actual, limit: self.limits.max_encoded_bytes });
        };
        self.encoded_bytes = total;
        self.pending = output;
        Ok(())
    }

    fn step<E>(&mut self) -> Result<bool, ContentEncodeError<E>> {
        if let Some(data) = self.source_data.as_mut() {
            let quantum = self.limits.chunk_bytes;
            let output = if self.coding == ContentCoding::Identity {
                data.copy_to_bytes(data.remaining().min(quantum))
            } else {
                let input = data.chunk();
                let input = &input[..input.len().min(quantum)];
                let result = self.codec.as_mut().expect("live encoder retains codec").encode(input, quantum);
                let (read, output) = match result {
                    Ok(step) => step,
                    Err(error) => return Err(self.codec_error(error)),
                };
                data.advance(read);
                output
            };
            if !data.has_remaining() {
                self.source_data = None;
                self.flush_pending = true;
            }
            self.output(output)?;
            return Ok(true);
        }
        if self.flush_pending || (self.source_ended && !self.finished) {
            let finish = !self.flush_pending;
            let result = self.codec.as_mut().expect("live encoder retains codec")
                .flush(finish, self.limits.chunk_bytes);
            let (complete, output) = result.map_err(|error| self.codec_error(error))?;
            if finish { self.finished = complete; } else { self.flush_pending = !complete; }
            self.output(output)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn take_trailers(&mut self) -> Option<HeaderMap> {
        let original = self.trailers.take()?;
        if self.coding == ContentCoding::Identity { return Some(original); }
        let mut trailers = HeaderMap::new();
        for (name, value) in original.iter() {
            if super::decode::invalidated_field(name.as_str()) { continue; }
            let value = if name.as_str().eq_ignore_ascii_case("etag") {
                match value.to_str() {
                    Ok(value) if !value.starts_with("W/") => HeaderValue::from_string(format!("W/{value}")),
                    _ => value.clone(),
                }
            } else { value.clone() };
            trailers.append(name.clone(), value);
        }
        Some(trailers)
    }
}

impl<B: Body> Body for ContentEncodedBody<B> {
    type Data = BytesCursor;
    type Error = ContentEncodeError<B::Error>;

    fn poll_frame(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        if this.state.done { return Poll::Ready(None); }
        if let Some(cancel) = this.cancellation.as_mut() { cancel.register(task); }
        let error = 'encoding: {
            for _ in 0..POLL_STEPS {
                if let Some(cancel) = this.cancellation.as_ref()
                    && let Err(kind) = cancel.check()
                {
                    break 'encoding ContentEncodeError::Cancelled { kind };
                }
                if !this.state.pending.is_empty() {
                    let length = this.state.pending.len().min(this.state.limits.chunk_bytes);
                    let data = this.state.pending.split_to(length);
                    if this.state.pending.is_empty() { this.state.pending = Bytes::new(); }
                    this.state.emitted_bytes += length;
                    return Poll::Ready(Some(Ok(Frame::Data(BytesCursor::new(data)))));
                }
                match this.state.step() {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(error) => break 'encoding error,
                }
                if this.state.finished {
                    let trailers = this.state.take_trailers();
                    this.state.terminate();
                    this.inner.set(None);
                    *this.cancellation = None;
                    return Poll::Ready(trailers.map(|trailers| Ok(Frame::Trailers(trailers))));
                }
                let source = this.inner.as_mut().as_pin_mut().expect("live encoder retains source until EOF");
                match source.poll_frame(task) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(Ok(Frame::Data(data)))) => {
                        if this.state.trailers.is_some() {
                            break 'encoding ContentEncodeError::Encode(io::Error::new(io::ErrorKind::InvalidData, "body data follows trailers"));
                        }
                        let actual = this.state.source_bytes.checked_add(data.remaining());
                        let Some(total) = actual.filter(|total| *total <= this.state.limits.max_source_bytes) else {
                            break 'encoding ContentEncodeError::SourceLimit { actual, limit: this.state.limits.max_source_bytes };
                        };
                        this.state.source_bytes = total;
                        if data.has_remaining() { this.state.source_data = Some(data); }
                    }
                    Poll::Ready(Some(Ok(Frame::Trailers(trailers)))) => {
                        if this.state.trailers.replace(trailers).is_some() {
                            break 'encoding ContentEncodeError::Encode(io::Error::new(io::ErrorKind::InvalidData, "duplicate body trailer frame"));
                        }
                    }
                    Poll::Ready(Some(Err(error))) => break 'encoding ContentEncodeError::Body(error),
                    Poll::Ready(None) => {
                        this.state.source_ended = true;
                        this.inner.set(None);
                    }
                }
            }
            task.waker().wake_by_ref();
            return Poll::Pending;
        };
        this.state.terminate();
        this.inner.set(None);
        *this.cancellation = None;
        Poll::Ready(Some(Err(error)))
    }

    fn is_end_stream(&self) -> bool { self.state.done }

    fn size_hint(&self) -> SizeHint {
        if self.state.done { return SizeHint::with_exact(0); }
        let mut hint = SizeHint::new();
        hint.set_upper(u64::try_from(self.state.limits.max_encoded_bytes.saturating_sub(self.state.emitted_bytes)).unwrap_or(u64::MAX));
        hint
    }
}
