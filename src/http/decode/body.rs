//! Pull-driven content decoding without a task, channel, or second body owner.

use super::{Coding, ContentDecoder, IDENTITY, decoder_for, invalidated_field, is_limit_error};
use crate::Cx;
use crate::bytes::{Buf, Bytes, BytesCursor};
use crate::cx::CancelWakerToken;
use crate::http::body::{Body, Frame, HeaderMap, SizeHint};
use crate::http::compress::{DecompressionLimit, Decompressor, decompression_limit_error};
use crate::types::CancelKind;
use std::fmt;
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll};

const DEFAULT_CHUNK_BYTES: usize = 16 * 1024;
const MAX_CHUNK_BYTES: usize = 64 * 1024;
const MAX_STEPS_PER_POLL: usize = 32;

/// Mandatory resource ceilings for a [`ContentDecodedBody`].
///
/// `max_encoded_bytes` counts all source data, and `max_decoded_bytes` bounds
/// the cumulative output of **each** coding stage, including identity. A
/// stage cannot evade the bound by emitting many individually small chunks.
/// Zero totals accept only empty representations. At most eight codings are
/// accepted. Zstd additionally retains its HTTP window limit of 8 MiB.
///
/// The chunk size limits input submitted to a codec and each returned frame.
/// It does **not** limit a codec's expansion of one input chunk: gzip,
/// deflate, and Brotli can retain up to the remaining decoded total for that
/// stage. There is at most one pending output buffer per stage, plus the
/// current source frame and codec working storage. Configure the source's
/// own receive/queue limits separately. Allocation capacity can exceed the
/// logical byte counts due to allocator and codec growth policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentDecodeLimits {
    max_encoded_bytes: usize,
    max_decoded_bytes: usize,
    chunk_bytes: usize,
}

impl ContentDecodeLimits {
    /// Set independent wire-input and per-stage decoded-output limits.
    #[must_use]
    pub const fn new(max_encoded_bytes: usize, max_decoded_bytes: usize) -> Self {
        Self {
            max_encoded_bytes,
            max_decoded_bytes,
            chunk_bytes: DEFAULT_CHUNK_BYTES,
        }
    }

    /// Set the input quantum and returned data-frame ceiling.
    ///
    /// Values above 64 KiB are clamped to 64 KiB to bound cooperative work.
    #[must_use]
    pub fn with_chunk_size(mut self, bytes: NonZeroUsize) -> Self {
        self.chunk_bytes = bytes.get().min(MAX_CHUNK_BYTES);
        self
    }

    /// Return the cumulative encoded-input ceiling.
    #[must_use]
    pub const fn max_encoded_bytes(self) -> usize {
        self.max_encoded_bytes
    }

    /// Return the cumulative decoded-output ceiling for every stage.
    #[must_use]
    pub const fn max_decoded_bytes(self) -> usize {
        self.max_decoded_bytes
    }

    /// Return the input quantum and emitted data-frame ceiling.
    #[must_use]
    pub const fn chunk_size(self) -> usize {
        self.chunk_bytes
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) const fn tightened(self, total: usize) -> Self {
        Self {
            max_encoded_bytes: if self.max_encoded_bytes < total { self.max_encoded_bytes } else { total },
            max_decoded_bytes: if self.max_decoded_bytes < total { self.max_decoded_bytes } else { total },
            chunk_bytes: self.chunk_bytes,
        }
    }
}

/// A terminal source, decoding, resource, or cancellation failure.
///
/// Earlier data frames are provisional until successful stream completion.
/// Following an error, the source and decoder storage are released and
/// subsequent polls return `None`; no trailers are delivered on that path.
#[derive(Debug)]
#[non_exhaustive]
pub enum ContentDecodeError<E> {
    /// The original source failure, without erasing its concrete type.
    Body(E),
    /// Invalid compressed data, invalid frame order, or a decoded-size limit.
    Decode(io::Error),
    /// Encoded bytes exceeded the caller's input ceiling.
    EncodedLimit {
        /// Observed total, or `None` if adding the frame overflowed.
        actual: Option<usize>,
        /// Configured maximum encoded bytes.
        limit: usize,
    },
    /// An explicitly attached context was cancelled while consuming the body.
    Cancelled {
        /// The authoritative cancellation category.
        kind: CancelKind,
    },
}

impl<E> ContentDecodeError<E> {
    /// Whether this adapter refused an encoded, decoded, or codec-window bound.
    /// Source-specific resource errors remain in [`Self::Body`].
    #[must_use]
    pub fn is_limit_exceeded(&self) -> bool {
        match self {
            Self::EncodedLimit { .. } => true,
            Self::Decode(error) => is_limit_error(error),
            Self::Body(_) | Self::Cancelled { .. } => false,
        }
    }
}

impl<E: fmt::Display> fmt::Display for ContentDecodeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Body(error) => write!(f, "encoded body source failed: {error}"),
            Self::Decode(error) => write!(f, "content decoding failed: {error}"),
            Self::EncodedLimit { actual, limit } => {
                write!(f, "encoded body exceeds {limit} bytes (observed {actual:?})")
            }
            Self::Cancelled { kind } => write!(f, "content decoding cancelled: {kind:?}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ContentDecodeError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Body(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::EncodedLimit { .. } | Self::Cancelled { .. } => None,
        }
    }
}

/// Incrementally decode a bounded content-coding stack from any HTTP [`Body`].
///
/// Codings are supplied in application order, including repeated fields, and
/// decoded in reverse order. Constructing the adapter validates the complete
/// list and codec availability without polling the source. Gzip, deflate, and
/// Brotli require `compression`; zstd requires `zstd`; identity needs neither.
///
/// The adapter is pull-driven: it drains pending downstream output before
/// reading more upstream input. It creates no tasks or queues and owns the
/// source for its entire lifetime. Dropping it or returning an error drops
/// the source immediately, preserving its cancellation/drain policy. Dropping
/// a pending polling future while retaining the body preserves decoder state.
/// An optional [`Self::with_cx`] also observes cancellation while decoded
/// output is queued, without waiting for another source poll.
///
/// **Progressive data is provisional.** A checksum, truncated footer, source
/// error, or later resource refusal can follow data already returned. Commit
/// upload side effects only after observing successful EOF. This is not the
/// atomic publication contract of buffered response/request decoding.
/// Trailers are withheld until every decoder finishes and the source reaches
/// EOF. After a non-identity transform, encoded length/coding/digest fields
/// are removed from those trailers. The caller owns the original head and
/// must distinguish its encoded metadata from the decoded byte stream.
///
/// See [`ContentDecodeLimits`] for the distinction between returned frame
/// size and retained per-stage output, which can be larger than one frame.
#[pin_project::pin_project]
pub struct ContentDecodedBody<B: Body> {
    #[pin]
    inner: Option<B>,
    state: DecodeState<B::Data>,
    cancellation: Option<DecodeCancellation>,
}

impl<B: Body> fmt::Debug for ContentDecodedBody<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContentDecodedBody")
            .field("limits", &self.state.limits)
            .field("stages", &self.state.stages.len())
            .field("encoded_bytes", &self.state.encoded_bytes)
            .field("decoded_bytes", &self.state.emitted_bytes)
            .field("done", &self.state.done)
            .finish_non_exhaustive()
    }
}

impl<B: Body> ContentDecodedBody<B> {
    /// Validate and construct a decoder without polling `inner`.
    ///
    /// Coding fields use strict HTTP token syntax. An empty iterator means
    /// identity; an explicitly empty coding list is malformed. On error,
    /// ownership of `inner` is released without consuming a frame.
    pub fn new<'a>(
        inner: B,
        fields: impl IntoIterator<Item = &'a str>,
        limits: ContentDecodeLimits,
    ) -> io::Result<Self> {
        let plan = ContentDecodePlan::new(ContentDecoder::from_request_fields(fields)?, limits)?;
        Ok(Self::from_plan(inner, plan))
    }

    pub(crate) fn from_plan(inner: B, plan: ContentDecodePlan) -> Self {
        let buffers = vec![Bytes::new(); plan.stages.len() + 1];
        Self {
            inner: Some(inner),
            state: DecodeState {
                limits: plan.limits,
                stages: plan.stages,
                buffers,
                source_data: None,
                trailers: None,
                source_ended: false,
                transformed: plan.transformed,
                encoded_bytes: 0,
                emitted_bytes: 0,
                done: false,
            },
            cancellation: None,
        }
    }

    /// Attach the caller's context, including while decoded output is queued.
    #[must_use]
    pub fn with_cx(mut self, cx: &Cx) -> Self {
        self.cancellation = Some(DecodeCancellation { cx: cx.clone(), token: None });
        self
    }

    /// Return the effective limits used by this body.
    #[must_use]
    pub const fn limits(&self) -> ContentDecodeLimits {
        self.state.limits
    }
}

// Own exactly this adapter's cancellation registration. Keeping the guard in
// an unpinned field lets pin_project preserve a potentially !Unpin source.
struct DecodeCancellation {
    cx: Cx,
    token: Option<CancelWakerToken>,
}

impl DecodeCancellation {
    fn register(&mut self, task: &Context<'_>) {
        self.token = Some(self.cx.refresh_cancel_waker(self.token.take(), task.waker()));
    }
}

impl Drop for DecodeCancellation {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.cx.clear_cancel_waker(token);
        }
    }
}

/// Prepared separately so web extraction can reject unsupported codecs
/// before taking ownership of the single-consumer streaming request slot.
pub(crate) struct ContentDecodePlan {
    limits: ContentDecodeLimits,
    stages: Vec<DecoderStage>,
    transformed: bool,
}

impl ContentDecodePlan {
    pub(crate) fn new(decoder: ContentDecoder, limits: ContentDecodeLimits) -> io::Result<Self> {
        let transformed = !decoder.is_identity();
        let stages = decoder.codings.into_iter().rev()
            .map(|coding| DecoderStage::new(coding, limits.max_decoded_bytes))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self { limits, stages, transformed })
    }
}

enum Codec {
    Identity,
    Standard(Box<dyn Decompressor>),
    #[cfg(feature = "zstd")]
    Zstd(Box<asupersync_zstd::StreamDecoder>),
}

struct DecoderStage {
    codec: Codec,
    produced: usize,
    limit: usize,
    drain: bool,
    finished: bool,
}

impl DecoderStage {
    fn new(coding: Coding, limit: usize) -> io::Result<Self> {
        let codec = match coding {
            IDENTITY => Codec::Identity,
            Coding::Standard(encoding) => Codec::Standard(decoder_for(encoding, DecompressionLimit::new(limit))?),
            #[cfg(feature = "zstd")]
            Coding::Zstd => Codec::Zstd(Box::new(asupersync_zstd::StreamDecoder::new(
                asupersync_zstd::DecodeLimits::new(limit),
            ))),
            #[cfg(not(feature = "zstd"))]
            Coding::Zstd => return Err(io::Error::new(io::ErrorKind::Unsupported, "content codec requires zstd feature")),
        };
        Ok(Self { codec, produced: 0, limit, drain: false, finished: false })
    }

    fn account(&mut self, count: usize) -> io::Result<()> {
        let Some(total) = self.produced.checked_add(count).filter(|total| *total <= self.limit) else {
            return Err(decompression_limit_error("decoded stage exceeds output limit"));
        };
        self.produced = total;
        Ok(())
    }

    fn decode(&mut self, input: &Bytes, quantum: usize) -> io::Result<(usize, Bytes)> {
        let input = input.slice(..input.len().min(quantum));
        let (read, output) = match &mut self.codec {
            Codec::Identity => (input.len(), input),
            Codec::Standard(decoder) => {
                let mut output = Vec::new();
                decoder.decompress(&input, &mut output)?;
                (input.len(), output.into())
            }
            #[cfg(feature = "zstd")]
            Codec::Zstd(decoder) => {
                let mut output = vec![0; quantum];
                let progress = decoder.decode(&input, &mut output)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                output.truncate(progress.output_written);
                self.drain = progress.status == asupersync_zstd::StreamStatus::NeedOutput;
                (progress.input_read, output.into())
            }
        };
        self.account(output.len())?;
        Ok((read, output))
    }

    fn finish(&mut self, _quantum: usize) -> io::Result<Bytes> {
        let mut output = Vec::new();
        match &mut self.codec {
            Codec::Identity => self.finished = true,
            Codec::Standard(decoder) => {
                decoder.finish(&mut output)?;
                self.finished = true;
            }
            #[cfg(feature = "zstd")]
            Codec::Zstd(decoder) => {
                output.resize(_quantum, 0);
                let progress = decoder.finish(&mut output)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                output.truncate(progress.output_written);
                self.finished = progress.status == asupersync_zstd::StreamStatus::Finished;
            }
        }
        self.account(output.len())?;
        Ok(output.into())
    }
}

struct DecodeState<D> {
    limits: ContentDecodeLimits,
    stages: Vec<DecoderStage>,
    // Buffer i is the input to stage i; the last is ready handler output.
    // A stage runs only while its destination is empty.
    buffers: Vec<Bytes>,
    source_data: Option<D>,
    trailers: Option<HeaderMap>,
    source_ended: bool,
    transformed: bool,
    encoded_bytes: usize,
    emitted_bytes: usize,
    done: bool,
}

impl<D: Buf> DecodeState<D> {
    fn terminate(&mut self) {
        self.done = true;
        self.source_data = None;
        self.trailers = None;
        self.buffers.clear();
        self.stages.clear();
    }

    fn output(&mut self) -> Option<BytesCursor> {
        let output = self.buffers.last_mut()?;
        if output.is_empty() {
            return None;
        }
        let data = output.split_to(output.len().min(self.limits.chunk_bytes));
        if output.is_empty() {
            *output = Bytes::new();
        }
        self.emitted_bytes += data.len();
        Some(BytesCursor::new(data))
    }

    fn advance_stage(&mut self) -> io::Result<bool> {
        for index in (0..self.stages.len()).rev() {
            if self.stages[index].finished || !self.buffers[index + 1].is_empty() {
                continue;
            }
            let upstream_finished = if index == 0 {
                self.source_ended
            } else {
                self.stages[index - 1].finished
            };
            if !self.buffers[index].is_empty() || self.stages[index].drain {
                let (read, output) = self.stages[index].decode(&self.buffers[index], self.limits.chunk_bytes)?;
                let remaining = &mut self.buffers[index];
                let _ = remaining.split_to(read);
                if remaining.is_empty() {
                    *remaining = Bytes::new();
                }
                self.buffers[index + 1] = output;
                return Ok(true);
            }
            if upstream_finished {
                self.buffers[index + 1] = self.stages[index].finish(self.limits.chunk_bytes)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn admit<E>(&mut self, data: D) -> Result<(), ContentDecodeError<E>> {
        let actual = self.encoded_bytes.checked_add(data.remaining());
        let Some(total) = actual.filter(|total| *total <= self.limits.max_encoded_bytes) else {
            return Err(ContentDecodeError::EncodedLimit { actual, limit: self.limits.max_encoded_bytes });
        };
        // With no Content-Encoding fields there is no codec stage to count
        // identity output, so enforce that ceiling at source admission.
        if self.stages.is_empty() && total > self.limits.max_decoded_bytes {
            return Err(ContentDecodeError::Decode(decompression_limit_error("identity body exceeds output limit")));
        }
        self.encoded_bytes = total;
        if data.has_remaining() {
            self.source_data = Some(data);
        }
        Ok(())
    }

    fn take_trailers(&mut self) -> Option<HeaderMap> {
        let trailers = self.trailers.take()?;
        if !self.transformed {
            return Some(trailers);
        }
        let mut decoded = HeaderMap::new();
        for (name, value) in trailers.iter() {
            if !invalidated_field(name.as_str()) {
                decoded.append(name.clone(), value.clone());
            }
        }
        Some(decoded)
    }
}

impl<B: Body> Body for ContentDecodedBody<B> {
    type Data = BytesCursor;
    type Error = ContentDecodeError<B::Error>;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        if this.state.done {
            return Poll::Ready(None);
        }
        // Register before checking cancellation: a source may remain Pending
        // forever, or carry a different context from the handler that owns us.
        if let Some(cancellation) = this.cancellation.as_mut() {
            cancellation.register(cx);
        }
        // Keep failure cleanup on one path: the live source must not be kept
        // alive by an adapter that has stopped accepting frames.
        let failure = 'decoding: {
            for _ in 0..MAX_STEPS_PER_POLL {
                if let Some(cancellation) = this.cancellation.as_ref()
                    && cancellation.cx.checkpoint().is_err()
                {
                    let kind = cancellation.cx.cancel_reason().map_or(CancelKind::User, |reason| reason.kind());
                    break 'decoding ContentDecodeError::Cancelled { kind };
                }
                if let Some(output) = this.state.output() {
                    return Poll::Ready(Some(Ok(Frame::Data(output))));
                }
                match this.state.advance_stage() {
                    Ok(true) => continue,
                    Err(error) => {
                        break 'decoding ContentDecodeError::Decode(error);
                    }
                    Ok(false) => {}
                }
                if let Some(data) = this.state.source_data.as_mut() {
                    // Buf may have multiple disjoint chunks; copy_to_bytes
                    // advances correctly across all of them, and BytesCursor
                    // provides a zero-copy implementation for native bodies.
                    let chunk = data.copy_to_bytes(data.remaining().min(this.state.limits.chunk_bytes));
                    this.state.buffers[0] = chunk;
                    if !data.has_remaining() {
                        this.state.source_data = None;
                    }
                    continue;
                }
                if this.state.source_ended {
                    let trailers = this.state.take_trailers();
                    this.state.terminate();
                    this.inner.set(None);
                    *this.cancellation = None;
                    return Poll::Ready(trailers.map(|trailers| Ok(Frame::Trailers(trailers))));
                }
                let Some(source) = this.inner.as_mut().as_pin_mut() else {
                    unreachable!("live content decoder retains its source until EOF");
                };
                match source.poll_frame(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(Ok(Frame::Data(data)))) => {
                        if this.state.trailers.is_some() {
                            break 'decoding ContentDecodeError::Decode(io::Error::new(io::ErrorKind::InvalidData, "body data follows trailers"));
                        }
                        if let Err(error) = this.state.admit(data) {
                            break 'decoding error;
                        }
                    }
                    Poll::Ready(Some(Ok(Frame::Trailers(trailers)))) => {
                        if this.state.trailers.replace(trailers).is_some() {
                            break 'decoding ContentDecodeError::Decode(io::Error::new(io::ErrorKind::InvalidData, "duplicate body trailer frame"));
                        }
                    }
                    Poll::Ready(Some(Err(error))) => {
                        break 'decoding ContentDecodeError::Body(error);
                    }
                    Poll::Ready(None) => {
                        this.state.source_ended = true;
                        this.inner.set(None);
                    }
                }
            }
            cx.waker().wake_by_ref();
            return Poll::Pending;
        };
        this.state.terminate();
        this.inner.set(None);
        *this.cancellation = None;
        Poll::Ready(Some(Err(failure)))
    }

    fn is_end_stream(&self) -> bool {
        self.state.done
    }

    fn size_hint(&self) -> SizeHint {
        if self.state.done {
            SizeHint::with_exact(0)
        } else {
            let mut hint = SizeHint::new();
            hint.set_upper(u64::try_from(self.state.limits.max_decoded_bytes.saturating_sub(self.state.emitted_bytes)).unwrap_or(u64::MAX));
            hint
        }
    }
}
