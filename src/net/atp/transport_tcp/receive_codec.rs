//! Decode queued TCP chunks on scoped blocking workers, preserving wire order.

use super::{
    AsyncReadExt, AsyncWriteExt, CodecAccept, Cx, Frame, FrameTransport, FrameType, ManifestEntry,
    StagedEntryReceive, TransportError, codec, parse_data_frame, with_transport_timeout,
};
use crate::codec::Decoder;
use crate::runtime::spawn_blocking::DrainedBlockingHandle;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

pub(super) const MAX_DECODE_SLOTS: u8 = 4;
type ReceivedFrame = (Frame, Option<Vec<u8>>);

enum Slot {
    Wire(Result<Frame, TransportError>),
    Decoding(
        Arc<Frame>,
        DrainedBlockingHandle<Result<Vec<u8>, TransportError>>,
    ),
}

#[derive(Default)]
pub(super) struct DecodeQueue {
    slots: VecDeque<Slot>,
}

impl DecodeQueue {
    /// An unavailable next frame never holds up writing the current chunk.
    /// Stop at the first control or raw frame; never read across ObjectComplete.
    pub(super) async fn next<S>(
        &mut self,
        cx: &Cx,
        transport: &mut FrameTransport<S>,
        entries: &[ManifestEntry],
        states: &[StagedEntryReceive],
        timeout: Duration,
    ) -> Result<ReceivedFrame, TransportError>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        if self.slots.is_empty() {
            let first =
                with_transport_timeout(cx, timeout, "receive frame", transport.recv()).await?;
            let Some(accept) = transport.chunk_codec else {
                return Ok((first, None));
            };
            let depth = usize::from(accept.decode_slots.min(MAX_DECODE_SLOTS));
            let mut frame = first;
            let mut next_chunk = None;
            loop {
                if !self.enqueue(cx, frame, accept, entries, states, &mut next_chunk)
                    || self.slots.len() >= depth
                {
                    break;
                }
                // Look only in the framing buffer. A partial frame remains in
                // the codec/transport for the next receive. No speculative
                // socket read delays staging or resets the peer idle timer.
                match transport.codec.decode(&mut transport.rbuf) {
                    Ok(Some(ready)) => frame = ready,
                    Ok(None) => break,
                    Err(error) => {
                        self.slots
                            .push_back(Slot::Wire(Err(TransportError::Frame(error.to_string()))));
                        break;
                    }
                }
            }
        }
        // Waiting through a borrowed handle keeps the queue intact if the wait
        // is dropped. Dropping the whole receive leaves running jobs with the
        // task's region and cancels jobs that have not started.
        let raw =
            match self.slots.front_mut().expect("received a frame") {
                Slot::Wire(_) => None,
                Slot::Decoding(_, job) => Some(job.join_cancellable(cx).await.map_err(
                    |error| match error {
                        crate::runtime::JoinError::Cancelled(_) => TransportError::Cancelled,
                        error => TransportError::Frame(format!("join TCP chunk decoder: {error}")),
                    },
                )??),
            };
        match self.slots.pop_front().expect("received a frame") {
            Slot::Wire(frame) => Ok((frame?, None)),
            Slot::Decoding(frame, _) => Ok((Arc::unwrap_or_clone(frame), raw)),
        }
    }

    fn enqueue(
        &mut self,
        cx: &Cx,
        frame: Frame,
        accept: CodecAccept,
        entries: &[ManifestEntry],
        states: &[StagedEntryReceive],
        next_chunk: &mut Option<(u32, u64)>,
    ) -> bool {
        // Only consecutive chunks of the same entry are decoded ahead. The
        // first entry offset comes from the writer, subsequent offsets from
        // the validated raw lengths. Other frames follow the normal checks.
        let geometry = (|| {
            if frame.frame_type() != FrameType::ObjectData {
                return None;
            }
            let (index, offset, payload) = parse_data_frame(&frame).ok()?;
            let expected = next_chunk.unwrap_or((index, states.get(index as usize)?.bytes_written));
            let entry = entries.get(index as usize)?;
            let remaining = entry.size.checked_sub(offset)?;
            let record = frame.header.extensions.get(&codec::CHUNK_CODEC_EXTENSION)?;
            let chunk = codec::ChunkCodec::from_bytes(record)?;
            let raw_len = u64::from(chunk.raw_len);
            if expected != (index, offset)
                || payload.len() as u64 > u64::from(accept.max_chunk_raw)
                || chunk.codec != accept.codec
                || raw_len > remaining.min(u64::from(accept.max_chunk_raw))
            {
                return None;
            }
            Some((index, offset + raw_len, remaining))
        })();
        let Some((index, next_offset, remaining)) = geometry else {
            self.slots.push_back(Slot::Wire(Ok(frame)));
            return false;
        };
        let frame = Arc::new(frame);
        let input = Arc::clone(&frame);
        let job = cx.spawn_blocking_drained(move |_| {
            let (_, _, payload) = parse_data_frame(&input)?;
            let record = &input.header.extensions[&codec::CHUNK_CODEC_EXTENSION];
            let mut raw = Vec::new();
            codec::decompress_chunk(record, Some(&accept), remaining, payload, &mut raw)
                .map_err(|error| TransportError::Frame(format!("ObjectData chunk: {error}")))?;
            Ok(raw)
        });
        if let Ok(job) = job {
            self.slots.push_back(Slot::Decoding(frame, job));
            *next_chunk = Some((index, next_offset));
            true
        } else {
            self.slots
                .push_back(Slot::Wire(Ok(Arc::unwrap_or_clone(frame))));
            false
        }
    }
}

#[cfg(test)]
#[path = "receive_codec_inline_tests.rs"]
mod tests;
