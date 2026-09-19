use super::{PollCaptureError, PollCaptureLimits, PollMismatch, PollReplayError};
use super::super::{OrderedEffect, OrderedRecordedSession};
use crate::io::replay::IoOperation;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::io::IoSlice;
use zeroize::Zeroize;

pub(super) enum Request<'a, 'b> {
    Read(usize),
    Write(&'a [u8]),
    Vectored(&'a [IoSlice<'b>]),
    Flush,
    Shutdown,
}
impl Request<'_, '_> {
    pub(super) fn operation(&self) -> IoOperation {
        match self {
            Self::Read(_) => IoOperation::Read,
            Self::Write(_) => IoOperation::Write,
            Self::Vectored(_) => IoOperation::WriteVectored,
            Self::Flush => IoOperation::Flush,
            Self::Shutdown => IoOperation::Shutdown,
        }
    }
    fn slices(&self) -> usize {
        match self { Self::Vectored(bufs) => bufs.len(), _ => 0 }
    }
    fn length(&self) -> Option<usize> {
        match self {
            Self::Read(n) => Some(*n),
            Self::Write(bytes) => Some(bytes.len()),
            Self::Vectored(bufs) => bufs.iter().try_fold(0usize, |sum, b| sum.checked_add(b.len())),
            Self::Flush | Self::Shutdown => Some(0),
        }
    }
    fn is_write(&self) -> bool { matches!(self, Self::Write(_) | Self::Vectored(_)) }
    fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"asupersync.polled-io-request.v1");
        match self {
            Self::Read(_) | Self::Flush | Self::Shutdown => {}
            Self::Write(bytes) => hash.update(*bytes),
            Self::Vectored(bufs) => {
                // Exact boundaries matter even when concatenated content matches.
                for bytes in *bufs {
                    hash.update((bytes.len() as u64).to_le_bytes());
                    hash.update(&**bytes);
                }
            }
        }
        hash.finalize().into()
    }
}

pub(super) struct IoStep {
    pub(super) effect: usize,
    pub(super) operation: IoOperation,
    pub(super) length: usize,
    pub(super) slices: usize,
    pub(super) digest: [u8; 32],
    pub(super) pending: bool,
}
impl Drop for IoStep {
    fn drop(&mut self) { self.digest.zeroize(); }
}
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Checkpoint {
    pub(super) effects: usize,
    pub(super) io: usize,
}
#[derive(Clone, Copy)]
pub(super) struct PollStep {
    pub(super) checkpoint: Checkpoint,
    pub(super) ready: bool,
}
pub(super) struct PollTape {
    pub(super) io: Vec<IoStep>,
    pub(super) frames: Vec<PollStep>,
    pub(super) construction: Checkpoint,
    pub(super) terminal: Checkpoint,
}
impl PollTape {
    // Check exact ready-I/O coverage and monotone checkpoints without providers.
    // Pending does not consume an ordered effect or component tape entry.
    pub(super) fn covers(&self, ordered: &OrderedRecordedSession) -> bool {
        // Pending attempts belong to this transcript, not also to the nested order.
        // Refuse the independent V2 pending-I/O mode rather than double-count it.
        if ordered.is_poll_aware() || self.frames.is_empty() || self.terminal.effects != ordered.effects()
            || self.terminal.io != self.io.len() { return false; }
        let mut floor = 0;
        let mut ready_count = 0;
        for step in &self.io {
            if step.effect < floor || step.effect > self.terminal.effects { return false; }
            if !step.pending {
                if ordered.order.entries.get(step.effect).map(|e| e.effect) != Some(OrderedEffect::Io(step.operation)) {
                    return false;
                }
                floor = step.effect + 1;
                ready_count += 1;
            } else { floor = step.effect; }
        }
        if ready_count != ordered.components.io_operations() { return false; }
        let mut previous = Checkpoint::default();
        for checkpoint in std::iter::once(self.construction)
            .chain(self.frames.iter().map(|frame| frame.checkpoint))
            .chain(std::iter::once(self.terminal))
        {
            if checkpoint.effects < previous.effects || checkpoint.io < previous.io
                || checkpoint.effects > self.terminal.effects || checkpoint.io > self.io.len() {
                return false;
            }
            if let Some(prior) = checkpoint.io.checked_sub(1).and_then(|i| self.io.get(i)) {
                if prior.effect > checkpoint.effects || (!prior.pending && prior.effect == checkpoint.effects) {
                    return false;
                }
            }
            if let Some(next) = self.io.get(checkpoint.io) {
                if next.effect < checkpoint.effects { return false; }
            }
            previous = checkpoint;
        }
        self.frames.iter().enumerate().all(|(i, frame)| frame.ready == (i + 1 == self.frames.len()))
    }
}

struct RecordState {
    tape: PollTape,
    limits: PollCaptureLimits,
    written: usize,
    active: bool,
    finished: bool,
    failure: Option<PollCaptureError>,
}
pub(super) struct RecordTrace(Mutex<RecordState>);
impl RecordTrace {
    pub(super) fn new(limits: PollCaptureLimits) -> Self {
        Self(Mutex::new(RecordState {
            tape: PollTape { io: Vec::new(), frames: Vec::new(), construction: Checkpoint::default(), terminal: Checkpoint::default() },
            limits, written: 0, active: false, finished: false, failure: None,
        }))
    }
    pub(super) fn invalidate(&self, error: PollCaptureError) {
        self.0.lock().failure.get_or_insert(error);
    }
    pub(super) fn begin(&self, request: &Request<'_, '_>, effect: usize) -> Option<RecordIo<'_>> {
        let mut state = self.0.lock();
        if state.finished || state.failure.is_some() { return None; }
        let error = if state.active { Some(PollCaptureError::Overlap) }
            else if state.tape.io.len() == state.limits.max_io_polls { Some(PollCaptureError::Limit("I/O polls")) }
            else if request.slices() > state.limits.max_vectored_slices { Some(PollCaptureError::Limit("vectored slices")) }
            else { None };
        if let Some(error) = error { state.failure = Some(error); return None; }
        let Some(length) = request.length() else { state.failure = Some(PollCaptureError::Overflow); return None; };
        let written = if request.is_write() { length } else { 0 };
        if written > state.limits.max_write_bytes - state.written {
            state.failure = Some(PollCaptureError::Limit("write bytes")); return None;
        }
        if state.tape.io.len() == state.tape.io.capacity() {
            let extra = (state.limits.max_io_polls - state.tape.io.len()).min(state.tape.io.len().max(8));
            if state.tape.io.try_reserve_exact(extra).is_err() {
                state.failure = Some(PollCaptureError::Allocation); return None;
            }
        }
        // Only bounded internal hashing runs here, never a provider/waker callback.
        let index = state.tape.io.len();
        state.tape.io.push(IoStep {
            effect, operation: request.operation(), length, slices: request.slices(),
            digest: request.digest(), pending: false,
        });
        state.written += written;
        state.active = true;
        Some(RecordIo { trace: self, index, completed: false })
    }
    pub(super) fn construction(&self, effects: usize) {
        let mut state = self.0.lock();
        state.tape.construction = Checkpoint { effects, io: state.tape.io.len() };
    }
    pub(super) fn boundary(&self, effects: usize, ready: bool) {
        let mut state = self.0.lock();
        if state.failure.is_some() { return; }
        if state.active { state.failure = Some(PollCaptureError::Overlap); return; }
        if state.tape.frames.len() == state.limits.max_polls {
            state.failure = Some(PollCaptureError::Limit("consumer polls")); return;
        }
        if state.tape.frames.len() == state.tape.frames.capacity() {
            let extra = (state.limits.max_polls - state.tape.frames.len()).min(state.tape.frames.len().max(8));
            if state.tape.frames.try_reserve_exact(extra).is_err() {
                state.failure = Some(PollCaptureError::Allocation); return;
            }
        }
        let checkpoint = Checkpoint { effects, io: state.tape.io.len() };
        state.tape.frames.push(PollStep { checkpoint, ready });
    }
    pub(super) fn finish(&self, effects: usize) -> Result<PollTape, PollCaptureError> {
        let mut state = self.0.lock();
        state.finished = true;
        if state.active { state.failure.get_or_insert(PollCaptureError::Overlap); }
        if let Some(error) = state.failure { return Err(error); }
        let terminal = Checkpoint { effects, io: state.tape.io.len() };
        Ok(PollTape {
            io: std::mem::take(&mut state.tape.io), frames: std::mem::take(&mut state.tape.frames),
            construction: state.tape.construction, terminal,
        })
    }
}
pub(super) struct RecordIo<'a> {
    trace: &'a RecordTrace,
    index: usize,
    completed: bool,
}
impl RecordIo<'_> {
    pub(super) fn finish(mut self, pending: bool) {
        let mut state = self.trace.0.lock();
        state.tape.io[self.index].pending = pending;
        state.active = false;
        self.completed = true;
    }
}
impl Drop for RecordIo<'_> {
    fn drop(&mut self) {
        if !self.completed {
            let mut state = self.trace.0.lock();
            state.active = false;
            state.failure.get_or_insert(PollCaptureError::Interrupted);
        }
    }
}

struct ReplayState {
    tape: PollTape,
    io: usize,
    poll: usize,
    failure: Option<PollReplayError>,
}
impl ReplayState {
    fn refuse(&mut self, reason: PollMismatch) -> PollReplayError {
        *self.failure.get_or_insert(PollReplayError { poll: self.poll, io_poll: self.io, reason })
    }
    fn checkpoint(&self, effects: usize) -> Checkpoint { Checkpoint { effects, io: self.io } }
}
pub(super) struct ReplayTrace(Mutex<ReplayState>);
impl ReplayTrace {
    pub(super) fn new(tape: PollTape) -> Self {
        Self(Mutex::new(ReplayState { tape, io: 0, poll: 0, failure: None }))
    }
    pub(super) fn refuse(&self, reason: PollMismatch) -> PollReplayError { self.0.lock().refuse(reason) }
    pub(super) fn enter(&self, request: &Request<'_, '_>, effect: usize) -> Result<bool, PollReplayError> {
        let mut state = self.0.lock();
        if let Some(error) = state.failure { return Err(error); }
        let Some(step) = state.tape.io.get(state.io) else { return Err(state.refuse(PollMismatch::Exhausted)); };
        if step.effect != effect { return Err(state.refuse(PollMismatch::Position)); }
        // Reject gross shape differences before walking vectors or hashing writes.
        if step.operation != request.operation() || step.slices != request.slices()
            || request.length() != Some(step.length) { return Err(state.refuse(PollMismatch::Request)); }
        let mut digest = request.digest();
        let matches = digest == step.digest;
        digest.zeroize();
        if !matches { return Err(state.refuse(PollMismatch::Request)); }
        let pending = step.pending;
        state.io += 1;
        Ok(pending)
    }
    pub(super) fn construction(&self, effects: usize) -> Result<(), PollReplayError> {
        let mut state = self.0.lock();
        if let Some(error) = state.failure { return Err(error); }
        if state.checkpoint(effects) != state.tape.construction {
            return Err(state.refuse(PollMismatch::Construction));
        }
        Ok(())
    }
    pub(super) fn before_poll(&self) -> Result<(), PollReplayError> {
        let mut state = self.0.lock();
        if let Some(error) = state.failure { return Err(error); }
        if state.poll == state.tape.frames.len() { return Err(state.refuse(PollMismatch::Exhausted)); }
        Ok(())
    }
    pub(super) fn boundary(&self, effects: usize, ready: bool) -> Result<(), PollReplayError> {
        let mut state = self.0.lock();
        if let Some(error) = state.failure { return Err(error); }
        let Some(frame) = state.tape.frames.get(state.poll) else { return Err(state.refuse(PollMismatch::Exhausted)); };
        if frame.ready != ready || frame.checkpoint != state.checkpoint(effects) {
            return Err(state.refuse(PollMismatch::Boundary));
        }
        state.poll += 1;
        Ok(())
    }
    pub(super) fn finish(&self, effects: usize) -> Result<(), PollReplayError> {
        let mut state = self.0.lock();
        if let Some(error) = state.failure { return Err(error); }
        if state.poll != state.tape.frames.len() || state.checkpoint(effects) != state.tape.terminal {
            return Err(state.refuse(PollMismatch::Completion));
        }
        Ok(())
    }
}
