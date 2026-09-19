//! Host-independent admission, lifecycle and response-buffer accounting.
use super::{FetchBytesError, FetchBytesLimits};
use asupersync::types::{
    WasmAbiOutcomeEnvelope, WasmAbiRecoverability, WasmAbiVersion, WasmBoundaryState,
    WasmDispatchError, WasmFetchRequest, WasmHandleRef,
};
use std::marker::PhantomData;
use std::ops::Range;
use std::rc::Rc;

fn admission_error(error: WasmDispatchError) -> FetchBytesError {
    match error {
        WasmDispatchError::CapabilityDenied { .. } => FetchBytesError::CapabilityDenied,
        WasmDispatchError::Incompatible { .. } => FetchBytesError::IncompatibleAbi,
        WasmDispatchError::Handle(_) | WasmDispatchError::InvalidState { .. } => {
            FetchBytesError::OwnerUnavailable
        }
        WasmDispatchError::InvalidRequest { .. } => FetchBytesError::InvalidRequest,
    }
}

pub(super) fn prepare(
    request: WasmFetchRequest,
    limits: FetchBytesLimits,
    consumer_version: Option<WasmAbiVersion>,
) -> Result<(WasmFetchRequest, FetchLease), FetchBytesError> {
    if request.body.as_ref().is_some_and(|body| body.len() > limits.max_request_bytes) {
        return Err(FetchBytesError::RequestLimit { limit: limits.max_request_bytes });
    }
    let request = crate::normalize_fetch_request(request)
        .map_err(|_| FetchBytesError::InvalidRequest)?;
    let handle = crate::DISPATCHER.with(|dispatcher| {
        dispatcher.borrow_mut().fetch_request(&request, consumer_version)
    }).map_err(admission_error)?;
    Ok((request, FetchLease { handle: Some(handle), _local: PhantomData }))
}

// A dispatcher handle belongs to this thread/JS realm. Even the host-free test
// form must not be Send: moving it would release a different realm's handle.
pub(super) struct FetchLease {
    handle: Option<WasmHandleRef>,
    _local: PhantomData<Rc<()>>,
}

impl FetchLease {
    pub(super) fn handle(&self) -> WasmHandleRef {
        self.handle.expect("fetch lease exists until terminal publication")
    }

    pub(super) fn check_active(&self) -> Result<(), FetchBytesError> {
        let Some(handle) = self.handle else { return Err(FetchBytesError::Cancelled); };
        crate::DISPATCHER.with(|dispatcher| {
            let dispatcher = dispatcher.borrow();
            if dispatcher.handles().get(&handle)
                .is_ok_and(|entry| entry.state == WasmBoundaryState::Active)
            {
                Ok(())
            } else {
                Err(FetchBytesError::Cancelled)
            }
        })
    }

    pub(super) fn publish(&mut self, outcome: WasmAbiOutcomeEnvelope) -> Result<(), FetchBytesError> {
        let Some(handle) = self.handle else { return Err(FetchBytesError::Publication); };
        if !crate::dispatcher_handle_is_live(&handle) {
            self.handle = None;
            return Err(FetchBytesError::Cancelled);
        }
        if matches!(&outcome, WasmAbiOutcomeEnvelope::Ok { .. }) {
            self.check_active()?;
        }
        crate::DISPATCHER.with(|dispatcher| {
            let mut dispatcher = dispatcher.borrow_mut();
            if matches!(&outcome, WasmAbiOutcomeEnvelope::Cancelled { .. }) {
                let _ = dispatcher.apply_abort(&handle);
            }
            dispatcher.fetch_complete(&handle, outcome)
        }).map_err(|_| FetchBytesError::Publication)?;
        self.handle = None;
        Ok(())
    }
}

impl Drop for FetchLease {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else { return; };
        // Generation validation prevents a late destructor from releasing a
        // different request after owner close and slot reuse.
        if crate::dispatcher_handle_is_live(&handle) {
            let _ = crate::DISPATCHER.with(|dispatcher| {
                let mut dispatcher = dispatcher.borrow_mut();
                let _ = dispatcher.apply_abort(&handle);
                dispatcher.fetch_complete(&handle, error_outcome(FetchBytesError::Cancelled))
            });
        }
    }
}

pub(super) fn error_outcome(error: FetchBytesError) -> WasmAbiOutcomeEnvelope {
    if error == FetchBytesError::Cancelled {
        crate::cancelled_outcome("fetch_owner_cancelled", "completed", None, None)
    } else {
        // Typed fixed-size errors cannot serialize credentials, URL queries,
        // host exception objects or arbitrary response bodies into diagnostics.
        let recoverability = match error {
            FetchBytesError::Host { .. } | FetchBytesError::Allocation => WasmAbiRecoverability::Transient,
            _ => WasmAbiRecoverability::Permanent,
        };
        crate::fetch_error_outcome(error.to_string(), recoverability)
    }
}

pub(super) struct BodyBudget {
    limits: FetchBytesLimits,
    reads: usize,
}

impl BodyBudget {
    pub(super) const fn new(limits: FetchBytesLimits) -> Self {
        Self { limits, reads: 0 }
    }

    pub(super) fn begin_read(&mut self) -> Result<(), FetchBytesError> {
        if self.reads >= self.limits.max_body_reads {
            return Err(FetchBytesError::ReadLimit { limit: self.limits.max_body_reads });
        }
        // The comparison also makes the increment safe when the limit is MAX.
        self.reads += 1;
        Ok(())
    }

    pub(super) fn checked_end(&self, current: usize, extra: usize) -> Result<usize, FetchBytesError> {
        let end = current.checked_add(extra).ok_or(FetchBytesError::LengthOverflow)?;
        if end > self.limits.max_response_bytes {
            Err(FetchBytesError::ResponseLimit { limit: self.limits.max_response_bytes })
        } else {
            Ok(end)
        }
    }

    // The caller obtains a checked destination before reading/copying the JS
    // chunk. On refusal the existing prefix is unchanged and never returned.
    pub(super) fn reserve_chunk(&self, body: &mut Vec<u8>, extra: usize) -> Result<Range<usize>, FetchBytesError> {
        let start = body.len();
        let end = self.checked_end(start, extra)?;
        body.try_reserve_exact(extra).map_err(|_| FetchBytesError::Allocation)?;
        body.resize(end, 0);
        Ok(start..end)
    }
}
