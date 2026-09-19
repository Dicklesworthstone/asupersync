//! The browser-owned abort/reader boundary. No background Rust tasks.
use super::state::{BodyBudget, FetchLease, error_outcome, prepare};
use super::{FetchBytesError, FetchBytesLimits, FetchBytesResponse, FetchBytesStage};
use asupersync::types::{WasmAbiOutcomeEnvelope, WasmAbiValue, WasmAbiVersion, WasmFetchRequest, WasmHandleRef};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{AbortController, AbortSignal, ReadableStreamDefaultReader, RequestCredentials, RequestInit, RequestRedirect, Response};

#[cfg(test)]
mod tests;

struct HostFetch {
    lease: FetchLease,
    handle: WasmHandleRef,
    controller: AbortController,
    signal: AbortSignal,
    reader: Option<ReadableStreamDefaultReader>,
    completed: bool,
}

impl HostFetch {
    fn new(lease: FetchLease) -> Result<Self, FetchBytesError> {
        let controller = AbortController::new()
            .map_err(|_| FetchBytesError::Host { stage: FetchBytesStage::Setup })?;
        let handle = lease.handle();
        let signal = controller.signal();
        let operation = Self {
            lease, handle, controller, signal, reader: None, completed: false,
        };
        crate::register_inflight_fetch(handle, operation.controller.clone());
        operation.check_active()?;
        Ok(operation)
    }

    fn check_active(&self) -> Result<(), FetchBytesError> {
        if self.signal.aborted() {
            return Err(FetchBytesError::Cancelled);
        }
        self.lease.check_active()
    }

    fn request_init(&self, request: &WasmFetchRequest) -> RequestInit {
        let init = RequestInit::new();
        init.set_method(&request.method);
        init.set_signal(Some(&self.signal));
        init.set_credentials(if request.credentials {
            RequestCredentials::Include
        } else {
            RequestCredentials::Omit
        });
        // The scope authorizes the initial URL, not the whole redirect chain.
        // A post-response redirected check would be too late to prevent effects.
        init.set_redirect(RequestRedirect::Error);
        if let Some(body) = &request.body {
            let bytes = js_sys::Uint8Array::from(body.as_slice());
            init.set_body(bytes.as_ref());
        }
        init
    }

    async fn run(&mut self, request: &WasmFetchRequest, limits: FetchBytesLimits)
        -> Result<FetchBytesResponse, FetchBytesError>
    {
        let init = self.request_init(request);
        self.check_active()?;
        let promise = crate::host_fetch_with_str_and_init(&request.url, &init)
            .map_err(|_| FetchBytesError::Host { stage: FetchBytesStage::Setup })?;
        let result = JsFuture::from(promise).await;
        // Cancellation dominates an already-queued response or rejection.
        self.check_active()?;
        let value = result.map_err(|_| FetchBytesError::Host { stage: FetchBytesStage::Response })?;
        let response = value.dyn_into::<Response>().map_err(|_| FetchBytesError::InvalidResponse)?;
        self.read_response(response, limits).await
    }

    async fn read_response(&mut self, response: Response, limits: FetchBytesLimits)
        -> Result<FetchBytesResponse, FetchBytesError>
    {
        self.check_active()?;
        let status = response.status();
        if status == 0 || response.redirected() {
            return Err(FetchBytesError::InvalidResponse);
        }
        let Some(stream) = response.body() else {
            self.check_active()?;
            return Ok(FetchBytesResponse { status, body: Vec::new() });
        };
        let reader = ReadableStreamDefaultReader::new(&stream)
            .map_err(|_| FetchBytesError::Host { stage: FetchBytesStage::Reader })?;
        self.reader = Some(reader);
        let mut budget = BodyBudget::new(limits);
        let mut body = Vec::new();
        loop {
            self.check_active()?;
            // This charges empty chunks and the EOF read, not merely byteful
            // chunks. An endless empty stream cannot bypass the work budget.
            budget.begin_read()?;
            let promise = self.reader.as_ref().expect("reader remains owned until retirement").read();
            let result = JsFuture::from(promise).await;
            self.check_active()?;
            let chunk = result.map_err(|_| FetchBytesError::Host { stage: FetchBytesStage::Read })?;
            let done = js_sys::Reflect::get(&chunk, &JsValue::from_str("done"))
                .map_err(|_| FetchBytesError::InvalidResponse)?
                .as_bool().ok_or(FetchBytesError::InvalidResponse)?;
            self.check_active()?;
            if done {
                return Ok(FetchBytesResponse { status, body });
            }
            let value = js_sys::Reflect::get(&chunk, &JsValue::from_str("value"))
                .map_err(|_| FetchBytesError::InvalidResponse)?;
            let bytes = value.dyn_into::<js_sys::Uint8Array>()
                .map_err(|_| FetchBytesError::InvalidResponse)?;
            self.check_active()?;
            let length = usize::try_from(bytes.length()).map_err(|_| FetchBytesError::LengthOverflow)?;
            // The limit is enforced BEFORE JS bytes enter the Rust allocation.
            // The host's existing chunk is explicitly outside this byte bound.
            let destination = budget.reserve_chunk(&mut body, length)?;
            bytes.copy_to(&mut body[destination]);
        }
    }

    fn finish(mut self, mut result: Result<FetchBytesResponse, FetchBytesError>)
        -> Result<FetchBytesResponse, FetchBytesError>
    {
        if self.check_active().is_err() {
            result = Err(FetchBytesError::Cancelled);
        }
        let summary = match &result {
            Ok(response) => WasmAbiOutcomeEnvelope::Ok { value: WasmAbiValue::U64(u64::from(response.status)) },
            Err(error) => error_outcome(*error),
        };
        // Do not copy body bytes into the handle ledger. The caller alone owns
        // them, and a failed publication cannot manufacture successful delivery.
        let publication = self.lease.publish(summary);
        match publication {
            Ok(()) => {
                self.completed = result.is_ok();
                result
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for HostFetch {
    fn drop(&mut self) {
        // Remove registry ownership before invoking synchronous abort listeners.
        // Both this guard and scope cleanup can arrive first; abort is idempotent.
        let _ = crate::take_inflight_fetch(&self.handle);
        if !self.completed {
            self.controller.abort();
        }
        if let Some(reader) = self.reader.take() {
            // Fetch abort errors its response stream. Releasing the reader also
            // rejects any outstanding read Promise, whose JsFuture already owns
            // a rejection handler even when that Rust future has been dropped.
            reader.release_lock();
        }
        // FetchLease's destructor releases an unpublished handle, if still live,
        // after host callbacks finish and all registry borrows have been dropped.
    }
}

pub(super) async fn fetch_bytes(
    request: WasmFetchRequest,
    limits: FetchBytesLimits,
    consumer_version: Option<WasmAbiVersion>,
) -> Result<FetchBytesResponse, FetchBytesError> {
    let (request, lease) = prepare(request, limits, consumer_version)?;
    let mut operation = HostFetch::new(lease)?;
    let result = operation.run(&request, limits).await;
    operation.finish(result)
}
