//! An owned pending read survives cancellation of a temporary next-chunk wait.
use super::*;
use crate::fetch::stream::{FetchStream, FetchStreamLimits, StreamBudget};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

pub(crate) struct HostBody {
    // Abort and reader release run before the pending JsFuture is destroyed.
    operation: Option<HostFetch>,
    pending: Option<Pin<Box<JsFuture>>>,
    budget: StreamBudget,
    status: u16,
    terminal: Option<Result<(), FetchBytesError>>,
}

impl HostBody {
    fn from_response(
        mut operation: HostFetch,
        response: Response,
        limits: FetchStreamLimits,
    ) -> Result<Self, FetchBytesError> {
        let setup = (|| {
            operation.check_active()?;
            let status = response.status();
            if status == 0 || response.redirected() {
                return Err(FetchBytesError::InvalidResponse);
            }
            if let Some(stream) = response.body() {
                operation.reader = Some(ReadableStreamDefaultReader::new(&stream)
                    .map_err(|_| FetchBytesError::Host { stage: FetchBytesStage::Reader })?);
            }
            operation.check_active()?;
            Ok(status)
        })();
        let status = match setup {
            Ok(status) => status,
            Err(error) => return Err(retire_error(operation, error)),
        };
        Ok(Self {
            operation: Some(operation), pending: None,
            budget: StreamBudget::new(limits), status, terminal: None,
        })
    }

    pub(crate) fn received_bytes(&self) -> usize { self.budget.received() }

    fn poll_read(&mut self, cx: &mut Context<'_>)
        -> Poll<Result<Option<Vec<u8>>, FetchBytesError>>
    {
        let operation = self.operation.as_ref().expect("nonterminal body owns its request");
        operation.check_active()?;
        let Some(reader) = operation.reader.as_ref() else {
            return Poll::Ready(Ok(None));
        };
        if self.pending.is_none() {
            self.budget.begin_read()?;
            // Store the actual Promise owner before yielding. A dropped wait
            // must not issue a second read that could skip this read's bytes.
            self.pending = Some(Box::pin(JsFuture::from(reader.read())));
        }
        let result = ready!(self.pending.as_mut().expect("read is installed").as_mut().poll(cx));
        self.pending = None;
        operation.check_active()?;
        let chunk = result.map_err(|_| FetchBytesError::Host { stage: FetchBytesStage::Read })?;
        let done = js_sys::Reflect::get(&chunk, &JsValue::from_str("done"))
            .map_err(|_| FetchBytesError::InvalidResponse)?
            .as_bool().ok_or(FetchBytesError::InvalidResponse)?;
        operation.check_active()?;
        if done { return Poll::Ready(Ok(None)); }
        let value = js_sys::Reflect::get(&chunk, &JsValue::from_str("value"))
            .map_err(|_| FetchBytesError::InvalidResponse)?;
        let bytes = value.dyn_into::<js_sys::Uint8Array>()
            .map_err(|_| FetchBytesError::InvalidResponse)?;
        operation.check_active()?;
        let length = usize::try_from(bytes.length()).map_err(|_| FetchBytesError::LengthOverflow)?;
        let mut output = self.budget.copy_buffer(length)?;
        bytes.copy_to(&mut output);
        operation.check_active()?;
        self.budget.commit(length)?;
        Poll::Ready(Ok(Some(output)))
    }

    pub(crate) fn poll_chunk(&mut self, cx: &mut Context<'_>)
        -> Poll<Result<Option<Vec<u8>>, FetchBytesError>>
    {
        if let Some(terminal) = self.terminal {
            return Poll::Ready(terminal.map(|()| None));
        }
        let result = ready!(self.poll_read(cx));
        if matches!(&result, Ok(Some(_))) { return Poll::Ready(result); }

        // Only actual EOF publishes success. Never copy delivered chunks into
        // the dispatcher. Retire the abort/reader owner before returning Ready.
        let terminal = result.map(|_| ());
        self.terminal = Some(terminal);
        let summary = terminal.map(|()| FetchBytesResponse { status: self.status, body: Vec::new() });
        let published = self.operation.take().expect("terminal body owns its request")
            .finish(summary).map(|_| ());
        // Finish also applies cancellation dominance and publication failures.
        self.terminal = Some(published);
        self.pending = None;
        Poll::Ready(published.map(|()| None))
    }
}

pub(crate) async fn open(
    request: WasmFetchRequest,
    limits: FetchStreamLimits,
    consumer_version: Option<WasmAbiVersion>,
) -> Result<FetchStream, FetchBytesError> {
    let (request, lease) = prepare(request, limits.transfer, consumer_version)?;
    let mut operation = HostFetch::new(lease)?;
    let response = match operation.open_response(&request).await {
        Ok(response) => response,
        Err(error) => return Err(retire_error(operation, error)),
    };
    let body = HostBody::from_response(operation, response, limits)?;
    Ok(FetchStream { status: body.status, body, _local: std::marker::PhantomData })
}

fn retire_error(operation: HostFetch, error: FetchBytesError) -> FetchBytesError {
    operation.finish(Err(error)).err().expect("an error cannot publish success")
}

#[cfg(test)]
mod tests;
