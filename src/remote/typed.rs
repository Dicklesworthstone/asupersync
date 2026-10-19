//! Typed JSON computations over the existing named-computation transport.
//!
//! This is an opt-in application codec inside [`RemoteInput`]. It does not
//! change the V1/V2/V3 envelopes, authentication, leases, or idempotency rules.
//! A bounded, versioned envelope identifies the computation, direction, and
//! declared input/output schemas before application deserialization runs.
//! [`HasSchema`] must describe the application's serde contract honestly;
//! schema fingerprints detect disagreement and do not authenticate a peer.
//!
//! Payloads are JSON encoded inside a JSON string. This preserves duplicate
//! fields for the application's deserializer and lets the adapter validate
//! envelope metadata before calling any application deserialization code.
//! Envelope fields are strict; payload rules, including serde field aliases
//! and `deny_unknown_fields`, belong to the application's input/output types.

use super::{
    ComputationName, NodeId, RemoteComputationRegistry, RemoteError, RemoteHandle, RemoteInput,
    RemoteOutcome, RemoteTaskId, RemoteTaskState, spawn_remote,
};
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
use super::{NativeRemoteAdmittedHandle, NativeRemoteReservation};
use crate::cx::Cx;
use crate::distributed::{HasSchema, SchemaDescriptor};
use crate::types::{CancelReason, Outcome};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::future::Future;
use std::io::{self, Write};
use std::marker::PhantomData;
use std::sync::Arc;
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
use std::time::Duration;

const CODEC_VERSION: u16 = 1;
const MAX_COMPUTATION_NAME_BYTES: usize = 255;

/// A stable computation name and its declared JSON input and output types.
///
/// Implement this on a zero-sized marker shared by client and server. The
/// serde representations and [`HasSchema`] descriptors must agree between
/// them. This trait does not ship Rust closures or infer a schema from serde.
pub trait TypedRemoteComputation: 'static {
    /// Stable registry name, between one and 255 UTF-8 bytes.
    const NAME: &'static str;
    /// Input accepted by the registered handler.
    type Input: HasSchema + Serialize + DeserializeOwned + Send + 'static;
    /// Successful output produced by the registered handler.
    type Output: HasSchema + Serialize + DeserializeOwned + Send + 'static;
}

/// Per-call encoded application-envelope bounds, independent of transport caps.
///
/// The transport may impose a smaller limit after its own framing/encoding.
/// These limits bound codec buffers, not memory allocated by user serializers,
/// deserializers, or handler code. Zero explicitly refuses every encoded value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypedRemoteLimits {
    max_request_bytes: usize,
    max_response_bytes: usize,
}

impl TypedRemoteLimits {
    /// Sets complete encoded request and successful-response envelope limits.
    #[must_use]
    pub const fn new(max_request_bytes: usize, max_response_bytes: usize) -> Self {
        Self {
            max_request_bytes,
            max_response_bytes,
        }
    }

    /// Maximum encoded application request, including its metadata.
    #[must_use]
    pub const fn max_request_bytes(self) -> usize {
        self.max_request_bytes
    }

    /// Maximum encoded successful application response, including its metadata.
    #[must_use]
    pub const fn max_response_bytes(self) -> usize {
        self.max_response_bytes
    }

    const fn for_stage(self, stage: TypedRemoteStage) -> usize {
        match stage {
            TypedRemoteStage::Request => self.max_request_bytes,
            TypedRemoteStage::Response => self.max_response_bytes,
        }
    }
}

impl Default for TypedRemoteLimits {
    fn default() -> Self {
        Self::new(16 * 1024, 16 * 1024)
    }
}

/// Direction of a typed application envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypedRemoteStage {
    /// Handler input sent to the remote node.
    Request,
    /// Successful handler output sent to the origin.
    Response,
}

impl fmt::Display for TypedRemoteStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Request => "request",
            Self::Response => "response",
        })
    }
}

/// Typed-codec refusal or the unchanged underlying remote-lifecycle failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TypedRemoteError {
    /// A marker supplied a name the native named-computation path cannot accept.
    #[error("typed remote computation name must contain 1..=255 bytes")]
    InvalidName,
    /// Serialization or received bytes exceed the complete envelope limit.
    #[error("typed remote {stage} exceeds its {limit}-byte envelope limit")]
    LimitExceeded {
        /// Affected direction.
        stage: TypedRemoteStage,
        /// Configured envelope limit.
        limit: usize,
    },
    /// User serialization or envelope encoding failed.
    #[error("typed remote {stage} encoding failed: {message}")]
    Encode {
        /// Affected direction.
        stage: TypedRemoteStage,
        /// Diagnostic supplied by the serializer or envelope codec.
        message: String,
    },
    /// The strict envelope or its application payload is not valid JSON for its type.
    #[error("typed remote {stage} decoding failed: {message}")]
    Decode {
        /// Affected direction.
        stage: TypedRemoteStage,
        /// Diagnostic supplied by the deserializer or envelope codec.
        message: String,
    },
    /// The application-codec version is unsupported.
    #[error("unsupported typed remote codec version {actual}; expected 1")]
    Version {
        /// Received codec version.
        actual: u16,
    },
    /// An envelope was delivered for a different named computation.
    #[error("typed remote computation mismatch: expected {expected}, received {actual}")]
    Computation {
        /// Marker name expected by this endpoint.
        expected: &'static str,
        /// Name carried by the bounded envelope.
        actual: String,
    },
    /// A request was reflected as a response, or the reverse.
    #[error("typed remote direction mismatch: expected {expected}, received {actual}")]
    Direction {
        /// Expected envelope direction.
        expected: TypedRemoteStage,
        /// Received envelope direction.
        actual: TypedRemoteStage,
    },
    /// An input or output schema differs before application decoding begins.
    #[error("typed remote {stage} schema mismatch: expected {expected:016x}, received {actual:016x}")]
    Schema {
        /// Schema that disagrees, independent of the envelope direction.
        stage: TypedRemoteStage,
        /// Declared fingerprint at this endpoint.
        expected: u64,
        /// Fingerprint carried by the bounded envelope.
        actual: u64,
    },
    /// The existing registry refused a duplicate computation name.
    #[error(transparent)]
    Registration(#[from] crate::distributed::ComputationSchemaRegistryError),
    /// Original capability, transport, lease, cancellation, or terminal-consumption error.
    #[error(transparent)]
    Remote(#[from] RemoteError),
    /// The existing charged native domain refused local admission or control.
    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    #[error(transparent)]
    Admission(#[from] super::NativeRemoteAdmissionError),
}

/// Remote terminal outcome with a decoded successful value.
///
/// A cancelled observation remains the outer `Outcome::Err(Remote(...))` as
/// on [`RemoteHandle`]. A remotely cancelled computation is this inner
/// `Cancelled` variant. The two are deliberately not collapsed.
#[derive(Clone, Debug)]
pub enum TypedRemoteOutcome<T> {
    /// Successfully decoded application output.
    Success(T),
    /// Application failure reported by the remote handler.
    Failed(String),
    /// Remote computation cancellation with its original reason.
    Cancelled(CancelReason),
    /// Remote computation panic with its original diagnostic.
    Panicked(String),
}

#[derive(Clone, Copy)]
struct Signature {
    name: &'static str,
    input: u64,
    output: u64,
}

impl Signature {
    fn of<C: TypedRemoteComputation>() -> Result<Self, TypedRemoteError> {
        if C::NAME.is_empty() || C::NAME.len() > MAX_COMPUTATION_NAME_BYTES {
            return Err(TypedRemoteError::InvalidName);
        }
        Ok(Self {
            name: C::NAME,
            input: C::Input::schema_fingerprint().to_u64(),
            output: C::Output::schema_fingerprint().to_u64(),
        })
    }
}

#[derive(Serialize)]
struct EncodeEnvelope<'a> {
    version: u16,
    computation: &'a str,
    direction: TypedRemoteStage,
    input_schema: u64,
    output_schema: u64,
    payload: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodeEnvelope {
    version: u16,
    computation: String,
    direction: TypedRemoteStage,
    input_schema: u64,
    output_schema: u64,
    payload: String,
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "typed envelope limit",
            ));
        }
        let required = self.bytes.len() + bytes.len();
        if required > self.bytes.capacity() {
            let capacity = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(64)
                .max(required)
                .min(self.limit);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(io::Error::other)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_bounded(
    value: &impl Serialize,
    stage: TypedRemoteStage,
    limit: usize,
) -> Result<Vec<u8>, TypedRemoteError> {
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        limit,
        exceeded: false,
    };
    let encoded = serde_json::to_writer(&mut writer, value);
    // A custom serializer can swallow an element's write error and still finish.
    // An attempted oversize write must refuse publication even in that case.
    if writer.exceeded {
        return Err(TypedRemoteError::LimitExceeded { stage, limit });
    }
    encoded.map_err(|error| TypedRemoteError::Encode {
        stage,
        message: error.to_string(),
    })?;
    Ok(writer.bytes)
}

fn encode_value(
    signature: Signature,
    stage: TypedRemoteStage,
    value: &impl Serialize,
    limits: TypedRemoteLimits,
) -> Result<Vec<u8>, TypedRemoteError> {
    let limit = limits.for_stage(stage);
    let payload = encode_bounded(value, stage, limit)?;
    let payload = std::str::from_utf8(&payload).map_err(|error| TypedRemoteError::Encode {
        stage,
        message: error.to_string(),
    })?;
    encode_bounded(
        &EncodeEnvelope {
            version: CODEC_VERSION,
            computation: signature.name,
            direction: stage,
            input_schema: signature.input,
            output_schema: signature.output,
            payload,
        },
        stage,
        limit,
    )
}

fn decode_value<T: DeserializeOwned>(
    signature: Signature,
    stage: TypedRemoteStage,
    bytes: &[u8],
    limits: TypedRemoteLimits,
) -> Result<T, TypedRemoteError> {
    let limit = limits.for_stage(stage);
    if bytes.len() > limit {
        return Err(TypedRemoteError::LimitExceeded { stage, limit });
    }
    let envelope: DecodeEnvelope =
        serde_json::from_slice(bytes).map_err(|error| TypedRemoteError::Decode {
            stage,
            message: error.to_string(),
        })?;
    if envelope.version != CODEC_VERSION {
        return Err(TypedRemoteError::Version {
            actual: envelope.version,
        });
    }
    if envelope.computation != signature.name {
        return Err(TypedRemoteError::Computation {
            expected: signature.name,
            actual: envelope.computation,
        });
    }
    if envelope.direction != stage {
        return Err(TypedRemoteError::Direction {
            expected: stage,
            actual: envelope.direction,
        });
    }
    for (schema_stage, expected, actual) in [
        (TypedRemoteStage::Request, signature.input, envelope.input_schema),
        (TypedRemoteStage::Response, signature.output, envelope.output_schema),
    ] {
        if expected != actual {
            return Err(TypedRemoteError::Schema {
                stage: schema_stage,
                expected,
                actual,
            });
        }
    }
    serde_json::from_str(&envelope.payload).map_err(|error| TypedRemoteError::Decode {
        stage,
        message: error.to_string(),
    })
}

// The negotiated registry commits to this opt-in codec and version as well as
// its decoded payload types. A raw registration of the same I/O types does not
// accidentally advertise the typed-JSON adapter's dispatch contract.
struct RequestSchema<C>(PhantomData<fn() -> C>);
struct ResponseSchema<C>(PhantomData<fn() -> C>);

impl<C: TypedRemoteComputation> HasSchema for RequestSchema<C> {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::structure(
            "asupersync.remote.typed-json.request.v1",
            vec![
                ("decoded_input", C::Input::schema()),
                ("decoded_output", C::Output::schema()),
            ],
        )
    }
}

impl<C: TypedRemoteComputation> HasSchema for ResponseSchema<C> {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::structure(
            "asupersync.remote.typed-json.response.v1",
            vec![
                ("decoded_input", C::Input::schema()),
                ("decoded_output", C::Output::schema()),
            ],
        )
    }
}

impl RemoteComputationRegistry {
    /// Registers a typed handler with bounded JSON decoding and encoding.
    ///
    /// The adapter validates its strict envelope, direction, name, version, and
    /// both declared schemas before deserializing input or invoking `handler`.
    /// Its versioned codec schemas participate in the existing authenticated
    /// registry handshake. Codec refusal uses the existing serialization-error
    /// dispatch path. Application failures, cancellation and panics retain the
    /// existing remote terminal variants.
    ///
    /// No task is spawned here: the established service owns the actual handler
    /// task, lease, cancellation, idempotency record, and descendant cleanup.
    ///
    /// ```
    /// use asupersync::remote::{
    ///     RemoteComputationRegistry, TypedRemoteComputation, TypedRemoteLimits,
    ///     TypedRemoteOutcome,
    /// };
    /// struct Add;
    /// impl TypedRemoteComputation for Add {
    ///     const NAME: &'static str = "add";
    ///     type Input = (u64, u64);
    ///     type Output = u64;
    /// }
    /// let mut registry = RemoteComputationRegistry::new();
    /// registry.register_typed_json::<Add, _, _>(
    ///     TypedRemoteLimits::default(),
    ///     |_cx, (a, b)| async move { TypedRemoteOutcome::Success(a + b) },
    /// ).unwrap();
    /// ```
    pub fn register_typed_json<C, F, Fut>(
        &mut self,
        limits: TypedRemoteLimits,
        handler: F,
    ) -> Result<(), TypedRemoteError>
    where
        C: TypedRemoteComputation,
        F: Fn(Cx, C::Input) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = TypedRemoteOutcome<C::Output>> + Send + 'static,
    {
        let signature = Signature::of::<C>()?;
        let handler = Arc::new(handler);
        self.register::<RequestSchema<C>, ResponseSchema<C>, _, _>(
            C::NAME,
            move |cx, invocation| {
                let handler = Arc::clone(&handler);
                async move {
                    if let Some(reason) = caller_cancellation(&cx) {
                        return Ok(RemoteOutcome::Cancelled(reason));
                    }
                    let input = decode_value::<C::Input>(
                        signature,
                        TypedRemoteStage::Request,
                        invocation.request().input.data(),
                        limits,
                    )
                    .map_err(codec_dispatch_error)?;
                    // A custom deserializer may have cooperated with an
                    // external cancellation request; never start its handler
                    // after that request has become observable.
                    if let Some(reason) = caller_cancellation(&cx) {
                        return Ok(RemoteOutcome::Cancelled(reason));
                    }
                    match handler(cx, input).await {
                        TypedRemoteOutcome::Success(value) => encode_value(
                            signature,
                            TypedRemoteStage::Response,
                            &value,
                            limits,
                        )
                        .map(RemoteOutcome::Success)
                        .map_err(codec_dispatch_error),
                        TypedRemoteOutcome::Failed(message) => Ok(RemoteOutcome::Failed(message)),
                        TypedRemoteOutcome::Cancelled(reason) => Ok(RemoteOutcome::Cancelled(reason)),
                        TypedRemoteOutcome::Panicked(message) => Ok(RemoteOutcome::Panicked(message)),
                    }
                }
            },
        )?;
        Ok(())
    }
}

fn codec_dispatch_error(error: TypedRemoteError) -> RemoteError {
    match error {
        TypedRemoteError::Remote(error) => error,
        other => RemoteError::SerializationError(other.to_string()),
    }
}

fn check_caller(cx: &Cx) -> Result<(), TypedRemoteError> {
    if let Some(reason) = caller_cancellation(cx) {
        return Err(RemoteError::Cancelled(reason).into());
    }
    Ok(())
}

fn caller_cancellation(cx: &Cx) -> Option<CancelReason> {
    cx.checkpoint().err().map(|_| {
        cx.cancel_reason()
            .unwrap_or_else(CancelReason::parent_cancelled)
    })
}

/// Bounded encoded input ready for one typed remote publication.
///
/// Encoding is separate from native reservation so admission waiters need not
/// own an extra payload. Prepared bytes are caller-owned until publication;
/// they are not charged to a native admission domain while the caller holds
/// them. Reserve [`encoded_len`](Self::encoded_len), then consume this value
/// with `commit` on native TLS builds.
#[must_use = "a prepared call performs no remote work until it is published"]
pub struct PreparedTypedRemoteCall<C: TypedRemoteComputation> {
    input: RemoteInput,
    signature: Signature,
    limits: TypedRemoteLimits,
    marker: PhantomData<fn() -> C>,
}

impl<C: TypedRemoteComputation> fmt::Debug for PreparedTypedRemoteCall<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedTypedRemoteCall")
            .field("computation", &self.signature.name)
            .field("encoded_len", &self.input.len())
            .finish_non_exhaustive()
    }
}

impl<C: TypedRemoteComputation> PreparedTypedRemoteCall<C> {
    /// Encodes input, refusing oversize output before a remote task is admitted.
    pub fn encode(input: &C::Input, limits: TypedRemoteLimits) -> Result<Self, TypedRemoteError> {
        let signature = Signature::of::<C>()?;
        let bytes = encode_value(signature, TypedRemoteStage::Request, input, limits)?;
        Ok(Self {
            input: RemoteInput::new(bytes),
            signature,
            limits,
            marker: PhantomData,
        })
    }

    /// Exact application input length to supply to native admission.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.input.len()
    }

    /// Borrows the bounded application envelope for an existing wire adapter.
    ///
    /// These bytes are caller-owned. Borrowing them does not reserve capacity,
    /// publish a request, or acquire remote authority.
    #[must_use]
    pub fn encoded_input(&self) -> &[u8] {
        self.input.data()
    }

    /// Publishes through the caller's existing remote capability.
    pub fn spawn(self, cx: &Cx, node: NodeId) -> Result<TypedRemoteHandle<C>, TypedRemoteError> {
        check_caller(cx)?;
        let handle = spawn_remote(cx, node, ComputationName::new(C::NAME), self.input)?;
        Ok(TypedRemoteHandle {
            inner: Handle::Plain(handle),
            signature: self.signature,
            limits: self.limits,
            marker: PhantomData,
        })
    }

    /// Commits a caller-acquired reservation to the existing charged native path.
    ///
    /// The reservation must cover exactly `encoded_len()`. All native frame,
    /// peer, cancellation and closed-domain checks still run before publication.
    /// The returned handle retains the native charge through driver retirement
    /// and consumption of an unread terminal result.
    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    pub fn commit(
        self,
        cx: &Cx,
        reservation: NativeRemoteReservation,
        lease: Duration,
    ) -> Result<TypedRemoteHandle<C>, TypedRemoteError> {
        let handle = reservation.commit(
            cx,
            &ComputationName::new(C::NAME),
            self.input.data(),
            lease,
        )?;
        Ok(TypedRemoteHandle {
            inner: Handle::Admitted(handle),
            signature: self.signature,
            limits: self.limits,
            marker: PhantomData,
        })
    }
}

/// Encodes and spawns a typed computation through an existing remote capability.
///
/// Cancellation and missing authority are checked before application encoding.
/// Use [`PreparedTypedRemoteCall`] with a native reservation when per-peer
/// queued/active buffer admission is required.
///
/// Input types are checked before code can publish a request:
///
/// ```compile_fail
/// use asupersync::{Cx, remote::{
///     NodeId, TypedRemoteComputation, TypedRemoteLimits, spawn_remote_typed,
/// }};
/// struct Add;
/// impl TypedRemoteComputation for Add {
///     const NAME: &'static str = "add";
///     type Input = (u64, u64);
///     type Output = u64;
/// }
/// fn wrong_input(cx: &Cx) {
///     let _ = spawn_remote_typed::<Add>(
///         cx, NodeId::new("worker"), &"not a pair", TypedRemoteLimits::default(),
///     );
/// }
/// ```
pub fn spawn_remote_typed<C: TypedRemoteComputation>(
    cx: &Cx,
    node: NodeId,
    input: &C::Input,
    limits: TypedRemoteLimits,
) -> Result<TypedRemoteHandle<C>, TypedRemoteError> {
    check_caller(cx)?;
    if cx.remote().is_none() {
        return Err(RemoteError::NoCapability.into());
    }
    PreparedTypedRemoteCall::<C>::encode(input, limits)?.spawn(cx, node)
}

enum Handle {
    Plain(RemoteHandle),
    #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
    Admitted(NativeRemoteAdmittedHandle),
}

/// Typed result decoding without replacing the underlying remote lifecycle.
///
/// Dropping a live handle delegates to the established cancellation backstop.
/// Call [`close`](Self::close) and await it to collect remote terminal cleanup.
/// A cancelled `join` leaves this handle usable for a later join or close. An
/// output-codec error consumes the already-terminal result exactly once.
#[must_use = "remote work must be joined or closed to observe its terminal outcome"]
pub struct TypedRemoteHandle<C: TypedRemoteComputation> {
    inner: Handle,
    signature: Signature,
    limits: TypedRemoteLimits,
    marker: PhantomData<fn() -> C>,
}

impl<C: TypedRemoteComputation> fmt::Debug for TypedRemoteHandle<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypedRemoteHandle")
            .field("computation", &self.signature.name)
            .field("task", &self.remote_task_id())
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl<C: TypedRemoteComputation> TypedRemoteHandle<C> {
    /// Existing transport correlation identity.
    #[must_use]
    pub fn remote_task_id(&self) -> RemoteTaskId {
        match &self.inner {
            Handle::Plain(handle) => handle.remote_task_id(),
            #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
            Handle::Admitted(handle) => handle.remote_task_id(),
        }
    }

    /// Current state as observed by the existing remote adapter.
    #[must_use]
    pub fn state(&self) -> RemoteTaskState {
        match &self.inner {
            Handle::Plain(handle) => handle.state(),
            #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
            Handle::Admitted(handle) => handle.state(),
        }
    }

    /// Waits for a result while preserving cancellation of only this observation.
    pub async fn join(&mut self, cx: &Cx) -> Outcome<TypedRemoteOutcome<C::Output>, TypedRemoteError> {
        let result = match &mut self.inner {
            Handle::Plain(handle) => handle.join(cx).await,
            #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
            Handle::Admitted(handle) => handle.join(cx).await,
        };
        self.decode_observation(result)
    }

    /// Consumes a ready terminal result once; pending observations retain ownership.
    pub fn try_join(&mut self) -> Result<Option<TypedRemoteOutcome<C::Output>>, TypedRemoteError> {
        let result = match &mut self.inner {
            Handle::Plain(handle) => handle.try_join(),
            #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
            Handle::Admitted(handle) => handle.try_join(),
        }?;
        result.map(|outcome| self.decode_outcome(outcome)).transpose()
    }

    /// Requests cancellation through the underlying handle's existing authority.
    ///
    /// This does not wait for retirement. The native admitted variant preserves
    /// its bounded protected-control refusal and exact cancellation reason.
    pub fn abort(&self, cx: &Cx) -> Result<(), TypedRemoteError> {
        match &self.inner {
            Handle::Plain(handle) => handle.abort(cx),
            #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
            Handle::Admitted(handle) => {
                let reason = cx
                    .cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("remote handle abort"));
                handle.cancel(&reason)?;
            }
        }
        Ok(())
    }

    /// Cancels and collects the terminal result without interrupting the drain.
    pub async fn close(&mut self, cx: &Cx) -> Outcome<TypedRemoteOutcome<C::Output>, TypedRemoteError> {
        let result = match &mut self.inner {
            Handle::Plain(handle) => handle.close(cx).await,
            #[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
            Handle::Admitted(handle) => {
                let reason = cx
                    .cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("remote handle close"));
                match handle.close(cx, &reason).await {
                    Ok(result) => result,
                    Err(error) => return Outcome::Err(error.into()),
                }
            }
        };
        self.decode_observation(result)
    }

    fn decode_observation(
        &self,
        result: Outcome<RemoteOutcome, RemoteError>,
    ) -> Outcome<TypedRemoteOutcome<C::Output>, TypedRemoteError> {
        match result {
            Outcome::Ok(outcome) => match self.decode_outcome(outcome) {
                Ok(value) => Outcome::Ok(value),
                Err(error) => Outcome::Err(error),
            },
            Outcome::Err(error) => Outcome::Err(error.into()),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    fn decode_outcome(
        &self,
        outcome: RemoteOutcome,
    ) -> Result<TypedRemoteOutcome<C::Output>, TypedRemoteError> {
        Ok(match outcome {
            RemoteOutcome::Success(bytes) => TypedRemoteOutcome::Success(decode_value(
                self.signature,
                TypedRemoteStage::Response,
                &bytes,
                self.limits,
            )?),
            RemoteOutcome::Failed(message) => TypedRemoteOutcome::Failed(message),
            RemoteOutcome::Cancelled(reason) => TypedRemoteOutcome::Cancelled(reason),
            RemoteOutcome::Panicked(message) => TypedRemoteOutcome::Panicked(message),
        })
    }
}

#[cfg(test)]
mod tests;
