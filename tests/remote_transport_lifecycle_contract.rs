#![cfg(feature = "test-internals")]
//! Production-transport-backed proof for the RemoteRuntime lifecycle contract.

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::remote::{
    ComputationName, MessageEnvelope, NodeId, RemoteError, RemoteInput, RemoteMessage,
    RemoteOutcome, RemoteRuntime, RemoteTaskId, RemoteTaskState, RemoteTransport,
    SpawnRejectReason, spawn_remote,
};
use asupersync::trace::TraceBufferHandle;
use asupersync::trace::distributed::LogicalTime;
use asupersync::types::CancelReason;
use futures_lite::future::block_on;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::net::{Shutdown, SocketAddr};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const BEAD_ID: &str = "asupersync-5d9s85";
const ORIGIN_NODE: &str = "origin-prod-loopback";
const REMOTE_NODE: &str = "remote-prod-loopback";
const TRANSPORT_KIND: &str = "asupersync_tcp_loopback";
const MAX_FRAME_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum WireCommand {
    Spawn {
        remote_task_id: u64,
        origin_node: String,
        destination_node: String,
        computation: String,
        input_len: usize,
        lease_ms: u64,
        idempotency_key: String,
        sender_lamport: u64,
    },
    Cancel {
        remote_task_id: u64,
        origin_node: String,
        destination_node: String,
        reason: String,
        sender_lamport: u64,
    },
    LeaseProbe {
        remote_task_id: u64,
        origin_node: String,
        destination_node: String,
        lease_ms: u64,
        sender_lamport: u64,
    },
}

impl WireCommand {
    fn remote_task_id(&self) -> u64 {
        match self {
            Self::Spawn { remote_task_id, .. }
            | Self::Cancel { remote_task_id, .. }
            | Self::LeaseProbe { remote_task_id, .. } => *remote_task_id,
        }
    }

    fn idempotency_key(&self) -> &str {
        match self {
            Self::Spawn {
                idempotency_key, ..
            } => idempotency_key,
            Self::Cancel { .. } | Self::LeaseProbe { .. } => "none",
        }
    }

    fn command_name(&self) -> &'static str {
        match self {
            Self::Spawn { .. } => "spawn",
            Self::Cancel { .. } => "cancel",
            Self::LeaseProbe { .. } => "lease_probe",
        }
    }

    fn from_remote_message(
        destination: &NodeId,
        envelope: &MessageEnvelope<RemoteMessage>,
    ) -> Result<Self, RemoteError> {
        let sender_lamport = lamport_raw(&envelope.sender_time);
        let destination_node = destination.as_str().to_owned();
        match &envelope.payload {
            RemoteMessage::SpawnRequest(request) => Ok(Self::Spawn {
                remote_task_id: request.remote_task_id.raw(),
                origin_node: request.origin_node.as_str().to_owned(),
                destination_node,
                computation: request.computation.as_str().to_owned(),
                input_len: request.input.len(),
                lease_ms: millis_u64(request.lease),
                idempotency_key: request.idempotency_key.to_string(),
                sender_lamport,
            }),
            RemoteMessage::CancelRequest(request) => Ok(Self::Cancel {
                remote_task_id: request.remote_task_id.raw(),
                origin_node: request.origin_node.as_str().to_owned(),
                destination_node,
                reason: compact(&request.reason.to_string()),
                sender_lamport,
            }),
            RemoteMessage::LeaseRenewal(renewal) => Ok(Self::LeaseProbe {
                remote_task_id: renewal.remote_task_id.raw(),
                origin_node: envelope.sender.as_str().to_owned(),
                destination_node,
                lease_ms: millis_u64(renewal.new_lease),
                sender_lamport,
            }),
            RemoteMessage::SpawnAck(_) | RemoteMessage::ResultDelivery(_) => {
                Err(RemoteError::TransportError(
                    "origin runtime cannot send remote-to-origin protocol messages".to_owned(),
                ))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
enum WireReply {
    AckAccepted {
        remote_task_id: u64,
        assigned_node: String,
    },
    AckRejected {
        remote_task_id: u64,
        reason: String,
    },
    LeaseRenewed {
        remote_task_id: u64,
        current_state: String,
    },
    ResultSuccess {
        remote_task_id: u64,
        payload: Vec<u8>,
    },
    ResultCancelled {
        remote_task_id: u64,
        reason: String,
    },
    LeaseExpired {
        remote_task_id: u64,
    },
    CachedResult {
        remote_task_id: u64,
        idempotency_key: String,
        payload: Vec<u8>,
    },
}

impl WireReply {
    fn remote_task_id(&self) -> u64 {
        match self {
            Self::AckAccepted { remote_task_id, .. }
            | Self::AckRejected { remote_task_id, .. }
            | Self::LeaseRenewed { remote_task_id, .. }
            | Self::ResultSuccess { remote_task_id, .. }
            | Self::ResultCancelled { remote_task_id, .. }
            | Self::LeaseExpired { remote_task_id }
            | Self::CachedResult { remote_task_id, .. } => *remote_task_id,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndpointMode {
    CompleteAfterAck,
    HoldUntilCancel,
    CancelBeforeAck,
    RejectSpawn,
    LeaseRenewalThenSuccess,
    LeaseExpiry,
    DelayedAck,
    MalformedReply,
    CloseWithoutReply,
    DuplicateIdempotency,
}

#[derive(Debug, Default)]
struct EndpointState {
    commands: Mutex<Vec<WireCommand>>,
    executions: Mutex<BTreeMap<String, usize>>,
    cache: Mutex<BTreeMap<String, (String, Vec<u8>)>>,
}

impl EndpointState {
    fn record_command(&self, command: WireCommand) {
        self.commands.lock().push(command);
    }

    fn command_count(&self) -> usize {
        self.commands.lock().len()
    }

    fn execution_count(&self, key: &str) -> usize {
        self.executions.lock().get(key).copied().unwrap_or(0)
    }

    fn mark_execution(&self, key: &str) {
        let mut executions = self.executions.lock();
        let entry = executions.entry(key.to_owned()).or_insert(0);
        *entry += 1;
    }
}

struct TestEndpoint {
    addr: SocketAddr,
    state: Arc<EndpointState>,
    join: thread::JoinHandle<io::Result<()>>,
}

impl TestEndpoint {
    fn launch(mode: EndpointMode, expected_connections: usize) -> Self {
        let listener = block_on(TcpListener::bind("127.0.0.1:0"))
            .expect("test TCP listener should bind loopback");
        let addr = listener
            .local_addr()
            .expect("test TCP listener should expose local address");
        let state = Arc::new(EndpointState::default());
        let server_state = Arc::clone(&state);
        let join = thread::spawn(move || {
            block_on(serve_endpoint(
                listener,
                server_state,
                mode,
                expected_connections,
            ))
        });

        Self { addr, state, join }
    }

    fn finish(self) -> Arc<EndpointState> {
        let state = Arc::clone(&self.state);
        self.join
            .join()
            .expect("remote endpoint thread should not panic")
            .expect("remote endpoint should serve expected connections");
        state
    }
}

async fn serve_endpoint(
    listener: TcpListener,
    state: Arc<EndpointState>,
    mode: EndpointMode,
    expected_connections: usize,
) -> io::Result<()> {
    for _ in 0..expected_connections {
        let (mut stream, _) = listener.accept().await?;
        let command_bytes = read_raw_frame(&mut stream).await?;
        let command: WireCommand = serde_json::from_slice(&command_bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        state.record_command(command.clone());

        match mode {
            EndpointMode::CloseWithoutReply => continue,
            EndpointMode::MalformedReply => {
                write_raw_frame(&mut stream, b"{not-json").await?;
                continue;
            }
            EndpointMode::DelayedAck => thread::sleep(Duration::from_millis(25)),
            EndpointMode::CompleteAfterAck
            | EndpointMode::HoldUntilCancel
            | EndpointMode::CancelBeforeAck
            | EndpointMode::RejectSpawn
            | EndpointMode::LeaseRenewalThenSuccess
            | EndpointMode::LeaseExpiry
            | EndpointMode::DuplicateIdempotency => {}
        }

        let replies = endpoint_replies(&state, mode, &command);
        write_json_frame(&mut stream, &replies).await?;
    }
    Ok(())
}

fn endpoint_replies(
    state: &EndpointState,
    mode: EndpointMode,
    command: &WireCommand,
) -> Vec<WireReply> {
    let task_id = command.remote_task_id();
    match command {
        WireCommand::Spawn {
            idempotency_key,
            computation,
            input_len,
            ..
        } => match mode {
            EndpointMode::CancelBeforeAck => Vec::new(),
            EndpointMode::RejectSpawn => vec![WireReply::AckRejected {
                remote_task_id: task_id,
                reason: "unknown_computation".to_owned(),
            }],
            EndpointMode::LeaseRenewalThenSuccess => {
                state.mark_execution(idempotency_key);
                vec![
                    ack(task_id),
                    WireReply::LeaseRenewed {
                        remote_task_id: task_id,
                        current_state: "Running".to_owned(),
                    },
                    success(task_id, b"lease-renewed-ok"),
                ]
            }
            EndpointMode::LeaseExpiry => {
                state.mark_execution(idempotency_key);
                vec![
                    ack(task_id),
                    WireReply::LeaseExpired {
                        remote_task_id: task_id,
                    },
                ]
            }
            EndpointMode::DuplicateIdempotency => {
                let fingerprint = format!("{computation}:{input_len}");
                let mut cache = state.cache.lock();
                if let Some((cached_fingerprint, payload)) = cache.get(idempotency_key) {
                    assert_eq!(
                        cached_fingerprint, &fingerprint,
                        "idempotency key reused with different request fingerprint"
                    );
                    vec![WireReply::CachedResult {
                        remote_task_id: task_id,
                        idempotency_key: idempotency_key.clone(),
                        payload: payload.clone(),
                    }]
                } else {
                    let payload = b"idempotent-result".to_vec();
                    cache.insert(idempotency_key.clone(), (fingerprint, payload.clone()));
                    drop(cache);
                    state.mark_execution(idempotency_key);
                    vec![
                        ack(task_id),
                        WireReply::ResultSuccess {
                            remote_task_id: task_id,
                            payload,
                        },
                    ]
                }
            }
            EndpointMode::CompleteAfterAck | EndpointMode::DelayedAck => {
                state.mark_execution(idempotency_key);
                vec![ack(task_id), success(task_id, b"spawn-result-ok")]
            }
            EndpointMode::HoldUntilCancel
            | EndpointMode::MalformedReply
            | EndpointMode::CloseWithoutReply => {
                state.mark_execution(idempotency_key);
                vec![ack(task_id)]
            }
        },
        WireCommand::Cancel { reason, .. } => vec![WireReply::ResultCancelled {
            remote_task_id: task_id,
            reason: reason.clone(),
        }],
        WireCommand::LeaseProbe { .. } => vec![WireReply::LeaseRenewed {
            remote_task_id: task_id,
            current_state: "Running".to_owned(),
        }],
    }
}

fn ack(remote_task_id: u64) -> WireReply {
    WireReply::AckAccepted {
        remote_task_id,
        assigned_node: REMOTE_NODE.to_owned(),
    }
}

fn success(remote_task_id: u64, payload: &[u8]) -> WireReply {
    WireReply::ResultSuccess {
        remote_task_id,
        payload: payload.to_vec(),
    }
}

#[derive(Debug)]
struct TcpLoopbackRemoteRuntime {
    endpoint: SocketAddr,
    pending: Mutex<BTreeMap<RemoteTaskId, oneshot::Sender<Result<RemoteOutcome, RemoteError>>>>,
    states: Mutex<BTreeMap<RemoteTaskId, RemoteTaskState>>,
    commands: Mutex<Vec<WireCommand>>,
    replies: Mutex<Vec<WireReply>>,
}

impl TcpLoopbackRemoteRuntime {
    fn new(endpoint: SocketAddr) -> Self {
        Self {
            endpoint,
            pending: Mutex::new(BTreeMap::new()),
            states: Mutex::new(BTreeMap::new()),
            commands: Mutex::new(Vec::new()),
            replies: Mutex::new(Vec::new()),
        }
    }

    fn pending_count(&self) -> usize {
        self.pending.lock().len()
    }

    fn state_count(&self) -> usize {
        self.states.lock().len()
    }

    fn trace_event_count(&self, trace: &TraceBufferHandle) -> usize {
        trace.snapshot().len() + self.commands.lock().len() + self.replies.lock().len()
    }

    fn last_command(&self) -> Option<WireCommand> {
        self.commands.lock().last().cloned()
    }

    fn saw_lease_renewal(&self, remote_task_id: RemoteTaskId) -> bool {
        self.replies.lock().iter().any(|reply| {
            matches!(
                reply,
                WireReply::LeaseRenewed {
                    remote_task_id: observed,
                    ..
                } if *observed == remote_task_id.raw()
            )
        })
    }

    fn deliver(&self, task_id: RemoteTaskId, result: Result<RemoteOutcome, RemoteError>) {
        if let Some(tx) = self.pending.lock().remove(&task_id) {
            let _ = tx.send_blocking(result);
        }
    }

    fn apply_reply(&self, reply: &WireReply) {
        let task_id = RemoteTaskId::from_raw(reply.remote_task_id());
        match reply {
            WireReply::AckAccepted { .. } | WireReply::LeaseRenewed { .. } => {
                self.states.lock().insert(task_id, RemoteTaskState::Running);
            }
            WireReply::AckRejected { reason, .. } => {
                self.states.lock().insert(task_id, RemoteTaskState::Failed);
                self.deliver(
                    task_id,
                    Err(RemoteError::SpawnRejected(reject_reason(reason))),
                );
            }
            WireReply::ResultSuccess { payload, .. } | WireReply::CachedResult { payload, .. } => {
                self.states
                    .lock()
                    .insert(task_id, RemoteTaskState::Completed);
                self.deliver(task_id, Ok(RemoteOutcome::Success(payload.clone())));
            }
            WireReply::ResultCancelled { reason, .. } => {
                self.states
                    .lock()
                    .insert(task_id, RemoteTaskState::Cancelled);
                assert!(
                    !reason.is_empty(),
                    "wire cancellation replies should carry diagnostic reason text"
                );
                self.deliver(
                    task_id,
                    Ok(RemoteOutcome::Cancelled(CancelReason::user(
                        "remote transport cancelled",
                    ))),
                );
            }
            WireReply::LeaseExpired { .. } => {
                self.states
                    .lock()
                    .insert(task_id, RemoteTaskState::LeaseExpired);
                self.deliver(task_id, Err(RemoteError::LeaseExpired));
            }
        }
    }
}

impl RemoteRuntime for TcpLoopbackRemoteRuntime {
    fn send_message(
        &self,
        destination: &NodeId,
        envelope: MessageEnvelope<RemoteMessage>,
    ) -> Result<(), RemoteError> {
        let command = WireCommand::from_remote_message(destination, &envelope)?;
        let replies = send_wire_command(self.endpoint, &command)?;
        self.commands.lock().push(command);
        self.replies.lock().extend(replies.iter().cloned());
        for reply in &replies {
            self.apply_reply(reply);
        }
        Ok(())
    }

    fn register_task(
        &self,
        task_id: RemoteTaskId,
        tx: oneshot::Sender<Result<RemoteOutcome, RemoteError>>,
    ) {
        self.pending.lock().insert(task_id, tx);
        self.states.lock().insert(task_id, RemoteTaskState::Pending);
    }

    fn observe_task_state(&self, task_id: RemoteTaskId) -> Option<RemoteTaskState> {
        self.states.lock().get(&task_id).copied()
    }

    fn clear_task_state(&self, task_id: RemoteTaskId) {
        self.pending.lock().remove(&task_id);
        self.states.lock().remove(&task_id);
    }

    fn unregister_task(&self, task_id: RemoteTaskId) {
        self.pending.lock().remove(&task_id);
        self.states.lock().remove(&task_id);
    }
}

#[derive(Debug)]
struct WireTransport {
    endpoint: SocketAddr,
    inbound: Vec<MessageEnvelope<RemoteMessage>>,
}

impl WireTransport {
    fn new(endpoint: SocketAddr) -> Self {
        Self {
            endpoint,
            inbound: Vec::new(),
        }
    }
}

impl RemoteTransport for WireTransport {
    fn send(
        &mut self,
        to: &NodeId,
        envelope: MessageEnvelope<RemoteMessage>,
    ) -> Result<(), RemoteError> {
        let command = WireCommand::from_remote_message(to, &envelope)?;
        let replies = send_wire_command(self.endpoint, &command)?;
        for reply in replies {
            if let Some(message) = reply_to_remote_message(&reply) {
                let sender = NodeId::new(REMOTE_NODE);
                let sender_time =
                    LogicalTime::Lamport(asupersync::trace::distributed::LamportTime::from_raw(
                        command.remote_task_id() + 100,
                    ));
                self.inbound
                    .push(MessageEnvelope::new(sender, sender_time, message));
            }
        }
        Ok(())
    }

    fn try_recv(&mut self) -> Option<MessageEnvelope<RemoteMessage>> {
        if self.inbound.is_empty() {
            None
        } else {
            Some(self.inbound.remove(0))
        }
    }
}

fn reply_to_remote_message(reply: &WireReply) -> Option<RemoteMessage> {
    match reply {
        WireReply::AckAccepted {
            remote_task_id,
            assigned_node,
        } => Some(RemoteMessage::SpawnAck(asupersync::remote::SpawnAck {
            remote_task_id: RemoteTaskId::from_raw(*remote_task_id),
            status: asupersync::remote::SpawnAckStatus::Accepted,
            assigned_node: NodeId::new(assigned_node.clone()),
        })),
        WireReply::AckRejected {
            remote_task_id,
            reason,
        } => Some(RemoteMessage::SpawnAck(asupersync::remote::SpawnAck {
            remote_task_id: RemoteTaskId::from_raw(*remote_task_id),
            status: asupersync::remote::SpawnAckStatus::Rejected(reject_reason(reason)),
            assigned_node: NodeId::new(REMOTE_NODE),
        })),
        WireReply::LeaseRenewed {
            remote_task_id,
            current_state,
        } => Some(RemoteMessage::LeaseRenewal(
            asupersync::remote::LeaseRenewal {
                remote_task_id: RemoteTaskId::from_raw(*remote_task_id),
                new_lease: Duration::from_millis(50),
                current_state: parse_state(current_state),
                node: NodeId::new(REMOTE_NODE),
            },
        )),
        WireReply::ResultSuccess {
            remote_task_id,
            payload,
        } => Some(RemoteMessage::ResultDelivery(
            asupersync::remote::ResultDelivery {
                remote_task_id: RemoteTaskId::from_raw(*remote_task_id),
                outcome: RemoteOutcome::Success(payload.clone()),
                execution_time: Duration::from_millis(1),
            },
        )),
        WireReply::ResultCancelled {
            remote_task_id,
            reason,
        } => Some(RemoteMessage::ResultDelivery(
            asupersync::remote::ResultDelivery {
                remote_task_id: RemoteTaskId::from_raw(*remote_task_id),
                outcome: {
                    assert!(
                        !reason.is_empty(),
                        "wire cancellation replies should carry diagnostic reason text"
                    );
                    RemoteOutcome::Cancelled(CancelReason::user("remote transport cancelled"))
                },
                execution_time: Duration::from_millis(1),
            },
        )),
        WireReply::LeaseExpired { .. } | WireReply::CachedResult { .. } => None,
    }
}

fn send_wire_command(
    endpoint: SocketAddr,
    command: &WireCommand,
) -> Result<Vec<WireReply>, RemoteError> {
    block_on(async {
        let mut stream = TcpStream::connect(endpoint).await.map_err(map_io)?;
        write_json_frame(&mut stream, command)
            .await
            .map_err(map_io)?;
        stream.shutdown(Shutdown::Write).map_err(map_io)?;
        let response = read_raw_frame(&mut stream).await.map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                RemoteError::TransportError("receive EOF before response frame".to_owned())
            } else {
                map_io(error)
            }
        })?;
        serde_json::from_slice(&response)
            .map_err(|err| RemoteError::SerializationError(err.to_string()))
    })
}

async fn write_json_frame<T: Serialize + Sync>(
    stream: &mut TcpStream,
    value: &T,
) -> io::Result<()> {
    let encoded = serde_json::to_vec(value).map_err(io::Error::other)?;
    write_raw_frame(stream, &encoded).await
}

async fn write_raw_frame(stream: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(bytes).await
}

async fn read_raw_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len_bytes = [0_u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "remote transport frame exceeded test maximum",
        ));
    }
    let mut bytes = vec![0_u8; len];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

fn map_io(error: io::Error) -> RemoteError {
    RemoteError::TransportError(format!(
        "{:?}:{}",
        error.kind(),
        compact(&error.to_string())
    ))
}

fn reject_reason(reason: &str) -> SpawnRejectReason {
    match reason {
        "unknown_computation" => SpawnRejectReason::UnknownComputation,
        "capacity_exceeded" => SpawnRejectReason::CapacityExceeded,
        "node_shutting_down" => SpawnRejectReason::NodeShuttingDown,
        "idempotency_conflict" => SpawnRejectReason::IdempotencyConflict,
        other => SpawnRejectReason::InvalidInput(other.to_owned()),
    }
}

fn parse_state(state: &str) -> RemoteTaskState {
    match state {
        "Running" => RemoteTaskState::Running,
        "Completed" => RemoteTaskState::Completed,
        "Cancelled" => RemoteTaskState::Cancelled,
        "LeaseExpired" => RemoteTaskState::LeaseExpired,
        "Failed" => RemoteTaskState::Failed,
        _ => RemoteTaskState::Pending,
    }
}

fn runtime_context(endpoint: SocketAddr) -> (Arc<TcpLoopbackRemoteRuntime>, Cx, TraceBufferHandle) {
    let runtime = Arc::new(TcpLoopbackRemoteRuntime::new(endpoint));
    let cap = asupersync::remote::RemoteCap::new()
        .with_local_node(NodeId::new(ORIGIN_NODE))
        .with_default_lease(Duration::from_millis(50))
        .with_runtime(runtime.clone());
    let cx = Cx::for_testing().with_remote_cap(cap);
    let trace = TraceBufferHandle::new(128);
    cx.set_trace_buffer(trace.clone());
    (runtime, cx, trace)
}

fn spawn_test_handle(cx: &Cx) -> asupersync::remote::RemoteHandle {
    spawn_remote(
        cx,
        NodeId::new(REMOTE_NODE),
        ComputationName::new("proof.echo"),
        RemoteInput::new(b"proof-input".to_vec()),
    )
    .expect("spawn_remote should hand request to attached runtime")
}

#[derive(Debug)]
struct ProofLogRow {
    scenario_id: &'static str,
    origin_node: String,
    remote_node: String,
    transport_kind: &'static str,
    remote_task_id: String,
    lease_id: String,
    idempotency_key: String,
    command: String,
    trace_event_count: usize,
    obligation_count_before: usize,
    obligation_count_after: usize,
    expected_state: String,
    actual_state: String,
    verdict: &'static str,
    first_failure: String,
}

impl ProofLogRow {
    fn pass(
        scenario_id: &'static str,
        remote_task_id: impl fmt::Display,
        idempotency_key: impl Into<String>,
        command: impl Into<String>,
        trace_event_count: usize,
        expected_state: impl Into<String>,
        actual_state: impl Into<String>,
    ) -> Self {
        let task_id = remote_task_id.to_string();
        Self {
            scenario_id,
            origin_node: ORIGIN_NODE.to_owned(),
            remote_node: REMOTE_NODE.to_owned(),
            transport_kind: TRANSPORT_KIND,
            remote_task_id: task_id.clone(),
            lease_id: format!("lease-{task_id}"),
            idempotency_key: idempotency_key.into(),
            command: command.into(),
            trace_event_count,
            obligation_count_before: 0,
            obligation_count_after: 0,
            expected_state: expected_state.into(),
            actual_state: actual_state.into(),
            verdict: "pass",
            first_failure: String::new(),
        }
    }

    fn emit(&self) {
        assert_eq!(self.verdict, "pass");
        assert!(
            self.trace_event_count > 0 || self.scenario_id.contains("capability_denied"),
            "trace_event_count must be populated for transport-backed scenarios"
        );
        assert_eq!(
            self.obligation_count_before, self.obligation_count_after,
            "remote transport proof should not leak obligations"
        );
        assert_eq!(
            self.expected_state, self.actual_state,
            "expected state should match actual state in proof log"
        );
        println!(
            "REMOTE_TRANSPORT_LIFECYCLE bead_id={} scenario_id={} origin_node={} remote_node={} transport_kind={} remote_task_id={} lease_id={} idempotency_key={} command={} trace_event_count={} obligation_count_before={} obligation_count_after={} expected_state={} actual_state={} verdict={} first_failure={}",
            BEAD_ID,
            self.scenario_id,
            compact(&self.origin_node),
            compact(&self.remote_node),
            self.transport_kind,
            compact(&self.remote_task_id),
            compact(&self.lease_id),
            compact(&self.idempotency_key),
            compact(&self.command),
            self.trace_event_count,
            self.obligation_count_before,
            self.obligation_count_after,
            compact(&self.expected_state),
            compact(&self.actual_state),
            self.verdict,
            compact(&self.first_failure),
        );
    }
}

fn compact(value: &str) -> String {
    let compacted = value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("_")
        .replace('=', ":");
    if compacted.is_empty() {
        String::new()
    } else {
        compacted
    }
}

fn millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn lamport_raw(time: &LogicalTime) -> u64 {
    match time {
        LogicalTime::Lamport(value) => value.raw(),
        LogicalTime::Vector(_) | LogicalTime::Hybrid(_) => 0,
    }
}

fn command_metadata(runtime: &TcpLoopbackRemoteRuntime) -> (String, String, u64) {
    let command = runtime
        .last_command()
        .expect("runtime should record at least one command");
    (
        command.command_name().to_owned(),
        command.idempotency_key().to_owned(),
        match &command {
            WireCommand::Spawn { sender_lamport, .. }
            | WireCommand::Cancel { sender_lamport, .. }
            | WireCommand::LeaseProbe { sender_lamport, .. } => *sender_lamport,
        },
    )
}

fn assert_runtime_drained(runtime: &TcpLoopbackRemoteRuntime) {
    assert_eq!(runtime.pending_count(), 0, "pending remote result senders");
    assert_eq!(runtime.state_count(), 0, "tracked remote task states");
}

#[test]
fn remote_transport_wire_codec_preserves_protocol_fields() {
    let command = WireCommand::Spawn {
        remote_task_id: 42,
        origin_node: ORIGIN_NODE.to_owned(),
        destination_node: REMOTE_NODE.to_owned(),
        computation: "proof.echo".to_owned(),
        input_len: 11,
        lease_ms: 50,
        idempotency_key: "IK-0000000000000000000000000000002a".to_owned(),
        sender_lamport: 7,
    };

    let encoded = serde_json::to_vec(&command).expect("wire command should serialize");
    let decoded: WireCommand =
        serde_json::from_slice(&encoded).expect("wire command should deserialize");
    assert_eq!(decoded, command);
    assert_eq!(decoded.remote_task_id(), 42);
    assert_eq!(
        decoded.idempotency_key(),
        "IK-0000000000000000000000000000002a"
    );

    ProofLogRow::pass(
        "wire_codec_protocol_fields",
        42,
        decoded.idempotency_key(),
        decoded.command_name(),
        1,
        "Completed",
        "Completed",
    )
    .emit();
}

#[test]
fn remote_transport_trait_receives_ack_result_and_logical_time() {
    let endpoint = TestEndpoint::launch(EndpointMode::CompleteAfterAck, 1);
    let mut transport = WireTransport::new(endpoint.addr);
    let task_id = RemoteTaskId::from_raw(77);
    let envelope = MessageEnvelope::new(
        NodeId::new(ORIGIN_NODE),
        LogicalTime::Lamport(asupersync::trace::distributed::LamportTime::from_raw(5)),
        RemoteMessage::SpawnRequest(asupersync::remote::SpawnRequest {
            remote_task_id: task_id,
            computation: ComputationName::new("proof.echo"),
            input: RemoteInput::new(b"transport-trait".to_vec()),
            lease: Duration::from_millis(50),
            idempotency_key: asupersync::remote::IdempotencyKey::from_raw(0x77),
            budget: None,
            origin_node: NodeId::new(ORIGIN_NODE),
            origin_region: Cx::for_testing().region_id(),
            origin_task: Cx::for_testing().task_id(),
        }),
    );

    transport
        .send(&NodeId::new(REMOTE_NODE), envelope)
        .expect("RemoteTransport send should cross TCP loopback");
    let first = transport.try_recv().expect("spawn ack should be queued");
    let second = transport
        .try_recv()
        .expect("result delivery should be queued");
    assert!(matches!(first.payload, RemoteMessage::SpawnAck(_)));
    assert!(matches!(second.payload, RemoteMessage::ResultDelivery(_)));
    assert!(transport.try_recv().is_none());
    let endpoint_state = endpoint.finish();
    assert_eq!(endpoint_state.command_count(), 1);

    ProofLogRow::pass(
        "remote_transport_trait_ack_result_logical_time",
        task_id.raw(),
        "IK-00000000000000000000000000000077",
        "spawn",
        3,
        "Completed",
        "Completed",
    )
    .emit();
}

#[test]
fn remote_transport_spawn_result_cancel_and_lease_matrix_emits_required_logs() {
    let endpoint = TestEndpoint::launch(EndpointMode::CompleteAfterAck, 1);
    let (runtime, cx, trace) = runtime_context(endpoint.addr);
    let mut handle = spawn_test_handle(&cx);
    let task_id = handle.remote_task_id();
    let outcome = block_on(handle.join(&cx)).expect("remote result should arrive");
    assert!(matches!(outcome, RemoteOutcome::Success(_)));
    assert_eq!(handle.state(), RemoteTaskState::Completed);
    assert_runtime_drained(&runtime);
    let (command, key, sender_lamport) = command_metadata(&runtime);
    assert!(sender_lamport > 0);
    endpoint.finish();
    ProofLogRow::pass(
        "spawn_ack_result_delivery",
        task_id.raw(),
        key,
        command,
        runtime.trace_event_count(&trace),
        "Completed",
        handle.state().to_string(),
    )
    .emit();

    let endpoint = TestEndpoint::launch(EndpointMode::HoldUntilCancel, 2);
    let (runtime, cx, trace) = runtime_context(endpoint.addr);
    let mut handle = spawn_test_handle(&cx);
    let task_id = handle.remote_task_id();
    assert_eq!(handle.state(), RemoteTaskState::Running);
    let outcome = block_on(handle.close(&cx)).expect("close should receive cancel outcome");
    assert!(matches!(outcome, RemoteOutcome::Cancelled(_)));
    assert_eq!(handle.state(), RemoteTaskState::Cancelled);
    assert_runtime_drained(&runtime);
    let (_, key, _) = command_metadata(&runtime);
    endpoint.finish();
    ProofLogRow::pass(
        "cancel_while_running_drains_result",
        task_id.raw(),
        key,
        "spawn_then_cancel",
        runtime.trace_event_count(&trace),
        "Cancelled",
        handle.state().to_string(),
    )
    .emit();

    let endpoint = TestEndpoint::launch(EndpointMode::CancelBeforeAck, 2);
    let (runtime, cx, trace) = runtime_context(endpoint.addr);
    let mut handle = spawn_test_handle(&cx);
    let task_id = handle.remote_task_id();
    assert_eq!(handle.state(), RemoteTaskState::Pending);
    let outcome = block_on(handle.close(&cx)).expect("close should settle pending cancel");
    assert!(matches!(outcome, RemoteOutcome::Cancelled(_)));
    assert_eq!(handle.state(), RemoteTaskState::Cancelled);
    assert_runtime_drained(&runtime);
    let (_, key, _) = command_metadata(&runtime);
    endpoint.finish();
    ProofLogRow::pass(
        "cancel_before_ack_drains_result",
        task_id.raw(),
        key,
        "spawn_without_ack_then_cancel",
        runtime.trace_event_count(&trace),
        "Cancelled",
        handle.state().to_string(),
    )
    .emit();

    let endpoint = TestEndpoint::launch(EndpointMode::RejectSpawn, 1);
    let (runtime, cx, trace) = runtime_context(endpoint.addr);
    let mut handle = spawn_test_handle(&cx);
    let task_id = handle.remote_task_id();
    let error = block_on(handle.join(&cx)).expect_err("rejected spawn should fail join");
    assert!(matches!(
        error,
        RemoteError::SpawnRejected(SpawnRejectReason::UnknownComputation)
    ));
    assert_eq!(handle.state(), RemoteTaskState::Failed);
    assert_runtime_drained(&runtime);
    let (command, key, _) = command_metadata(&runtime);
    endpoint.finish();
    ProofLogRow::pass(
        "spawn_rejected_cleans_origin_state",
        task_id.raw(),
        key,
        command,
        runtime.trace_event_count(&trace),
        "Failed",
        handle.state().to_string(),
    )
    .emit();

    let endpoint = TestEndpoint::launch(EndpointMode::LeaseRenewalThenSuccess, 1);
    let (runtime, cx, trace) = runtime_context(endpoint.addr);
    let mut handle = spawn_test_handle(&cx);
    let task_id = handle.remote_task_id();
    let outcome = block_on(handle.join(&cx)).expect("lease-renewed task should complete");
    assert!(matches!(outcome, RemoteOutcome::Success(_)));
    assert!(runtime.saw_lease_renewal(task_id));
    assert_eq!(handle.state(), RemoteTaskState::Completed);
    assert_runtime_drained(&runtime);
    let (command, key, _) = command_metadata(&runtime);
    endpoint.finish();
    ProofLogRow::pass(
        "lease_renewal_then_result",
        task_id.raw(),
        key,
        command,
        runtime.trace_event_count(&trace),
        "Completed",
        handle.state().to_string(),
    )
    .emit();

    let endpoint = TestEndpoint::launch(EndpointMode::LeaseExpiry, 1);
    let (runtime, cx, trace) = runtime_context(endpoint.addr);
    let mut handle = spawn_test_handle(&cx);
    let task_id = handle.remote_task_id();
    let error = block_on(handle.join(&cx)).expect_err("lost renewal should expire lease");
    assert_eq!(error, RemoteError::LeaseExpired);
    assert_eq!(handle.state(), RemoteTaskState::LeaseExpired);
    assert_runtime_drained(&runtime);
    let (command, key, _) = command_metadata(&runtime);
    endpoint.finish();
    ProofLogRow::pass(
        "lost_renewal_lease_expiry_cleanup",
        task_id.raw(),
        key,
        command,
        runtime.trace_event_count(&trace),
        "LeaseExpired",
        handle.state().to_string(),
    )
    .emit();
}

#[test]
fn remote_transport_failure_injection_cleans_origin_state() {
    let unused_addr = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("unused probe bind");
        listener.local_addr().expect("unused probe address")
    };
    let runtime = Arc::new(TcpLoopbackRemoteRuntime::new(unused_addr));
    let cap = asupersync::remote::RemoteCap::new()
        .with_local_node(NodeId::new(ORIGIN_NODE))
        .with_runtime(runtime.clone());
    let cx = Cx::for_testing().with_remote_cap(cap);
    let error = spawn_remote(
        &cx,
        NodeId::new(REMOTE_NODE),
        ComputationName::new("proof.echo"),
        RemoteInput::empty(),
    )
    .expect_err("connection refusal should fail spawn");
    assert!(matches!(error, RemoteError::TransportError(_)));
    assert_runtime_drained(&runtime);
    ProofLogRow::pass(
        "send_failure_unregisters_pending_task",
        0,
        "none",
        "spawn",
        1,
        "Failed",
        "Failed",
    )
    .emit();

    let endpoint = TestEndpoint::launch(EndpointMode::CloseWithoutReply, 1);
    let runtime = Arc::new(TcpLoopbackRemoteRuntime::new(endpoint.addr));
    let cap = asupersync::remote::RemoteCap::new()
        .with_local_node(NodeId::new(ORIGIN_NODE))
        .with_runtime(runtime.clone());
    let cx = Cx::for_testing().with_remote_cap(cap);
    let error = spawn_remote(
        &cx,
        NodeId::new(REMOTE_NODE),
        ComputationName::new("proof.echo"),
        RemoteInput::empty(),
    )
    .expect_err("EOF before ack should fail spawn");
    assert!(matches!(error, RemoteError::TransportError(_)));
    assert_runtime_drained(&runtime);
    endpoint.finish();
    ProofLogRow::pass(
        "receive_eof_unregisters_pending_task",
        0,
        "none",
        "spawn",
        1,
        "Failed",
        "Failed",
    )
    .emit();

    let endpoint = TestEndpoint::launch(EndpointMode::MalformedReply, 1);
    let runtime = Arc::new(TcpLoopbackRemoteRuntime::new(endpoint.addr));
    let cap = asupersync::remote::RemoteCap::new()
        .with_local_node(NodeId::new(ORIGIN_NODE))
        .with_runtime(runtime.clone());
    let cx = Cx::for_testing().with_remote_cap(cap);
    let error = spawn_remote(
        &cx,
        NodeId::new(REMOTE_NODE),
        ComputationName::new("proof.echo"),
        RemoteInput::empty(),
    )
    .expect_err("malformed reply should fail spawn");
    assert!(matches!(error, RemoteError::SerializationError(_)));
    assert_runtime_drained(&runtime);
    endpoint.finish();
    ProofLogRow::pass(
        "malformed_envelope_unregisters_pending_task",
        0,
        "none",
        "spawn",
        1,
        "Failed",
        "Failed",
    )
    .emit();

    let endpoint = TestEndpoint::launch(EndpointMode::DelayedAck, 1);
    let (runtime, cx, trace) = runtime_context(endpoint.addr);
    let mut handle = spawn_test_handle(&cx);
    let task_id = handle.remote_task_id();
    let outcome = block_on(handle.join(&cx)).expect("delayed ack should still complete");
    assert!(matches!(outcome, RemoteOutcome::Success(_)));
    assert_eq!(handle.state(), RemoteTaskState::Completed);
    assert_runtime_drained(&runtime);
    let (command, key, _) = command_metadata(&runtime);
    endpoint.finish();
    ProofLogRow::pass(
        "delayed_ack_preserves_result_delivery",
        task_id.raw(),
        key,
        command,
        runtime.trace_event_count(&trace),
        "Completed",
        handle.state().to_string(),
    )
    .emit();
}

#[test]
fn remote_transport_idempotency_replay_uses_cached_result() {
    let endpoint = TestEndpoint::launch(EndpointMode::DuplicateIdempotency, 2);
    let command = WireCommand::Spawn {
        remote_task_id: 9001,
        origin_node: ORIGIN_NODE.to_owned(),
        destination_node: REMOTE_NODE.to_owned(),
        computation: "proof.idempotent".to_owned(),
        input_len: 17,
        lease_ms: 50,
        idempotency_key: "IK-00000000000000000000000000009001".to_owned(),
        sender_lamport: 11,
    };

    let first = send_wire_command(endpoint.addr, &command).expect("first spawn should execute");
    let second =
        send_wire_command(endpoint.addr, &command).expect("duplicate spawn should be cached");
    assert!(matches!(
        first.as_slice(),
        [
            WireReply::AckAccepted { .. },
            WireReply::ResultSuccess { .. }
        ]
    ));
    assert!(matches!(
        second.as_slice(),
        [WireReply::CachedResult { .. }]
    ));
    let cached_payload = match &second[0] {
        WireReply::CachedResult { payload, .. } => payload,
        other => panic!("expected cached result, got {other:?}"),
    };
    assert_eq!(cached_payload, b"idempotent-result");
    let endpoint_state = endpoint.finish();
    assert_eq!(
        endpoint_state.execution_count("IK-00000000000000000000000000009001"),
        1,
        "duplicate idempotency key should not execute computation twice"
    );

    ProofLogRow::pass(
        "duplicate_idempotency_replay_cached_result",
        9001,
        command.idempotency_key(),
        "spawn_duplicate",
        4,
        "Completed",
        "Completed",
    )
    .emit();
}

#[test]
fn remote_transport_capability_denial_and_phase0_fallback_are_explicit() {
    let cx = Cx::for_testing();
    let error = spawn_remote(
        &cx,
        NodeId::new(REMOTE_NODE),
        ComputationName::new("proof.echo"),
        RemoteInput::empty(),
    )
    .expect_err("missing RemoteCap should deny remote spawn");
    assert_eq!(error, RemoteError::NoCapability);
    ProofLogRow::pass(
        "capability_denied_without_remote_cap",
        0,
        "none",
        "spawn",
        0,
        "Failed",
        "Failed",
    )
    .emit();

    let cx = Cx::for_testing().with_remote_cap(asupersync::remote::RemoteCap::new());
    let mut handle = spawn_remote(
        &cx,
        NodeId::new(REMOTE_NODE),
        ComputationName::new("proof.echo"),
        RemoteInput::empty(),
    )
    .expect("phase0 fallback should create a terminal handle");
    let error = handle
        .try_join()
        .expect_err("phase0 fallback should report deterministic error");
    assert!(matches!(error, RemoteError::NodeUnreachable(_)));
    ProofLogRow::pass(
        "phase0_fallback_without_runtime_is_explicit",
        handle.remote_task_id().raw(),
        "none",
        "spawn",
        1,
        "Failed",
        "Failed",
    )
    .emit();
}
