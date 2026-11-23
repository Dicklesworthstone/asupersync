//! Bounded topic administration over the retained librdkafka backend.
//!
//! A batch owns one native client from construction through destruction on a
//! region-owned blocking job. The public client is only configuration and an
//! admission limit; it owns no poller that could outlive request retirement.

use super::{KafkaError, ProducerConfig};
use crate::cx::Cx;
use crate::runtime::SpawnError;
use crate::runtime::spawn_blocking::DrainedBlockingHandle;
use std::collections::BTreeSet;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const MAX_TOPICS: usize = 100;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_TOPIC_CONFIGS: usize = 32;
const MAX_IN_FLIGHT: usize = 64;

/// Failure of topic administration or its admission.
///
/// An [`OutcomeUnknown`](Self::OutcomeUnknown) does not mean that the broker
/// rolled back the request. Inspect the cluster before retrying a mutation.
/// Per-topic broker refusals instead appear in [`KafkaAdminReport`].
#[derive(Debug)]
#[non_exhaustive]
pub enum KafkaAdminError {
    /// Invalid or over-budget input; nothing was submitted to a broker.
    InvalidInput(&'static str),
    /// This client and its clones already own the configured number of jobs.
    Busy {
        /// Maximum queued or running batches for this client family.
        limit: usize,
    },
    /// The runtime did not admit a blocking job.
    Admission(SpawnError),
    /// Failure before submitting the mutation, including feature refusal.
    Client(KafkaError),
    /// A native submission attempt produced no complete, trustworthy topic report.
    /// Some or all broker mutations may already have happened.
    OutcomeUnknown(KafkaError),
}

impl KafkaAdminError {
    /// Whether a broker mutation may have happened without a complete report.
    #[must_use]
    pub const fn outcome_unknown(&self) -> bool {
        matches!(self, Self::OutcomeUnknown(_))
    }
}

impl fmt::Display for KafkaAdminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(f, "invalid Kafka admin request: {message}"),
            Self::Busy { limit } => write!(f, "Kafka admin has reached its {limit}-batch limit"),
            Self::Admission(error) => write!(f, "Kafka admin admission failed: {error}"),
            Self::Client(error) => write!(f, "Kafka admin request was not submitted: {error}"),
            Self::OutcomeUnknown(error) => {
                write!(f, "Kafka admin mutation outcome is unknown: {error}")
            }
        }
    }
}

impl std::error::Error for KafkaAdminError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error),
            Self::Client(error) | Self::OutcomeUnknown(error) => Some(error),
            Self::InvalidInput(_) | Self::Busy { .. } => None,
        }
    }
}

/// An owned, validated specification for one topic creation.
///
/// Names follow Kafka's 1..=249 byte ASCII topic grammar. Partitions and the
/// fixed replication factor must be positive; the factor fits a signed 16-bit
/// Kafka field. Topic configuration accepts at most 32 unique properties,
/// with keys of at most 255 bytes and values of at most 4096 bytes. A whole
/// batch has a separate 64 KiB input limit. Debug output omits property values.
#[derive(Clone)]
pub struct KafkaNewTopic {
    name: String,
    partitions: i32,
    replication_factor: i32,
    configuration: Vec<(String, String)>,
}

impl fmt::Debug for KafkaNewTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KafkaNewTopic")
            .field("name", &self.name)
            .field("partitions", &self.partitions)
            .field("replication_factor", &self.replication_factor)
            .field("configuration_entries", &self.configuration.len())
            .finish_non_exhaustive()
    }
}

impl KafkaNewTopic {
    /// Specify a topic with an explicit partition count and replication factor.
    pub fn new(
        name: impl Into<String>,
        partitions: i32,
        replication_factor: i32,
    ) -> Result<Self, KafkaAdminError> {
        let name = name.into();
        validate_topic_name(&name)?;
        if partitions <= 0 {
            return Err(KafkaAdminError::InvalidInput("partitions must be positive"));
        }
        if !(1..=i32::from(i16::MAX)).contains(&replication_factor) {
            return Err(KafkaAdminError::InvalidInput(
                "replication factor must be in 1..=32767",
            ));
        }
        Ok(Self {
            name,
            partitions,
            replication_factor,
            configuration: Vec::new(),
        })
    }

    /// Set one topic property. Repeated keys replace their earlier value.
    ///
    /// Names and values must not contain NUL. Property validity is decided by
    /// Kafka; the client bounds storage without inventing a broker allowlist.
    pub fn with_config(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, KafkaAdminError> {
        let key = key.into();
        let value = value.into();
        if key.is_empty()
            || key.len() > 255
            || key.contains('\0')
            || value.len() > 4096
            || value.contains('\0')
        {
            return Err(KafkaAdminError::InvalidInput(
                "invalid topic configuration key or value size",
            ));
        }
        if let Some(existing) = self
            .configuration
            .iter_mut()
            .find(|(existing, _)| *existing == key)
        {
            existing.1 = value;
        } else {
            if self.configuration.len() == MAX_TOPIC_CONFIGS {
                return Err(KafkaAdminError::InvalidInput(
                    "a topic accepts at most 32 configuration properties",
                ));
            }
            self.configuration.push((key, value));
        }
        Ok(self)
    }

    /// The requested topic name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The requested initial number of partitions.
    #[must_use]
    pub const fn partitions(&self) -> i32 {
        self.partitions
    }

    /// The requested fixed replication factor.
    #[must_use]
    pub const fn replication_factor(&self) -> i32 {
        self.replication_factor
    }

    fn input_bytes(&self) -> usize {
        self.name.len()
            + self
                .configuration
                .iter()
                .map(|(key, value)| key.len() + value.len())
                .sum::<usize>()
    }
}

/// A broker's exact per-topic error code, without an upstream public type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KafkaTopicBrokerError {
    code: i32,
    name: String,
}

impl KafkaTopicBrokerError {
    /// librdkafka's numeric broker/error code; no string parsing is required.
    #[must_use]
    pub const fn code(&self) -> i32 {
        self.code
    }

    /// The typed backend error's stable diagnostic name, with no broker text.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for KafkaTopicBrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.code)
    }
}

impl std::error::Error for KafkaTopicBrokerError {}

/// The broker's reported result for one topic in an administrative batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KafkaTopicAdminResult {
    topic: String,
    result: Result<(), KafkaTopicBrokerError>,
}

impl KafkaTopicAdminResult {
    /// The topic named by the caller, in caller order within the report.
    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// The broker's reported success or typed per-topic refusal.
    ///
    /// A timeout error, including a per-topic timeout, does not establish that
    /// the mutation was rolled back. Do not blindly replay timed-out mutations.
    pub fn result(&self) -> Result<(), &KafkaTopicBrokerError> {
        self.result.as_ref().copied()
    }
}

/// A complete per-topic broker report in the original request order.
///
/// Topic administration is not transactional: one topic can succeed while
/// another fails. A successful outer result means the report was complete,
/// not that every topic mutation succeeded. Topic visibility or full deletion
/// can lag the controller's acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KafkaAdminReport {
    topics: Vec<KafkaTopicAdminResult>,
}

impl KafkaAdminReport {
    /// Every requested topic, once, including individual broker errors.
    #[must_use]
    pub fn topics(&self) -> &[KafkaTopicAdminResult] {
        &self.topics
    }

    /// Whether the broker reported success for every requested topic.
    #[must_use]
    pub fn all_succeeded(&self) -> bool {
        self.topics.iter().all(|topic| topic.result.is_ok())
    }
}

/// A retained administrative batch and its actual native retirement receipt.
///
/// `join().await` returns an outer runtime result and an inner broker/report
/// result. A dropped borrowing `join` may be resumed on the same handle.
/// `join_cancellable(cx)` interrupts observation and requests cancellation,
/// while keeping the eventual report for a later `join`. After native request
/// submission, cancellation cannot undo topic changes: the worker drains the
/// request and preserves its report before destroying its native client.
/// A panic or hard runtime failure is not proof of broker rollback.
///
/// Dropping this handle requests cancellation. Its owning region retains the
/// admitted job through native client destruction, including joining the
/// backend's poll thread. Keep the handle if the result must be recovered.
pub type KafkaAdminOperation = DrainedBlockingHandle<Result<KafkaAdminReport, KafkaAdminError>>;

struct AdminState {
    #[cfg_attr(not(any(feature = "kafka", test)), allow(dead_code))]
    connection: ProducerConfig,
    limit: usize,
    active: AtomicUsize,
}

/// Topic creation/deletion with bounded, region-owned native operations.
///
/// Uses the existing `kafka` feature and [`ProducerConfig`] transport security,
/// credentials, bootstrap addresses and raw connection properties. Producer
/// record settings do not change topic creation or deletion semantics.
/// Construction validates configuration without opening a broker connection.
/// The no-feature lane always returns [`KafkaError::FeatureDisabled`] from
/// operations, including tests; it never substitutes an in-process broker.
///
/// Each admitted batch creates a native admin client on the runtime blocking
/// pool, submits one request, drains its report, then destroys the client on
/// that worker. Native poller threads are owned by that client and joined
/// before retirement. There is no persistent native client to close. Closing
/// the owning region drains admitted jobs; it cannot forcibly preempt native
/// code. A finite native request timeout is not a hard native-destruction bound.
///
/// Clones share the admission limit. At most 100 topics and 64 KiB of topic
/// names/properties are accepted per batch. Native protocol buffers, connection
/// configuration and caller-owned inputs are separate from this input bound.
///
/// # Example
///
/// Enable the `kafka` feature and use a runtime context with a blocking pool.
/// Keep the returned handle while observing a mutation; cancelling a wait does
/// not create a new request, and the same handle can recover its eventual report.
///
/// ```no_run
/// use asupersync::cx::Cx;
/// use asupersync::messaging::kafka::{KafkaAdmin, KafkaNewTopic, ProducerConfig};
///
/// async fn create_events(cx: &Cx) -> Result<(), Box<dyn std::error::Error>> {
///     let admin = KafkaAdmin::new(ProducerConfig::default())?;
///     let topic = KafkaNewTopic::new("events", 3, 1)?
///         .with_config("retention.ms", "86400000")?;
///     let mut operation = admin.create_topics(cx, &[topic])?;
///
///     // The first result is runtime retirement; the second is the admin report.
///     let report = operation.join().await??;
///     for topic in report.topics() {
///         match topic.result() {
///             Ok(()) => println!("created {}", topic.topic()),
///             Err(error) => eprintln!("{}: {}", topic.topic(), error),
///         }
///     }
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct KafkaAdmin {
    state: Arc<AdminState>,
}

impl fmt::Debug for KafkaAdmin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KafkaAdmin")
            .field("max_in_flight", &self.state.limit)
            .field("in_flight", &self.in_flight())
            .finish_non_exhaustive()
    }
}

impl KafkaAdmin {
    /// Validate configuration with an admission limit of four batches.
    ///
    /// `request_timeout` must round down to 1..=i32::MAX milliseconds. It bounds
    /// each native request, is also supplied as the broker operation timeout,
    /// and is tightened by the submitting context's remaining deadline.
    pub fn new(connection: ProducerConfig) -> Result<Self, KafkaAdminError> {
        Self::with_max_in_flight(connection, NonZeroUsize::new(4).expect("four is nonzero"))
    }

    /// Construct a client with 1..=64 queued or running batches across clones.
    pub fn with_max_in_flight(
        connection: ProducerConfig,
        limit: NonZeroUsize,
    ) -> Result<Self, KafkaAdminError> {
        connection.validate().map_err(KafkaAdminError::Client)?;
        validate_timeout(connection.request_timeout)?;
        if limit.get() > MAX_IN_FLIGHT {
            return Err(KafkaAdminError::InvalidInput(
                "at most 64 administrative batches may be in flight",
            ));
        }
        Ok(Self {
            state: Arc::new(AdminState {
                connection,
                limit: limit.get(),
                active: AtomicUsize::new(0),
            }),
        })
    }

    /// Number of batches retaining an admission slot, including queued jobs.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.state.active.load(Ordering::Acquire)
    }

    /// Admit a nonempty, bounded topic-creation batch and return its handle.
    ///
    /// Duplicate names are rejected before admission. No mutation is submitted
    /// on an immediate error. Admission needs runtime spawning, I/O authority
    /// and a blocking pool; no worker or inline fallback is created here.
    pub fn create_topics(
        &self,
        cx: &Cx,
        topics: &[KafkaNewTopic],
    ) -> Result<KafkaAdminOperation, KafkaAdminError> {
        validate_batch(topics.iter().map(|topic| (topic.name(), topic.input_bytes())))?;
        self.submit(cx, AdminRequest::Create(topics.to_vec()))
    }

    /// Admit a nonempty, bounded topic-deletion batch and return its handle.
    ///
    /// Deletions are independently reported, not atomic. Cancellation after
    /// submission cannot undo deletion. Inspect every returned topic result.
    pub fn delete_topics(
        &self,
        cx: &Cx,
        topics: &[&str],
    ) -> Result<KafkaAdminOperation, KafkaAdminError> {
        validate_batch(topics.iter().map(|topic| (*topic, topic.len())))?;
        self.submit(
            cx,
            AdminRequest::Delete(topics.iter().map(|topic| (*topic).to_owned()).collect()),
        )
    }

    fn submit(
        &self,
        cx: &Cx,
        request: AdminRequest,
    ) -> Result<KafkaAdminOperation, KafkaAdminError> {
        cx.checkpoint()
            .map_err(|_| KafkaAdminError::Client(KafkaError::Cancelled))?;
        #[cfg(not(feature = "kafka"))]
        {
            let _ = request;
            Err(KafkaAdminError::Client(KafkaError::FeatureDisabled))
        }
        #[cfg(feature = "kafka")]
        {
            self.submit_with(cx, request, execute_native)
        }
    }

    #[cfg(any(feature = "kafka", test))]
    fn submit_with<F>(
        &self,
        cx: &Cx,
        request: AdminRequest,
        execute: F,
    ) -> Result<KafkaAdminOperation, KafkaAdminError>
    where
        F: FnOnce(&Cx, &ProducerConfig, AdminRequest) -> Result<KafkaAdminReport, KafkaAdminError>
            + Send
            + 'static,
    {
        cx.checkpoint()
            .map_err(|_| KafkaAdminError::Client(KafkaError::Cancelled))?;
        if !io_allowed(cx) {
            return Err(KafkaAdminError::Client(KafkaError::Config(
                "Kafka administration requires I/O authority".to_owned(),
            )));
        }
        let permit = AdminPermit::acquire(Arc::clone(&self.state))?;
        let state = Arc::clone(&self.state);
        cx.spawn_blocking_drained(move |child| {
            let _permit = permit;
            child
                .checkpoint()
                .map_err(|_| KafkaAdminError::Client(KafkaError::Cancelled))?;
            execute(&child, &state.connection, request)
        })
        .map_err(KafkaAdminError::Admission)
    }
}

#[cfg_attr(not(any(feature = "kafka", test)), allow(dead_code))]
enum AdminRequest {
    Create(Vec<KafkaNewTopic>),
    Delete(Vec<String>),
}

impl AdminRequest {
    #[cfg(any(feature = "kafka", test))]
    fn names(&self) -> Vec<String> {
        match self {
            Self::Create(topics) => topics.iter().map(|topic| topic.name.clone()).collect(),
            Self::Delete(topics) => topics.clone(),
        }
    }
}

#[cfg(any(feature = "kafka", test))]
struct AdminPermit {
    state: Arc<AdminState>,
}

#[cfg(any(feature = "kafka", test))]
impl AdminPermit {
    fn acquire(state: Arc<AdminState>) -> Result<Self, KafkaAdminError> {
        state
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < state.limit).then_some(active + 1)
            })
            .map_err(|_| KafkaAdminError::Busy { limit: state.limit })?;
        Ok(Self { state })
    }
}

#[cfg(any(feature = "kafka", test))]
impl Drop for AdminPermit {
    fn drop(&mut self) {
        self.state.active.fetch_sub(1, Ordering::Release);
    }
}

fn validate_topic_name(name: &str) -> Result<(), KafkaAdminError> {
    if name.is_empty()
        || name.len() > 249
        || matches!(name, "." | "..")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(KafkaAdminError::InvalidInput("invalid topic name"));
    }
    Ok(())
}

fn validate_batch<'a>(
    topics: impl IntoIterator<Item = (&'a str, usize)>,
) -> Result<(), KafkaAdminError> {
    let mut names = BTreeSet::new();
    let mut bytes = 0_usize;
    for (name, size) in topics {
        validate_topic_name(name)?;
        if names.len() == MAX_TOPICS {
            return Err(KafkaAdminError::InvalidInput(
                "a batch accepts at most 100 topics",
            ));
        }
        if !names.insert(name) {
            return Err(KafkaAdminError::InvalidInput("duplicate topic in batch"));
        }
        bytes = bytes
            .checked_add(size)
            .filter(|total| *total <= MAX_REQUEST_BYTES)
            .ok_or(KafkaAdminError::InvalidInput("topic batch exceeds 64 KiB"))?;
    }
    if names.is_empty() {
        return Err(KafkaAdminError::InvalidInput("topic batch must not be empty"));
    }
    Ok(())
}

fn validate_timeout(timeout: Duration) -> Result<(), KafkaAdminError> {
    if !(1..=i32::MAX as u128).contains(&timeout.as_millis()) {
        return Err(KafkaAdminError::InvalidInput(
            "request timeout must be 1..=i32::MAX milliseconds",
        ));
    }
    Ok(())
}

#[cfg(any(feature = "kafka", test))]
fn io_allowed(cx: &Cx) -> bool {
    cx.runtime_mask.has(crate::cx::cap::CapMask::IO)
        && Cx::current().is_none_or(|ambient| ambient.runtime_mask.has(crate::cx::cap::CapMask::IO))
}

#[cfg(any(feature = "kafka", test))]
fn normalize_report(
    expected: &[String],
    reports: Vec<KafkaTopicAdminResult>,
) -> Result<KafkaAdminReport, KafkaAdminError> {
    let malformed = || {
        KafkaAdminError::OutcomeUnknown(KafkaError::Protocol(
            "admin response must report every requested topic exactly once".to_owned(),
        ))
    };
    if reports.len() != expected.len() {
        return Err(malformed());
    }
    let mut by_name = std::collections::BTreeMap::new();
    for report in reports {
        if !expected.contains(&report.topic)
            || by_name.insert(report.topic.clone(), report).is_some()
        {
            return Err(malformed());
        }
    }
    let topics = expected
        .iter()
        .map(|name| by_name.remove(name).ok_or_else(malformed))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(KafkaAdminReport { topics })
}

#[cfg(feature = "kafka")]
fn execute_native(
    cx: &Cx,
    connection: &ProducerConfig,
    request: AdminRequest,
) -> Result<KafkaAdminReport, KafkaAdminError> {
    use rdkafka::admin::{AdminClient, AdminOptions, NewTopic, TopicReplication};
    let config = super::build_client_config(connection, None);
    let native: AdminClient<super::KafkaContext> = config
        .create_with_context(super::KafkaContext)
        .map_err(|error| KafkaAdminError::Client(redacted_native_error(&error)))?;
    // Construction can take time. Check the operation's own context at the
    // last boundary before invoking a native API that submits synchronously.
    cx.checkpoint()
        .map_err(|_| KafkaAdminError::Client(KafkaError::Cancelled))?;
    let remaining = cx.remaining_budget();
    if cx.budget().deadline.is_some() && remaining.deadline.is_none() {
        return Err(KafkaAdminError::Client(KafkaError::Cancelled));
    }
    let timeout = remaining
        .deadline
        .map_or(connection.request_timeout, |remaining| {
            remaining.min(connection.request_timeout)
        });
    if timeout.as_millis() == 0 {
        return Err(KafkaAdminError::Client(KafkaError::Cancelled));
    }
    let options = AdminOptions::new()
        .request_timeout(Some(timeout))
        .operation_timeout(Some(timeout));
    let expected = request.names();
    // No cancellation shortcut after submission: only the backend's actual
    // report settles the mutation. Client destruction stays on this worker.
    let result = match &request {
        AdminRequest::Create(topics) => {
            let native_topics: Vec<_> = topics
                .iter()
                .map(|topic| {
                    let mut native = NewTopic::new(
                        &topic.name,
                        topic.partitions,
                        TopicReplication::Fixed(topic.replication_factor),
                    );
                    for (key, value) in &topic.configuration {
                        native = native.set(key, value);
                    }
                    native
                })
                .collect();
            drain_native_future(native.create_topics(&native_topics, &options))
        }
        AdminRequest::Delete(topics) => {
            let names: Vec<_> = topics.iter().map(String::as_str).collect();
            drain_native_future(native.delete_topics(&names, &options))
        }
    }
    .map_err(|error| KafkaAdminError::OutcomeUnknown(redacted_native_error(&error)))?;
    let reports = result
        .into_iter()
        .map(|result| match result {
            Ok(topic) => KafkaTopicAdminResult {
                topic,
                result: Ok(()),
            },
            Err((topic, code)) => KafkaTopicAdminResult {
                topic,
                result: Err(KafkaTopicBrokerError {
                    code: code as i32,
                    name: format!("{code:?}"),
                }),
            },
        })
        .collect();
    normalize_report(&expected, reports)
}

#[cfg(feature = "kafka")]
fn redacted_native_error(error: &rdkafka::error::KafkaError) -> KafkaError {
    use rdkafka::error::KafkaError as NativeError;
    match error {
        NativeError::ClientConfig(result, _, key, _) => {
            KafkaError::Config(super::redacted_config_message(*result, key))
        }
        _ => match super::rdkafka_error_code(error) {
            Some(code) => super::map_error_code(code, None),
            // Native string errors may include configuration values. Keep
            // them out of public errors, Debug and their source chains.
            None => KafkaError::Broker("native administrative operation failed".to_owned()),
        },
    }
}

#[cfg(feature = "kafka")]
fn drain_native_future<F: std::future::Future>(future: F) -> F::Output {
    struct ThreadWake(std::thread::Thread);
    impl std::task::Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut context = std::task::Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(result) => return result,
            std::task::Poll::Pending => std::thread::park(),
        }
    }
}

#[cfg(test)]
#[path = "admin_tests.rs"]
mod tests;
