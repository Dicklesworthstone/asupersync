//! Messaging surfaces for external services today, and the future native
//! Semantic Subject Fabric.
//!
//! The shipped code in this module currently exposes cancel-correct client
//! integrations for external systems such as Redis, NATS, JetStream, and Kafka.
//! The planned native fabric work must coexist with those integrations rather
//! than replace them with ambient or protocol-first shortcuts.
//!
//! # FABRIC North Star
//!
//! Future fabric work in this module is governed by five success criteria:
//!
//! 1. The public mental model stays NATS-small even when internal semantics get
//!    richer.
//! 2. Stronger guarantees are named service classes, not hidden taxes on the
//!    common case.
//! 3. Radical behavior lowers into small inspectable artifacts such as tokens,
//!    certificates, leases, cut records, and explain plans.
//! 4. Autonomous policy loops run only inside declared safety envelopes with
//!    replay, evidence, and rollback.
//! 5. The first product wedge targets systems that need sovereignty, durable
//!    partial progress, and post-incident explanation at the same time.
//!
//! Anti-goal: do not build a grand unified fabric that makes the default path
//! slower, the rare path magical, or the operator story less legible than NATS.
//!
//! # FABRIC Guardrail Summary
//!
//! Future native messaging work here must preserve a few hard boundaries:
//!
//! - Guarantees hold only inside Asupersync's capability boundary; unmanaged
//!   side effects still need explicit modeling.
//! - Packet-plane ergonomics stay cheap by default; authority, evidence,
//!   recoverability, and advanced control are opt-in.
//! - Distributed execution uses idempotency plus leases, not magical
//!   exactly-once claims.
//! - Control capsules, cuts, cursor state, and recoverability policies stay
//!   bounded, auditable, and replay-friendly.
//! - Advanced surfaces such as speculative execution, heavy crypto proofs, or
//!   randomized transforms on authority-bearing edges remain explicitly gated.
//!
//! The full numbered checklist lives in `docs/FABRIC_GUARDRAILS.md`.
//!
//! # Progressive Disclosure
//!
//! The native fabric API must grow in layers, not as a single all-or-nothing
//! surface:
//! The experimental native brokerless fabric surface is gated behind the
//! `messaging-fabric` feature until the higher layers are ready to ship.
//!
//! - Layer 0: connect, publish, and subscribe stay NATS-small on the packet
//!   plane with the ephemeral-interactive delivery class as the default.
//! - Layer 1: request/reply adds bounded coordination and timeout semantics
//!   without silently requiring durability or session contracts.
//! - Layer 2: durable streams, consumers, and explicit acknowledgements opt
//!   into stronger durable-ordered and obligation-backed semantics.
//! - Layer 3: service contracts, session protocols, and mobility-sensitive
//!   flows opt into richer obligation-backed and mobility-safe behavior.
//! - Layer 4: replay-heavy, evidence-rich, and counterfactual tooling stays in
//!   the explicit forensic-replayable tier.
//!
//! Lower layers must remain correct on their own terms. A Layer 0 or Layer 1
//! caller must not need hidden Layer 2+ machinery to be safe, observable, or
//! performant, and moving upward must always be an explicit API choice.
//!
//! # Review Discipline
//!
//! Any future FABRIC PR touching this module should state:
//!
//! - which of the five north-star criteria it advances,
//! - which numbered guardrails it relies on or tightens,
//! - what downgrade or fallback path keeps the common case truthful, and
//! - what evidence or replay surface makes the behavior inspectable.

#[cfg(feature = "messaging-fabric")]
pub mod class;
#[cfg(feature = "messaging-fabric")]
pub mod consumer;
#[cfg(feature = "messaging-fabric")]
pub mod cut;
#[cfg(feature = "messaging-fabric")]
pub mod fabric;
#[cfg(feature = "messaging-fabric")]
pub mod ir;
pub mod jetstream;
pub mod kafka;
pub mod kafka_consumer;
#[cfg(feature = "messaging-fabric")]
pub mod morphism;
pub mod nats;
pub mod redis;
#[cfg(feature = "messaging-fabric")]
pub mod stream;
#[cfg(feature = "messaging-fabric")]
pub mod subject;

#[cfg(feature = "messaging-fabric")]
pub use class::{
    AckKind, DeliveryClass, DeliveryClassPolicy, DeliveryClassPolicyError, DeliveryCostVector,
};
#[cfg(feature = "messaging-fabric")]
pub use cut::{
    CapsuleDigest, CertifiedMobility, ConsumerStateDigest, CutCertificate, CutMobilityError,
    MobilityOperation,
};
pub use jetstream::{
    AckPolicy, Consumer, ConsumerConfig, DeliverPolicy, DiscardPolicy, JetStreamContext, JsError,
    JsMessage, PubAck, RetentionPolicy, StorageType, StreamConfig, StreamInfo, StreamState,
};
pub use kafka::{
    Acks, Compression, KafkaError, KafkaProducer, ProducerConfig, RecordMetadata, Transaction,
    TransactionalConfig, TransactionalProducer,
};
pub use kafka_consumer::{
    AutoOffsetReset, ConsumerConfig as KafkaConsumerConfig, ConsumerRecord as KafkaConsumerRecord,
    IsolationLevel, KafkaConsumer, TopicPartitionOffset,
};
#[cfg(feature = "messaging-fabric")]
pub use morphism::{
    AuthorityFacet, CostFacet, FabricCapability, Morphism, MorphismCertificate, MorphismClass,
    MorphismFacetSet, MorphismValidationError, ObservabilityFacet, QuotaPolicy, ResponsePolicy,
    ReversibilityFacet, ReversibilityRequirement, SecrecyFacet, SharingPolicy, SubjectTransform,
};
pub use nats::{Message as NatsMessage, NatsClient, NatsConfig, NatsError, Subscription};
pub use redis::{RedisClient, RedisConfig, RedisError};
#[cfg(feature = "messaging-fabric")]
pub use subject::{
    Subject, SubjectPattern, SubjectPatternError, SubjectToken, Sublist, SublistResult,
    SubscriptionGuard, SubscriptionId,
};
