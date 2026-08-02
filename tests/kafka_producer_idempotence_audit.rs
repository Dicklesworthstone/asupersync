//! Downstream-consumer contract for Kafka's default-feature boundary.
//!
//! The root package's dev-dependency cycle enables internal features for its
//! ordinary integration tests. This source is therefore also declared as an
//! integration-test target of `tests/fixtures/downstream-consumer-proof`, whose
//! dependency on `asupersync` has no dev-dependency cycle and enables only the
//! root crate's default features. Both tests use public runtime APIs exclusively.
//!
//! The crate-local deterministic broker is not a Kafka implementation. Without
//! the `kafka` feature, a downstream producer must return `FeatureDisabled`
//! rather than silently route traffic to that internal harness.

#[cfg(not(feature = "kafka"))]
use asupersync::Cx;
#[cfg(not(feature = "kafka"))]
use asupersync::messaging::kafka::KafkaError;
#[cfg(not(feature = "kafka"))]
use asupersync::messaging::kafka::{KafkaProducer, ProducerConfig};
#[cfg(not(feature = "kafka"))]
use asupersync::runtime::RuntimeBuilder;

#[cfg(not(feature = "kafka"))]
#[test]
fn default_feature_send_fails_closed_instead_of_using_internal_harness() {
    let config = ProducerConfig::default()
        .enable_idempotence(true)
        .retries(3);
    assert!(config.enable_idempotence);

    let producer = KafkaProducer::new(config).unwrap();
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build public current-thread runtime");
    runtime.block_on(async {
        let cx = Cx::current().expect("Runtime::block_on installs a public Cx");
        let send_result = producer
            .send(&cx, "idempotence-test", Some(b"key1"), b"message1", None)
            .await;

        assert!(
            matches!(send_result, Err(KafkaError::FeatureDisabled)),
            "a downstream default-feature build must not reach internal Kafka test infrastructure"
        );
    });
}

#[cfg(not(feature = "kafka"))]
#[test]
fn default_feature_send_fails_closed_for_every_producer_instance() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build public current-thread runtime");
    runtime.block_on(async {
        let cx = Cx::current().expect("Runtime::block_on installs a public Cx");
        let producer1 = KafkaProducer::new(
            ProducerConfig::default()
                .enable_idempotence(true)
                .client_id("producer-1"),
        )
        .unwrap();

        let producer2 = KafkaProducer::new(
            ProducerConfig::default()
                .enable_idempotence(true)
                .client_id("producer-2"),
        )
        .unwrap();

        let first_send = producer1
            .send(&cx, "producer-id-test", Some(b"key"), b"from-p1", None)
            .await;
        let second_send = producer2
            .send(&cx, "producer-id-test", Some(b"key"), b"from-p2", None)
            .await;

        assert!(
            matches!(first_send, Err(KafkaError::FeatureDisabled)),
            "producer 1 should hit the default-feature fail-closed boundary"
        );
        assert!(
            matches!(second_send, Err(KafkaError::FeatureDisabled)),
            "producer 2 should hit the default-feature fail-closed boundary"
        );
    });
}
