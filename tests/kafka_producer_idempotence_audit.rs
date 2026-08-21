//! Downstream-consumer contracts for Kafka's feature boundary.
//!
//! The root package's dev-dependency cycle enables internal features for its
//! ordinary integration tests. This source is therefore also declared as an
//! integration-test target of `tests/fixtures/downstream-consumer-proof`, whose
//! dependency on `asupersync` has no dev-dependency cycle and enables only the
//! root crate's default features. Both tests use public runtime APIs exclusively.
//!
//! The crate-local deterministic broker is not a Kafka implementation. Without
//! the `kafka` feature, a downstream producer must return `FeatureDisabled`
//! rather than silently route traffic to that internal harness. With the
//! feature enabled, this target must still execute the public real-producer
//! construction and pre-network validation path instead of reporting a
//! misleading zero-test success. Broker-side deduplication remains the scope of
//! the explicitly provisioned `kafka_real_broker` lane.

use asupersync::Cx;
use asupersync::messaging::kafka::KafkaError;
use asupersync::messaging::kafka::{KafkaProducer, ProducerConfig};
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

#[cfg(feature = "kafka")]
#[test]
fn kafka_feature_constructs_real_producer_and_runs_pre_network_send_checks() {
    let mut config = ProducerConfig::new(vec!["127.0.0.1:1".to_string()])
        .enable_idempotence(true)
        .retries(1)
        .linger_ms(0)
        .require_kafka_feature();
    config.max_message_size = 1_000;

    assert!(
        config.validate().is_ok(),
        "the kafka feature must satisfy an explicitly required real-producer config"
    );
    let producer = KafkaProducer::new(config)
        .expect("constructing rdkafka's producer is local and must not require a reachable broker");
    assert!(
        producer.config().enable_idempotence,
        "the public producer must preserve the caller's idempotence requirement"
    );

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build public current-thread runtime");
    runtime.block_on(async {
        let cx = Cx::current().expect("Runtime::block_on installs a public Cx");
        let oversized_payload = vec![b'x'; 1_001];
        let result = producer
            .send(
                &cx,
                "idempotence-test",
                Some(b"key"),
                &oversized_payload,
                None,
            )
            .await;

        assert!(
            matches!(
                result,
                Err(KafkaError::MessageTooLarge {
                    size: 1_001,
                    max_size: 1_000
                })
            ),
            "feature-enabled send must execute the public production path and reject an oversized payload before broker I/O; got {result:?}"
        );
        assert!(
            !producer.is_closed(),
            "a rejected pre-network send must not close the producer"
        );
    });
}
