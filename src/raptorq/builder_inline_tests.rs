    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::transport::error::{SinkError, StreamError};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct NoopSink;

    impl SymbolSink for NoopSink {
        fn poll_send(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _symbol: crate::security::AuthenticatedSymbol,
        ) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Unpin for NoopSink {}

    struct NoopStream;

    impl SymbolStream for NoopStream {
        fn poll_next(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<crate::security::AuthenticatedSymbol, StreamError>>> {
            Poll::Ready(None)
        }
    }

    impl Unpin for NoopStream {}

    #[test]
    fn test_sender_builder_missing_transport_errors() {
        let result = RaptorQSenderBuilder::<NoopSink>::default()
            .config(RaptorQConfig::default())
            .build();
        match result {
            Err(err) => assert_eq!(err.kind(), ErrorKind::InvalidEncodingParams),
            Ok(_) => panic!("expected missing transport error"),
        }
    }

    #[test]
    fn test_receiver_builder_missing_source_errors() {
        let result = RaptorQReceiverBuilder::<NoopStream>::default()
            .config(RaptorQConfig::default())
            .build();
        match result {
            Err(err) => assert_eq!(err.kind(), ErrorKind::InvalidEncodingParams),
            Ok(_) => panic!("expected missing source error"),
        }
    }

    #[test]
    fn test_sender_builder_invalid_config_errors() {
        let mut config = RaptorQConfig::default();
        config.encoding.symbol_size = 0;

        let result = RaptorQSenderBuilder::new()
            .config(config)
            .transport(NoopSink)
            .build();
        match result {
            Err(err) => assert_eq!(err.kind(), ErrorKind::InvalidEncodingParams),
            Ok(_) => panic!("expected invalid config error"),
        }
    }

    #[test]
    fn test_receiver_builder_invalid_config_errors() {
        let mut config = RaptorQConfig::default();
        config.encoding.symbol_size = 0;

        let result = RaptorQReceiverBuilder::new()
            .config(config)
            .source(NoopStream)
            .build();
        match result {
            Err(err) => assert_eq!(err.kind(), ErrorKind::InvalidEncodingParams),
            Ok(_) => panic!("expected invalid config error"),
        }
    }

    #[test]
    fn test_sender_builder_default_config_used_when_missing() {
        let sender = RaptorQSenderBuilder::new()
            .transport(NoopSink)
            .build()
            .unwrap();
        assert_eq!(sender.config().encoding.symbol_size, 256);
    }

    #[test]
    fn test_sender_builder_same_inputs_are_idempotent() {
        let mut config = RaptorQConfig::default();
        config.encoding.symbol_size = 512;
        config.encoding.repair_overhead = 1.25;
        let expected = format!("{config:?}");

        let sender_a = RaptorQSenderBuilder::new()
            .config(config.clone())
            .transport(NoopSink)
            .build()
            .unwrap();
        let sender_b = RaptorQSenderBuilder::new()
            .config(config)
            .transport(NoopSink)
            .build()
            .unwrap();

        assert_eq!(format!("{:?}", sender_a.config()), expected);
        assert_eq!(format!("{:?}", sender_b.config()), expected);
        assert_eq!(
            format!("{:?}", sender_a.config()),
            format!("{:?}", sender_b.config())
        );
    }

    #[test]
    fn mr_builder_config_setter_order_invariant() {
        let mut config = RaptorQConfig::default();
        config.encoding.symbol_size = 512;
        config.encoding.repair_overhead = 1.125;
        let expected = format!("{config:?}");

        let sender_config_first = RaptorQSenderBuilder::new()
            .config(config.clone())
            .transport(NoopSink)
            .build()
            .unwrap();
        let sender_transport_first = RaptorQSenderBuilder::new()
            .transport(NoopSink)
            .config(config.clone())
            .build()
            .unwrap();

        assert_eq!(format!("{:?}", sender_config_first.config()), expected);
        assert_eq!(
            format!("{:?}", sender_config_first.config()),
            format!("{:?}", sender_transport_first.config())
        );

        let receiver_config_first = RaptorQReceiverBuilder::new()
            .config(config.clone())
            .source(NoopStream)
            .build()
            .unwrap();
        let receiver_source_first = RaptorQReceiverBuilder::new()
            .source(NoopStream)
            .config(config)
            .build()
            .unwrap();

        assert_eq!(
            format!("{:?}", receiver_config_first.config()),
            format!("{:?}", receiver_source_first.config())
        );
    }

    #[test]
    fn mr_builder_last_config_assignment_wins() {
        let mut first_config = RaptorQConfig::default();
        first_config.encoding.symbol_size = 384;
        first_config.encoding.repair_overhead = 1.0625;

        let mut final_config = RaptorQConfig::default();
        final_config.encoding.symbol_size = 768;
        final_config.encoding.repair_overhead = 1.25;

        let sender_direct = RaptorQSenderBuilder::new()
            .config(final_config.clone())
            .transport(NoopSink)
            .build()
            .unwrap();
        let sender_overridden = RaptorQSenderBuilder::new()
            .config(first_config.clone())
            .config(final_config.clone())
            .transport(NoopSink)
            .build()
            .unwrap();
        assert_eq!(
            format!("{:?}", sender_overridden.config()),
            format!("{:?}", sender_direct.config()),
            "an earlier sender config assignment must not perturb the final config"
        );

        let receiver_direct = RaptorQReceiverBuilder::new()
            .config(final_config.clone())
            .source(NoopStream)
            .build()
            .unwrap();
        let receiver_overridden = RaptorQReceiverBuilder::new()
            .config(first_config)
            .config(final_config)
            .source(NoopStream)
            .build()
            .unwrap();
        assert_eq!(
            format!("{:?}", receiver_overridden.config()),
            format!("{:?}", receiver_direct.config()),
            "an earlier receiver config assignment must not perturb the final config"
        );
    }

    #[test]
    fn test_receiver_builder_accepts_security_and_metrics() {
        let security = SecurityContext::for_testing(7);
        let metrics = Metrics::new();
        let receiver = RaptorQReceiverBuilder::new()
            .source(NoopStream)
            .security(security)
            .metrics(metrics)
            .build();
        assert!(receiver.is_ok());
    }
