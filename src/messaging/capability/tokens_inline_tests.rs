    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::messaging::fabric::CellEpoch;
    use crate::messaging::subject::SubjectPattern;

    struct DemoProtocol;
    impl ProtocolMarker for DemoProtocol {
        const NAME: &'static str = "fabric.demo";
    }

    struct Init;
    impl SessionStateMarker for Init {
        const NAME: &'static str = "init";
    }

    struct Established;
    impl SessionStateMarker for Established {
        const NAME: &'static str = "established";
    }

    struct EmptyProtocol;
    impl ProtocolMarker for EmptyProtocol {
        const NAME: &'static str = "";
    }

    fn schema_with(
        families: Vec<SubjectFamily>,
        delivery_classes: Vec<DeliveryClass>,
        permissions: Vec<CapabilityPermission>,
    ) -> CapabilityTokenSchema {
        CapabilityTokenSchema {
            name: "fabric.token.demo".to_owned(),
            families,
            delivery_classes,
            permissions,
        }
    }

    fn demo_cell_id(epoch: CellEpoch) -> CellId {
        CellId::for_partition(epoch, &SubjectPattern::new("orders.created"))
    }

    #[test]
    fn publish_permit_validates_family_permission_and_class() {
        let schema = schema_with(
            vec![SubjectFamily::Event],
            vec![DeliveryClass::EphemeralInteractive],
            vec![CapabilityPermission::Publish],
        );

        let permit =
            PublishPermit::<EventFamily>::authorize(&schema, DeliveryClass::EphemeralInteractive)
                .expect("event publish permit should authorize");

        assert_eq!(permit.schema_name(), "fabric.token.demo");
        assert_eq!(permit.family(), SubjectFamily::Event);
        assert_eq!(permit.delivery_class(), DeliveryClass::EphemeralInteractive);
    }

    #[test]
    fn subscribe_token_rejects_wrong_family() {
        let schema = schema_with(
            vec![SubjectFamily::Reply],
            vec![DeliveryClass::EphemeralInteractive],
            vec![CapabilityPermission::Subscribe],
        );

        let error =
            SubscribeToken::<EventFamily>::authorize(&schema, DeliveryClass::EphemeralInteractive)
                .expect_err("mismatched family should fail");

        assert_eq!(
            error,
            CapabilityTokenError::MissingSubjectFamily {
                schema: "fabric.token.demo".to_owned(),
                required_family: "event",
            }
        );
    }

    #[test]
    fn publish_permit_rejects_missing_permission() {
        let schema = schema_with(
            vec![SubjectFamily::Event],
            vec![DeliveryClass::EphemeralInteractive],
            vec![CapabilityPermission::Subscribe],
        );

        let error =
            PublishPermit::<EventFamily>::authorize(&schema, DeliveryClass::EphemeralInteractive)
                .expect_err("missing publish permission should fail");

        assert_eq!(
            error,
            CapabilityTokenError::MissingPermission {
                schema: "fabric.token.demo".to_owned(),
                required_permission: "publish",
            }
        );
    }

    #[test]
    fn session_token_validates_and_advances_typestate() {
        let token = SessionToken::<DemoProtocol, Init>::new(9).expect("session token");
        let next = token
            .advance::<Established>()
            .expect("session advance should preserve metadata");

        assert_eq!(next.session_id(), 9);
        assert_eq!(
            next.to_string(),
            "session-token[protocol=fabric.demo, state=established, session_id=9]"
        );
    }

    #[test]
    fn session_token_rejects_empty_protocol_name() {
        assert!(matches!(
            SessionToken::<EmptyProtocol, Init>::new(7),
            Err(CapabilityTokenError::EmptyProtocolName)
        ));
    }

    #[test]
    fn cursor_authority_lease_rejects_zero_expiry() {
        let epoch = CellEpoch::new(7, 2);
        let error = CursorAuthorityLease::new(demo_cell_id(epoch), epoch, Time::ZERO)
            .expect_err("zero expiry must fail");
        assert_eq!(error, CapabilityTokenError::ZeroLeaseExpiry);
    }

    #[test]
    fn append_certificate_rejects_zero_sequence() {
        let epoch = CellEpoch::new(11, 4);
        let error = AppendCertificate::new(demo_cell_id(epoch), epoch, 0)
            .expect_err("zero sequence must fail");
        assert_eq!(error, CapabilityTokenError::ZeroSequence);
    }

    #[test]
    fn display_formats_are_stable() {
        let schema = schema_with(
            vec![SubjectFamily::Event],
            vec![DeliveryClass::DurableOrdered],
            vec![
                CapabilityPermission::Publish,
                CapabilityPermission::Subscribe,
            ],
        );
        let epoch = CellEpoch::new(5, 3);
        let cell_id = demo_cell_id(epoch);

        let publish =
            PublishPermit::<EventFamily>::authorize(&schema, DeliveryClass::DurableOrdered)
                .expect("publish token");
        let subscribe =
            SubscribeToken::<EventFamily>::authorize(&schema, DeliveryClass::DurableOrdered)
                .expect("subscribe token");
        let session = SessionToken::<DemoProtocol, Init>::new(21).expect("session token");
        let lease =
            CursorAuthorityLease::new(cell_id, epoch, Time::from_secs(30)).expect("cursor lease");
        let append = AppendCertificate::new(cell_id, epoch, 17).expect("append cert");
        let fence = FenceToken::new(cell_id, epoch);

        assert_eq!(
            publish.to_string(),
            "publish-permit[schema=fabric.token.demo, family=event, class=durable-ordered]"
        );
        assert_eq!(
            subscribe.to_string(),
            "subscribe-token[schema=fabric.token.demo, family=event, class=durable-ordered]"
        );
        assert_eq!(
            session.to_string(),
            "session-token[protocol=fabric.demo, state=init, session_id=21]"
        );
        assert_eq!(
            lease.to_string(),
            format!(
                "cursor-authority-lease[cell={}, epoch=5:3, expires_at_ns={}]",
                cell_id,
                Time::from_secs(30).as_nanos()
            )
        );
        assert_eq!(
            append.to_string(),
            format!("append-certificate[cell={cell_id}, epoch=5:3, sequence=17]")
        );
        assert_eq!(
            fence.to_string(),
            format!("fence-token[cell={cell_id}, epoch=5:3]")
        );
    }

    #[test]
    fn debug_redacts_linear_authority_metadata() {
        let schema = schema_with(
            vec![SubjectFamily::Event],
            vec![DeliveryClass::DurableOrdered],
            vec![
                CapabilityPermission::Publish,
                CapabilityPermission::Subscribe,
            ],
        );
        let epoch = CellEpoch::new(5, 3);
        let cell_id = demo_cell_id(epoch);

        let publish =
            PublishPermit::<EventFamily>::authorize(&schema, DeliveryClass::DurableOrdered)
                .expect("publish token");
        let subscribe =
            SubscribeToken::<EventFamily>::authorize(&schema, DeliveryClass::DurableOrdered)
                .expect("subscribe token");
        let session = SessionToken::<DemoProtocol, Init>::new(21).expect("session token");
        let lease =
            CursorAuthorityLease::new(cell_id, epoch, Time::from_secs(30)).expect("cursor lease");
        let append = AppendCertificate::new(cell_id, epoch, 17).expect("append cert");
        let fence = FenceToken::new(cell_id, epoch);

        let debug_values = [
            format!("{publish:?}"),
            format!("{subscribe:?}"),
            format!("{session:?}"),
            format!("{lease:?}"),
            format!("{append:?}"),
            format!("{fence:?}"),
        ];

        for debug in debug_values {
            assert!(
                debug.contains("<redacted>"),
                "linear authority Debug must make redaction explicit: {debug}"
            );
            assert!(
                !debug.contains("fabric.token.demo"),
                "schema names authorize capability use and must not leak through Debug: {debug}"
            );
            assert!(
                !debug.contains("fabric.demo"),
                "protocol names must not leak through Debug: {debug}"
            );
            assert!(
                !debug.contains("session_id"),
                "session authority metadata must not leak through Debug: {debug}"
            );
            assert!(
                !debug.contains(&cell_id.to_string()),
                "cell authority metadata must not leak through Debug: {debug}"
            );
            assert!(
                !debug.contains("epoch"),
                "epoch fences must not leak through Debug: {debug}"
            );
            assert!(
                !debug.contains("sequence"),
                "append certificate sequences must not leak through Debug: {debug}"
            );
        }
    }
