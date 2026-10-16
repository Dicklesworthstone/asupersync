    use super::*;
    use crate::atp::policy::{CapabilityAction, ResourceScope, ScopeConstraints, TemporalScope};
    use crate::net::atp::protocol::PeerId;
    use std::collections::HashSet;
    use std::time::Duration;

    #[test]
    fn grant_info_tracks_usage() {
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let capability = crate::atp::policy::Capability::new(
            "test-grant".to_string(),
            PeerId::test(1),
            PeerId::test(2),
            ResourceScope::Any,
            actions,
            TemporalScope::once(),
            ScopeConstraints::default(),
        );

        let mut grant_info = GrantInfo::new(capability);

        assert!(grant_info.is_usable());
        assert_eq!(grant_info.usage_count, 0);

        grant_info.record_usage();
        assert_eq!(grant_info.usage_count, 1);
        assert_eq!(grant_info.state, GrantState::Expired); // Max uses was 1
        assert!(!grant_info.is_usable());
    }

    #[test]
    fn grant_info_usage_count_saturates_at_u64_max() {
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let capability = crate::atp::policy::Capability::new(
            "saturating-grant".to_string(),
            PeerId::test(1),
            PeerId::test(2),
            ResourceScope::Any,
            actions,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
        );

        let mut grant_info = GrantInfo::new(capability);
        grant_info.usage_count = u64::MAX;

        grant_info.record_usage();

        assert_eq!(grant_info.usage_count, u64::MAX);
        assert_eq!(grant_info.state, GrantState::Active);
    }

    #[test]
    fn grant_templates_create_common_patterns() {
        let read_once = GrantTemplate::read_once();
        assert_eq!(read_once.name, "read-once");
        assert!(read_once.actions.contains(&CapabilityAction::ReadOnce));
        assert_eq!(read_once.temporal.max_uses, Some(1));

        let share_24h = GrantTemplate::share_24h();
        assert_eq!(share_24h.name, "share-24h");
        assert!(share_24h.actions.contains(&CapabilityAction::Share));

        let inbox = GrantTemplate::inbox_write();
        assert_eq!(inbox.name, "inbox-write");
        assert!(inbox.actions.contains(&CapabilityAction::WriteInbox));
        assert!(matches!(inbox.scope, ResourceScope::Inbox));

        let team = GrantTemplate::team_read("engineering".to_string());
        assert_eq!(team.name, "team-engineering-read");
        assert!(team.actions.contains(&CapabilityAction::Read));
        assert!(matches!(team.scope, ResourceScope::Team(ref t) if t == "engineering"));
    }

    #[test]
    fn grant_redacted_summary_includes_key_info() {
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);
        actions.insert(CapabilityAction::Share);

        let capability = crate::atp::policy::Capability::new(
            "test-grant-12345".to_string(),
            PeerId::test(1),
            PeerId::test(2),
            ResourceScope::Inbox,
            actions,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
        );

        let grant_info = GrantInfo::new(capability);
        let summary = grant_info.redacted_summary();

        assert!(summary.contains("grant=test-gra"));
        assert!(summary.contains("scope=inbox"));
        assert!(summary.contains("Read"));
        assert!(summary.contains("Share"));
        assert!(summary.contains("state=Active"));
    }

    #[test]
    fn grant_query_provides_filtering() {
        let query = GrantQuery {
            subject: Some(PeerId::test(1)),
            state: Some(GrantState::Active),
            usable_only: true,
            limit: Some(10),
            ..Default::default()
        };

        assert_eq!(query.subject, Some(PeerId::test(1)));
        assert_eq!(query.state, Some(GrantState::Active));
        assert!(query.usable_only);
        assert_eq!(query.limit, Some(10));
    }
