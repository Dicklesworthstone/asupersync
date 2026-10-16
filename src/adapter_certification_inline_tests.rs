    use super::{
        ADAPTER_CERTIFICATIONS, AdapterCategory, AdapterCertificationStatus, AdapterRenderedStatus,
        adapter_certification,
    };

    #[test]
    fn adapter_certifications_have_stable_ids_and_statuses() {
        assert_eq!(ADAPTER_CERTIFICATIONS.len(), 5);
        let http = adapter_certification("http-h1-h2").expect("http adapter");
        assert_eq!(http.category, AdapterCategory::Http);
        assert_eq!(
            http.certification_status,
            AdapterCertificationStatus::CertifiedLive
        );
        assert_eq!(http.rendered_status, AdapterRenderedStatus::Pass);
        assert!(!http.fail_closed_without_full_reference);

        let database =
            adapter_certification("database-postgres-mysql-sqlite").expect("database adapter");
        assert_eq!(
            database.certification_status,
            AdapterCertificationStatus::PartialFailClosed
        );
        assert_eq!(database.rendered_status, AdapterRenderedStatus::Xfail);
        assert!(database.fail_closed_without_full_reference);
    }
