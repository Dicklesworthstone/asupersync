    use super::WebBodyDiagnostic;

    #[test]
    fn web_body_diagnostic_codes_are_stable_and_unique() {
        let cases = [
            (WebBodyDiagnostic::TotalBodyLimit, "ASUP-E505"),
            (WebBodyDiagnostic::MultipartFieldLimit, "ASUP-E506"),
            (WebBodyDiagnostic::MalformedMultipart, "ASUP-E507"),
            (WebBodyDiagnostic::Timeout, "ASUP-E508"),
            (WebBodyDiagnostic::ClientAbort, "ASUP-E509"),
            (WebBodyDiagnostic::ResponseProducerFailure, "ASUP-E510"),
        ];
        let mut observed = std::collections::BTreeSet::new();
        for (diagnostic, expected) in cases {
            assert_eq!(diagnostic.code(), expected);
            assert!(observed.insert(diagnostic.code()));
        }
    }
