    use super::*;

    fn head() -> Vec<Header> {
        vec![Header::new(":status", "200"), Header::new("content-type", "application/grpc")]
    }

    #[test]
    fn preserves_distinct_initial_and_trailing_binary_metadata_and_status_details() {
        let mut state = ResponseHead::new(1024, false);
        let mut headers = head();
        headers.push(Header::new("x-value", "initial"));
        state.headers(headers, false).unwrap();
        state.data(false).unwrap();
        state.headers(vec![
            Header::new("grpc-status", "3"), Header::new("grpc-message", "bad%20%25%0A"),
            Header::new("grpc-status-details-bin", "AP8="),
            Header::new("x-value", "trailing"), Header::new("x-proof-bin", "YQ==, Yg"),
        ], true).unwrap();
        assert_eq!(state.terminal.as_ref().unwrap().code(), Code::InvalidArgument);
        assert_eq!(state.terminal.as_ref().unwrap().message(), "bad %\n");
        assert_eq!(state.terminal.as_ref().unwrap().details().unwrap().as_ref(), &[0, 255]);
        assert_eq!(state.trailers.as_ref().unwrap().len(), 3);
        assert_eq!(state.initial.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn terminal_and_content_type_validation_does_not_accept_grpc_web_or_early_status() {
        for value in ["application/grpc-web", "application/grpcx", "text/plain", "application/grpc+"] {
            let mut state = ResponseHead::new(1024, false);
            assert!(state.headers(vec![Header::new(":status", "200"), Header::new("content-type", value)], false).is_err());
        }
        for value in ["application/grpc", "application/grpc+proto", "Application/Grpc; charset=utf-8"] {
            assert!(ResponseHead::new(1024, false).headers(vec![Header::new(":status", "200"), Header::new("content-type", value)], false).is_ok());
        }
        let mut headers = head();
        headers.push(Header::new("grpc-status", "0"));
        assert!(ResponseHead::new(1024, false).headers(headers.clone(), false).is_err());
        let mut state = ResponseHead::new(1024, false);
        state.headers(headers, true).unwrap();
        assert!(state.initial.unwrap().is_empty());
        assert_eq!(state.terminal.unwrap().code(), Code::Ok);
    }

    #[test]
    fn trailers_refuse_duplicates_missing_status_and_reframing() {
        for fields in [
            vec![Header::new("grpc-status", "0"), Header::new("grpc-status", "0")],
            vec![Header::new("grpc-status", "+0")],
            vec![Header::new("grpc-status", "17")],
            vec![Header::new("grpc-status", "0"), Header::new("grpc-encoding", "gzip")],
            vec![Header::new("grpc-status", "0"), Header::new("x-bin", "invalid!")],
            vec![],
        ] {
            let mut state = ResponseHead::new(1024, false);
            state.headers(head(), false).unwrap();
            assert!(state.headers(fields, true).is_err());
        }
    }

    #[test]
    fn metadata_budget_counts_hpack_field_overhead_and_informational_blocks_are_bounded() {
        assert!(ResponseHead::new(10, false).headers(head(), false).is_err());
        let mut state = ResponseHead::new(1024, false);
        for _ in 0..16 {
            state.headers(vec![Header::new(":status", "103")], false).unwrap();
            assert!(state.initial.is_none());
        }
        assert!(state.headers(vec![Header::new(":status", "103")], false).is_err());
    }

    #[test]
    fn joined_binary_metadata_charges_each_retained_entry_and_ascii_metadata() {
        let name = "x-proof-bin";
        let joined = ",,,,,,,";
        let retained = (name.len() + 32) * 8 + "x-text".len() + "v".len() + 32;
        for terminal in [false, true] {
            for binary_first in [false, true] {
                let mut headers = head();
                let mut custom = vec![Header::new(name, joined), Header::new("x-text", "v")];
                if !binary_first {
                    custom.reverse();
                }
                headers.extend(custom);
                if terminal {
                    headers.push(Header::new("grpc-status", "0"));
                }
                let wire: usize = headers.iter()
                    .map(|header| header.name.len() + header.value.len() + 32)
                    .sum();
                assert!(wire < retained - 1, "the joined wire field fits both limits");

                let mut exact = ResponseHead::new(retained, false);
                exact.headers(headers.clone(), terminal).unwrap();
                let metadata = if terminal { exact.trailers } else { exact.initial }.unwrap();
                assert_eq!(metadata.len(), 9, "empty binary values remain distinct entries");

                let mut limited = ResponseHead::new(retained - 1, false);
                let error = limited.headers(headers, terminal).unwrap_err();
                assert_eq!(error.code(), Code::ResourceExhausted);
                assert!(limited.initial.is_none());
                assert!(limited.trailers.is_none());
                assert!(limited.terminal.is_none());
                assert!(!limited.ended, "a refused block must not publish partial state");
            }
        }
    }

    #[test]
    fn trailing_metadata_expansion_preserves_the_accepted_initial_head() {
        let mut state = ResponseHead::new(512, false);
        let mut initial = head();
        initial.push(Header::new("x-initial", "accepted"));
        state.headers(initial, false).unwrap();

        let error = state.headers(vec![
            Header::new("grpc-status", "0"),
            Header::new("x-proof-bin", ",".repeat(19)),
        ], true).unwrap_err();
        assert_eq!(error.code(), Code::ResourceExhausted);
        assert_eq!(state.initial.as_ref().unwrap().len(), 1);
        assert!(state.trailers.is_none());
        assert!(state.terminal.is_none());
        assert!(!state.ended);
    }

    #[test]
    fn http_fallback_applies_only_when_grpc_status_is_missing() {
        for (http, code) in [(401, Code::Unauthenticated), (404, Code::Unimplemented), (503, Code::Unavailable), (200, Code::Unknown)] {
            assert_eq!(http_fallback(http).code(), code);
        }
        let mut state = ResponseHead::new(1024, false);
        state.headers(vec![Header::new(":status", "503"), Header::new("grpc-status", "7")], true).unwrap();
        assert_eq!(state.terminal.unwrap().code(), Code::PermissionDenied);
    }

    #[test]
    fn unsupported_response_encoding_maps_to_internal() {
        let mut state = ResponseHead::new(1024, false);
        let mut headers = head();
        headers.push(Header::new("grpc-encoding", "deflate"));
        let err = state.headers(headers, false).unwrap_err();
        assert_eq!(err.code(), Code::Internal);
        assert_eq!(err.message(), "unsupported gRPC response compression");
    }

    /// Review r27-e8 (br-asupersync-grpc-client-server-audit-jq0c7j): a
    /// trailers-only error that names an encoding this client does not accept
    /// keeps its grpc-status (UNAUTHENTICATED here); it used to fail INTERNAL
    /// "unsupported gRPC response compression" before grpc-status was read.
    #[test]
    fn trailers_only_status_wins_over_an_unaccepted_response_encoding() {
        let mut state = ResponseHead::new(1024, false);
        let mut headers = head();
        headers.push(Header::new("grpc-encoding", "deflate"));
        headers.push(Header::new("grpc-status", "16"));
        state.headers(headers, true).unwrap();
        assert!(
            state.encoding.is_none(),
            "an unchecked encoding is not kept"
        );
        assert_eq!(state.terminal.unwrap().code(), Code::Unauthenticated);
    }
