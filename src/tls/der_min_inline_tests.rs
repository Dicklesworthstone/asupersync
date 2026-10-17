    use super::*;

    const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

    fn encoded_length(length: usize) -> Vec<u8> {
        if length <= 127 {
            return vec![length.to_be_bytes()[core::mem::size_of::<usize>() - 1]];
        }
        let bytes = length.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .expect("nonzero long-form length");
        let significant = &bytes[first..];
        let mut encoded = Vec::with_capacity(significant.len() + 1);
        let octet_count = significant.len().to_be_bytes()[core::mem::size_of::<usize>() - 1];
        encoded.push(0x80 | octet_count);
        encoded.extend_from_slice(significant);
        encoded
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let length = encoded_length(content.len());
        let mut encoded = Vec::with_capacity(1 + length.len() + content.len());
        encoded.push(tag);
        encoded.extend_from_slice(&length);
        encoded.extend_from_slice(content);
        encoded
    }

    fn concatenate(parts: Vec<Vec<u8>>) -> Vec<u8> {
        parts.into_iter().flatten().collect()
    }

    fn sequence(parts: Vec<Vec<u8>>) -> Vec<u8> {
        tlv(TAG_SEQUENCE, &concatenate(parts))
    }

    fn oid(content: &[u8]) -> Vec<u8> {
        tlv(TAG_OID, content)
    }

    fn integer(content: &[u8]) -> Vec<u8> {
        tlv(TAG_INTEGER, content)
    }

    fn algorithm_identifier() -> Vec<u8> {
        sequence(vec![oid(OID_RSA_ENCRYPTION), tlv(TAG_NULL, &[])])
    }

    fn attribute(oid_content: &[u8], value_tag: u8, value: &[u8]) -> Vec<u8> {
        sequence(vec![oid(oid_content), tlv(value_tag, value)])
    }

    fn rdn(mut attributes: Vec<Vec<u8>>) -> Vec<u8> {
        attributes.sort();
        tlv(TAG_SET, &concatenate(attributes))
    }

    fn name(rdns: Vec<Vec<u8>>) -> Vec<u8> {
        sequence(rdns)
    }

    fn common_name(value_tag: u8, value: &[u8]) -> Vec<u8> {
        name(vec![rdn(vec![attribute(
            OID_COMMON_NAME,
            value_tag,
            value,
        )])])
    }

    fn validity(not_before: &[u8], not_after: &[u8]) -> Vec<u8> {
        sequence(vec![
            tlv(TAG_UTC_TIME, not_before),
            tlv(TAG_UTC_TIME, not_after),
        ])
    }

    fn default_validity() -> Vec<u8> {
        validity(b"250101000000Z", b"260101000000Z")
    }

    fn subject_public_key_info(key_bytes: &[u8]) -> Vec<u8> {
        let mut bit_string = Vec::with_capacity(key_bytes.len() + 1);
        bit_string.push(0);
        bit_string.extend_from_slice(key_bytes);
        sequence(vec![
            algorithm_identifier(),
            tlv(TAG_BIT_STRING, &bit_string),
        ])
    }

    fn extension(oid_content: &[u8], critical: Option<bool>, inner_der: &[u8]) -> Vec<u8> {
        let mut fields = vec![oid(oid_content)];
        if let Some(critical) = critical {
            fields.push(tlv(TAG_BOOLEAN, &[if critical { 0xff } else { 0 }]));
        }
        fields.push(tlv(TAG_OCTET_STRING, inner_der));
        sequence(fields)
    }

    fn certificate(
        serial_content: &[u8],
        certificate_validity: Vec<u8>,
        subject: Vec<u8>,
        spki: Vec<u8>,
        extensions: Option<Vec<Vec<u8>>>,
        signature_content: &[u8],
    ) -> Vec<u8> {
        let mut tbs_fields = vec![
            tlv(TAG_VERSION_EXPLICIT, &integer(&[2])),
            integer(serial_content),
            algorithm_identifier(),
            common_name(TAG_UTF8_STRING, b"Issuer"),
            certificate_validity,
            subject,
            spki,
        ];
        if let Some(rows) = extensions {
            tbs_fields.push(tlv(TAG_EXTENSIONS_EXPLICIT, &sequence(rows)));
        }
        sequence(vec![
            sequence(tbs_fields),
            algorithm_identifier(),
            tlv(TAG_BIT_STRING, signature_content),
        ])
    }

    fn default_certificate(extensions: Option<Vec<Vec<u8>>>) -> Vec<u8> {
        certificate(
            &[1],
            default_validity(),
            common_name(TAG_UTF8_STRING, b"example.com"),
            subject_public_key_info(&[1, 2, 3]),
            extensions,
            &[0, 1],
        )
    }

    fn expect_error<T>(result: Result<T, DerError>, class: DerErrorClass) -> DerError {
        let error = result.err().expect("expected deterministic DER error");
        assert_eq!(error.class, class);
        error
    }

    #[test]
    fn four_profiles_return_only_approved_borrowed_facts() {
        let basic_constraints = extension(
            OID_BASIC_CONSTRAINTS,
            None,
            &sequence(vec![tlv(TAG_BOOLEAN, &[0xff]), integer(&[0])]),
        );
        let key_usage = extension(OID_KEY_USAGE, Some(true), &tlv(TAG_BIT_STRING, &[7, 0x80]));
        let extended_key_usage = extension(
            OID_EXTENDED_KEY_USAGE,
            None,
            &sequence(vec![oid(OID_SERVER_AUTH)]),
        );
        let san_inner = sequence(vec![tlv(0x82, b"example.com"), tlv(0x87, &[192, 0, 2, 1])]);
        let subject_alt_name = extension(OID_SUBJECT_ALT_NAME, None, &san_inner);
        let spki = subject_public_key_info(&[1, 2, 3]);
        let certificate = certificate(
            &[1],
            default_validity(),
            common_name(TAG_UTF8_STRING, b"example.com"),
            spki.clone(),
            Some(vec![
                basic_constraints,
                key_usage,
                extended_key_usage,
                subject_alt_name,
            ]),
            &[0, 1],
        );

        assert_eq!(
            extract_spki_der(&certificate).expect("SPKI profile"),
            spki.as_slice()
        );
        assert_eq!(
            inspect_basic_constraints_ca(&certificate).expect("root profile"),
            BasicConstraintsFact::Present { ca: true }
        );
        let metadata =
            inspect_server_chain_metadata(&certificate).expect("acceptor preflight profile");
        assert!(metadata.subject_identity_present);
        assert!(metadata.validity.not_before < metadata.validity.not_after);

        let pin = inspect_pinned_leaf_shape(&certificate).expect("pinned leaf profile");
        assert_eq!(pin.extended_key_usage, ExtensionFact::Present(true));
        assert_eq!(pin.key_usage, ExtensionFact::Present(true));
        assert_eq!(
            pin.subject_alt_name,
            ExtensionFact::Present(SubjectAltNameFacts {
                dns_names: vec![b"example.com".as_slice()],
                ip_addresses: vec![[192, 0, 2, 1].as_slice()],
            })
        );

        let absent = default_certificate(None);
        assert_eq!(
            inspect_basic_constraints_ca(&absent).expect("absent root facts"),
            BasicConstraintsFact::Absent
        );
        let absent_pin = inspect_pinned_leaf_shape(&absent).expect("absent pin facts");
        assert_eq!(absent_pin.extended_key_usage, ExtensionFact::Absent);
        assert_eq!(absent_pin.key_usage, ExtensionFact::Absent);
        assert_eq!(absent_pin.subject_alt_name, ExtensionFact::Absent);
    }

    #[test]
    fn full_consumption_and_every_truncation_offset_fail_closed() {
        let certificate = default_certificate(Some(vec![extension(
            OID_SUBJECT_ALT_NAME,
            None,
            &sequence(vec![tlv(0x82, b"example.com")]),
        )]));
        for end in 0..certificate.len() {
            assert!(extract_spki_der(&certificate[..end]).is_err(), "end={end}");
            assert!(
                inspect_basic_constraints_ca(&certificate[..end]).is_err(),
                "end={end}"
            );
            assert!(
                inspect_server_chain_metadata(&certificate[..end]).is_err(),
                "end={end}"
            );
            assert!(
                inspect_pinned_leaf_shape(&certificate[..end]).is_err(),
                "end={end}"
            );
        }
        assert!(extract_spki_der(&certificate).is_ok());

        let mut trailing = certificate;
        trailing.push(0);
        expect_error(extract_spki_der(&trailing), DerErrorClass::EmptyOrTrailing);
    }

    #[test]
    fn tag_and_length_boundaries_are_canonical_and_deterministic() {
        for length in [0, 1, 127, 128, 255, 256] {
            let encoded = tlv(TAG_OCTET_STRING, &vec![0; length]);
            let mut parser = Parser::new(&encoded).expect("bounded parser");
            let mut cursor = Cursor::new(0, encoded.len(), 1);
            let value = parser
                .expect(&mut cursor, TAG_OCTET_STRING)
                .expect("canonical TLV");
            assert_eq!(value.content_len(), length);
            assert!(cursor.is_empty());
        }

        for (input, class) in [
            (
                vec![TAG_OCTET_STRING, 0x80],
                DerErrorClass::IndefiniteLength,
            ),
            (
                vec![TAG_OCTET_STRING, 0x81, 0x01, 0],
                DerErrorClass::NonminimalLength,
            ),
            (
                vec![TAG_OCTET_STRING, 0x82, 0, 0x80],
                DerErrorClass::NonminimalLength,
            ),
            (vec![0x1f, 0], DerErrorClass::Tag),
            (vec![TAG_OCTET_STRING, 0x89], DerErrorClass::LengthOverflow),
        ] {
            let mut parser = Parser::new(&input).expect("nonempty parser");
            let mut cursor = Cursor::new(0, input.len(), 1);
            expect_error(parser.read_tlv(&mut cursor), class);
        }

        let input = [0x10, 0];
        let mut parser = Parser::new(&input).expect("nonempty parser");
        let mut cursor = Cursor::new(0, input.len(), 1);
        expect_error(
            parser.expect(&mut cursor, TAG_SEQUENCE),
            DerErrorClass::ConstructedBit,
        );

        let nested_bounds = [TAG_SEQUENCE, 2, TAG_OCTET_STRING, 1, TAG_NULL, 0];
        let mut parser = Parser::new(&nested_bounds).expect("nonempty parser");
        let mut root = Cursor::new(0, nested_bounds.len(), 1);
        let sequence = parser
            .expect(&mut root, TAG_SEQUENCE)
            .expect("outer sequence");
        let mut inner = sequence.child_cursor();
        expect_error(parser.read_tlv(&mut inner), DerErrorClass::Bounds);
    }

    #[test]
    fn extension_duplicates_and_criticality_are_fail_closed() {
        let san = extension(
            OID_SUBJECT_ALT_NAME,
            None,
            &sequence(vec![tlv(0x82, b"example.com")]),
        );
        let duplicate_extension = default_certificate(Some(vec![san.clone(), san]));
        expect_error(
            inspect_pinned_leaf_shape(&duplicate_extension),
            DerErrorClass::DuplicateExtension,
        );

        let duplicate_eku = default_certificate(Some(vec![extension(
            OID_EXTENDED_KEY_USAGE,
            None,
            &sequence(vec![oid(OID_SERVER_AUTH), oid(OID_SERVER_AUTH)]),
        )]));
        expect_error(
            inspect_pinned_leaf_shape(&duplicate_eku),
            DerErrorClass::DuplicateEku,
        );

        let unknown_oid = [0x2a, 0x03, 0x04];
        let unknown_critical =
            default_certificate(Some(vec![extension(&unknown_oid, Some(true), &[])]));
        expect_error(
            inspect_pinned_leaf_shape(&unknown_critical),
            DerErrorClass::UnknownCritical,
        );
        let unknown_noncritical =
            default_certificate(Some(vec![extension(&unknown_oid, None, &[])]));
        assert!(inspect_pinned_leaf_shape(&unknown_noncritical).is_ok());

        let unsupported_general_name = sequence(vec![tlv(0x81, b"mail@example.com")]);
        let critical_san = default_certificate(Some(vec![extension(
            OID_SUBJECT_ALT_NAME,
            Some(true),
            &unsupported_general_name,
        )]));
        expect_error(
            inspect_pinned_leaf_shape(&critical_san),
            DerErrorClass::UnknownCritical,
        );
        let noncritical_san = default_certificate(Some(vec![extension(
            OID_SUBJECT_ALT_NAME,
            None,
            &unsupported_general_name,
        )]));
        let pin = inspect_pinned_leaf_shape(&noncritical_san).expect("skipped noncritical name");
        assert_eq!(
            pin.subject_alt_name,
            ExtensionFact::Present(SubjectAltNameFacts {
                dns_names: Vec::new(),
                ip_addresses: Vec::new(),
            })
        );

        let explicit_false =
            default_certificate(Some(vec![extension(&unknown_oid, Some(false), &[])]));
        expect_error(
            inspect_pinned_leaf_shape(&explicit_false),
            DerErrorClass::ExplicitDefault,
        );
    }

    #[test]
    fn selected_extension_semantics_preserve_presence_and_defaults() {
        let empty_basic_constraints = default_certificate(Some(vec![extension(
            OID_BASIC_CONSTRAINTS,
            Some(true),
            &sequence(Vec::new()),
        )]));
        assert_eq!(
            inspect_basic_constraints_ca(&empty_basic_constraints).expect("empty defaults"),
            BasicConstraintsFact::Present { ca: false }
        );

        let explicit_false = default_certificate(Some(vec![extension(
            OID_BASIC_CONSTRAINTS,
            Some(true),
            &sequence(vec![tlv(TAG_BOOLEAN, &[0])]),
        )]));
        expect_error(
            inspect_basic_constraints_ca(&explicit_false),
            DerErrorClass::ExplicitDefault,
        );

        let path_without_ca = default_certificate(Some(vec![extension(
            OID_BASIC_CONSTRAINTS,
            Some(true),
            &sequence(vec![integer(&[0])]),
        )]));
        expect_error(
            inspect_basic_constraints_ca(&path_without_ca),
            DerErrorClass::SelectedExtension,
        );

        let digital_signature = default_certificate(Some(vec![extension(
            OID_KEY_USAGE,
            None,
            &tlv(TAG_BIT_STRING, &[7, 0x80]),
        )]));
        assert_eq!(
            inspect_pinned_leaf_shape(&digital_signature)
                .expect("digitalSignature")
                .key_usage,
            ExtensionFact::Present(true)
        );
        let key_encipherment = default_certificate(Some(vec![extension(
            OID_KEY_USAGE,
            None,
            &tlv(TAG_BIT_STRING, &[5, 0x20]),
        )]));
        assert_eq!(
            inspect_pinned_leaf_shape(&key_encipherment)
                .expect("keyEncipherment")
                .key_usage,
            ExtensionFact::Present(false)
        );
        let nonminimal_named_bits = default_certificate(Some(vec![extension(
            OID_KEY_USAGE,
            None,
            &tlv(TAG_BIT_STRING, &[0, 0x80, 0]),
        )]));
        expect_error(
            inspect_pinned_leaf_shape(&nonminimal_named_bits),
            DerErrorClass::BitString,
        );
    }

    #[test]
    fn validity_and_directory_strings_are_strict_without_policy() {
        let invalid_date = certificate(
            &[1],
            validity(b"250229000000Z", b"260101000000Z"),
            common_name(TAG_UTF8_STRING, b"example.com"),
            subject_public_key_info(&[1]),
            None,
            &[0, 1],
        );
        expect_error(
            inspect_server_chain_metadata(&invalid_date),
            DerErrorClass::Time,
        );

        let reversed = certificate(
            &[1],
            validity(b"260101000000Z", b"250101000000Z"),
            common_name(TAG_UTF8_STRING, b"example.com"),
            subject_public_key_info(&[1]),
            None,
            &[0, 1],
        );
        expect_error(
            inspect_server_chain_metadata(&reversed),
            DerErrorClass::ValidityOrder,
        );

        for subject in [
            common_name(TAG_UTF8_STRING, &[0xff]),
            common_name(TAG_PRINTABLE_STRING, b"bad@value"),
            common_name(TAG_BMP_STRING, &[0]),
            common_name(TAG_UNIVERSAL_STRING, &[0, 0, 0]),
        ] {
            let malformed = certificate(
                &[1],
                default_validity(),
                subject,
                subject_public_key_info(&[1]),
                None,
                &[0, 1],
            );
            expect_error(
                inspect_server_chain_metadata(&malformed),
                DerErrorClass::String,
            );
        }

        let teletex = certificate(
            &[1],
            default_validity(),
            common_name(TAG_TELETEX_STRING, b"Legacy"),
            subject_public_key_info(&[1]),
            None,
            &[0, 1],
        );
        assert!(
            !inspect_server_chain_metadata(&teletex)
                .expect("Teletex is recognized but not a supported identity")
                .subject_identity_present
        );
    }

    #[test]
    fn every_configured_resource_budget_fails_before_unbounded_work() {
        let oversized_certificate = vec![0; MAX_CERTIFICATE_DER_BYTES + 1];
        let certificate_error = expect_error(
            extract_spki_der(&oversized_certificate),
            DerErrorClass::CertificateLimit,
        );
        assert_eq!(certificate_error.offset, MAX_CERTIFICATE_DER_BYTES);

        let mut extension_rows = Vec::new();
        for suffix in 0..=MAX_EXTENSION_COUNT {
            let suffix_octet = suffix.to_be_bytes()[core::mem::size_of::<usize>() - 1];
            extension_rows.push(extension(&[0x2a, 0x03, suffix_octet], None, &[]));
        }
        let too_many_extensions = default_certificate(Some(extension_rows));
        expect_error(
            inspect_pinned_leaf_shape(&too_many_extensions),
            DerErrorClass::CountLimit,
        );

        let oversized_extension = default_certificate(Some(vec![extension(
            &[0x2a, 0x03, 1],
            None,
            &vec![0; MAX_EXTENSION_VALUE_BYTES + 1],
        )]));
        expect_error(
            inspect_pinned_leaf_shape(&oversized_extension),
            DerErrorClass::ValueLimit,
        );

        let encoded_attribute = attribute(OID_COMMON_NAME, TAG_UTF8_STRING, b"x");
        let too_many_rdns = name(
            (0..=MAX_SUBJECT_RDNS)
                .map(|_| rdn(vec![encoded_attribute.clone()]))
                .collect(),
        );
        let rdn_limited_certificate = certificate(
            &[1],
            default_validity(),
            too_many_rdns,
            subject_public_key_info(&[1]),
            None,
            &[0, 1],
        );
        expect_error(
            inspect_server_chain_metadata(&rdn_limited_certificate),
            DerErrorClass::CountLimit,
        );

        let too_many_attributes = name(vec![rdn(vec![
            encoded_attribute.clone();
            MAX_SUBJECT_ATTRIBUTES + 1
        ])]);
        let attribute_limited_certificate = certificate(
            &[1],
            default_validity(),
            too_many_attributes,
            subject_public_key_info(&[1]),
            None,
            &[0, 1],
        );
        expect_error(
            inspect_server_chain_metadata(&attribute_limited_certificate),
            DerErrorClass::CountLimit,
        );

        let oversized_string = certificate(
            &[1],
            default_validity(),
            common_name(TAG_UTF8_STRING, &vec![b'x'; MAX_DIRECTORY_STRING_BYTES + 1]),
            subject_public_key_info(&[1]),
            None,
            &[0, 1],
        );
        expect_error(
            inspect_server_chain_metadata(&oversized_string),
            DerErrorClass::ValueLimit,
        );

        let eku_purposes = (0..=MAX_EKU_PURPOSE_COUNT)
            .map(|suffix| {
                let suffix_octet = suffix.to_be_bytes()[core::mem::size_of::<usize>() - 1];
                oid(&[0x2a, 0x03, suffix_octet])
            })
            .collect();
        let too_many_eku = default_certificate(Some(vec![extension(
            OID_EXTENDED_KEY_USAGE,
            None,
            &sequence(eku_purposes),
        )]));
        expect_error(
            inspect_pinned_leaf_shape(&too_many_eku),
            DerErrorClass::CountLimit,
        );

        let too_many_sans = default_certificate(Some(vec![extension(
            OID_SUBJECT_ALT_NAME,
            None,
            &sequence(vec![tlv(0x82, b"x"); MAX_SAN_ENTRY_COUNT + 1]),
        )]));
        expect_error(
            inspect_pinned_leaf_shape(&too_many_sans),
            DerErrorClass::CountLimit,
        );

        let oversized_dns = default_certificate(Some(vec![extension(
            OID_SUBJECT_ALT_NAME,
            None,
            &sequence(vec![tlv(0x82, &vec![b'x'; MAX_DNS_SAN_BYTES + 1])]),
        )]));
        expect_error(
            inspect_pinned_leaf_shape(&oversized_dns),
            DerErrorClass::ValueLimit,
        );

        let oversized_spki = certificate(
            &[1],
            default_validity(),
            common_name(TAG_UTF8_STRING, b"x"),
            subject_public_key_info(&vec![1; MAX_SPKI_DER_BYTES - 24]),
            None,
            &[0, 1],
        );
        expect_error(extract_spki_der(&oversized_spki), DerErrorClass::ValueLimit);

        let oversized_integer = certificate(
            &vec![1; MAX_INTEGER_CONTENT_BYTES + 1],
            default_validity(),
            common_name(TAG_UTF8_STRING, b"x"),
            subject_public_key_info(&[1]),
            None,
            &[0, 1],
        );
        expect_error(
            extract_spki_der(&oversized_integer),
            DerErrorClass::ValueLimit,
        );

        let oversized_signature = certificate(
            &[1],
            default_validity(),
            common_name(TAG_UTF8_STRING, b"x"),
            subject_public_key_info(&[1]),
            None,
            &vec![0; MAX_BIT_STRING_CONTENT_BYTES + 1],
        );
        expect_error(
            extract_spki_der(&oversized_signature),
            DerErrorClass::ValueLimit,
        );

        let oversized_oid = certificate(
            &[1],
            default_validity(),
            name(vec![rdn(vec![attribute(
                &vec![0x2a; MAX_OID_CONTENT_BYTES + 1],
                TAG_UTF8_STRING,
                b"x",
            )])]),
            subject_public_key_info(&[1]),
            None,
            &[0, 1],
        );
        expect_error(extract_spki_der(&oversized_oid), DerErrorClass::ValueLimit);

        let input = [TAG_NULL, 0];
        let mut parser = Parser::new(&input).expect("nonempty parser");
        let mut too_deep = Cursor::new(0, input.len(), MAX_TLV_DEPTH + 1);
        expect_error(parser.read_tlv(&mut too_deep), DerErrorClass::DepthLimit);

        let mut nodes = Vec::with_capacity((MAX_TLV_NODES + 1) * 2);
        for _ in 0..=MAX_TLV_NODES {
            nodes.extend_from_slice(&[TAG_NULL, 0]);
        }
        let mut parser = Parser::new(&nodes).expect("bounded node corpus");
        let mut cursor = Cursor::new(0, nodes.len(), 1);
        for _ in 0..MAX_TLV_NODES {
            parser.read_tlv(&mut cursor).expect("within node budget");
        }
        expect_error(parser.read_tlv(&mut cursor), DerErrorClass::NodeLimit);
    }

    #[test]
    fn deterministic_mutations_repeat_the_same_bounded_result() {
        let certificate = default_certificate(Some(vec![
            extension(
                OID_EXTENDED_KEY_USAGE,
                None,
                &sequence(vec![oid(OID_SERVER_AUTH)]),
            ),
            extension(OID_KEY_USAGE, None, &tlv(TAG_BIT_STRING, &[7, 0x80])),
            extension(
                OID_SUBJECT_ALT_NAME,
                None,
                &sequence(vec![tlv(0x82, b"example.com")]),
            ),
        ]));

        for index in 0..certificate.len() {
            let mut mutated = certificate.clone();
            mutated[index] ^= 1;
            assert_eq!(
                extract_spki_der(&mutated),
                extract_spki_der(&mutated),
                "SPKI mutation index {index}"
            );
            assert_eq!(
                inspect_basic_constraints_ca(&mutated),
                inspect_basic_constraints_ca(&mutated),
                "root mutation index {index}"
            );
            assert_eq!(
                inspect_server_chain_metadata(&mutated),
                inspect_server_chain_metadata(&mutated),
                "preflight mutation index {index}"
            );
            assert_eq!(
                inspect_pinned_leaf_shape(&mutated),
                inspect_pinned_leaf_shape(&mutated),
                "pin mutation index {index}"
            );
        }
    }

    fn first_pem_certificate(pem: &[u8]) -> Vec<u8> {
        crate::tls::Certificate::from_pem(pem)
            .expect("certificate fixture must be valid PEM")
            .into_iter()
            .next()
            .expect("certificate fixture must contain one certificate")
            .as_der()
            .to_vec()
    }

    fn x509_parser_accepts_one_complete_certificate(input: &[u8]) -> bool {
        x509_parser::parse_x509_certificate(input)
            .is_ok_and(|(remaining, _certificate)| remaining.is_empty())
    }

    #[test]
    fn real_certificate_matches_the_complete_x509_parser_overlap() {
        let certificate =
            first_pem_certificate(include_bytes!("../../tests/fixtures/tls/server.crt"));
        let (remaining, parsed) =
            x509_parser::parse_x509_certificate(&certificate).expect("x509-parser fixture");
        assert!(remaining.is_empty());

        assert_eq!(
            extract_spki_der(&certificate).expect("residue SPKI"),
            parsed.public_key().raw
        );
        assert_eq!(
            inspect_basic_constraints_ca(&certificate).expect("residue BasicConstraints"),
            BasicConstraintsFact::Absent
        );
        assert!(
            inspect_server_chain_metadata(&certificate)
                .expect("residue preflight")
                .subject_identity_present
        );
        let pin = inspect_pinned_leaf_shape(&certificate).expect("residue pin facts");
        assert_eq!(pin.extended_key_usage, ExtensionFact::Absent);
        assert_eq!(pin.key_usage, ExtensionFact::Absent);
        assert_eq!(
            pin.subject_alt_name,
            ExtensionFact::Present(SubjectAltNameFacts {
                dns_names: vec![b"localhost".as_slice()],
                ip_addresses: vec![[127, 0, 0, 1].as_slice()],
            })
        );

        for end in 0..certificate.len() {
            assert!(!x509_parser_accepts_one_complete_certificate(
                &certificate[..end]
            ));
            assert!(extract_spki_der(&certificate[..end]).is_err());
        }
    }

    #[test]
    fn generated_fixture_profiles_document_intentional_strictness() {
        let fixtures = [
            (
                include_bytes!("../../tests/fixtures/x509_adversarial/ca.crt").as_slice(),
                BasicConstraintsFact::Present { ca: true },
            ),
            (
                include_bytes!("../../tests/fixtures/x509_adversarial/allowed.crt").as_slice(),
                BasicConstraintsFact::Present { ca: false },
            ),
            (
                include_bytes!("../../tests/fixtures/x509_adversarial/blocked.crt").as_slice(),
                BasicConstraintsFact::Present { ca: false },
            ),
            (
                include_bytes!("../../tests/fixtures/x509_adversarial/wildcard.crt").as_slice(),
                BasicConstraintsFact::Present { ca: false },
            ),
        ];

        for (pem, basic_constraints) in fixtures {
            let certificate = first_pem_certificate(pem);
            assert!(x509_parser_accepts_one_complete_certificate(&certificate));
            assert!(extract_spki_der(&certificate).is_ok());
            assert_eq!(
                inspect_basic_constraints_ca(&certificate).expect("root facts"),
                basic_constraints
            );
            assert!(inspect_server_chain_metadata(&certificate).is_ok());
            expect_error(
                inspect_pinned_leaf_shape(&certificate),
                DerErrorClass::UnknownCritical,
            );
        }
    }

    #[test]
    fn differential_divergences_are_narrow_and_explained() {
        let canonical = default_certificate(None);
        assert!(x509_parser_accepts_one_complete_certificate(&canonical));
        assert!(extract_spki_der(&canonical).is_ok());

        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(!x509_parser_accepts_one_complete_certificate(&trailing));
        expect_error(extract_spki_der(&trailing), DerErrorClass::EmptyOrTrailing);

        let san = extension(
            OID_SUBJECT_ALT_NAME,
            None,
            &sequence(vec![tlv(0x82, b"example.com")]),
        );
        let duplicate_extension = default_certificate(Some(vec![san.clone(), san]));
        assert!(x509_parser_accepts_one_complete_certificate(
            &duplicate_extension
        ));
        expect_error(
            inspect_pinned_leaf_shape(&duplicate_extension),
            DerErrorClass::DuplicateExtension,
        );

        let unknown_critical =
            default_certificate(Some(vec![extension(&[0x2a, 0x03, 0x04], Some(true), &[])]));
        assert!(x509_parser_accepts_one_complete_certificate(
            &unknown_critical
        ));
        expect_error(
            inspect_pinned_leaf_shape(&unknown_critical),
            DerErrorClass::UnknownCritical,
        );

        let spki = subject_public_key_info(&[1, 2, 3]);
        let mut malformed_spki = certificate(
            &[1],
            default_validity(),
            common_name(TAG_UTF8_STRING, b"example.com"),
            spki.clone(),
            None,
            &[0, 1],
        );
        let spki_offset = malformed_spki
            .windows(spki.len())
            .position(|window| window == spki)
            .expect("SPKI fixture location");
        malformed_spki[spki_offset] = TAG_SEQUENCE ^ 0x20;
        // Divergence: x509-parser 0.18 (asn1-rs) tolerates a SEQUENCE whose
        // constructed bit is cleared and still yields one complete
        // certificate; DER requires the bit (X.690 8.1.2.5), so the pinned
        // parser refuses the SPKI with `ConstructedBit`.
        assert!(x509_parser_accepts_one_complete_certificate(
            &malformed_spki
        ));
        expect_error(
            extract_spki_der(&malformed_spki),
            DerErrorClass::ConstructedBit,
        );
    }
