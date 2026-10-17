    use super::*;

    fn tape() -> IoTape {
        IoTape {
            events: vec![
                Event::Read {
                    capacity: 5,
                    bytes: b"secret"[..4].to_vec(),
                    error: None,
                },
                Event::Write {
                    length: 3,
                    slices: Some(vec![1, 0, 2]),
                    digest: zeroize::Zeroizing::new([42; 32]),
                    accepted: 2,
                    error: None,
                },
                Event::Flush(Some(IoFailure {
                    kind: io::ErrorKind::InvalidInput,
                    raw: None,
                })),
                Event::Shutdown(None),
            ],
            read_bytes: 4,
            write_bytes: 3,
            vectored: true,
        }
    }
    fn limits() -> IoTapeDecodeLimits {
        IoTapeDecodeLimits::new(4096, IoCaptureLimits::new(32, 1024, 1024, 16), 8192)
    }
    fn seal(bytes: &mut [u8]) {
        let body = bytes.len() - CHECKSUM;
        let hash = checksum(&bytes[..body]);
        bytes[body..].copy_from_slice(&hash);
    }

    #[test]
    fn canonical_io_tape_roundtrips_every_event_and_redacts_debug() {
        let encoded = tape().to_canonical_bytes(4096).unwrap();
        let decoded = IoTape::from_canonical_bytes(encoded.as_ref(), limits()).unwrap();
        assert_eq!(
            (
                decoded.operations(),
                decoded.read_bytes(),
                decoded.write_bytes()
            ),
            (4, 4, 3)
        );
        assert_eq!(
            decoded.to_canonical_bytes(4096).unwrap().as_ref(),
            encoded.as_ref()
        );
        assert!(!format!("{decoded:?} {encoded:?}").contains("secr"));
        assert!(matches!(
            tape().to_canonical_bytes(1),
            Err(IoTapeError::Limit("encoded bytes"))
        ));
    }

    #[test]
    fn every_truncation_and_single_byte_mutation_is_rejected() {
        let encoded = tape().to_canonical_bytes(4096).unwrap();
        for end in 0..encoded.as_ref().len() {
            assert!(IoTape::from_canonical_bytes(&encoded.as_ref()[..end], limits()).is_err());
        }
        for index in 0..encoded.as_ref().len() {
            let mut changed = encoded.as_ref().to_vec();
            changed[index] ^= 1;
            assert!(
                IoTape::from_canonical_bytes(&changed, limits()).is_err(),
                "offset={index}"
            );
        }
    }

    #[test]
    fn recomputed_checksum_does_not_admit_invalid_progress_or_extra_data() {
        let encoded = tape().to_canonical_bytes(4096).unwrap();
        let start = FIXED_HEADER + std::env::consts::OS.len();
        let mut changed = encoded.as_ref().to_vec();
        changed[start + 1..start + 9].copy_from_slice(&1u64.to_le_bytes()); // capacity < returned bytes
        seal(&mut changed);
        assert!(matches!(
            IoTape::from_canonical_bytes(&changed, limits()),
            Err(IoTapeError::Invalid("read count"))
        ));
        let mut extra = encoded.as_ref()[..encoded.as_ref().len() - CHECKSUM].to_vec();
        extra.push(0);
        extra.extend_from_slice(&[0; CHECKSUM]);
        seal(&mut extra);
        assert!(matches!(
            IoTape::from_canonical_bytes(&extra, limits()),
            Err(IoTapeError::Invalid("trailing bytes"))
        ));
    }

    #[test]
    fn logical_storage_and_declared_event_limits_are_enforced() {
        let encoded = tape().to_canonical_bytes(4096).unwrap();
        let mut bounded = limits();
        bounded.capture.max_operations = 3;
        assert!(matches!(
            IoTape::from_canonical_bytes(encoded.as_ref(), bounded),
            Err(IoTapeError::Limit("operations"))
        ));
        let mut bounded = limits();
        bounded.max_decoded_bytes = 1;
        assert!(matches!(
            IoTape::from_canonical_bytes(encoded.as_ref(), bounded),
            Err(IoTapeError::Limit("decoded bytes"))
        ));
        let mut bounded = limits();
        bounded.capture.max_vectored_slices = 2;
        assert!(matches!(
            IoTape::from_canonical_bytes(encoded.as_ref(), bounded),
            Err(IoTapeError::Limit("vectored slices"))
        ));
    }

    #[test]
    fn native_errors_cannot_be_reinterpreted_under_a_different_os_tag() {
        // File-not-found on both POSIX and Windows. EINVAL's POSIX value (22)
        // is not a portable Windows error and may map to an unexportable kind.
        let error = io::Error::from_raw_os_error(2);
        let tape = IoTape {
            events: vec![Event::Flush(Some(IoFailure::capture(&error)))],
            read_bytes: 0,
            write_bytes: 0,
            vectored: false,
        };
        let encoded = tape.to_canonical_bytes(4096).unwrap();
        let decoded = IoTape::from_canonical_bytes(encoded.as_ref(), limits()).unwrap();
        assert_eq!(
            decoded.to_canonical_bytes(4096).unwrap().as_ref(),
            encoded.as_ref()
        );
        let mut changed = encoded.as_ref().to_vec();
        changed[FIXED_HEADER] = if changed[FIXED_HEADER] == b'x' {
            b'y'
        } else {
            b'x'
        };
        seal(&mut changed);
        assert!(matches!(
            IoTape::from_canonical_bytes(&changed, limits()),
            Err(IoTapeError::PlatformMismatch)
        ));
    }
