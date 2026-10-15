#[cfg(feature = "compression")]
use asupersync::net::atp::transport_common::PreEncodeCompression;
#[cfg(not(feature = "compression"))]
use asupersync::net::atp::transport_common::{CompressionAlgorithm, CompressionDescriptor};
use asupersync::net::atp::transport_common::{
    CompressionError, CompressionPolicy, decompress_pre_encoded, maybe_compress_pre_encode,
};

#[cfg(feature = "compression")]
fn accepting_policy() -> CompressionPolicy {
    CompressionPolicy {
        min_input_bytes: 1,
        min_savings_bytes: 1,
        min_savings_bps: 1,
        ..CompressionPolicy::default()
    }
}

#[cfg(not(feature = "compression"))]
fn feature_disabled_policy() -> CompressionPolicy {
    CompressionPolicy {
        min_input_bytes: 1,
        min_savings_bytes: 1,
        min_savings_bps: 1,
        ..CompressionPolicy::default()
    }
}

#[cfg(feature = "compression")]
#[test]
fn restore_rejects_inflated_output_past_limit_even_when_descriptor_claims_small() {
    let raw = b"streaming output limit\n".repeat(256);
    let PreEncodeCompression::Compressed {
        mut descriptor,
        bytes,
    } = maybe_compress_pre_encode(&raw, accepting_policy()).expect("compress")
    else {
        panic!("compressible data should be encoded");
    };
    descriptor.original_size = 1;

    let err = decompress_pre_encoded(descriptor, &bytes, 1024).expect_err("limit exceeded");
    match err {
        CompressionError::OutputTooLarge { limit, actual } => {
            assert_eq!(limit, 1024);
            assert!(actual > limit);
        }
        other => panic!("expected output limit error, got {other:?}"),
    }
}

#[cfg(not(feature = "compression"))]
#[test]
fn compression_attempt_reports_feature_disabled() {
    let raw = b"feature disabled\n".repeat(128);

    let err =
        maybe_compress_pre_encode(&raw, feature_disabled_policy()).expect_err("feature disabled");
    assert_eq!(
        err,
        CompressionError::FeatureDisabled(CompressionAlgorithm::Gzip)
    );
}

#[cfg(not(feature = "compression"))]
#[test]
fn restore_reports_feature_disabled_after_descriptor_checks() {
    let descriptor = CompressionDescriptor {
        algorithm: CompressionAlgorithm::Gzip,
        original_size: 4,
        encoded_size: 4,
    };

    let err = decompress_pre_encoded(descriptor, b"gzip", 4).expect_err("feature disabled");
    assert_eq!(
        err,
        CompressionError::FeatureDisabled(CompressionAlgorithm::Gzip)
    );
}
