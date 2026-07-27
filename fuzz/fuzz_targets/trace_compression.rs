#![no_main]

//! Bounded differential target for the owned trace LZ4 block experiment.
//!
//! The trace format uses a four-byte little-endian output-size prefix followed
//! by one independent LZ4 block. Frames, dictionaries, and LZ4-native checksums
//! are outside this target because the persisted trace contract rejects them.

use asupersync::trace::lz4_harness;
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_COMPRESSED_BYTES: usize = 1024 * 1024;
const MAX_FUZZ_DECOMPRESSED_BYTES: usize = 1024 * 1024;
const MAX_FUZZ_PAYLOAD_BYTES: usize = 256 * 1024;
const MAX_FUZZ_ENCODED_BYTES: usize = 512 * 1024;
const MAX_EXPANSION_RATIO: usize = 256;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_COMPRESSED_BYTES {
        return;
    }

    let owned = lz4_harness::decode(
        data,
        MAX_FUZZ_COMPRESSED_BYTES,
        MAX_FUZZ_DECOMPRESSED_BYTES,
        MAX_EXPANSION_RATIO,
    );
    if let Ok(decoded) = &owned {
        assert!(decoded.len() <= MAX_FUZZ_DECOMPRESSED_BYTES);
        let incumbent = lz4_flex::decompress_size_prepended(data)
            .expect("every block accepted by the owned decoder must decode with the incumbent");
        assert_eq!(
            incumbent, *decoded,
            "owned and incumbent decoders diverged on an accepted block"
        );
    }

    if data.len() <= MAX_FUZZ_PAYLOAD_BYTES {
        let owned_encoded =
            lz4_harness::encode(data, MAX_FUZZ_PAYLOAD_BYTES, MAX_FUZZ_ENCODED_BYTES)
                .expect("the fuzz payload and encoded ceilings must admit every bounded payload");
        let owned_encoded_again =
            lz4_harness::encode(data, MAX_FUZZ_PAYLOAD_BYTES, MAX_FUZZ_ENCODED_BYTES)
                .expect("deterministic re-encoding must remain within the same ceilings");
        assert_eq!(owned_encoded, owned_encoded_again);

        let owned_roundtrip = lz4_harness::decode(
            &owned_encoded,
            MAX_FUZZ_ENCODED_BYTES,
            MAX_FUZZ_PAYLOAD_BYTES,
            MAX_EXPANSION_RATIO,
        )
        .expect("owned encoder output must decode under the same bounded contract");
        assert_eq!(owned_roundtrip, data);
        assert_eq!(
            lz4_flex::decompress_size_prepended(&owned_encoded)
                .expect("incumbent must decode owned output"),
            data
        );

        let incumbent_encoded = lz4_flex::compress_prepend_size(data);
        assert_eq!(
            lz4_harness::decode(
                &incumbent_encoded,
                MAX_FUZZ_ENCODED_BYTES,
                MAX_FUZZ_PAYLOAD_BYTES,
                MAX_EXPANSION_RATIO,
            )
            .expect("owned decoder must accept current incumbent output"),
            data
        );
    }

    if data.len() >= 4 {
        let mut mutated = data.to_vec();
        for prefix in [0_u32, u32::MAX] {
            mutated[..4].copy_from_slice(&prefix.to_le_bytes());
            if let Ok(decoded) = lz4_harness::decode(
                &mutated,
                MAX_FUZZ_COMPRESSED_BYTES,
                MAX_FUZZ_DECOMPRESSED_BYTES,
                MAX_EXPANSION_RATIO,
            ) {
                assert!(decoded.len() <= MAX_FUZZ_DECOMPRESSED_BYTES);
            }
        }
    }
});
