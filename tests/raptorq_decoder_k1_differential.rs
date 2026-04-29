use std::collections::BTreeSet;

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::SystematicEncoder;
use raptorq::{
    Decoder as RaptorqRsDecoder, EncodingPacket as RaptorqRsEncodingPacket,
    ObjectTransmissionInformation as RaptorqRsObjectTransmissionInformation,
    PayloadId as RaptorqRsPayloadId,
};

fn make_source_data(symbol_size: usize) -> Vec<Vec<u8>> {
    vec![(0..symbol_size)
        .map(|idx| ((idx * 73 + 11) % 256) as u8)
        .collect()]
}

fn build_received_symbols(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    drop_indices: &[usize],
    repair_count: usize,
) -> Vec<ReceivedSymbol> {
    let dropped: BTreeSet<_> = drop_indices.iter().copied().collect();
    let mut received = decoder.constraint_symbols();

    for (esi, data) in source.iter().enumerate() {
        if !dropped.contains(&esi) {
            received.push(ReceivedSymbol::source(
                u32::try_from(esi).expect("source ESI must fit in u32"),
                data.clone(),
            ));
        }
    }

    let k_u32 = u32::try_from(source.len()).expect("K must fit in u32");
    for repair_offset in 0..repair_count {
        let esi = k_u32 + u32::try_from(repair_offset).expect("repair offset must fit in u32");
        let (cols, coefs) = decoder
            .repair_equation(esi)
            .unwrap_or_else(|err| panic!("repair equation for esi={esi} failed: {err:?}"));
        received.push(ReceivedSymbol::repair(
            esi,
            cols,
            coefs,
            encoder.repair_symbol(esi),
        ));
    }

    received
}

fn reference_decode_with_raptorq_rs(
    source: &[Vec<u8>],
    encoder: &SystematicEncoder,
    drop_indices: &[usize],
    repair_count: usize,
) -> Vec<u8> {
    let transfer_length = source
        .len()
        .checked_mul(source[0].len())
        .expect("transfer length overflow");
    let symbol_size =
        u16::try_from(source[0].len()).expect("symbol size must fit in u16 for raptorq-rs");
    let config =
        RaptorqRsObjectTransmissionInformation::new(transfer_length as u64, symbol_size, 1, 1, 1);
    let mut decoder = RaptorqRsDecoder::new(config);
    let dropped: BTreeSet<_> = drop_indices.iter().copied().collect();

    for (esi, data) in source.iter().enumerate() {
        if !dropped.contains(&esi) {
            let esi_u32 = u32::try_from(esi).expect("source ESI must fit in u32");
            let packet =
                RaptorqRsEncodingPacket::new(RaptorqRsPayloadId::new(0, esi_u32), data.clone());
            if let Some(decoded) = decoder.decode(packet) {
                return decoded;
            }
        }
    }

    let k_u32 = u32::try_from(source.len()).expect("K must fit in u32");
    for repair_offset in 0..repair_count {
        let esi = k_u32 + u32::try_from(repair_offset).expect("repair offset must fit in u32");
        let packet = RaptorqRsEncodingPacket::new(
            RaptorqRsPayloadId::new(0, esi),
            encoder.repair_symbol(esi),
        );
        if let Some(decoded) = decoder.decode(packet) {
            return decoded;
        }
    }

    panic!("raptorq-rs reference decode must succeed for the K=1 single-repair case");
}

#[test]
fn k1_single_repair_matches_raptorq_rs() {
    let k = 1usize;
    let symbol_size = 32usize;
    let seed = 0x6330_0001_u64;
    let drop_indices = [0usize];
    let repair_count = 1usize;

    let source = make_source_data(symbol_size);
    let encoder =
        SystematicEncoder::new(&source, symbol_size, seed).expect("encoder setup must succeed");
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let received = build_received_symbols(&decoder, &encoder, &source, &drop_indices, repair_count);

    let ours = decoder.decode(&received).unwrap_or_else(|err| {
        panic!("K=1 single-repair differential decode must succeed: {err:?}")
    });
    let reference =
        reference_decode_with_raptorq_rs(&source, &encoder, &drop_indices, repair_count);

    assert_eq!(
        ours.source.concat(),
        reference,
        "our decoder must match raptorq-rs for the degenerate K=1 single-repair case"
    );
    assert_eq!(
        ours.source, source,
        "a single repair packet must recover the original K=1 source symbol"
    );
}
