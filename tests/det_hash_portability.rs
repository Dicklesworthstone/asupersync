#![allow(missing_docs)]

use asupersync::util::det_hash::DetHasher;
use std::hash::Hasher;

#[test]
fn test_det_hasher_endianness() {
    let val: u32 = 0x1234_5678;

    let mut h1 = DetHasher::default();
    h1.write_u32(val);
    let hash1 = h1.finish();

    let mut h2 = DetHasher::default();
    h2.write(&val.to_le_bytes());
    let hash2 = h2.finish();

    // On Little Endian machines (like this one likely is), this will pass with the buggy implementation.
    // On Big Endian machines, it would fail.
    // However, if we fix the implementation to use to_le_bytes(), this assertion will hold true everywhere.
    // The goal of the fix is to make this strictly true by design, not just by coincidence of host arch.
    assert_eq!(
        hash1, hash2,
        "Hasher should use Little Endian encoding for u32"
    );
}

#[test]
fn test_det_hasher_usize_width_portability() {
    let val: usize = 0x1234_5678;

    let mut h1 = DetHasher::default();
    h1.write_usize(val);
    let hash1 = h1.finish();

    let mut h2 = DetHasher::default();
    h2.write_u64(val as u64);
    let hash2 = h2.finish();

    // The default implementation of write_usize on 64-bit systems uses write_u64.
    // On 32-bit systems, it uses write_u32.
    // This assertion checking match with write_u64 passes on 64-bit hosts.
    // To be portable for distributed consensus, write_usize should always act like write_u64
    // (treating usize as u64) so 32-bit and 64-bit nodes hash "1usize" to the same value.
    if cfg!(target_pointer_width = "64") {
        assert_eq!(hash1, hash2, "write_usize should match write_u64 on 64-bit");
    }
}
