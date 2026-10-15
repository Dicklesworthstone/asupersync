//! RFC 6330 §5.3.5.2 degree generator — full-domain distribution proof.
//!
//! bd-3uox5 (RAPTORQ-RFC6330 conformance, Track-D property verification).
//!
//! The degree generator `Deg[v]` partitions the domain `v ∈ [0, 2²⁰)`
//! into 30 contiguous bands defined by the cumulative table `f[0..=30]`
//! (RFC 6330 §5.3.5.2, Table). Existing tests pin the *boundary* points
//! of each band (off-by-one drift). This test is stronger: it sweeps the
//! ENTIRE domain and verifies that the count of values mapping to each
//! degree `d` equals exactly `f[d] - f[d-1]`. That is a complete
//! conformance proof of the degree distribution — a single mis-placed
//! threshold anywhere in the table moves at least one value across a
//! band edge and trips the count.
//!
//! The `f` table below is transcribed directly from RFC 6330 §5.3.5.2
//! and serves as the independent golden source (the implementation's own
//! threshold table is a private module const).
//!
//! Repro: `cargo test --test raptorq_deg_full_distribution`

use asupersync::raptorq::rfc6330::deg;

/// RFC 6330 §5.3.5.2 cumulative degree thresholds f[0..=30].
/// `Deg[v] = j` for the unique j with `f[j-1] <= v < f[j]`.
const F: [u32; 31] = [
    0, 5243, 529531, 704294, 791675, 844104, 879057, 904023, 922747, 937311, 948962, 958494,
    966438, 973160, 978921, 983914, 988283, 992138, 995565, 998631, 1001391, 1003887, 1006157,
    1008229, 1010129, 1011876, 1013490, 1014983, 1016370, 1017662, 1048576,
];

const DOMAIN: u32 = 1 << 20; // 2^20 = 1048576 == f[30]

#[test]
fn deg_full_domain_distribution_matches_rfc_table() {
    // Sanity: the table is monotone strictly increasing and spans the
    // entire degree-generator domain.
    assert_eq!(F[0], 0, "f[0] must be 0");
    assert_eq!(F[30], DOMAIN, "f[30] must equal 2^20");
    for w in F.windows(2) {
        assert!(w[0] < w[1], "RFC f-table must be strictly increasing");
    }

    // Tally deg(v) across the whole domain.
    let mut counts = [0u32; 31]; // index = degree (1..=30)
    for v in 0..DOMAIN {
        let d = deg(v);
        assert!(
            (1..=30).contains(&d),
            "deg({v}) = {d} outside RFC range 1..=30"
        );
        counts[d] += 1;
    }

    // Each degree band must have exactly f[d] - f[d-1] members.
    let mut total = 0u32;
    for d in 1..=30usize {
        let expected = F[d] - F[d - 1];
        assert_eq!(
            counts[d],
            expected,
            "degree {d}: counted {} values, RFC band f[{d}]-f[{}]={expected}; \
             repro='cargo test --test raptorq_deg_full_distribution'",
            counts[d],
            d - 1
        );
        total += counts[d];
    }
    assert_eq!(
        total, DOMAIN,
        "all 2^20 domain values must be accounted for"
    );
}
