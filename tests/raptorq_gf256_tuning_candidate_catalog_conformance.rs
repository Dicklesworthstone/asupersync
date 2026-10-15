//! Conformance contract for `gf256_tuning_candidate_catalog()` and its
//! cross-consistency with `gf256_profile_pack_catalog()`.
//!
//! Background (bd-3uox5 — RFC6330 conformance/optimization program, AC7/AC8):
//! The GF(256) dual-kernel runtime dispatch is governed by two deterministic
//! static catalogs:
//!   * the *tuning candidate catalog* — every (tile, unroll, prefetch, fusion)
//!     point the offline tuner explored, and
//!   * the *profile-pack catalog* — the per-architecture pack that names which
//!     single candidate was *selected* and which were *rejected*.
//!
//! For deterministic, replayable offline tuning these two data sources must be
//! mutually consistent: every pack reference must resolve into the candidate
//! catalog (with matching architecture), every catalog candidate must be
//! referenced exactly once, and the human-readable `candidate_id` string must
//! agree with the structured numeric tuning fields it claims to encode.
//!
//! `gf256_tuning_candidate_catalog()` carried zero coverage prior to this file;
//! `gf256_profile_pack_catalog()` was exercised elsewhere but the *cross-link*
//! between the two catalogs was not pinned anywhere. These tests are additive,
//! oracle-free (every assertion is derived from the data's own internal
//! structure), deterministic, and require no cargo features.

use asupersync::raptorq::gf256::{
    Gf256ArchitectureClass, Gf256ProfilePackId, Gf256TuningCandidateMetadata,
    gf256_profile_pack_catalog, gf256_tuning_candidate_catalog,
};
use std::collections::HashSet;

/// Canonical pairing between a profile-pack id and its architecture class.
fn arch_for_pack(pack: Gf256ProfilePackId) -> Gf256ArchitectureClass {
    match pack {
        Gf256ProfilePackId::ScalarConservativeV1 => Gf256ArchitectureClass::GenericScalar,
        Gf256ProfilePackId::X86Avx2BalancedV1 => Gf256ArchitectureClass::X86Avx2,
        Gf256ProfilePackId::Aarch64NeonBalancedV1 => Gf256ArchitectureClass::Aarch64Neon,
    }
}

/// Parse the structured tuning parameters that a stable `candidate_id` encodes.
///
/// Identifiers follow the shape `<arch-prefix>-t<tile>-u<unroll>-pf<prefetch>-<fusion-shape>-v1`,
/// e.g. `x86-avx2-t32-u4-pf64-split-balanced-v1`. Returns `(tile, unroll,
/// prefetch, fusion_shape)`; the fusion shape itself may contain a hyphen.
fn parse_candidate_id(id: &str) -> (usize, usize, usize, String) {
    let tokens: Vec<&str> = id.split('-').collect();
    assert!(
        tokens.len() >= 5,
        "candidate_id `{id}` too short to encode tuning params"
    );
    assert_eq!(
        *tokens.last().expect("non-empty token list"),
        "v1",
        "candidate_id `{id}` must end with version token `v1`"
    );

    let digits = |tok: &str, prefix: &str| -> Option<usize> {
        let rest = tok.strip_prefix(prefix)?;
        if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
            rest.parse::<usize>().ok()
        } else {
            None
        }
    };

    let mut tile = None;
    let mut unroll = None;
    let mut prefetch = None;
    let mut pf_index = None;
    for (i, &tok) in tokens.iter().enumerate() {
        if let Some(v) = digits(tok, "pf") {
            prefetch = Some(v);
            pf_index = Some(i);
        } else if let Some(v) = digits(tok, "t") {
            tile = Some(v);
        } else if let Some(v) = digits(tok, "u") {
            unroll = Some(v);
        }
    }

    let tile = tile.unwrap_or_else(|| panic!("candidate_id `{id}` missing t<N> token"));
    let unroll = unroll.unwrap_or_else(|| panic!("candidate_id `{id}` missing u<N> token"));
    let prefetch = prefetch.unwrap_or_else(|| panic!("candidate_id `{id}` missing pf<N> token"));
    let pf_index = pf_index.expect("pf token index set when prefetch parsed");

    // Fusion shape is everything between the pf<N> token and the trailing `v1`.
    let fusion_tokens = &tokens[pf_index + 1..tokens.len() - 1];
    assert!(
        !fusion_tokens.is_empty(),
        "candidate_id `{id}` missing fusion-shape segment"
    );
    (tile, unroll, prefetch, fusion_tokens.join("-"))
}

#[test]
fn tuning_catalog_is_deterministic_nonempty_and_well_formed() {
    let a = gf256_tuning_candidate_catalog();
    let b = gf256_tuning_candidate_catalog();

    // Pure, deterministic accessor over `&'static` storage: identical contents
    // and the same backing array address across calls.
    assert_eq!(a, b, "catalog must be deterministic across calls");
    assert_eq!(
        a.as_ptr(),
        b.as_ptr(),
        "catalog must reference the same static storage"
    );

    assert!(!a.is_empty(), "catalog must not be empty");
    assert_eq!(
        a.len(),
        8,
        "catalog pins the 8-candidate offline-tuning exploration set"
    );

    for c in a {
        assert!(!c.candidate_id.is_empty(), "candidate_id must be non-empty");
        assert!(
            !c.fusion_shape.is_empty(),
            "fusion_shape must be non-empty for `{}`",
            c.candidate_id
        );
        assert!(
            c.tile_bytes > 0,
            "tile_bytes must be positive for `{}`",
            c.candidate_id
        );
        assert!(
            c.unroll > 0,
            "unroll must be positive for `{}`",
            c.candidate_id
        );
        assert!(
            c.candidate_id.ends_with("-v1"),
            "candidate_id `{}` must carry the `-v1` version suffix",
            c.candidate_id
        );
    }
}

#[test]
fn tuning_catalog_candidate_ids_are_unique() {
    let catalog = gf256_tuning_candidate_catalog();
    let mut ids = HashSet::new();
    for c in catalog {
        assert!(
            ids.insert(c.candidate_id),
            "duplicate candidate_id `{}` in tuning catalog",
            c.candidate_id
        );
    }
    assert_eq!(
        ids.len(),
        catalog.len(),
        "unique candidate_id count must equal catalog length"
    );
}

/// Headline metamorphic invariant: the stable string identifier and the
/// structured numeric fields it claims to encode must agree, entry by entry.
#[test]
fn candidate_id_string_encodes_structured_tuning_fields() {
    for c in gf256_tuning_candidate_catalog() {
        let (tile, unroll, prefetch, fusion) = parse_candidate_id(c.candidate_id);
        assert_eq!(
            tile, c.tile_bytes,
            "tile in id `{}` disagrees with tile_bytes field",
            c.candidate_id
        );
        assert_eq!(
            unroll, c.unroll,
            "unroll in id `{}` disagrees with unroll field",
            c.candidate_id
        );
        assert_eq!(
            prefetch, c.prefetch_distance,
            "prefetch in id `{}` disagrees with prefetch_distance field",
            c.candidate_id
        );
        assert_eq!(
            fusion, c.fusion_shape,
            "fusion shape in id `{}` disagrees with fusion_shape field",
            c.candidate_id
        );
    }
}

#[test]
fn candidate_architecture_class_agrees_with_profile_pack() {
    for c in gf256_tuning_candidate_catalog() {
        assert_eq!(
            c.architecture_class,
            arch_for_pack(c.profile_pack),
            "candidate `{}` architecture_class disagrees with its profile_pack",
            c.candidate_id
        );
    }
}

/// Forward cross-link: every candidate a profile pack names (selected or
/// rejected) must resolve into the tuning catalog with matching arch + pack.
#[test]
fn profile_pack_candidate_references_resolve_into_tuning_catalog() {
    let catalog = gf256_tuning_candidate_catalog();
    let lookup = |id: &str| -> Option<&Gf256TuningCandidateMetadata> {
        catalog.iter().find(|c| c.candidate_id == id)
    };

    for pack in gf256_profile_pack_catalog() {
        let sel = lookup(pack.selected_tuning_candidate_id).unwrap_or_else(|| {
            panic!(
                "pack {:?} selected candidate `{}` missing from tuning catalog",
                pack.profile_pack, pack.selected_tuning_candidate_id
            )
        });
        assert_eq!(
            sel.profile_pack, pack.profile_pack,
            "selected candidate `{}` profile_pack mismatch",
            sel.candidate_id
        );
        assert_eq!(
            sel.architecture_class, pack.architecture_class,
            "selected candidate `{}` architecture_class mismatch",
            sel.candidate_id
        );

        for &rid in pack.rejected_tuning_candidate_ids {
            let rej = lookup(rid).unwrap_or_else(|| {
                panic!(
                    "pack {:?} rejected candidate `{rid}` missing from tuning catalog",
                    pack.profile_pack
                )
            });
            assert_eq!(
                rej.profile_pack, pack.profile_pack,
                "rejected candidate `{}` profile_pack mismatch",
                rej.candidate_id
            );
            assert_eq!(
                rej.architecture_class, pack.architecture_class,
                "rejected candidate `{}` architecture_class mismatch",
                rej.candidate_id
            );
        }
    }
}

/// Reverse cross-link / bijection: every catalog candidate is referenced by a
/// profile pack exactly once (no orphan candidate, no dangling reference, no
/// candidate counted twice). Together with the forward test this pins a clean
/// partition of the catalog into {selected} ∪ {rejected...} across all packs.
#[test]
fn every_catalog_candidate_is_referenced_exactly_once_by_a_profile_pack() {
    let packs = gf256_profile_pack_catalog();
    assert_eq!(
        packs.len(),
        3,
        "profile-pack catalog pins the 3 architecture-class packs"
    );
    let distinct_packs: HashSet<&str> = packs.iter().map(|p| p.profile_pack.as_str()).collect();
    assert_eq!(
        distinct_packs.len(),
        packs.len(),
        "profile-pack ids must be distinct"
    );

    let catalog = gf256_tuning_candidate_catalog();
    let catalog_ids: HashSet<&str> = catalog.iter().map(|c| c.candidate_id).collect();

    let mut referenced: HashSet<&str> = HashSet::new();
    let mut reference_count = 0usize;
    for pack in packs {
        assert!(
            referenced.insert(pack.selected_tuning_candidate_id),
            "candidate `{}` referenced as selected more than once across packs",
            pack.selected_tuning_candidate_id
        );
        reference_count += 1;
        for &rid in pack.rejected_tuning_candidate_ids {
            assert!(
                referenced.insert(rid),
                "candidate `{rid}` referenced more than once across packs"
            );
            reference_count += 1;
        }
    }

    assert_eq!(
        reference_count,
        catalog.len(),
        "total pack references must equal catalog size (no orphan, no double reference)"
    );
    assert_eq!(
        referenced, catalog_ids,
        "set of pack-referenced candidates must equal the full tuning catalog"
    );
}

#[test]
fn profile_pack_selected_is_disjoint_from_rejected_and_counts_partition() {
    let catalog = gf256_tuning_candidate_catalog();
    for pack in gf256_profile_pack_catalog() {
        assert!(
            !pack
                .rejected_tuning_candidate_ids
                .contains(&pack.selected_tuning_candidate_id),
            "pack {:?} lists its selected candidate `{}` as rejected",
            pack.profile_pack,
            pack.selected_tuning_candidate_id
        );

        let mut seen = HashSet::new();
        for &rid in pack.rejected_tuning_candidate_ids {
            assert!(
                seen.insert(rid),
                "pack {:?} repeats rejected candidate `{rid}`",
                pack.profile_pack
            );
        }

        let tagged = catalog
            .iter()
            .filter(|c| c.profile_pack == pack.profile_pack)
            .count();
        assert_eq!(
            tagged,
            1 + pack.rejected_tuning_candidate_ids.len(),
            "pack {:?}: catalog entries tagged with this pack must equal selected(1) + rejected({})",
            pack.profile_pack,
            pack.rejected_tuning_candidate_ids.len()
        );
    }
}
