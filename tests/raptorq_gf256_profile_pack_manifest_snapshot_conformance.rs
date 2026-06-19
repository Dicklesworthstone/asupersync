//! Conformance contract for the public `gf256_profile_pack_manifest_snapshot()`
//! aggregator.
//!
//! Background (bd-3uox5 — RFC6330 conformance/optimization program, AC7/AC8):
//! The GF(256) dual-kernel runtime dispatch publishes a single deterministic
//! *manifest snapshot* that aggregates four independently-accessible views of
//! the active tuning governance:
//!   * the runtime dual-kernel **policy** selection (`active_policy`),
//!   * the effective **profile-pack metadata** for that policy,
//!   * the static **profile-pack catalog** and **tuning-candidate catalog**, and
//!   * deterministic build-target **environment metadata**.
//!
//! The no-argument public entry point `gf256_profile_pack_manifest_snapshot()`
//! wires the *runtime-detected* policy (`dual_policy()`) and active kernel
//! (`dispatch().kind`) into that aggregate. Its private parameterized sibling
//! `_for(policy, kernel)` is exercised by in-module unit tests, but the public
//! aggregator and — crucially — its *cross-consistency with the standalone
//! accessors it claims to embed* carried zero external coverage prior to this
//! file.
//!
//! These tests are additive, oracle-free (every assertion derives from the
//! data's own internal structure or an independent standalone accessor used as
//! a differential oracle), deterministic, and require no cargo features.

use asupersync::raptorq::gf256::{
    Gf256ArchitectureClass, Gf256ProfilePackId, active_kernel, dual_kernel_policy_snapshot,
    gf256_profile_pack_catalog, gf256_profile_pack_manifest_snapshot,
    gf256_tuning_candidate_catalog,
};

/// Canonical pairing between a profile-pack id and its architecture class,
/// mirroring the static catalog wiring. Used as an independent oracle.
fn arch_for_pack(pack: Gf256ProfilePackId) -> Gf256ArchitectureClass {
    match pack {
        Gf256ProfilePackId::ScalarConservativeV1 => Gf256ArchitectureClass::GenericScalar,
        Gf256ProfilePackId::X86Avx2BalancedV1 => Gf256ArchitectureClass::X86Avx2,
        Gf256ProfilePackId::Aarch64NeonBalancedV1 => Gf256ArchitectureClass::Aarch64Neon,
    }
}

/// The manifest is a pure function of process-stable runtime detection plus
/// `&'static` catalogs: repeated calls must be byte-equal, and the embedded
/// catalog slices must point at identical static storage across calls.
#[test]
fn manifest_snapshot_is_deterministic_and_pure() {
    let a = gf256_profile_pack_manifest_snapshot();
    let b = gf256_profile_pack_manifest_snapshot();

    assert_eq!(a, b, "manifest snapshot must be deterministic across calls");

    assert_eq!(
        a.profile_pack_catalog.as_ptr(),
        b.profile_pack_catalog.as_ptr(),
        "profile-pack catalog must reference identical static storage across calls"
    );
    assert_eq!(
        a.tuning_candidate_catalog.as_ptr(),
        b.tuning_candidate_catalog.as_ptr(),
        "tuning-candidate catalog must reference identical static storage across calls"
    );
}

/// The manifest schema marker is a pinned golden and is a *distinct role* from
/// the embedded policy snapshot's profile-schema marker.
#[test]
fn manifest_schema_version_is_pinned_and_distinct_from_policy_schema() {
    let m = gf256_profile_pack_manifest_snapshot();

    assert_eq!(
        m.schema_version, "raptorq-gf256-profile-pack-manifest-v5",
        "manifest schema-version marker is a pinned golden"
    );
    assert_eq!(
        m.active_policy.profile_schema_version, "raptorq-gf256-profile-pack-v5",
        "embedded policy snapshot carries the policy (not manifest) schema marker"
    );
    assert_ne!(
        m.schema_version, m.active_policy.profile_schema_version,
        "manifest and policy schema markers must denote distinct roles"
    );
}

/// Faithful-aggregator invariant: the catalogs the manifest embeds must equal
/// — and share static storage with — the standalone public accessors. The
/// manifest must not carry a divergent or copied catalog.
#[test]
fn manifest_embeds_canonical_standalone_catalogs() {
    let m = gf256_profile_pack_manifest_snapshot();

    assert_eq!(
        m.profile_pack_catalog,
        gf256_profile_pack_catalog(),
        "embedded profile-pack catalog must equal the standalone accessor"
    );
    assert_eq!(
        m.profile_pack_catalog.as_ptr(),
        gf256_profile_pack_catalog().as_ptr(),
        "embedded profile-pack catalog must share the standalone static storage"
    );

    assert_eq!(
        m.tuning_candidate_catalog,
        gf256_tuning_candidate_catalog(),
        "embedded tuning catalog must equal the standalone accessor"
    );
    assert_eq!(
        m.tuning_candidate_catalog.as_ptr(),
        gf256_tuning_candidate_catalog().as_ptr(),
        "embedded tuning catalog must share the standalone static storage"
    );

    // Tie back to the catalog cardinalities pinned by the catalog conformance:
    // 3 architecture-class packs, 8 explored tuning candidates.
    assert_eq!(
        m.profile_pack_catalog.len(),
        3,
        "manifest must embed the 3-pack profile catalog"
    );
    assert_eq!(
        m.tuning_candidate_catalog.len(),
        8,
        "manifest must embed the 8-candidate tuning catalog"
    );
}

/// The manifest's active policy view must equal the independently-obtained
/// standalone policy snapshot, and its kernel must equal the runtime-selected
/// active kernel. Both are differential oracles built from the same detection.
#[test]
fn manifest_active_policy_matches_standalone_policy_snapshot() {
    let m = gf256_profile_pack_manifest_snapshot();

    assert_eq!(
        m.active_policy,
        dual_kernel_policy_snapshot(),
        "manifest active_policy must equal the standalone policy snapshot"
    );
    assert_eq!(
        m.active_policy.kernel,
        active_kernel(),
        "manifest active_policy.kernel must equal the runtime-selected active kernel"
    );
}

/// The manifest derives its `active_profile_metadata` and `active_policy` from
/// the *same* detected policy. Every field the policy contributes to both
/// projections must therefore agree, regardless of any environment overrides
/// (these fields are copied verbatim from the shared policy in both paths).
#[test]
fn manifest_active_profile_metadata_is_coherent_with_active_policy() {
    let m = gf256_profile_pack_manifest_snapshot();
    let meta = m.active_profile_metadata;
    let pol = m.active_policy;

    // Pack identity (the metadata is looked up by the policy's pack id).
    assert_eq!(
        meta.profile_pack, pol.profile_pack,
        "active profile metadata pack must match the active policy pack"
    );

    // Verbatim policy-derived fields.
    assert_eq!(
        meta.tuning_corpus_id, pol.tuning_corpus_id,
        "tuning_corpus_id disagrees between metadata and policy"
    );
    assert_eq!(
        meta.selected_tuning_candidate_id, pol.selected_tuning_candidate_id,
        "selected_tuning_candidate_id disagrees between metadata and policy"
    );
    assert_eq!(
        meta.rejected_tuning_candidate_ids, pol.rejected_tuning_candidate_ids,
        "rejected_tuning_candidate_ids disagree between metadata and policy"
    );
    assert_eq!(
        meta.mul_min_total, pol.mul_min_total,
        "mul_min_total disagrees"
    );
    assert_eq!(
        meta.mul_max_total, pol.mul_max_total,
        "mul_max_total disagrees"
    );
    assert_eq!(
        meta.addmul_min_total, pol.addmul_min_total,
        "addmul_min_total disagrees"
    );
    assert_eq!(
        meta.addmul_max_total, pol.addmul_max_total,
        "addmul_max_total disagrees"
    );
    assert_eq!(
        meta.addmul_min_lane, pol.addmul_min_lane,
        "addmul_min_lane disagrees"
    );
    assert_eq!(
        meta.max_lane_ratio, pol.max_lane_ratio,
        "max_lane_ratio disagrees"
    );
    assert_eq!(
        meta.replay_pointer, pol.replay_pointer,
        "replay_pointer disagrees"
    );
    assert_eq!(
        meta.command_bundle, pol.command_bundle,
        "command_bundle disagrees"
    );

    // Decision-contract provenance the policy snapshot copies from the
    // effective profile metadata.
    assert_eq!(
        meta.decision_artifact_id, pol.decision_artifact_id,
        "decision_artifact_id disagrees"
    );
    assert_eq!(
        meta.decision_role, pol.decision_role,
        "decision_role disagrees"
    );
    assert_eq!(
        meta.decision_evidence_status, pol.decision_evidence_status,
        "decision_evidence_status disagrees"
    );

    // The profile metadata carries the policy (not manifest) schema marker.
    assert_eq!(
        meta.schema_version, pol.profile_schema_version,
        "profile metadata schema marker must match the policy schema marker"
    );
}

/// Headline metamorphic invariant for the optional active selection: the
/// `active_selected_tuning_candidate` resolves *exactly* the catalog lookup of
/// the active policy's selected candidate id (Some iff the id is a catalog
/// member). In the default no-override runtime environment the active
/// selection is always a catalog member, so it additionally resolves to a
/// coherent `Some`.
#[test]
fn manifest_active_selected_candidate_resolves_policy_selection() {
    let m = gf256_profile_pack_manifest_snapshot();
    let selected_id = m.active_policy.selected_tuning_candidate_id;

    // Env-robust: the Option mirrors the catalog lookup of the selection.
    let expected = m
        .tuning_candidate_catalog
        .iter()
        .find(|c| c.candidate_id == selected_id);
    assert_eq!(
        m.active_selected_tuning_candidate.map(|c| c.candidate_id),
        expected.map(|c| c.candidate_id),
        "active_selected_tuning_candidate must resolve the active selection from the catalog"
    );

    // Default-environment characterization: the selection is a catalog member.
    let candidate = m
        .active_selected_tuning_candidate
        .expect("active selected tuning candidate must resolve in the default environment");
    assert_eq!(
        candidate.candidate_id, selected_id,
        "resolved candidate id must equal the active policy selection"
    );
    assert!(
        m.tuning_candidate_catalog.iter().any(|c| c == candidate),
        "resolved candidate must be a member of the embedded tuning catalog"
    );
    assert_eq!(
        candidate.profile_pack, m.active_policy.profile_pack,
        "resolved candidate pack must match the active policy pack"
    );
    assert_eq!(
        candidate.architecture_class,
        arch_for_pack(candidate.profile_pack),
        "resolved candidate architecture_class must follow its pack's canonical pairing"
    );
}

/// The active profile metadata's pack must be drawn from the embedded
/// profile-pack catalog, and its architecture class must match both the catalog
/// entry and the canonical pairing for that pack.
#[test]
fn manifest_active_profile_pack_is_a_catalog_member() {
    let m = gf256_profile_pack_manifest_snapshot();
    let active_pack = m.active_profile_metadata.profile_pack;

    let entry = m
        .profile_pack_catalog
        .iter()
        .find(|p| p.profile_pack == active_pack)
        .expect("active profile pack must be present in the embedded profile-pack catalog");

    assert_eq!(
        entry.architecture_class, m.active_profile_metadata.architecture_class,
        "catalog entry architecture_class must match active profile metadata"
    );
    assert_eq!(
        entry.architecture_class,
        arch_for_pack(active_pack),
        "active pack must follow its canonical architecture pairing"
    );
}

/// Environment metadata must faithfully reflect the compile/run target: the
/// architecture and OS strings equal `std::env::consts`, and endianness /
/// pointer width agree with the running target the test binary executes on.
#[test]
fn manifest_environment_metadata_matches_compile_target() {
    let env = gf256_profile_pack_manifest_snapshot().environment_metadata;

    assert_eq!(
        env.target_arch,
        std::env::consts::ARCH,
        "target_arch must equal std::env::consts::ARCH"
    );
    assert_eq!(
        env.target_os,
        std::env::consts::OS,
        "target_os must equal std::env::consts::OS"
    );
    assert!(!env.target_arch.is_empty(), "target_arch must be non-empty");
    assert!(!env.target_os.is_empty(), "target_os must be non-empty");

    assert!(
        matches!(env.target_endian, "little" | "big"),
        "target_endian must be `little` or `big`, got {:?}",
        env.target_endian
    );
    assert!(
        matches!(env.target_pointer_width_bits, 16 | 32 | 64 | 128),
        "target_pointer_width_bits must be a standard width, got {}",
        env.target_pointer_width_bits
    );

    // The test binary runs on the same target it was compiled for, so the
    // reported width/endianness must match the runtime characteristics.
    assert_eq!(
        env.target_pointer_width_bits,
        usize::BITS as usize,
        "pointer width must match the running target"
    );
    assert_eq!(
        env.target_endian,
        if cfg!(target_endian = "little") {
            "little"
        } else {
            "big"
        },
        "endianness must match the running target"
    );
}
