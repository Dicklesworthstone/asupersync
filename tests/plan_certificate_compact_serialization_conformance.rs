//! Conformance for the compact `RewriteCertificate` wire artifact (tjrmwz.2).
//!
//! The bead makes the rewrite certificate a versioned **public artifact**:
//! `RewriteCertificate::compact()` strips the human-readable detail strings and
//! produces a fixed-width [`CompactCertificate`] suitable for serialization and
//! size-bounded storage (header + 9 bytes/step). The full-form certificate is
//! covered by `plan_certificate_format_golden.rs` and the rewrite-ladder
//! contracts, but the compact serialization surface — `compact()`,
//! `CompactCertificate`, `byte_size_bound()`, `is_within_linear_bound()`, and
//! the `CompactStep` encoding — had **zero external coverage**. This pins it
//! oracle-free: every claim is a structural relationship between the full
//! certificate, the DAG it certifies, and the compact form.
//!
//! Construction mirrors the sibling rewrite-savings contract: build a real
//! `PlanDag`, run `apply_rewrites_certified(conservative, MENU)` to get a
//! genuine certificate, then compact it. No `Cx`, no execution, no wall-clock.

use asupersync::plan::certificate::{CertificateVersion, CompactCertificate, CompactStep};
use asupersync::plan::{
    PlanBuilder, PlanDag, RewritePolicy, RewriteReport, RewriteRule, capture as capture_dag,
};

/// The full rule menu the certified ladder offers; the policy gates which fire.
/// Mirrors `REWRITE_RULE_MENU` in `src/plan/execute.rs`.
const MENU: [RewriteRule; 6] = [
    RewriteRule::JoinAssoc,
    RewriteRule::RaceAssoc,
    RewriteRule::JoinCommute,
    RewriteRule::RaceCommute,
    RewriteRule::TimeoutMin,
    RewriteRule::DedupRaceJoin,
];

fn fired(report: &RewriteReport, rule: RewriteRule) -> bool {
    report.steps().iter().any(|s| s.rule == rule)
}

/// `join(join(a, b), c)` — flattens under `JoinAssoc`, producing a genuine
/// non-identity certificate with at least one step.
fn nested_join_dag() -> PlanDag {
    capture_dag(|b: &mut PlanBuilder| {
        let l0 = b.leaf("l0");
        let l1 = b.leaf("l1");
        let l2 = b.leaf("l2");
        let inner = b.join([l0, l1]);
        b.join([inner, l2])
    })
    .expect("valid nested-join dag")
}

#[test]
fn compact_mirrors_the_full_certificate_header() {
    let mut dag = nested_join_dag();
    let (report, cert) = dag.apply_rewrites_certified(RewritePolicy::conservative(), &MENU);
    assert!(
        fired(&report, RewriteRule::JoinAssoc),
        "JoinAssoc must fire"
    );
    assert!(
        !cert.is_identity(),
        "a fired rule => non-identity certificate"
    );

    let compact = cert
        .compact()
        .expect("small node counts never overflow u32");

    // The compact header carries the identity-relevant fields verbatim.
    assert_eq!(compact.version, cert.version, "version preserved");
    assert_eq!(
        compact.before_hash, cert.before_hash,
        "before-hash preserved"
    );
    assert_eq!(compact.after_hash, cert.after_hash, "after-hash preserved");
    assert_eq!(
        compact.before_node_count as usize, cert.before_node_count,
        "before node count preserved"
    );
    assert_eq!(
        compact.after_node_count as usize, cert.after_node_count,
        "after node count preserved"
    );

    // The compact step list has exactly one entry per fired rewrite step — the
    // fired-rule list survives compaction (AC1's queryable certificate).
    assert_eq!(
        compact.steps.len(),
        cert.steps.len(),
        "every certified step survives compaction"
    );
    assert_eq!(
        compact.steps.len(),
        report.steps().len(),
        "compact step count matches the rewrite report's fired-step count"
    );
    assert!(
        !compact.steps.is_empty(),
        "a non-identity rewrite has >= 1 step"
    );
}

#[test]
fn byte_size_bound_is_header_plus_nine_per_step() {
    // The documented wire layout: a fixed 81-byte header plus 9 bytes per step.
    assert_eq!(CompactCertificate::HEADER_SIZE, 81, "fixed header size");
    assert_eq!(CompactStep::WIRE_SIZE, 9, "per-step wire size");

    let mut dag = nested_join_dag();
    let (_report, cert) = dag.apply_rewrites_certified(RewritePolicy::conservative(), &MENU);
    let compact = cert.compact().expect("compaction succeeds");

    assert_eq!(
        compact.byte_size_bound(),
        CompactCertificate::HEADER_SIZE + CompactStep::WIRE_SIZE * compact.steps.len(),
        "byte_size_bound is exactly header + 9*steps"
    );
}

#[test]
fn real_rewrite_certificate_is_within_the_linear_bound() {
    let mut dag = nested_join_dag();
    let (_report, cert) = dag.apply_rewrites_certified(RewritePolicy::conservative(), &MENU);
    let compact = cert.compact().expect("compaction succeeds");

    assert!(
        compact.is_within_linear_bound(),
        "a well-formed rewrite touches each node a bounded number of times: \
         steps {} must be <= node bound {}",
        compact.steps.len(),
        compact.after_node_count.max(compact.before_node_count)
    );
}

#[test]
fn compact_step_indices_and_rules_are_in_range() {
    let mut dag = nested_join_dag();
    let (_report, cert) = dag.apply_rewrites_certified(RewritePolicy::conservative(), &MENU);
    let compact = cert.compact().expect("compaction succeeds");

    // The arena only grows under rewrites (fresh nodes are pushed), so every
    // referenced node index — before or after — fits within the post-rewrite
    // node count, and every rule discriminant is one of the six menu rules.
    let node_bound = compact.after_node_count.max(compact.before_node_count);
    for (i, step) in compact.steps.iter().enumerate() {
        assert!(
            step.before < node_bound,
            "step {i} before-index {} must be < node bound {node_bound}",
            step.before
        );
        assert!(
            step.after < node_bound,
            "step {i} after-index {} must be < node bound {node_bound}",
            step.after
        );
        assert!(
            (step.rule as usize) < MENU.len(),
            "step {i} rule discriminant {} must index a menu rule (< {})",
            step.rule,
            MENU.len()
        );
    }
}

#[test]
fn compaction_is_deterministic_and_does_not_mutate_the_certificate() {
    let mut dag = nested_join_dag();
    let (_report, cert) = dag.apply_rewrites_certified(RewritePolicy::conservative(), &MENU);

    let first = cert.compact().expect("compaction succeeds");
    let second = cert.compact().expect("compaction is repeatable");
    assert_eq!(
        first, second,
        "compact() is a pure function of the certificate (CompactCertificate: Eq)"
    );

    // Compacting an independent clone yields the same artifact.
    let cloned = cert
        .clone()
        .compact()
        .expect("compaction of a clone succeeds");
    assert_eq!(
        first, cloned,
        "compaction is independent of certificate identity"
    );
}

#[test]
fn identity_certificate_compacts_to_a_stepless_header() {
    // A single leaf admits no rewrite, so the certificate is identity.
    let mut dag = capture_dag(|b: &mut PlanBuilder| b.leaf("solo")).expect("valid leaf dag");
    let (report, cert) = dag.apply_rewrites_certified(RewritePolicy::conservative(), &MENU);

    assert!(report.steps().is_empty(), "no rewrite fires on a bare leaf");
    assert!(
        cert.is_identity(),
        "no steps + equal hashes => identity certificate"
    );

    let compact = cert.compact().expect("identity compaction succeeds");
    assert!(
        compact.steps.is_empty(),
        "identity certificate has no compact steps"
    );
    assert_eq!(
        compact.byte_size_bound(),
        CompactCertificate::HEADER_SIZE,
        "a stepless certificate is exactly the header"
    );
    assert!(
        compact.is_within_linear_bound(),
        "zero steps is trivially within the linear bound"
    );
    assert_eq!(
        compact.before_hash, compact.after_hash,
        "identity rewrite leaves the hash unchanged"
    );
    assert_eq!(
        compact.before_node_count, compact.after_node_count,
        "identity rewrite leaves the node count unchanged"
    );
    assert_eq!(
        compact.version,
        CertificateVersion::CURRENT,
        "current schema version"
    );
}
