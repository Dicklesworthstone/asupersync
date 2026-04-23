//! Golden snapshots for plan rewrite certificate formats.

use asupersync::plan::certificate::{CompactCertificate, RewriteCertificate};
use asupersync::plan::{PlanDag, RewritePolicy, RewriteRule};
use insta::assert_json_snapshot;
use serde_json::{Value, json};

fn build_dedup_race_join_dag() -> PlanDag {
    let mut dag = PlanDag::new();
    let shared = dag.leaf("shared");
    let left = dag.leaf("left");
    let right = dag.leaf("right");
    let join_a = dag.join(vec![shared, left]);
    let join_b = dag.join(vec![shared, right]);
    let race = dag.race(vec![join_a, join_b]);
    dag.set_root(race);
    dag
}

fn build_identity_join_dag() -> PlanDag {
    let mut dag = PlanDag::new();
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let join = dag.join(vec![a, b]);
    dag.set_root(join);
    dag
}

fn rule_name(rule: RewriteRule) -> &'static str {
    match rule {
        RewriteRule::JoinAssoc => "join_assoc",
        RewriteRule::RaceAssoc => "race_assoc",
        RewriteRule::JoinCommute => "join_commute",
        RewriteRule::RaceCommute => "race_commute",
        RewriteRule::TimeoutMin => "timeout_min",
        RewriteRule::DedupRaceJoin => "dedup_race_join",
    }
}

fn policy_json(policy: RewritePolicy) -> Value {
    json!({
        "associativity": policy.associativity,
        "commutativity": policy.commutativity,
        "distributivity": policy.distributivity,
        "require_binary_joins": policy.require_binary_joins,
        "timeout_simplification": policy.timeout_simplification,
    })
}

fn certificate_json(cert: &RewriteCertificate) -> Value {
    json!({
        "version": cert.version.number(),
        "policy": policy_json(cert.policy),
        "before_hash": cert.before_hash.value(),
        "after_hash": cert.after_hash.value(),
        "before_node_count": cert.before_node_count,
        "after_node_count": cert.after_node_count,
        "fingerprint": cert.fingerprint(),
        "identity": cert.is_identity(),
        "steps": cert.steps.iter().map(|step| json!({
            "rule": rule_name(step.rule),
            "before": step.before.index(),
            "after": step.after.index(),
            "detail": step.detail,
        })).collect::<Vec<_>>(),
    })
}

fn compact_certificate_json(compact: &CompactCertificate) -> Value {
    json!({
        "version": compact.version.number(),
        "policy_bits": compact.policy_bits,
        "before_hash": compact.before_hash.value(),
        "after_hash": compact.after_hash.value(),
        "before_node_count": compact.before_node_count,
        "after_node_count": compact.after_node_count,
        "byte_size_bound": compact.byte_size_bound(),
        "within_linear_bound": compact.is_within_linear_bound(),
        "steps": compact.steps.iter().map(|step| json!({
            "rule": step.rule,
            "before": step.before,
            "after": step.after,
        })).collect::<Vec<_>>(),
    })
}

#[test]
fn plan_certificate_format_snapshot() {
    let mut dedup = build_dedup_race_join_dag();
    let (_, dedup_cert) = dedup
        .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);
    let dedup_compact = dedup_cert
        .compact()
        .expect("dedup certificate should fit compact format");

    let mut identity = build_identity_join_dag();
    let (_, identity_cert) = identity
        .apply_rewrites_certified(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);
    let identity_compact = identity_cert
        .compact()
        .expect("identity certificate should fit compact format");

    assert_json_snapshot!(
        "plan_certificate_format_snapshot",
        json!({
            "dedup_race_join": {
                "certificate": certificate_json(&dedup_cert),
                "compact": compact_certificate_json(&dedup_compact),
            },
            "identity_join": {
                "certificate": certificate_json(&identity_cert),
                "compact": compact_certificate_json(&identity_compact),
            }
        })
    );
}
