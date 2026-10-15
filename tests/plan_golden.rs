//! Golden tests for plan DAG rewrite and execution-shape snapshots.

use asupersync::plan::{PlanDag, RewritePolicy, RewriteRule};
use std::time::Duration;

/// Helper to scrub PlanId indices from Debug output to keep snapshots stable
/// regardless of node allocation order.
fn scrub_plan_ids(s: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if i + 6 <= chars.len() && chars[i..i + 6].iter().collect::<String>() == "PlanId" {
            out.push_str("PlanId([ID])");
            i += 6;
            // Skip until matching closing paren
            let mut depth = 0;
            let mut found_open = false;
            while i < chars.len() {
                if chars[i] == '(' {
                    depth += 1;
                    found_open = true;
                } else if chars[i] == ')' {
                    depth -= 1;
                    if depth == 0 && found_open {
                        i += 1;
                        break;
                    }
                }
                i += 1;
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Scrub Plan IDs from the rewrite report summary.
fn scrub_rewrite_summary(summary: &str) -> String {
    summary
        .lines()
        .map(|line| {
            if let Some((prefix, _)) = line.split_once(" (") {
                format!("{prefix} ([PLAN_ID] -> [PLAN_ID])")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn snapshot_rewrite(name: &str, dag: &mut PlanDag, rules: &[RewriteRule], policy: RewritePolicy) {
    let before = scrub_plan_ids(&format!("{:#?}", dag));
    let report = dag.apply_rewrites(policy, rules);
    let after = scrub_plan_ids(&format!("{:#?}", dag));
    let summary = scrub_rewrite_summary(&report.summary());

    let mut output = String::new();
    output.push_str("--- BEFORE ---\n");
    output.push_str(&before);
    output.push_str("\n--- REWRITE REPORT ---\n");
    output.push_str(&summary);
    output.push_str("\n\n--- AFTER ---\n");
    output.push_str(&after);

    insta::assert_snapshot!(name, output);
}

#[test]
fn golden_join_family_rewrites() {
    // 1. JoinAssoc
    let mut dag = PlanDag::new();
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let c = dag.leaf("c");
    let inner = dag.join(vec![a, b]);
    let outer = dag.join(vec![inner, c]);
    dag.set_root(outer);

    snapshot_rewrite(
        "join_assoc",
        &mut dag,
        &[RewriteRule::JoinAssoc],
        RewritePolicy::conservative(),
    );

    // 2. JoinCommute
    let mut dag = PlanDag::new();
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let c = dag.leaf("c");
    let join = dag.join(vec![c, b, a]);
    dag.set_root(join);

    snapshot_rewrite(
        "join_commute",
        &mut dag,
        &[RewriteRule::JoinCommute],
        RewritePolicy::assume_all(),
    );
}

#[test]
fn golden_race_family_rewrites() {
    // 1. RaceAssoc
    let mut dag = PlanDag::new();
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let c = dag.leaf("c");
    let inner = dag.race(vec![a, b]);
    let outer = dag.race(vec![inner, c]);
    dag.set_root(outer);

    snapshot_rewrite(
        "race_assoc",
        &mut dag,
        &[RewriteRule::RaceAssoc],
        RewritePolicy::conservative(),
    );

    // 2. RaceCommute
    let mut dag = PlanDag::new();
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let c = dag.leaf("c");
    let race = dag.race(vec![c, b, a]);
    dag.set_root(race);

    snapshot_rewrite(
        "race_commute",
        &mut dag,
        &[RewriteRule::RaceCommute],
        RewritePolicy::assume_all(),
    );

    // 3. DedupRaceJoin (Race/Join distributivity)
    let mut dag = PlanDag::new();
    let s = dag.leaf("shared");
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let j1 = dag.join(vec![s, a]);
    let j2 = dag.join(vec![s, b]);
    let race = dag.race(vec![j1, j2]);
    dag.set_root(race);

    snapshot_rewrite(
        "dedup_race_join",
        &mut dag,
        &[RewriteRule::DedupRaceJoin],
        RewritePolicy::conservative(),
    );
}

#[test]
fn golden_timeout_family_rewrites() {
    // 1. TimeoutMin
    let mut dag = PlanDag::new();
    let a = dag.leaf("a");
    let inner = dag.timeout(a, Duration::from_secs(10));
    let outer = dag.timeout(inner, Duration::from_secs(5));
    dag.set_root(outer);

    snapshot_rewrite(
        "timeout_min",
        &mut dag,
        &[RewriteRule::TimeoutMin],
        RewritePolicy::conservative(),
    );
}
