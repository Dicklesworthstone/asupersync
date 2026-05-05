#![allow(missing_docs)]

const PR_TEMPLATE: &str = include_str!("../.github/PULL_REQUEST_TEMPLATE.md");
const INTEGRATION_DOC: &str = include_str!("../docs/integration.md");
const ADOPTION_GUIDE: &str = include_str!("../docs/adoption/getting_started.md");

#[test]
fn pr_template_requires_proof_and_refinement_touchpoints() {
    for required_snippet in [
        "## Proof + Conformance Impact Declaration",
        "| Theorem touchpoints |",
        "| Refinement mapping touchpoints |",
        "### Critical Module Scope Declaration",
        "| Critical Path Touched | Owner Group | Why This Change Is Needed |",
    ] {
        assert!(
            PR_TEMPLATE.contains(required_snippet),
            "pull request template must include `{required_snippet}`"
        );
    }
}

#[test]
fn integration_doc_defines_review_artifact_requirements_for_critical_changes() {
    for required_snippet in [
        "Proof-Impact Classification and Routing",
        "PR/review artifact requirement for critical modules",
        "theorem_touchpoints",
        "refinement_mapping_touchpoints",
        "review_artifact_location",
        "Reviewers should reject PRs touching critical modules when this block is missing",
        "Additional hard requirements for `local` and `cross-cutting` changes",
    ] {
        assert!(
            INTEGRATION_DOC.contains(required_snippet),
            "integration workflow guidance must include `{required_snippet}`"
        );
    }
}

#[test]
fn adoption_guide_points_to_correctness_by_construction_workflow() {
    for required_snippet in [
        "Correctness-by-Construction Review Workflow",
        "Proof + Conformance Impact",
        "Theorem touchpoints",
        "Refinement mapping touchpoints",
        "rch exec -- cargo check --all-targets",
        "rch exec -- cargo clippy --all-targets -- -D warnings",
    ] {
        assert!(
            ADOPTION_GUIDE.contains(required_snippet),
            "adoption guide must include `{required_snippet}`"
        );
    }
}
