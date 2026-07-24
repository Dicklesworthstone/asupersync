//! Fail-closed registry contract shared by the golden benchmark and its focused tests.

#![allow(missing_docs)]

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Formatter};
use std::path::Path;

pub(super) const GOLDEN_CHECKSUMS_PATH: &str = "artifacts/golden_checksums.json";
pub(super) const GOLDEN_SCHEMA_VERSION: u32 = 1;
pub(super) const GOLDEN_GENERATED_BY: &str =
    "golden_output benchmark (br-asupersync-golden-registry-fail-closed-provenance-xzv2c4)";
pub(super) const GOLDEN_SCENARIOS: [&str; 14] = [
    "budget/combine_chain",
    "budget/deadline_check_matrix",
    "cancel/cancel_budgets",
    "cancel/tree_propagation_depth_5",
    "channel/mpsc_multi_producer_interleave",
    "channel/mpsc_try_send_recv_1000",
    "channel/oneshot_send_recv_sequence",
    "lab/deterministic_schedule_seed_1337",
    "lab/deterministic_schedule_seed_42",
    "obligation/region_cancel_propagation",
    "obligation/send_permit_lifecycle",
    "scheduler/global_inject_then_pop_50",
    "scheduler/mixed_cancel_ready_timed_200",
    "scheduler/priority_lane_ordering_100",
];

pub(super) type RegistryResult<T> = Result<T, String>;

/// Schema for the golden checksums JSON artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GoldenChecksumFile {
    pub(super) schema_version: u32,
    pub(super) generated_by: String,
    pub(super) checksums: StrictChecksumMap,
}

/// A single golden checksum entry with mandatory reviewed provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GoldenEntry {
    pub(super) output_hash: String,
    pub(super) git_sha: String,
    pub(super) generated_at: String,
}

/// Checksum map whose deserializer rejects duplicate scenario keys.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(transparent)]
pub(super) struct StrictChecksumMap(pub(super) BTreeMap<String, GoldenEntry>);

impl<'de> Deserialize<'de> for StrictChecksumMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictChecksumMapVisitor;

        impl<'de> Visitor<'de> for StrictChecksumMapVisitor {
            type Value = StrictChecksumMap;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("a checksum object with unique scenario keys")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut checksums = BTreeMap::new();
                while let Some((scenario, entry)) = access.next_entry::<String, GoldenEntry>()? {
                    if checksums.insert(scenario.clone(), entry).is_some() {
                        return Err(de::Error::custom(format!(
                            "duplicate golden checksum scenario: {scenario}"
                        )));
                    }
                }
                Ok(StrictChecksumMap(checksums))
            }
        }

        deserializer.deserialize_map(StrictChecksumMapVisitor)
    }
}

#[derive(Debug, Clone)]
pub(super) struct ReviewedProvenance {
    pub(super) git_sha: String,
    pub(super) generated_at: String,
}

fn expected_scenarios() -> BTreeSet<&'static str> {
    GOLDEN_SCENARIOS.into_iter().collect()
}

pub(super) fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_timestamp(value: &str) -> bool {
    value
        .strip_suffix('Z')
        .is_some_and(|seconds| !seconds.is_empty() && seconds.bytes().all(|b| b.is_ascii_digit()))
}

pub(super) fn validate_registry(file: &GoldenChecksumFile) -> RegistryResult<()> {
    if file.schema_version != GOLDEN_SCHEMA_VERSION {
        return Err(format!(
            "unsupported golden registry schema_version {}; expected {GOLDEN_SCHEMA_VERSION}",
            file.schema_version
        ));
    }
    if file.generated_by.trim().is_empty() {
        return Err("golden registry generated_by must be non-empty".into());
    }

    let expected = expected_scenarios();
    let actual: BTreeSet<&str> = file.checksums.0.keys().map(String::as_str).collect();
    let missing: Vec<&str> = expected.difference(&actual).copied().collect();
    let extra: Vec<&str> = actual.difference(&expected).copied().collect();
    if !missing.is_empty() || !extra.is_empty() {
        return Err(format!(
            "golden registry scenario set mismatch: missing={missing:?}, extra={extra:?}"
        ));
    }

    for (scenario, entry) in &file.checksums.0 {
        if entry.output_hash == "GENERATE" || !is_lower_hex(&entry.output_hash, 64) {
            return Err(format!(
                "golden registry {scenario} output_hash must be 64 lowercase hex characters"
            ));
        }
        if !is_lower_hex(&entry.git_sha, 40) {
            return Err(format!(
                "golden registry {scenario} git_sha must be a full 40-character lowercase hex commit"
            ));
        }
        if !validate_timestamp(&entry.generated_at) {
            return Err(format!(
                "golden registry {scenario} generated_at must be Unix seconds followed by Z"
            ));
        }
    }

    Ok(())
}

pub(super) fn parse_golden_registry(contents: &str) -> RegistryResult<GoldenChecksumFile> {
    let file: GoldenChecksumFile = serde_json::from_str(contents)
        .map_err(|error| format!("parse golden checksum registry: {error}"))?;
    validate_registry(&file)?;
    Ok(file)
}

pub(super) fn load_golden_registry_from_path(path: &Path) -> RegistryResult<GoldenChecksumFile> {
    let contents = std::fs::read_to_string(path)
        .map_err(|error| format!("read required golden registry {}: {error}", path.display()))?;
    parse_golden_registry(&contents)
}

pub(super) fn validate_reviewed_provenance(
    reviewed_sha: &str,
    head_sha: &str,
    tracked_status: &str,
) -> RegistryResult<()> {
    if !is_lower_hex(reviewed_sha, 40) {
        return Err(
            "GOLDEN_REVIEWED_GIT_SHA must be a full 40-character lowercase hex commit".into(),
        );
    }
    if reviewed_sha != head_sha {
        return Err(format!(
            "GOLDEN_REVIEWED_GIT_SHA {reviewed_sha} does not match HEAD {head_sha}"
        ));
    }
    if !tracked_status.trim().is_empty() {
        return Err(format!(
            "golden update requires a clean tracked tree; commit the reviewed behavior change first: {tracked_status:?}"
        ));
    }
    Ok(())
}

pub(super) fn build_update_candidate(
    updates: &BTreeMap<String, String>,
    provenance: &ReviewedProvenance,
) -> RegistryResult<GoldenChecksumFile> {
    let checksums = StrictChecksumMap(
        updates
            .iter()
            .map(|(scenario, output_hash)| {
                (
                    scenario.clone(),
                    GoldenEntry {
                        output_hash: output_hash.clone(),
                        git_sha: provenance.git_sha.clone(),
                        generated_at: provenance.generated_at.clone(),
                    },
                )
            })
            .collect(),
    );
    let file = GoldenChecksumFile {
        schema_version: GOLDEN_SCHEMA_VERSION,
        generated_by: GOLDEN_GENERATED_BY.into(),
        checksums,
    };
    validate_registry(&file)?;
    Ok(file)
}
