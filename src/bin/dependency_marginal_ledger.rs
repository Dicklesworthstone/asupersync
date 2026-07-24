//! Generate the Dependency Sovereignty Program's marginal-cost ledger.
//!
//! The generator deliberately resolves synthesized, out-of-workspace Cargo
//! consumers. Each active direct root edge is removed from a second valid
//! shadow manifest and Cargo resolves that counterfactual independently.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use toml::Value as TomlValue;

type AnyError = Box<dyn Error + Send + Sync>;
type Result<T> = std::result::Result<T, AnyError>;

const ARTIFACT_ID: &str = "dependency-marginal-ledger-v1";
const BEAD_ID: &str = "asupersync-dep-p1-foundations-upksjk.2";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const TAXONOMY_PATH: &str = "artifacts/dependency_safety_taxonomy_v1.json";
const GENERATOR_PATH: &str = "src/bin/dependency_marginal_ledger.rs";
const CONTRACT_PATH: &str = "tests/dependency_marginal_ledger_contract.rs";
const DOC_PATH: &str = "docs/dependency_marginal_ledger.md";

const CANONICAL_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "wasm32-unknown-unknown",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GraphScope {
    Consumer,
    WorkspaceAudit,
}

#[derive(Clone, Debug)]
struct ProfileSpec {
    id: &'static str,
    default_features: bool,
    features: &'static [&'static str],
    scope: GraphScope,
}

const CANONICAL_PROFILES: &[ProfileSpec] = &[
    ProfileSpec {
        id: "minimal",
        default_features: false,
        features: &[],
        scope: GraphScope::Consumer,
    },
    ProfileSpec {
        id: "default",
        default_features: true,
        features: &[],
        scope: GraphScope::Consumer,
    },
    ProfileSpec {
        id: "tls",
        default_features: true,
        features: &["tls"],
        scope: GraphScope::Consumer,
    },
    ProfileSpec {
        id: "sqlite",
        default_features: true,
        features: &["sqlite"],
        scope: GraphScope::Consumer,
    },
    ProfileSpec {
        id: "kafka",
        default_features: true,
        features: &["kafka"],
        scope: GraphScope::Consumer,
    },
    ProfileSpec {
        id: "metrics",
        default_features: true,
        features: &["metrics"],
        scope: GraphScope::Consumer,
    },
    ProfileSpec {
        id: "cli",
        default_features: true,
        features: &["cli"],
        scope: GraphScope::Consumer,
    },
    ProfileSpec {
        id: "compression",
        default_features: true,
        features: &["compression"],
        scope: GraphScope::Consumer,
    },
    ProfileSpec {
        id: "trace-compression",
        default_features: true,
        features: &["trace-compression"],
        scope: GraphScope::Consumer,
    },
    ProfileSpec {
        id: "io-uring",
        default_features: true,
        features: &["io-uring"],
        scope: GraphScope::Consumer,
    },
    ProfileSpec {
        id: "loom-tests",
        default_features: true,
        features: &["loom-tests"],
        scope: GraphScope::Consumer,
    },
    ProfileSpec {
        id: "fuzz-quarantine",
        default_features: true,
        features: &["fuzz"],
        scope: GraphScope::Consumer,
    },
    ProfileSpec {
        id: "workspace-dev-build-audit",
        default_features: true,
        features: &[],
        scope: GraphScope::WorkspaceAudit,
    },
];

#[derive(Debug)]
struct Config {
    repo_root: PathBuf,
    work_dir: PathBuf,
    output: Option<PathBuf>,
    source_commit: Option<String>,
    jobs: usize,
    offline: bool,
    selected_profiles: Option<BTreeSet<String>>,
    selected_targets: Option<BTreeSet<String>>,
}

impl Config {
    fn parse() -> Result<Self> {
        let mut args = env::args_os().skip(1);
        let mut repo_root = env::current_dir()?;
        let mut work_dir = None;
        let mut output = None;
        let mut source_commit = None;
        let mut jobs = 4;
        let mut offline = false;
        let mut selected_profiles = None;
        let mut selected_targets = None;

        while let Some(arg) = args.next() {
            match arg.to_string_lossy().as_ref() {
                "--repo-root" => {
                    repo_root = PathBuf::from(required_arg(&mut args, "--repo-root")?);
                }
                "--work-dir" => {
                    work_dir = Some(PathBuf::from(required_arg(&mut args, "--work-dir")?));
                }
                "--output" => {
                    let value = required_arg(&mut args, "--output")?;
                    if value != "-" {
                        output = Some(PathBuf::from(value));
                    }
                }
                "--source-commit" => {
                    source_commit = Some(
                        required_arg(&mut args, "--source-commit")?
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
                "--jobs" => {
                    let value = required_arg(&mut args, "--jobs")?;
                    jobs = value
                        .to_string_lossy()
                        .parse::<usize>()
                        .map_err(|error| format!("invalid --jobs value: {error}"))?;
                    if jobs == 0 || jobs > 32 {
                        return Err("--jobs must be in 1..=32".into());
                    }
                }
                "--offline" => offline = true,
                "--profiles" => {
                    selected_profiles = Some(csv_set(&required_arg(&mut args, "--profiles")?));
                }
                "--targets" => {
                    selected_targets = Some(csv_set(&required_arg(&mut args, "--targets")?));
                }
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {other}").into()),
            }
        }

        repo_root = repo_root.canonicalize()?;
        let work_dir = absolutize_cli_path(
            &repo_root,
            work_dir.unwrap_or_else(|| PathBuf::from("target/dependency-marginal-ledger")),
        );
        let output = output.map(|path| absolutize_cli_path(&repo_root, path));
        Ok(Self {
            repo_root,
            work_dir,
            output,
            source_commit,
            jobs,
            offline,
            selected_profiles,
            selected_targets,
        })
    }

    fn profiles(&self) -> Result<Vec<&'static ProfileSpec>> {
        let selected = self.selected_profiles.as_ref();
        let profiles = CANONICAL_PROFILES
            .iter()
            .filter(|profile| selected.is_none_or(|ids| ids.contains(profile.id)))
            .collect::<Vec<_>>();
        if profiles.is_empty() {
            return Err("profile selection matched no canonical profile".into());
        }
        if let Some(ids) = selected {
            let known = CANONICAL_PROFILES
                .iter()
                .map(|profile| profile.id)
                .collect::<BTreeSet<_>>();
            let unknown = ids
                .iter()
                .filter(|id| !known.contains(id.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            if !unknown.is_empty() {
                return Err(format!("unknown profiles: {}", unknown.join(", ")).into());
            }
        }
        Ok(profiles)
    }

    fn targets(&self) -> Result<Vec<String>> {
        let selected = self.selected_targets.as_ref();
        let targets = CANONICAL_TARGETS
            .iter()
            .filter(|target| selected.is_none_or(|ids| ids.contains(**target)))
            .map(|target| (*target).to_owned())
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return Err("target selection matched no canonical target".into());
        }
        if let Some(ids) = selected {
            let known = CANONICAL_TARGETS.iter().copied().collect::<BTreeSet<_>>();
            let unknown = ids
                .iter()
                .filter(|id| !known.contains(id.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            if !unknown.is_empty() {
                return Err(format!("unknown targets: {}", unknown.join(", ")).into());
            }
        }
        Ok(targets)
    }
}

fn absolutize_cli_path(repo_root: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        repo_root.join(path)
    }
}

fn required_arg(args: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<OsString> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn csv_set(value: &OsString) -> BTreeSet<String> {
    value
        .to_string_lossy()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn print_help() {
    println!(
        "dependency_marginal_ledger [--repo-root PATH] [--work-dir PATH] \
         [--output PATH|-] [--source-commit SHA] [--profiles CSV] \
         [--targets CSV] [--jobs 1..=32] [--offline]"
    );
}

#[derive(Clone, Debug, Serialize)]
struct DirectDependency {
    edge_id: String,
    dependency_name: String,
    package_name: String,
    dependency_edge_kind: String,
    target_condition: Option<String>,
    optional: bool,
    manifest_table: String,
}

#[derive(Clone, Debug, Serialize)]
struct TaxonomyRef {
    candidate_id: String,
    class_id: String,
    review_sensitivity_tags: Vec<String>,
    program_phase: String,
    program_verdict: String,
}

#[derive(Clone, Debug, Serialize)]
struct ProfileRecord {
    profile_id: String,
    default_features: bool,
    feature_vector: Vec<String>,
    graph_scope: String,
}

#[derive(Clone, Debug, Serialize)]
struct GraphRecord {
    feature_profile: String,
    target_triple: String,
    host_triple: String,
    baseline_manifest_hash: String,
    baseline_lockfile_hash: String,
    baseline_package_version_count: usize,
    baseline_unique_package_name_count: usize,
    active_direct_root_edges: Vec<String>,
    absent_direct_root_edges: Vec<String>,
    exact_command: String,
}

#[derive(Clone, Debug, Serialize)]
struct NativePackageEvidence {
    package_id: String,
    status: String,
    evidence_sources: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct NativeEvidence {
    status: String,
    packages: Vec<NativePackageEvidence>,
}

#[derive(Clone, Debug, Serialize)]
struct MarginalRecord {
    feature_profile: String,
    target_triple: String,
    host_triple: String,
    dependency_edge_kind: String,
    direct_root_edge: String,
    dependency_name: String,
    package_name: String,
    target_condition: Option<String>,
    execution_context: String,
    baseline_manifest_hash: String,
    counterfactual_manifest_hash: String,
    baseline_lockfile_hash: String,
    counterfactual_lockfile_hash: String,
    baseline_package_version_count: usize,
    counterfactual_package_version_count: usize,
    marginal_package_version_count: usize,
    marginal_package_versions: Vec<String>,
    marginal_unique_package_names: Vec<String>,
    unique_upstream_identities: Vec<String>,
    build_scripts: Vec<String>,
    proc_macros: Vec<String>,
    root_native_code: NativeEvidence,
    marginal_native_code: NativeEvidence,
    taxonomy_refs: Vec<TaxonomyRef>,
    unsafe_exposure_class: String,
    exact_baseline_command: String,
    exact_counterfactual_command: String,
}

#[derive(Clone, Debug, Serialize)]
struct PhaseForecast {
    feature_profile: String,
    target_triple: String,
    program_phase: String,
    lower_bound_unique_individual_marginals: usize,
    upper_bound_sum_individual_marginals: usize,
    contributing_direct_root_edges: Vec<String>,
    no_claim_boundary: String,
}

#[derive(Debug, Serialize)]
struct LedgerArtifact {
    schema_version: u64,
    artifact_id: &'static str,
    bead_id: &'static str,
    program_id: &'static str,
    source_commit: String,
    generator_path: &'static str,
    taxonomy_path: &'static str,
    contract_path: &'static str,
    documentation_path: &'static str,
    cargo_version: String,
    rustc_version: String,
    host_triple: String,
    canonical_profiles: Vec<ProfileRecord>,
    canonical_target_triples: Vec<String>,
    direct_dependency_inventory: Vec<DirectDependency>,
    graph_records: Vec<GraphRecord>,
    marginal_measurements: Vec<MarginalRecord>,
    generated_phase_forecasts: Vec<PhaseForecast>,
    upstream_identity_policy: Vec<String>,
    native_evidence_policy: Vec<String>,
    methodology: Vec<String>,
    no_claim_boundaries: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    resolve: Option<CargoResolve>,
    workspace_members: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    source: Option<String>,
    manifest_path: String,
    repository: Option<String>,
    checksum: Option<String>,
    targets: Vec<CargoTarget>,
}

#[derive(Clone, Debug, Deserialize)]
struct CargoTarget {
    kind: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct CargoResolve {
    nodes: Vec<CargoNode>,
}

#[derive(Clone, Debug, Deserialize)]
struct CargoNode {
    id: String,
    deps: Vec<CargoNodeDep>,
}

#[derive(Clone, Debug, Deserialize)]
struct CargoNodeDep {
    name: String,
    pkg: String,
    dep_kinds: Vec<CargoDepKind>,
}

#[derive(Clone, Debug, Deserialize)]
struct CargoDepKind {
    kind: Option<String>,
    target: Option<String>,
}

#[derive(Debug)]
struct Resolution {
    metadata: CargoMetadata,
    manifest_hash: String,
    lockfile_hash: String,
    exact_command: String,
    root_id: String,
    external_ids: BTreeSet<String>,
}

struct BaselineCell {
    profile: &'static ProfileSpec,
    target: String,
    case_root: PathBuf,
    baseline_manifest: PathBuf,
    baseline: Resolution,
    active_direct_dependencies: BTreeMap<String, String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("dependency marginal ledger generation failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let config = Config::parse()?;
    let manifest_path = config.repo_root.join("Cargo.toml");
    let manifest_text = fs::read_to_string(&manifest_path)?;
    let manifest = toml::from_str::<TomlValue>(&manifest_text)?;
    let dependencies = collect_direct_dependencies(&manifest)?;
    let first_party_package_names = first_party_package_names(&config.repo_root, &manifest)?;
    if dependencies.is_empty() {
        return Err("Cargo.toml contains no direct dependency edges".into());
    }

    let profiles = config.profiles()?;
    let targets = config.targets()?;
    fs::create_dir_all(&config.work_dir)?;

    let taxonomy = load_taxonomy(&config.repo_root)?;
    let cargo_version = cargo_version()?;
    let rustc_verbose = rustc_verbose()?;
    let host_triple = parse_host_triple(&rustc_verbose)?;
    let source_commit = match config.source_commit.as_deref() {
        Some(commit) => validate_source_commit(commit)?,
        None => validate_source_commit(&git_head(&config.repo_root)?)?,
    };

    let mut graph_records = Vec::new();
    let mut baseline_cells = Vec::new();

    for profile in &profiles {
        for target in &targets {
            let case_root = config
                .work_dir
                .join("profiles")
                .join(profile.id)
                .join(safe_component(target));
            let baseline_manifest = prepare_case(
                &config.repo_root,
                &case_root.join("baseline"),
                &manifest,
                profile,
                None,
            )?;
            seed_lockfile(
                &config.repo_root.join("Cargo.lock"),
                &baseline_manifest,
                "repository baseline",
            )?;
            let baseline = resolve_case(
                &config,
                &baseline_manifest,
                profile.scope,
                target,
                &config.repo_root,
                &first_party_package_names,
                false,
            )?;

            let active = active_direct_dependencies(&baseline, &dependencies)?;
            let active_ids = active.keys().cloned().collect::<BTreeSet<_>>();
            let absent_ids = dependencies
                .iter()
                .map(|dependency| dependency.edge_id.clone())
                .filter(|edge_id| !active_ids.contains(edge_id))
                .collect::<Vec<_>>();

            graph_records.push(GraphRecord {
                feature_profile: profile.id.to_owned(),
                target_triple: target.clone(),
                host_triple: host_triple.clone(),
                baseline_manifest_hash: baseline.manifest_hash.clone(),
                baseline_lockfile_hash: baseline.lockfile_hash.clone(),
                baseline_package_version_count: baseline.external_ids.len(),
                baseline_unique_package_name_count: unique_package_names(
                    &baseline.metadata,
                    &baseline.external_ids,
                )
                .len(),
                active_direct_root_edges: active_ids.iter().cloned().collect(),
                absent_direct_root_edges: absent_ids,
                exact_command: baseline.exact_command.clone(),
            });
            baseline_cells.push(BaselineCell {
                profile,
                target: target.clone(),
                case_root,
                baseline_manifest,
                baseline,
                active_direct_dependencies: active,
            });
        }
    }

    let mut measurements = resolve_measurements_parallel(
        &config,
        &manifest,
        &dependencies,
        &baseline_cells,
        &taxonomy,
        &first_party_package_names,
        &host_triple,
    )?;

    graph_records.sort_by(|left, right| {
        (
            &left.feature_profile,
            &left.target_triple,
            &left.host_triple,
        )
            .cmp(&(
                &right.feature_profile,
                &right.target_triple,
                &right.host_triple,
            ))
    });
    measurements.sort_by(|left, right| measurement_key(left).cmp(&measurement_key(right)));

    let artifact = LedgerArtifact {
        schema_version: 1,
        artifact_id: ARTIFACT_ID,
        bead_id: BEAD_ID,
        program_id: PROGRAM_ID,
        source_commit,
        generator_path: GENERATOR_PATH,
        taxonomy_path: TAXONOMY_PATH,
        contract_path: CONTRACT_PATH,
        documentation_path: DOC_PATH,
        cargo_version,
        rustc_version: rustc_verbose.lines().next().unwrap_or_default().to_owned(),
        host_triple,
        canonical_profiles: profiles
            .iter()
            .map(|profile| ProfileRecord {
                profile_id: profile.id.to_owned(),
                default_features: profile.default_features,
                feature_vector: profile
                    .features
                    .iter()
                    .map(|feature| (*feature).to_owned())
                    .collect(),
                graph_scope: match profile.scope {
                    GraphScope::Consumer => "synthesized-consumer",
                    GraphScope::WorkspaceAudit => "full-workspace-dev-build-audit",
                }
                .to_owned(),
            })
            .collect(),
        canonical_target_triples: targets,
        direct_dependency_inventory: dependencies,
        generated_phase_forecasts: phase_forecasts(&measurements),
        graph_records,
        marginal_measurements: measurements,
        upstream_identity_policy: vec![
            "Registry identities include the canonical registry source and checksum; a missing checksum remains explicit.".to_owned(),
            "Git identities include a normalized URL and immutable revision.".to_owned(),
            "Repository URLs are normalized by scheme, host case, trailing slash, and .git suffix.".to_owned(),
            "Missing repository metadata falls back to a source-derived identity or unknown:<package-id>; unrelated unknowns are never merged.".to_owned(),
        ],
        native_evidence_policy: vec![
            "Cargo resolution alone never proves native compilation.".to_owned(),
            "active requires a package-specific build.rs or emitted-link rule recorded by the generator.".to_owned(),
            "declared-inactive records a known native declaration whose activating edge is absent; signal-hook -> cc is a regression fixture.".to_owned(),
            "unknown is fail-closed for an unclassified custom-build package and is never reported as safe.".to_owned(),
        ],
        methodology: vec![
            "Each baseline uses a synthesized out-of-workspace consumer or a shadow of every workspace member manifest with inert targets.".to_owned(),
            "Every active direct root edge is removed from a second valid manifest and cargo metadata resolves the counterfactual independently.".to_owned(),
            "The repository Cargo.lock seeds each baseline; the resolved baseline lock seeds its offline counterfactuals.".to_owned(),
            "Package IDs, not package-name text, define graph reachability and marginal sets.".to_owned(),
            "Build dependencies and proc macros execute in host context even during cross-target resolution.".to_owned(),
            "First-party path packages and the synthetic roots are excluded explicitly; external path packages remain fail-closed.".to_owned(),
        ],
        no_claim_boundaries: vec![
            "The ledger measures Cargo resolution, not compilation, runtime correctness, performance, release readiness, or exploitability.".to_owned(),
            "Native active/declared-inactive/unknown evidence is an attribution receipt, not a safety certification.".to_owned(),
            "Individual-edge marginals do not equal an exact simultaneous multi-edge removal forecast; phase forecasts are bounded generated estimates.".to_owned(),
            "A taxonomy reference records review obligations and does not authorize implementation or cutover.".to_owned(),
        ],
    };

    let rendered = serde_json::to_string_pretty(&artifact)? + "\n";
    if let Some(output) = &config.output {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(output, rendered)?;
    } else {
        print!("{rendered}");
    }
    Ok(())
}

fn resolve_measurements_parallel(
    config: &Config,
    source_manifest: &TomlValue,
    dependencies: &[DirectDependency],
    baseline_cells: &[BaselineCell],
    taxonomy: &JsonValue,
    first_party_package_names: &BTreeSet<String>,
    host_triple: &str,
) -> Result<Vec<MarginalRecord>> {
    let jobs = baseline_cells
        .iter()
        .enumerate()
        .flat_map(|(cell_index, cell)| {
            dependencies
                .iter()
                .enumerate()
                .filter(|(_, dependency)| {
                    cell.active_direct_dependencies
                        .contains_key(&dependency.edge_id)
                })
                .map(move |(dependency_index, _)| (cell_index, dependency_index))
        })
        .collect::<Vec<_>>();
    if jobs.is_empty() {
        return Ok(Vec::new());
    }

    let next = AtomicUsize::new(0);
    let (sender, receiver) = mpsc::channel();
    let worker_count = config.jobs.min(jobs.len());
    let mut indexed = thread::scope(|scope| -> Result<Vec<_>> {
        for _ in 0..worker_count {
            let sender = sender.clone();
            let next = &next;
            let jobs = &jobs;
            scope.spawn(move || {
                loop {
                    let job_index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&(cell_index, dependency_index)) = jobs.get(job_index) else {
                        break;
                    };
                    let result = match (
                        baseline_cells.get(cell_index),
                        dependencies.get(dependency_index),
                    ) {
                        (Some(cell), Some(dependency)) => resolve_measurement(
                            config,
                            source_manifest,
                            cell,
                            dependency,
                            taxonomy,
                            first_party_package_names,
                            host_triple,
                        ),
                        _ => Err("counterfactual job index escaped its input tables".into()),
                    };
                    if sender.send((job_index, result)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(sender);
        let mut received = Vec::with_capacity(jobs.len());
        for _ in 0..jobs.len() {
            received.push(
                receiver
                    .recv()
                    .map_err(|error| format!("counterfactual worker failed: {error}"))?,
            );
        }
        Ok(received)
    })?;
    indexed.sort_by_key(|(job_index, _)| *job_index);
    indexed
        .into_iter()
        .map(|(_, measurement)| measurement)
        .collect()
}

fn resolve_measurement(
    config: &Config,
    source_manifest: &TomlValue,
    cell: &BaselineCell,
    dependency: &DirectDependency,
    taxonomy: &JsonValue,
    first_party_package_names: &BTreeSet<String>,
    host_triple: &str,
) -> Result<MarginalRecord> {
    let root_package_id = cell
        .active_direct_dependencies
        .get(&dependency.edge_id)
        .ok_or_else(|| format!("active root edge disappeared: {}", dependency.edge_id))?;
    let counterfactual_manifest = prepare_case(
        &config.repo_root,
        &cell
            .case_root
            .join("counterfactuals")
            .join(safe_component(&dependency.edge_id)),
        source_manifest,
        cell.profile,
        Some(dependency),
    )?;
    seed_counterfactual_lock(&cell.baseline_manifest, &counterfactual_manifest)?;
    let counterfactual = resolve_case(
        config,
        &counterfactual_manifest,
        cell.profile.scope,
        &cell.target,
        &config.repo_root,
        first_party_package_names,
        true,
    )?;
    if !counterfactual
        .external_ids
        .is_subset(&cell.baseline.external_ids)
    {
        return Err(format!(
            "{} / {} / {} counterfactual added packages",
            cell.profile.id, cell.target, dependency.edge_id
        )
        .into());
    }

    let marginal_ids = cell
        .baseline
        .external_ids
        .difference(&counterfactual.external_ids)
        .cloned()
        .collect::<BTreeSet<_>>();
    let root_closure = reachable_external_from(
        &cell.baseline,
        root_package_id,
        &config.repo_root,
        first_party_package_names,
    )?;
    let taxonomy_refs = taxonomy_refs_for(taxonomy, &dependency.package_name)?;
    let unsafe_exposure_class = if taxonomy_refs.is_empty() {
        "unclassified-fail-closed".to_owned()
    } else {
        taxonomy_refs
            .iter()
            .map(|reference| reference.class_id.as_str())
            .max_by_key(|class| safety_rank(class))
            .unwrap_or("unclassified-fail-closed")
            .to_owned()
    };

    Ok(MarginalRecord {
        feature_profile: cell.profile.id.to_owned(),
        target_triple: cell.target.clone(),
        host_triple: host_triple.to_owned(),
        dependency_edge_kind: dependency.dependency_edge_kind.clone(),
        direct_root_edge: dependency.edge_id.clone(),
        dependency_name: dependency.dependency_name.clone(),
        package_name: dependency.package_name.clone(),
        target_condition: dependency.target_condition.clone(),
        execution_context: execution_context(&cell.baseline.metadata, root_package_id, dependency),
        baseline_manifest_hash: cell.baseline.manifest_hash.clone(),
        counterfactual_manifest_hash: counterfactual.manifest_hash,
        baseline_lockfile_hash: cell.baseline.lockfile_hash.clone(),
        counterfactual_lockfile_hash: counterfactual.lockfile_hash,
        baseline_package_version_count: cell.baseline.external_ids.len(),
        counterfactual_package_version_count: counterfactual.external_ids.len(),
        marginal_package_version_count: marginal_ids.len(),
        marginal_package_versions: marginal_ids.iter().cloned().collect(),
        marginal_unique_package_names: unique_package_names(&cell.baseline.metadata, &marginal_ids),
        unique_upstream_identities: upstream_identities(&cell.baseline.metadata, &marginal_ids),
        build_scripts: packages_with_target_kind(
            &cell.baseline.metadata,
            &marginal_ids,
            "custom-build",
        ),
        proc_macros: packages_with_target_kind(
            &cell.baseline.metadata,
            &marginal_ids,
            "proc-macro",
        ),
        root_native_code: native_evidence(&cell.baseline, &root_closure, root_package_id)?,
        marginal_native_code: native_evidence(&cell.baseline, &marginal_ids, root_package_id)?,
        taxonomy_refs,
        unsafe_exposure_class,
        exact_baseline_command: cell.baseline.exact_command.clone(),
        exact_counterfactual_command: counterfactual.exact_command,
    })
}

fn measurement_key(record: &MarginalRecord) -> (&str, &str, &str, &str, &str) {
    (
        &record.feature_profile,
        &record.target_triple,
        &record.host_triple,
        &record.dependency_edge_kind,
        &record.direct_root_edge,
    )
}

fn collect_direct_dependencies(manifest: &TomlValue) -> Result<Vec<DirectDependency>> {
    let mut dependencies = Vec::new();
    collect_dependency_table(manifest, "dependencies", "normal", None, &mut dependencies)?;
    collect_dependency_table(
        manifest,
        "build-dependencies",
        "build",
        None,
        &mut dependencies,
    )?;
    collect_dependency_table(manifest, "dev-dependencies", "dev", None, &mut dependencies)?;

    if let Some(targets) = manifest.get("target").and_then(TomlValue::as_table) {
        for (target_condition, target) in targets {
            collect_dependency_table(
                target,
                "dependencies",
                "target-normal",
                Some(target_condition),
                &mut dependencies,
            )?;
            collect_dependency_table(
                target,
                "build-dependencies",
                "target-build",
                Some(target_condition),
                &mut dependencies,
            )?;
            collect_dependency_table(
                target,
                "dev-dependencies",
                "target-dev",
                Some(target_condition),
                &mut dependencies,
            )?;
        }
    }

    dependencies.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
    let ids = dependencies
        .iter()
        .map(|dependency| dependency.edge_id.as_str())
        .collect::<BTreeSet<_>>();
    if ids.len() != dependencies.len() {
        return Err("direct dependency edge ids are not unique".into());
    }
    Ok(dependencies)
}

fn collect_dependency_table(
    manifest: &TomlValue,
    table_name: &str,
    edge_kind: &str,
    target_condition: Option<&str>,
    dependencies: &mut Vec<DirectDependency>,
) -> Result<()> {
    let Some(table) = manifest.get(table_name).and_then(TomlValue::as_table) else {
        return Ok(());
    };
    for (name, value) in table {
        let package_name = value
            .as_table()
            .and_then(|dependency| dependency.get("package"))
            .and_then(TomlValue::as_str)
            .unwrap_or(name)
            .to_owned();
        let optional = value
            .as_table()
            .and_then(|dependency| dependency.get("optional"))
            .and_then(TomlValue::as_bool)
            .unwrap_or(false);
        let edge_id = match target_condition {
            Some(condition) => format!("{edge_kind}:{condition}:{name}"),
            None => format!("{edge_kind}:{name}"),
        };
        let manifest_table = match target_condition {
            Some(condition) => format!("target.{condition}.{table_name}"),
            None => table_name.to_owned(),
        };
        dependencies.push(DirectDependency {
            edge_id,
            dependency_name: name.clone(),
            package_name,
            dependency_edge_kind: edge_kind.to_owned(),
            target_condition: target_condition.map(str::to_owned),
            optional,
            manifest_table,
        });
    }
    Ok(())
}

fn prepare_case(
    repo_root: &Path,
    case_root: &Path,
    source_manifest: &TomlValue,
    profile: &ProfileSpec,
    removed: Option<&DirectDependency>,
) -> Result<PathBuf> {
    let shadow_dir = case_root.join("shadow");
    fs::create_dir_all(shadow_dir.join("src"))?;

    let mut shadow = source_manifest.clone();
    configure_shadow_package(
        &mut shadow,
        &shadow_dir,
        matches!(profile.scope, GraphScope::Consumer).then_some("asupersync-ledger-shadow"),
    )?;
    if let Some(dependency) = removed {
        remove_direct_dependency(&mut shadow, dependency)?;
    }

    match profile.scope {
        GraphScope::Consumer => {
            shadow
                .as_table_mut()
                .ok_or("root Cargo.toml must be a table")?
                .remove("workspace");
            absolutize_dependency_paths(&mut shadow, repo_root)?;
            shadow
                .as_table_mut()
                .expect("checked root table")
                .remove("dev-dependencies");
            remove_target_dependency_kind(&mut shadow, "dev-dependencies");
        }
        GraphScope::WorkspaceAudit => {
            prepare_workspace_member_shadows(repo_root, &shadow_dir, source_manifest)?;
        }
    }

    let shadow_manifest = shadow_dir.join("Cargo.toml");
    fs::write(&shadow_manifest, toml::to_string_pretty(&shadow)?)?;
    if matches!(profile.scope, GraphScope::WorkspaceAudit) {
        return Ok(shadow_manifest);
    }

    let consumer_dir = case_root.join("consumer");
    fs::create_dir_all(consumer_dir.join("src"))?;
    fs::write(consumer_dir.join("src/lib.rs"), "#![forbid(unsafe_code)]\n")?;
    let features = profile
        .features
        .iter()
        .map(|feature| format!("\"{feature}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let consumer_manifest = format!(
        "[package]\nname = \"asupersync-ledger-consumer\"\nversion = \"0.0.0\"\n\
         edition = \"2024\"\npublish = false\n\n[workspace]\nmembers = [\".\"]\n\
         resolver = \"3\"\n\n[dependencies.asupersync-ledger-shadow]\npath = \"{}\"\n\
         default-features = {}\nfeatures = [{}]\n",
        toml_path(&shadow_dir)?,
        profile.default_features,
        features
    );
    let consumer_manifest_path = consumer_dir.join("Cargo.toml");
    fs::write(&consumer_manifest_path, consumer_manifest)?;
    Ok(consumer_manifest_path)
}

fn configure_shadow_package(
    manifest: &mut TomlValue,
    package_dir: &Path,
    name_override: Option<&str>,
) -> Result<()> {
    let has_build_dependencies = manifest_contains_build_dependencies(manifest);
    let root = manifest
        .as_table_mut()
        .ok_or("Cargo.toml root must be a table")?;
    for key in ["bin", "test", "bench", "example"] {
        root.remove(key);
    }
    let package = root
        .get_mut("package")
        .and_then(TomlValue::as_table_mut)
        .ok_or("Cargo.toml package table is required")?;
    if let Some(name) = name_override {
        package.insert("name".to_owned(), TomlValue::String(name.to_owned()));
    }
    for key in [
        "include",
        "exclude",
        "readme",
        "documentation",
        "license-file",
    ] {
        package.remove(key);
    }
    for key in ["autobins", "autotests", "autoexamples", "autobenches"] {
        package.insert(key.to_owned(), TomlValue::Boolean(false));
    }
    if has_build_dependencies {
        package.insert("build".to_owned(), TomlValue::String("build.rs".to_owned()));
        fs::write(package_dir.join("build.rs"), "fn main() {}\n")?;
    } else {
        package.insert("build".to_owned(), TomlValue::Boolean(false));
    }

    let mut lib = root
        .remove("lib")
        .and_then(|value| value.as_table().cloned())
        .unwrap_or_default();
    lib.insert(
        "path".to_owned(),
        TomlValue::String("src/lib.rs".to_owned()),
    );
    root.insert("lib".to_owned(), TomlValue::Table(lib));
    fs::create_dir_all(package_dir.join("src"))?;
    fs::write(package_dir.join("src/lib.rs"), "#![forbid(unsafe_code)]\n")?;
    Ok(())
}

fn manifest_contains_build_dependencies(manifest: &TomlValue) -> bool {
    manifest
        .get("build-dependencies")
        .and_then(TomlValue::as_table)
        .is_some_and(|table| !table.is_empty())
        || manifest
            .get("target")
            .and_then(TomlValue::as_table)
            .is_some_and(|targets| {
                targets.values().any(|target| {
                    target
                        .get("build-dependencies")
                        .and_then(TomlValue::as_table)
                        .is_some_and(|table| !table.is_empty())
                })
            })
}

fn prepare_workspace_member_shadows(
    repo_root: &Path,
    shadow_root: &Path,
    root_manifest: &TomlValue,
) -> Result<()> {
    for member in workspace_member_paths(repo_root, root_manifest)? {
        let relative = member
            .strip_prefix(repo_root)
            .map_err(|_| "workspace member escaped the repository root")?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let source_manifest = member.join("Cargo.toml");
        let manifest_text = fs::read_to_string(&source_manifest)?;
        let mut manifest = toml::from_str::<TomlValue>(&manifest_text)?;
        let destination = shadow_root.join(relative);
        fs::create_dir_all(&destination)?;
        configure_shadow_package(&mut manifest, &destination, None)?;
        fs::write(
            destination.join("Cargo.toml"),
            toml::to_string_pretty(&manifest)?,
        )?;
    }
    Ok(())
}

fn workspace_member_paths(repo_root: &Path, manifest: &TomlValue) -> Result<Vec<PathBuf>> {
    let members = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(TomlValue::as_array)
        .ok_or("Cargo.toml workspace.members must be an array")?;
    let mut paths = Vec::new();
    for member in members {
        let member = member
            .as_str()
            .ok_or("workspace member entries must be strings")?;
        if member == "." {
            paths.push(repo_root.to_owned());
            continue;
        }
        if member.contains(['*', '?', '[', ']']) {
            return Err(format!("workspace member globs are unsupported: {member}").into());
        }
        let path = repo_root.join(member).canonicalize()?;
        if !path.starts_with(repo_root) {
            return Err(format!("workspace member escaped repository root: {member}").into());
        }
        paths.push(path);
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn first_party_package_names(
    repo_root: &Path,
    root_manifest: &TomlValue,
) -> Result<BTreeSet<String>> {
    workspace_member_paths(repo_root, root_manifest)?
        .into_iter()
        .map(|member| {
            let manifest = if member == repo_root {
                root_manifest.clone()
            } else {
                toml::from_str::<TomlValue>(&fs::read_to_string(member.join("Cargo.toml"))?)?
            };
            manifest
                .get("package")
                .and_then(|package| package.get("name"))
                .and_then(TomlValue::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    format!("workspace member {} has no package name", member.display()).into()
                })
        })
        .collect()
}

fn absolutize_dependency_paths(manifest: &mut TomlValue, repo_root: &Path) -> Result<()> {
    for table_name in ["dependencies", "build-dependencies", "dev-dependencies"] {
        if let Some(table) = manifest
            .get_mut(table_name)
            .and_then(TomlValue::as_table_mut)
        {
            absolutize_table_paths(table, repo_root)?;
        }
    }
    if let Some(targets) = manifest.get_mut("target").and_then(TomlValue::as_table_mut) {
        for (_, target) in targets.iter_mut() {
            for table_name in ["dependencies", "build-dependencies", "dev-dependencies"] {
                if let Some(table) = target.get_mut(table_name).and_then(TomlValue::as_table_mut) {
                    absolutize_table_paths(table, repo_root)?;
                }
            }
        }
    }
    Ok(())
}

fn absolutize_table_paths(
    table: &mut toml::map::Map<String, TomlValue>,
    repo_root: &Path,
) -> Result<()> {
    for (_, dependency) in table.iter_mut() {
        let Some(dependency) = dependency.as_table_mut() else {
            continue;
        };
        let Some(path) = dependency.get("path").and_then(TomlValue::as_str) else {
            continue;
        };
        let absolute = repo_root.join(path).canonicalize()?;
        dependency.insert("path".to_owned(), TomlValue::String(toml_path(&absolute)?));
    }
    Ok(())
}

fn toml_path(path: &Path) -> Result<String> {
    let text = path
        .to_str()
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()))?;
    Ok(text.replace('\\', "/"))
}

fn remove_direct_dependency(manifest: &mut TomlValue, dependency: &DirectDependency) -> Result<()> {
    let table_name = dependency
        .manifest_table
        .rsplit('.')
        .next()
        .ok_or("invalid dependency manifest table")?;
    let table = match &dependency.target_condition {
        Some(condition) => manifest
            .get_mut("target")
            .and_then(TomlValue::as_table_mut)
            .and_then(|targets| targets.get_mut(condition))
            .and_then(|target| target.get_mut(table_name))
            .and_then(TomlValue::as_table_mut),
        None => manifest
            .get_mut(table_name)
            .and_then(TomlValue::as_table_mut),
    }
    .ok_or_else(|| format!("missing manifest table {}", dependency.manifest_table))?;
    if table.remove(&dependency.dependency_name).is_none() {
        return Err(format!("missing direct edge {}", dependency.edge_id).into());
    }
    if !matches!(
        dependency.dependency_edge_kind.as_str(),
        "dev" | "target-dev"
    ) {
        remove_feature_references(manifest, &dependency.dependency_name);
    }
    Ok(())
}

fn remove_feature_references(manifest: &mut TomlValue, dependency_name: &str) {
    let Some(features) = manifest
        .get_mut("features")
        .and_then(TomlValue::as_table_mut)
    else {
        return;
    };
    for (_, values) in features.iter_mut() {
        let Some(values) = values.as_array_mut() else {
            continue;
        };
        values.retain(|value| {
            let Some(value) = value.as_str() else {
                return true;
            };
            let bare = value.strip_prefix("dep:").unwrap_or(value);
            let root = bare.split(['/', '?']).next().unwrap_or(bare);
            root != dependency_name
        });
    }
}

fn remove_target_dependency_kind(manifest: &mut TomlValue, table_name: &str) {
    let Some(targets) = manifest.get_mut("target").and_then(TomlValue::as_table_mut) else {
        return;
    };
    for (_, target) in targets.iter_mut() {
        if let Some(target) = target.as_table_mut() {
            target.remove(table_name);
        }
    }
}

fn resolve_case(
    config: &Config,
    manifest_path: &Path,
    scope: GraphScope,
    target: &str,
    repo_root: &Path,
    first_party_package_names: &BTreeSet<String>,
    force_offline: bool,
) -> Result<Resolution> {
    let manifest_text = fs::read_to_string(manifest_path)?;
    let manifest_hash = sha256(manifest_text.as_bytes());
    let mut args = vec![
        OsString::from("metadata"),
        OsString::from("--format-version"),
        OsString::from("1"),
        OsString::from("--manifest-path"),
        manifest_path.as_os_str().to_owned(),
        OsString::from("--filter-platform"),
        OsString::from(target),
    ];
    if matches!(scope, GraphScope::WorkspaceAudit) {
        args.push(OsString::from("--all-features"));
    }
    if config.offline || force_offline {
        args.push(OsString::from("--offline"));
    }

    let exact_command = normalize_exact_command(&render_command("cargo", &args), &config.work_dir)?;
    let output = Command::new("cargo")
        .args(&args)
        .current_dir(
            manifest_path
                .parent()
                .ok_or("manifest must have a parent directory")?,
        )
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "{exact_command} failed with status {}:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let metadata = serde_json::from_slice::<CargoMetadata>(&output.stdout)?;
    let root_name = match scope {
        GraphScope::Consumer => "asupersync-ledger-shadow",
        GraphScope::WorkspaceAudit => "asupersync",
    };
    let root_id = metadata
        .packages
        .iter()
        .find(|package| package.name == root_name)
        .map(|package| package.id.clone())
        .ok_or_else(|| format!("metadata did not contain {root_name}"))?;
    let external_ids = match scope {
        GraphScope::Consumer => {
            reachable_external(&metadata, &root_id, repo_root, first_party_package_names)?
        }
        GraphScope::WorkspaceAudit => {
            let mut external = BTreeSet::new();
            for workspace_member in &metadata.workspace_members {
                external.extend(reachable_external(
                    &metadata,
                    workspace_member,
                    repo_root,
                    first_party_package_names,
                )?);
            }
            external
        }
    };
    let lockfile = lockfile_for_manifest(manifest_path);
    let lockfile_hash = if lockfile.is_file() {
        sha256(&fs::read(lockfile)?)
    } else {
        "missing-lockfile".to_owned()
    };
    Ok(Resolution {
        metadata,
        manifest_hash,
        lockfile_hash,
        exact_command,
        root_id,
        external_ids,
    })
}

fn lockfile_for_manifest(manifest_path: &Path) -> PathBuf {
    manifest_path
        .parent()
        .expect("manifest must have parent")
        .join("Cargo.lock")
}

fn seed_counterfactual_lock(
    baseline_manifest: &Path,
    counterfactual_manifest: &Path,
) -> Result<()> {
    let baseline_lock = lockfile_for_manifest(baseline_manifest);
    seed_lockfile(&baseline_lock, counterfactual_manifest, "resolved baseline")
}

fn seed_lockfile(source_lock: &Path, destination_manifest: &Path, label: &str) -> Result<()> {
    if !source_lock.is_file() {
        return Err(format!("{label} lockfile is missing at {}", source_lock.display()).into());
    }
    let destination_lock = lockfile_for_manifest(destination_manifest);
    fs::copy(source_lock, destination_lock)?;
    Ok(())
}

fn render_command(program: &str, args: &[OsString]) -> String {
    std::iter::once(OsString::from(program))
        .chain(args.iter().cloned())
        .map(|part| shell_quote(&part.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalize_exact_command(command: &str, work_dir: &Path) -> Result<String> {
    Ok(command.replace(&toml_path(work_dir)?, "$LEDGER_WORK_DIR"))
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "-_./:=+".contains(character))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}

fn reachable_external(
    metadata: &CargoMetadata,
    root_id: &str,
    repo_root: &Path,
    first_party_package_names: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or("cargo metadata did not include a resolve graph")?;
    let nodes = resolve
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let packages = metadata
        .packages
        .iter()
        .map(|package| (package.id.as_str(), package))
        .collect::<BTreeMap<_, _>>();
    let mut queue = VecDeque::from([root_id.to_owned()]);
    let mut visited = BTreeSet::new();
    let mut external = BTreeSet::new();
    while let Some(package_id) = queue.pop_front() {
        if !visited.insert(package_id.clone()) {
            continue;
        }
        if package_id != root_id {
            let package = packages
                .get(package_id.as_str())
                .ok_or_else(|| format!("resolve references missing package {package_id}"))?;
            if !is_first_party_path_package(package, repo_root, first_party_package_names) {
                external.insert(package_id.clone());
            }
        }
        if let Some(node) = nodes.get(package_id.as_str()) {
            for dependency in &node.deps {
                queue.push_back(dependency.pkg.clone());
            }
        }
    }
    Ok(external)
}

fn reachable_external_from(
    resolution: &Resolution,
    root_id: &str,
    repo_root: &Path,
    first_party_package_names: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    reachable_external(
        &resolution.metadata,
        root_id,
        repo_root,
        first_party_package_names,
    )
}

fn is_first_party_path_package(
    package: &CargoPackage,
    repo_root: &Path,
    first_party_package_names: &BTreeSet<String>,
) -> bool {
    if package.source.is_some() {
        return false;
    }
    Path::new(&package.manifest_path).starts_with(repo_root)
        || package.name == "asupersync-ledger-shadow"
        || package.name == "asupersync-ledger-consumer"
        || first_party_package_names.contains(&package.name)
}

fn active_direct_dependencies(
    resolution: &Resolution,
    inventory: &[DirectDependency],
) -> Result<BTreeMap<String, String>> {
    let resolve = resolution
        .metadata
        .resolve
        .as_ref()
        .ok_or("cargo metadata did not include a resolve graph")?;
    let root = resolve
        .nodes
        .iter()
        .find(|node| node.id == resolution.root_id)
        .ok_or("shadow root is absent from resolve graph")?;
    let mut active = BTreeMap::new();
    for dependency in inventory {
        if let Some(node_dep) = root.deps.iter().find(|node_dep| {
            node_dep.name == dependency.dependency_name
                && node_dep
                    .dep_kinds
                    .iter()
                    .any(|kind| dep_kind_matches(dependency, kind))
        }) {
            active.insert(dependency.edge_id.clone(), node_dep.pkg.clone());
        }
    }
    Ok(active)
}

fn dep_kind_matches(dependency: &DirectDependency, kind: &CargoDepKind) -> bool {
    let actual_kind = kind.kind.as_deref().unwrap_or("normal");
    let expected_kind = match dependency.dependency_edge_kind.as_str() {
        "normal" | "target-normal" => "normal",
        "build" | "target-build" => "build",
        "dev" | "target-dev" => "dev",
        _ => return false,
    };
    if actual_kind != expected_kind {
        return false;
    }
    match (&dependency.target_condition, &kind.target) {
        (None, None) => true,
        (Some(expected), Some(actual)) => normalize_cfg(expected) == normalize_cfg(actual),
        _ => false,
    }
}

fn normalize_cfg(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn execution_context(
    metadata: &CargoMetadata,
    root_package_id: &str,
    dependency: &DirectDependency,
) -> String {
    if matches!(
        dependency.dependency_edge_kind.as_str(),
        "build" | "target-build"
    ) || package_has_target_kind(metadata, root_package_id, "proc-macro")
    {
        "host".to_owned()
    } else if matches!(
        dependency.dependency_edge_kind.as_str(),
        "dev" | "target-dev"
    ) {
        "target-dev".to_owned()
    } else {
        "target".to_owned()
    }
}

fn package_has_target_kind(metadata: &CargoMetadata, package_id: &str, kind: &str) -> bool {
    metadata
        .packages
        .iter()
        .find(|package| package.id == package_id)
        .is_some_and(|package| {
            package
                .targets
                .iter()
                .any(|target| target.kind.iter().any(|candidate| candidate == kind))
        })
}

fn unique_package_names(metadata: &CargoMetadata, package_ids: &BTreeSet<String>) -> Vec<String> {
    metadata
        .packages
        .iter()
        .filter(|package| package_ids.contains(&package.id))
        .map(|package| package.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn packages_with_target_kind(
    metadata: &CargoMetadata,
    package_ids: &BTreeSet<String>,
    kind: &str,
) -> Vec<String> {
    metadata
        .packages
        .iter()
        .filter(|package| package_ids.contains(&package.id))
        .filter(|package| {
            package
                .targets
                .iter()
                .any(|target| target.kind.iter().any(|candidate| candidate == kind))
        })
        .map(|package| package.id.clone())
        .collect()
}

fn upstream_identities(metadata: &CargoMetadata, package_ids: &BTreeSet<String>) -> Vec<String> {
    metadata
        .packages
        .iter()
        .filter(|package| package_ids.contains(&package.id))
        .map(upstream_identity)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn upstream_identity(package: &CargoPackage) -> String {
    if let Some(repository) = package.repository.as_deref() {
        let normalized = normalize_repository_url(repository);
        if !normalized.is_empty() {
            return format!("repository:{normalized}");
        }
    }
    match package.source.as_deref() {
        Some(source) if source.starts_with("registry+") => format!(
            "registry:{}#{}",
            normalize_source_url(source.trim_start_matches("registry+")),
            package.checksum.as_deref().unwrap_or("missing-checksum")
        ),
        Some(source) if source.starts_with("git+") => {
            let source = source.trim_start_matches("git+");
            let (url, revision) = source
                .rsplit_once('#')
                .map_or((source, "missing-revision"), |(url, revision)| {
                    (url, revision)
                });
            format!(
                "git:{}#{}",
                normalize_source_url(url),
                revision.to_ascii_lowercase()
            )
        }
        Some(source) => format!("source:{}", normalize_source_url(source)),
        None => format!("unknown:{}", package.id),
    }
}

fn normalize_repository_url(value: &str) -> String {
    let mut normalized = normalize_source_url(value);
    while normalized.ends_with('/') {
        normalized.pop();
    }
    if normalized.to_ascii_lowercase().ends_with(".git") {
        normalized.truncate(normalized.len() - 4);
    }
    normalized
}

fn normalize_source_url(value: &str) -> String {
    let value = value.trim();
    let Some((scheme, remainder)) = value.split_once("://") else {
        return value.trim_end_matches('/').to_owned();
    };
    let (authority, path) = remainder
        .split_once('/')
        .map_or((remainder, ""), |(authority, path)| (authority, path));
    let mut normalized = format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        authority.to_ascii_lowercase()
    );
    if !path.is_empty() {
        normalized.push('/');
        normalized.push_str(path.trim_end_matches('/'));
    }
    normalized
}

fn load_taxonomy(repo_root: &Path) -> Result<JsonValue> {
    let text = fs::read_to_string(repo_root.join(TAXONOMY_PATH))?;
    Ok(serde_json::from_str(&text)?)
}

fn taxonomy_refs_for(taxonomy: &JsonValue, package_name: &str) -> Result<Vec<TaxonomyRef>> {
    let classifications = taxonomy
        .get("classifications")
        .and_then(JsonValue::as_array)
        .ok_or("taxonomy classifications must be an array")?;
    let mut references = Vec::new();
    for row in classifications {
        let incumbents = row
            .get("incumbents")
            .and_then(JsonValue::as_array)
            .ok_or("taxonomy row incumbents must be an array")?;
        if !incumbents
            .iter()
            .filter_map(JsonValue::as_str)
            .any(|incumbent| incumbent == package_name)
        {
            continue;
        }
        references.push(TaxonomyRef {
            candidate_id: json_string(row, "candidate_id")?.to_owned(),
            class_id: json_string(row, "class_id")?.to_owned(),
            review_sensitivity_tags: row
                .get("review_sensitivity_tags")
                .and_then(JsonValue::as_array)
                .ok_or("taxonomy review_sensitivity_tags must be an array")?
                .iter()
                .map(|tag| {
                    tag.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| "taxonomy sensitivity tag must be a string".into())
                })
                .collect::<Result<Vec<_>>>()?,
            program_phase: json_string(row, "program_phase")?.to_owned(),
            program_verdict: json_string(row, "program_verdict")?.to_owned(),
        });
    }
    references.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
    Ok(references)
}

fn json_string<'a>(value: &'a JsonValue, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(JsonValue::as_str)
        .ok_or_else(|| format!("taxonomy field {key} must be a string").into())
}

fn safety_rank(class: &str) -> u8 {
    match class {
        "SAFE-OWN" => 1,
        "BOUNDARY-UNSAFE" => 2,
        "ALGORITHMIC-UNSAFE" => 3,
        _ => 4,
    }
}

fn native_evidence(
    resolution: &Resolution,
    package_ids: &BTreeSet<String>,
    direct_root_id: &str,
) -> Result<NativeEvidence> {
    let mut packages = Vec::new();
    let package_map = resolution
        .metadata
        .packages
        .iter()
        .map(|package| (package.id.as_str(), package))
        .collect::<BTreeMap<_, _>>();
    for package_id in package_ids {
        let package = package_map
            .get(package_id.as_str())
            .ok_or_else(|| format!("missing package for native evidence: {package_id}"))?;
        let mut evidence = Vec::new();
        let status = match package.name.as_str() {
            "ring" => {
                evidence.push(
                    "ring build.rs assembles and compiles target-specific native sources"
                        .to_owned(),
                );
                "active"
            }
            "aws-lc-sys" | "aws-lc-fips-sys" => {
                evidence.push(
                    "AWS-LC sys crate compiles and links native cryptographic code".to_owned(),
                );
                "active"
            }
            "libsqlite3-sys" => {
                evidence.push(
                    "rusqlite bundled feature activates the SQLite C amalgamation".to_owned(),
                );
                "active"
            }
            "rdkafka-sys" => {
                evidence.push(
                    "rdkafka-sys build.rs drives bundled configure/make or links librdkafka"
                        .to_owned(),
                );
                "active"
            }
            "psm" => {
                evidence.push("psm build.rs selects target assembly or a compiled shim".to_owned());
                "active"
            }
            "openssl-sys" | "libz-sys" | "zstd-sys" | "bzip2-sys" | "lzma-sys" => {
                evidence.push(format!(
                    "{} is a sys crate with a native build or link boundary",
                    package.name
                ));
                "active"
            }
            "signal-hook"
                if !has_active_package_dependency(&resolution.metadata, package_id, "cc") =>
            {
                evidence.push("signal-hook's cc build dependency is feature-declared but absent from this resolved closure".to_owned());
                "declared-inactive"
            }
            _ if package
                .targets
                .iter()
                .any(|target| target.kind.iter().any(|kind| kind == "custom-build")) =>
            {
                evidence.push("custom-build target is reachable but no package-specific native rule is registered".to_owned());
                "unknown"
            }
            _ => continue,
        };
        evidence.push(format!(
            "direct root package id for this measurement: {direct_root_id}"
        ));
        packages.push(NativePackageEvidence {
            package_id: package.id.clone(),
            status: status.to_owned(),
            evidence_sources: evidence,
        });
    }
    packages.sort_by(|left, right| left.package_id.cmp(&right.package_id));
    let status = if packages.iter().any(|package| package.status == "active") {
        "active"
    } else if packages.iter().any(|package| package.status == "unknown") {
        "unknown"
    } else if packages
        .iter()
        .any(|package| package.status == "declared-inactive")
    {
        "declared-inactive"
    } else {
        "none"
    };
    Ok(NativeEvidence {
        status: status.to_owned(),
        packages,
    })
}

fn has_active_package_dependency(
    metadata: &CargoMetadata,
    package_id: &str,
    dependency_name: &str,
) -> bool {
    let dependency_ids = metadata
        .packages
        .iter()
        .filter(|package| package.name == dependency_name)
        .map(|package| package.id.as_str())
        .collect::<BTreeSet<_>>();
    metadata
        .resolve
        .as_ref()
        .and_then(|resolve| resolve.nodes.iter().find(|node| node.id == package_id))
        .is_some_and(|node| {
            node.deps.iter().any(|dependency| {
                dependency.name == dependency_name
                    || dependency_ids.contains(dependency.pkg.as_str())
            })
        })
}

fn phase_forecasts(measurements: &[MarginalRecord]) -> Vec<PhaseForecast> {
    #[derive(Default)]
    struct Accumulator {
        marginals: BTreeSet<String>,
        sum: usize,
        edges: BTreeSet<String>,
    }
    let mut forecasts = BTreeMap::<(String, String, String), Accumulator>::new();
    for measurement in measurements {
        for taxonomy in &measurement.taxonomy_refs {
            let key = (
                measurement.feature_profile.clone(),
                measurement.target_triple.clone(),
                taxonomy.program_phase.clone(),
            );
            let accumulator = forecasts.entry(key).or_default();
            accumulator
                .marginals
                .extend(measurement.marginal_package_versions.iter().cloned());
            accumulator.sum += measurement.marginal_package_version_count;
            accumulator
                .edges
                .insert(measurement.direct_root_edge.clone());
        }
    }
    forecasts
        .into_iter()
        .map(
            |((feature_profile, target_triple, program_phase), accumulator)| {
                PhaseForecast {
                    feature_profile,
                    target_triple,
                    program_phase,
                    lower_bound_unique_individual_marginals: accumulator.marginals.len(),
                    upper_bound_sum_individual_marginals: accumulator.sum,
                    contributing_direct_root_edges: accumulator.edges.into_iter().collect(),
                    no_claim_boundary: "This generated interval combines individual-edge marginals; only a separately resolved multi-edge counterfactual can claim an exact phase result.".to_owned(),
                }
            },
        )
        .collect()
}

fn cargo_version() -> Result<String> {
    let output = Command::new("cargo").arg("--version").output()?;
    if !output.status.success() {
        return Err(format!(
            "cargo --version failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn rustc_verbose() -> Result<String> {
    let output = Command::new("rustc").arg("-vV").output()?;
    if !output.status.success() {
        return Err(format!(
            "rustc -vV failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn parse_host_triple(rustc_verbose: &str) -> Result<String> {
    rustc_verbose
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| "rustc -vV did not report a host triple".into())
}

fn git_head(repo_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_root)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn validate_source_commit(commit: &str) -> Result<String> {
    let commit = commit.trim();
    if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("--source-commit must be a full 40-character hexadecimal Git commit".into());
    }
    Ok(commit.to_ascii_lowercase())
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn safe_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_identity_normalization_is_deterministic() {
        assert_eq!(
            normalize_repository_url("HTTPS://GitHub.COM/Example/Repo.git/"),
            "https://github.com/Example/Repo"
        );
        assert_eq!(
            normalize_repository_url("https://github.com/Example/Repo.git"),
            "https://github.com/Example/Repo"
        );
    }

    #[test]
    fn missing_repository_metadata_fails_closed_per_package_id() {
        let package = CargoPackage {
            id: "path+file:///tmp/example#0.1.0".to_owned(),
            name: "example".to_owned(),
            source: None,
            manifest_path: "/tmp/example/Cargo.toml".to_owned(),
            repository: None,
            checksum: None,
            targets: Vec::new(),
        };
        assert_eq!(
            upstream_identity(&package),
            "unknown:path+file:///tmp/example#0.1.0"
        );
    }

    #[test]
    fn registry_identity_retains_source_and_missing_checksum() {
        let package = CargoPackage {
            id: "registry+https://github.com/rust-lang/crates.io-index#demo@1.0.0".to_owned(),
            name: "demo".to_owned(),
            source: Some("registry+https://github.com/rust-lang/crates.io-index".to_owned()),
            manifest_path: "/registry/demo/Cargo.toml".to_owned(),
            repository: None,
            checksum: None,
            targets: Vec::new(),
        };
        assert_eq!(
            upstream_identity(&package),
            "registry:https://github.com/rust-lang/crates.io-index#missing-checksum"
        );
    }

    #[test]
    fn dependency_inventory_distinguishes_kind_and_target() {
        let manifest = r#"[dependencies]
serde = "1"

[dev-dependencies]
serde = "1"

[target.'cfg(windows)'.dependencies]
windows-sys = "0.61"
        "#;
        let manifest = toml::from_str::<TomlValue>(manifest).expect("fixture TOML");
        let inventory = collect_direct_dependencies(&manifest).expect("dependency inventory");
        assert_eq!(
            inventory
                .iter()
                .map(|dependency| dependency.edge_id.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "normal:serde",
                "dev:serde",
                "target-normal:cfg(windows):windows-sys",
            ])
        );
    }

    #[test]
    fn counterfactual_removes_exact_edge_and_feature_references() {
        let manifest = r#"[features]
default = ["dep:serde", "serde?/derive", "other"]

[dependencies]
serde = { version = "1", optional = true }
other = "1"

[dev-dependencies]
serde = "1"
        "#;
        let mut manifest = toml::from_str::<TomlValue>(manifest).expect("fixture TOML");
        let dependency = DirectDependency {
            edge_id: "normal:serde".to_owned(),
            dependency_name: "serde".to_owned(),
            package_name: "serde".to_owned(),
            dependency_edge_kind: "normal".to_owned(),
            target_condition: None,
            optional: true,
            manifest_table: "dependencies".to_owned(),
        };
        remove_direct_dependency(&mut manifest, &dependency).expect("remove exact edge");
        assert!(
            manifest
                .get("dependencies")
                .and_then(TomlValue::as_table)
                .is_some_and(|table| !table.contains_key("serde"))
        );
        assert!(
            manifest
                .get("dev-dependencies")
                .and_then(TomlValue::as_table)
                .is_some_and(|table| table.contains_key("serde"))
        );
        assert_eq!(
            manifest
                .get("features")
                .and_then(|features| features.get("default"))
                .and_then(TomlValue::as_array)
                .expect("default feature"),
            &[TomlValue::String("other".to_owned())]
        );
    }

    #[test]
    fn dependency_kind_matching_preserves_host_target_distinction() {
        let build = DirectDependency {
            edge_id: "build:demo".to_owned(),
            dependency_name: "demo".to_owned(),
            package_name: "demo".to_owned(),
            dependency_edge_kind: "build".to_owned(),
            target_condition: None,
            optional: false,
            manifest_table: "build-dependencies".to_owned(),
        };
        assert!(dep_kind_matches(
            &build,
            &CargoDepKind {
                kind: Some("build".to_owned()),
                target: None,
            }
        ));
        assert!(!dep_kind_matches(
            &build,
            &CargoDepKind {
                kind: None,
                target: None,
            }
        ));
    }

    #[test]
    fn active_dependency_is_edge_local_not_closure_global() {
        let mut metadata = CargoMetadata {
            packages: vec![
                CargoPackage {
                    id: "signal-hook-id".to_owned(),
                    name: "signal-hook".to_owned(),
                    source: None,
                    manifest_path: "/registry/signal-hook/Cargo.toml".to_owned(),
                    repository: None,
                    checksum: None,
                    targets: Vec::new(),
                },
                CargoPackage {
                    id: "cc-id".to_owned(),
                    name: "cc".to_owned(),
                    source: None,
                    manifest_path: "/registry/cc/Cargo.toml".to_owned(),
                    repository: None,
                    checksum: None,
                    targets: Vec::new(),
                },
            ],
            resolve: Some(CargoResolve {
                nodes: vec![CargoNode {
                    id: "signal-hook-id".to_owned(),
                    deps: Vec::new(),
                }],
            }),
            workspace_members: Vec::new(),
        };
        assert!(!has_active_package_dependency(
            &metadata,
            "signal-hook-id",
            "cc"
        ));

        metadata
            .resolve
            .as_mut()
            .expect("fixture resolve graph")
            .nodes[0]
            .deps
            .push(CargoNodeDep {
                name: "cc".to_owned(),
                pkg: "cc-id".to_owned(),
                dep_kinds: vec![CargoDepKind {
                    kind: Some("build".to_owned()),
                    target: None,
                }],
            });
        assert!(has_active_package_dependency(
            &metadata,
            "signal-hook-id",
            "cc"
        ));
    }

    #[test]
    fn safe_components_cannot_escape_the_owned_work_directory() {
        assert_eq!(
            safe_component("target-normal:cfg(unix):xattr"),
            "target-normal_cfg_unix__xattr"
        );
        assert!(!safe_component("../../outside").contains('/'));
    }
}
