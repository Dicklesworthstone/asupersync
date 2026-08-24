//! Fail-closed contract for the R3.2.1 regex Unicode table packet.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const CONTRACT_PATH: &str = "artifacts/regex_unicode_table_contract_v1.json";
const INVENTORY_PATH: &str = "artifacts/regex_privacy_capability_inventory_v1.json";
const TERMINAL_RECEIPT_PATH: &str = "artifacts/regex_syntax_terminal_receipt_v1.json";
const DOC_PATH: &str = "docs/regex_unicode_table_contract.md";
const BEAD_ID: &str = "asupersync-5z2scg.8.3.2.1";
const CAPABILITY_ID: &str = "CAP-REGEX-PRIVACY";

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("failed to read {relative}: {error}"))
}

fn read_repo_bytes(relative: &str) -> Vec<u8> {
    fs::read(repo_path(relative))
        .unwrap_or_else(|error| panic!("failed to read {relative}: {error}"))
}

fn parse_repo_json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|error| panic!("failed to parse {relative}: {error}"))
}

fn object<'a>(value: &'a Value, key: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{key} must be an object"))
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{key} must be an array"))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be text"))
}

fn number(value: &Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{key} must be an unsigned integer"))
}

fn boolean(value: &Value, key: &str) -> Result<bool, String> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{key} must be a boolean"))
}

fn object_value(value: &Value, key: &str) -> Result<Value, String> {
    Ok(Value::Object(object(value, key)?.clone()))
}

fn row_ids(rows: &[Value], key: &str) -> Result<BTreeSet<String>, String> {
    rows.iter()
        .map(|row| text(row, key).map(str::to_owned))
        .collect()
}

fn exact_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn sha256(relative: &str) -> String {
    hex::encode(Sha256::digest(read_repo_bytes(relative)))
}

fn expected_input_rows() -> BTreeMap<&'static str, (u64, &'static str)> {
    BTreeMap::from([
        (
            "ReadMe.txt",
            (
                693,
                "14cafa23788d3a20dd21d6b0cdcb8d6dab520781fcd9ad9392f3b88ea607e633",
            ),
        ),
        (
            "PropertyAliases.txt",
            (
                9_389,
                "33a9f2266ad6b8e8de05c0ea3dfac411ac62cf8839ff1c94057471e4c5f6a2b3",
            ),
        ),
        (
            "PropertyValueAliases.txt",
            (
                80_773,
                "440fd3e5460b9bfe31da67b6f923992e1989d31fe2ed91e091c4b8f8e2620bf9",
            ),
        ),
        (
            "DerivedAge.txt",
            (
                134_680,
                "60caa81b99a4dfb0bc5d38440d323073e3f356f46f9ca7869da848cd0715408b",
            ),
        ),
        (
            "PropList.txt",
            (
                144_253,
                "53d614508e2a0b2305a8aa21cd60d993de9326cdf65993660dfcce4503548583",
            ),
        ),
        (
            "DerivedCoreProperties.txt",
            (
                1_115_959,
                "39d35161f2954497f69e08bdb9e701493f476a3d30222de20028feda36c1dabd",
            ),
        ),
        (
            "UnicodeData.txt",
            (
                2_175_362,
                "ff58e5823bd095166564a006e47d111130813dcf8bf234ef79fa51a870edb48f",
            ),
        ),
        (
            "emoji/emoji-data.txt",
            (
                113_024,
                "f1365a5173eee18e1f98b240cdc492e84a25f1ce7e0c9d1094eb29c41a22696a",
            ),
        ),
        (
            "CaseFolding.txt",
            (
                86_092,
                "6f1f9c588eb4a5c718d9e8f93b782685e5c7fec872cf05e8e6878053599e09bb",
            ),
        ),
        (
            "Scripts.txt",
            (
                189_588,
                "9e88f0a677df47311106340be8ede2ecdacd9c1c931831218d2be6d5508e0039",
            ),
        ),
        (
            "ScriptExtensions.txt",
            (
                20_576,
                "049117ce26b9769fe2749b06eef51a50a89faef4a97764dd2d81daa715980700",
            ),
        ),
        (
            "auxiliary/GraphemeBreakProperty.txt",
            (
                98_751,
                "c29360bd6f7132811d701d29069541e827eb44bfc4c8fbde8c370d6982689dc1",
            ),
        ),
        (
            "auxiliary/WordBreakProperty.txt",
            (
                112_730,
                "476464e71a4b7b779b8ba7c5671f4338fea77da8e6b6b05fb82b3fdd14603779",
            ),
        ),
        (
            "auxiliary/SentenceBreakProperty.txt",
            (
                218_895,
                "20aab5eca3842c7a27cc6756d74488a4a5f744c8dca2948ec1128f26a60d1f79",
            ),
        ),
    ])
}

fn expected_generated_rows() -> BTreeMap<&'static str, (&'static str, u64, &'static str)> {
    BTreeMap::from([
        (
            "age",
            (
                "ucd-generate age ucd-16.0.0 --chars",
                40_438,
                "71b7cf52acdb4aa98b44145303b8efbfa94913235493521941ef1e0092a0ffe2",
            ),
        ),
        (
            "case-folding-simple",
            (
                "ucd-generate case-folding-simple ucd-16.0.0 --chars --all-pairs",
                67_576,
                "7622c7f7f03ac0dc2f2bcd51c81a217d64de0cc912f62f1add5f676603a02456",
            ),
        ),
        (
            "general-category",
            (
                "ucd-generate general-category ucd-16.0.0 --chars --exclude surrogate",
                158_564,
                "9488e3721f7c2ae20e1b77fcff9a59b4ed8f22954b8645ea6d8592eac1856423",
            ),
        ),
        (
            "grapheme-cluster-break",
            (
                "ucd-generate grapheme-cluster-break ucd-16.0.0 --chars",
                32_905,
                "0dd9d66bad598f4ec3451b6699f05c17c52079e37d463baf6385bbe51aa218f1",
            ),
        ),
        (
            "perl-word",
            (
                "ucd-generate perl-word ucd-16.0.0 --chars",
                18_305,
                "30f073baae28ea34c373c7778c00f20c1621c3e644404eff031f7d1cc8e9c9e2",
            ),
        ),
        (
            "property-bool",
            (
                "ucd-generate property-bool ucd-16.0.0 --chars",
                266_293,
                "66cf5bd2a1438bf9694152f077a285cf014fbd50b9dd63a97233b2ea61d64962",
            ),
        ),
        (
            "property-names",
            (
                "ucd-generate property-names ucd-16.0.0",
                10_930,
                "8c93985d1bcb01735667a3c4cb92f7e260d267326bde9d7f048bc77cd7e07855",
            ),
        ),
        (
            "property-values",
            (
                "ucd-generate property-values ucd-16.0.0 --include gc,script,scx,age,gcb,wb,sb",
                33_890,
                "ef9131ce0a575c7327ec6d466aafd8b7c25600d80c232b5a4110bbf0a5a59136",
            ),
        ),
        (
            "script",
            (
                "ucd-generate script ucd-16.0.0 --chars",
                34_715,
                "41bd424f1e3a03290cf4995ced678dcf24c94b38c905c62f6819bf67e098a2ec",
            ),
        ),
        (
            "script-extension",
            (
                "ucd-generate script-extension ucd-16.0.0 --chars",
                43_190,
                "a314099ddbf50a07fe350bb0835bf2fe494ed5ad278b30e171e21506eb557906",
            ),
        ),
        (
            "sentence-break",
            (
                "ucd-generate sentence-break ucd-16.0.0 --chars",
                53_345,
                "be84fbe8c5c67e761b16fe6c27f16664dbb145357835cd6b92bc2a4a4c52ee79",
            ),
        ),
        (
            "word-break",
            (
                "ucd-generate word-break ucd-16.0.0 --chars",
                26_915,
                "c551681ad49ec28c7ae32bab1371945821c736ca8f0de410cb89f28066ec2ecf",
            ),
        ),
    ])
}

fn validate_contract(contract: &Value, inventory: &Value, terminal: &Value) -> Result<(), String> {
    if number(contract, "schema_version")? != 1
        || text(contract, "artifact_id")? != "regex-unicode-table-contract-v1"
        || text(contract, "program_id")? != "dependency-sovereignty"
        || text(contract, "bead_id")? != BEAD_ID
        || text(contract, "capability_id")? != CAPABILITY_ID
    {
        return Err("contract identity drifted".to_owned());
    }
    if text(inventory, "capability_id")? != CAPABILITY_ID {
        return Err("R1 capability identity drifted".to_owned());
    }
    if text(&object_value(terminal, "decision")?, "syntax_disposition")? != "KEEP_INCUMBENT_DEFER" {
        return Err("R3.1 terminal disposition no longer preserves the incumbent".to_owned());
    }

    let expected_source_digests = BTreeMap::from([
        (
            "Cargo.toml",
            "0f02e4fefedf5e9013054df794ece6f8fb259134fdbd95376e61d486c043fde3",
        ),
        (
            "Cargo.lock",
            "513cfba8f8671e69aab32317e042bd00737b9bfb30e2234012d6605f320f7a6a",
        ),
        (
            INVENTORY_PATH,
            "79705748f670ed1708339f285c7558bcb014db55135b5bcc42e04d09065ab5f9",
        ),
        (
            TERMINAL_RECEIPT_PATH,
            "410afeaeb0250a36b8d91c1a78b612c942d729fd495e7752c3f5965bbe8d5fbe",
        ),
    ]);
    let digest_rows = array(contract, "source_digests")?;
    if digest_rows.len() != expected_source_digests.len() {
        return Err("source digest row count drifted".to_owned());
    }
    for row in digest_rows {
        let path = text(row, "path")?;
        let expected = expected_source_digests
            .get(path)
            .ok_or_else(|| format!("unexpected source digest row {path}"))?;
        if text(row, "sha256")? != *expected || sha256(path) != *expected {
            return Err(format!("source digest drifted for {path}"));
        }
    }

    let decision = object_value(contract, "decision")?;
    if text(&decision, "disposition")? != "KEEP_INCUMBENT_DEFER"
        || text(&decision, "incumbent_state")? != "RETAIN_REGEX_SYNTAX_TABLES"
        || text(&decision, "owned_table_state")? != "NOT_AUTHORIZED"
        || boolean(&decision, "cutover_eligible")?
        || boolean(&decision, "dependency_removal_authorized")?
        || boolean(&decision, "hand_curated_subset_authorized")?
    {
        return Err("fail-closed decision drifted".to_owned());
    }
    for key in [
        "on_missing_input_table_or_checksum",
        "on_budget_regression",
        "on_validation_divergence",
    ] {
        if text(&decision, key)? != "KEEP_INCUMBENT_DEFER" {
            return Err(format!("{key} no longer fails closed"));
        }
    }
    let reason_codes = array(&decision, "reason_codes")?;
    let reason_code_set = reason_codes
        .iter()
        .map(|reason| {
            reason
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "reason code must be text".to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if reason_code_set
        != exact_set(&[
            "FULL_DEFAULT_UNICODE_SURFACE_REQUIRED",
            "UPSTREAM_TABLES_ARE_VERSIONED_AND_CHECKSUM_PINNED",
            "OWNED_TABLES_NOT_SHOWN_MATERIALLY_SAFER_OR_SMALLER",
            "INDEPENDENT_REGENERATION_PROBE_BLOCKED",
            "ISOLATED_BINARY_AND_COMPILE_DELTA_MISSING",
        ])
    {
        return Err("decision reason codes drifted".to_owned());
    }

    let unicode = object_value(contract, "unicode_source")?;
    if text(&unicode, "authority")? != "Unicode Character Database"
        || text(&unicode, "version")? != "16.0.0"
        || text(&unicode, "release_date")? != "2024-09-10"
        || number(&unicode, "archive_bytes")? != 9_020_779
        || text(&unicode, "archive_sha256")?
            != "c86dd81f2b14a43b0cc064aa5f89aa7241386801e35c59c7984e579832634eb2"
        || number(&unicode, "consumed_input_bytes")? != 4_500_765
    {
        return Err("Unicode authority pin drifted".to_owned());
    }
    let input_rows = array(&unicode, "consumed_files")?;
    let expected_inputs = expected_input_rows();
    if input_rows.len() != expected_inputs.len()
        || row_ids(input_rows, "path")?
            != expected_inputs
                .keys()
                .map(|path| (*path).to_owned())
                .collect()
    {
        return Err("authoritative input coverage drifted".to_owned());
    }
    let mut input_bytes = 0;
    for row in input_rows {
        let path = text(row, "path")?;
        let (expected_bytes, expected_digest) = expected_inputs
            .get(path)
            .ok_or_else(|| format!("unexpected input {path}"))?;
        let bytes = number(row, "bytes")?;
        if bytes != *expected_bytes || text(row, "sha256")? != *expected_digest {
            return Err(format!("authoritative input checksum drifted for {path}"));
        }
        input_bytes += bytes;
    }
    if input_bytes != number(&unicode, "consumed_input_bytes")? {
        return Err("authoritative input byte total drifted".to_owned());
    }
    let excluded = array(&unicode, "explicit_no_claim_inputs")?;
    if excluded.len() != 1
        || text(&excluded[0], "path")? != "DerivedNormalizationProps.txt"
        || !text(&excluded[0], "reason")?.contains("not evidence for full case folding")
    {
        return Err("normalization/full-fold no-claim boundary drifted".to_owned());
    }

    let generator = object_value(contract, "generator")?;
    if text(&generator, "package")? != "ucd-generate"
        || text(&generator, "version")? != "0.3.1"
        || text(&generator, "crate_sha256")?
            != "3a1a792412c6bf3cd714750a2595c4cdf609c6a12a0f805c77c7d3b1181ff85b"
        || text(&generator, "license")? != "MIT OR Apache-2.0"
        || array(&generator, "generation_preconditions")?.len() != 5
    {
        return Err("generator pin or admission policy drifted".to_owned());
    }
    let regeneration = object_value(&generator, "regeneration_probe")?;
    if text(&regeneration, "state")? != "BLOCKED_RCH_PREFLIGHT"
        || !boolean(&regeneration, "remote_compilation_required")?
        || boolean(&regeneration, "local_fallback_used")?
        || !boolean(&regeneration, "published_source_fetched")?
        || boolean(&regeneration, "compiler_started")?
        || boolean(&regeneration, "admissible_as_regeneration_proof")?
        || text(&regeneration, "disposition")? != "KEEP_INCUMBENT_DEFER"
    {
        return Err("blocked regeneration receipt drifted or was overclaimed".to_owned());
    }

    let table_rows = array(&generator, "generated_tables")?;
    let expected_tables = expected_generated_rows();
    if table_rows.len() != expected_tables.len()
        || row_ids(table_rows, "table_id")?
            != expected_tables
                .keys()
                .map(|table| (*table).to_owned())
                .collect()
    {
        return Err("generated table coverage drifted".to_owned());
    }
    let input_ids = expected_inputs
        .keys()
        .map(|path| (*path).to_owned())
        .collect::<BTreeSet<_>>();
    let mut generated_bytes = 0;
    for row in table_rows {
        let table_id = text(row, "table_id")?;
        let (expected_command, expected_bytes, expected_digest) = expected_tables
            .get(table_id)
            .ok_or_else(|| format!("unexpected table {table_id}"))?;
        let (expected_output, expected_input_paths): (&str, &[&str]) = match table_id {
            "age" => ("age.rs", &["DerivedAge.txt", "PropertyValueAliases.txt"]),
            "case-folding-simple" => ("case_folding_simple.rs", &["CaseFolding.txt"]),
            "general-category" => (
                "general_category.rs",
                &["UnicodeData.txt", "PropertyValueAliases.txt"],
            ),
            "grapheme-cluster-break" => (
                "grapheme_cluster_break.rs",
                &[
                    "auxiliary/GraphemeBreakProperty.txt",
                    "PropertyValueAliases.txt",
                ],
            ),
            "perl-word" => (
                "perl_word.rs",
                &[
                    "PropList.txt",
                    "DerivedCoreProperties.txt",
                    "UnicodeData.txt",
                ],
            ),
            "property-bool" => (
                "property_bool.rs",
                &[
                    "PropList.txt",
                    "DerivedCoreProperties.txt",
                    "UnicodeData.txt",
                    "emoji/emoji-data.txt",
                ],
            ),
            "property-names" => ("property_names.rs", &["PropertyAliases.txt"]),
            "property-values" => ("property_values.rs", &["PropertyValueAliases.txt"]),
            "script" => ("script.rs", &["Scripts.txt", "PropertyValueAliases.txt"]),
            "script-extension" => (
                "script_extension.rs",
                &[
                    "Scripts.txt",
                    "ScriptExtensions.txt",
                    "PropertyValueAliases.txt",
                ],
            ),
            "sentence-break" => (
                "sentence_break.rs",
                &[
                    "auxiliary/SentenceBreakProperty.txt",
                    "PropertyValueAliases.txt",
                ],
            ),
            "word-break" => (
                "word_break.rs",
                &[
                    "auxiliary/WordBreakProperty.txt",
                    "PropertyValueAliases.txt",
                ],
            ),
            _ => return Err(format!("missing exact output/input map for {table_id}")),
        };
        let bytes = number(row, "bytes")?;
        if text(row, "command")? != *expected_command
            || bytes != *expected_bytes
            || text(row, "sha256")? != *expected_digest
            || text(row, "output")? != expected_output
            || !Path::new(expected_output)
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
        {
            return Err(format!("generated receipt drifted for {table_id}"));
        }
        let inputs = array(row, "inputs")?;
        if inputs.is_empty() {
            return Err(format!("{table_id} lost its authoritative input mapping"));
        }
        let actual_input_paths = inputs
            .iter()
            .map(|input| {
                input
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{table_id} input must be text"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if actual_input_paths
            != expected_input_paths
                .iter()
                .map(|input| (*input).to_owned())
                .collect()
        {
            return Err(format!("{table_id} authoritative input map drifted"));
        }
        for input in actual_input_paths {
            if !input_ids.contains(&input) {
                return Err(format!("{table_id} references unknown input {input}"));
            }
        }
        generated_bytes += bytes;
    }
    if generated_bytes != 787_066 {
        return Err("generated table byte total drifted".to_owned());
    }
    let wiring = object_value(&generator, "module_wiring")?;
    if text(&wiring, "output")? != "mod.rs"
        || number(&wiring, "bytes")? != 1_258
        || text(&wiring, "sha256")?
            != "26c837099cd934c8062e24bc9a0aaecf15fe1de03f9c6da3f3e1e5ac3ca24bee"
    {
        return Err("module wiring receipt drifted".to_owned());
    }
    let fallbacks = array(&generator, "disabled_fallback_tables")?;
    if fallbacks.len() != 2
        || row_ids(fallbacks, "output")? != exact_set(&["perl_decimal.rs", "perl_space.rs"])
        || fallbacks
            .iter()
            .map(|row| number(row, "bytes"))
            .sum::<Result<u64, _>>()?
            != 2_529
    {
        return Err("disabled fallback table accounting drifted".to_owned());
    }

    let feature_rows = array(contract, "feature_surface")?;
    let expected_features = exact_set(&[
        "unicode-age",
        "unicode-bool",
        "unicode-case",
        "unicode-gencat",
        "unicode-perl",
        "unicode-script",
        "unicode-segment",
    ]);
    if feature_rows.len() != expected_features.len()
        || row_ids(feature_rows, "feature")? != expected_features
    {
        return Err("full default Unicode feature surface drifted".to_owned());
    }
    let table_ids = expected_tables
        .keys()
        .map(|table| (*table).to_owned())
        .collect::<BTreeSet<_>>();
    let mut referenced_tables = BTreeSet::new();
    for row in feature_rows {
        if array(row, "semantics")?.is_empty() || array(row, "tables")?.is_empty() {
            return Err("feature row lost semantics or tables".to_owned());
        }
        for table in array(row, "tables")? {
            let table = table
                .as_str()
                .ok_or_else(|| "feature table reference must be text".to_owned())?;
            if !table_ids.contains(table) {
                return Err(format!("feature references unknown table {table}"));
            }
            referenced_tables.insert(table.to_owned());
        }
    }
    if referenced_tables != table_ids {
        return Err("not every generated table is owned by a feature row".to_owned());
    }

    let r1_rows = array(contract, "r1_semantic_rows")?;
    let expected_r1 = exact_set(&[
        "RGX-SYN-010",
        "RGX-SYN-011",
        "RGX-SYN-013",
        "RGX-SYN-014",
        "RGX-SYN-019",
        "RGX-SYN-020",
        "RGX-SYN-021",
    ]);
    if r1_rows.len() != expected_r1.len() || row_ids(r1_rows, "case_id")? != expected_r1 {
        return Err("R1 Unicode semantic join drifted".to_owned());
    }
    let inventory_ids = row_ids(array(inventory, "syntax_corpus")?, "case_id")?;
    if !expected_r1.is_subset(&inventory_ids) {
        return Err("R1 inventory lost a required Unicode row".to_owned());
    }

    let budgets = object_value(contract, "budgets")?;
    if number(&budgets, "authoritative_archive_bytes")? != 9_020_779
        || number(&budgets, "consumed_input_bytes")? != 4_500_765
        || number(&budgets, "enabled_generated_table_bytes")? != generated_bytes
        || number(&budgets, "module_plus_enabled_table_bytes")? != 788_324
        || number(&budgets, "unicode_license_bytes")? != 2_847
        || number(&budgets, "disabled_fallback_table_bytes")? != 2_529
        || number(&budgets, "incumbent_regex_stack_crate_archive_bytes")? != 1_327_744
        || number(&budgets, "owned_source_parity_ceiling_bytes")? != 788_324
        || number(&budgets, "material_source_reduction_min_percent")? != 20
    {
        return Err("source or archive budget drifted".to_owned());
    }
    let graph = object_value(&budgets, "dependency_graph")?;
    if number(&graph, "base_unique_packages")? != 135
        || number(&graph, "metrics_unique_packages")? != 152
        || number(&graph, "metrics_aggregate_marginal_packages")? != 17
        || number(&graph, "regex_stack_marginal_packages")? != 4
        || number(&graph, "regex_stack_build_scripts")? != 0
        || number(&graph, "regex_stack_proc_macros")? != 0
        || number(&graph, "regex_stack_native_code_packages")? != 0
    {
        return Err("dependency or compile-unit delta drifted".to_owned());
    }
    let packages = array(&graph, "regex_stack_packages")?;
    if packages.len() != 4
        || packages
            .iter()
            .map(|row| number(row, "archive_bytes"))
            .sum::<Result<u64, _>>()?
            != 1_327_744
    {
        return Err("regex stack archive accounting drifted".to_owned());
    }
    let cargo_lock = read_repo_file("Cargo.lock");
    for row in packages {
        for value in ["package", "version", "sha256"] {
            if !cargo_lock.contains(text(row, value)?) {
                return Err(format!("Cargo.lock lost pinned {value} for regex stack"));
            }
        }
    }

    let compile_probe = object_value(&budgets, "compile_and_binary_probe")?;
    if text(&compile_probe, "worker")? != "hz2"
        || number(&compile_probe, "build_id")? != 29_947_326_818_680_879
        || text(&compile_probe, "terminal_state")? != "BLOCKED_STALE_PROGRESS_CANCELLED"
        || !boolean(&compile_probe, "heartbeat_fresh")?
        || number(&compile_probe, "progress_age_seconds_at_inspection")? != 223
        || boolean(&compile_probe, "artifact_measurement_admissible")?
        || boolean(&compile_probe, "metrics_comparison_started")?
        || boolean(&compile_probe, "local_fallback_used")?
    {
        return Err("blocked compile/binary probe drifted or was overclaimed".to_owned());
    }
    let cutover = object_value(&budgets, "future_cutover_gate")?;
    if !boolean(&cutover, "same_worker_same_toolchain_required")?
        || number(&cutover, "cold_runs_per_profile")? != 5
        || number(&cutover, "release_artifact_growth_max_percent")? != 0
        || number(&cutover, "compile_time_regression_max_percent")? != 5
        || number(&cutover, "new_build_scripts_max")? != 0
        || number(&cutover, "new_proc_macros_max")? != 0
        || number(&cutover, "new_native_code_packages_max")? != 0
        || text(&cutover, "missing_measurement_disposition")? != "KEEP_INCUMBENT_DEFER"
    {
        return Err("future cutover budget no longer fails closed".to_owned());
    }

    let validation = object_value(contract, "independent_validation")?;
    let runtime_cases = array(&validation, "runtime_cases")?
        .iter()
        .map(|case| {
            case.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "runtime case must be text".to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mutation_cases = array(&validation, "mutation_cases")?
        .iter()
        .map(|case| {
            case.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "mutation case must be text".to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if text(&validation, "required_feature")? != "metrics"
        || runtime_cases
            != exact_set(&[
                "UCD16-AGE-NEW-CYRILLIC",
                "UCD16-BOOL-EXTENDED-PICTOGRAPHIC",
                "UCD16-CASE-SIMPLE-SIGMA",
                "UCD16-CASE-NO-FULL-FOLD",
                "UCD16-GENCAT-LETTER",
                "UCD16-PERL-DECIMAL",
                "UCD16-PERL-SPACE",
                "UCD16-PERL-WORD",
                "UCD16-SCRIPT-GREEK",
                "UCD16-SCRIPT-EXTENSION",
                "UCD16-GCB-EXTEND",
                "UCD16-WB-KATAKANA",
                "UCD16-SB-ATERM",
                "UCD16-WORD-BOUNDARY-GREEK",
                "UCD16-ASCII-WORD-BOUNDARY",
                "UCD16-UNKNOWN-PROPERTY-REJECTED",
            ])
        || row_ids(
            &array(&validation, "r1_rows_replayed")?
                .iter()
                .map(|case| serde_json::json!({"case_id": case}))
                .collect::<Vec<_>>(),
            "case_id",
        )? != expected_r1
        || mutation_cases
            != exact_set(&[
                "UNICODE_VERSION_DRIFT",
                "MISSING_UCD_INPUT",
                "GENERATED_CHECKSUM_DRIFT",
                "MISSING_FEATURE_SURFACE",
                "CUTOVER_WITH_BLOCKED_REGENERATION",
                "CUTOVER_WITHOUT_BINARY_MEASUREMENT",
            ])
        || text(&validation, "test")? != "tests/regex_unicode_table_contract.rs"
    {
        return Err("independent validation inventory drifted".to_owned());
    }

    let licensing = object_value(contract, "licensing")?;
    if text(&licensing, "unicode_data_license_file")?
        != "regex-syntax-0.8.11/src/unicode_tables/LICENSE-UNICODE"
        || number(&licensing, "unicode_data_license_bytes")? != 2_847
        || text(&licensing, "unicode_data_license_sha256")?
            != "74db5baf44a41b1000312c673544b3374e4198af5605c7f9080a402cec42cfa3"
        || text(&licensing, "regex_syntax_license")? != "MIT OR Apache-2.0"
    {
        return Err("Unicode or crate licensing receipt drifted".to_owned());
    }
    if array(contract, "no_claims")?.len() != 8
        || !boolean(&object_value(contract, "replay")?, "no_local_fallback")?
    {
        return Err("no-claim or replay boundary drifted".to_owned());
    }

    Ok(())
}

#[test]
fn machine_contract_is_complete_and_fail_closed() {
    let contract = parse_repo_json(CONTRACT_PATH);
    let inventory = parse_repo_json(INVENTORY_PATH);
    let terminal = parse_repo_json(TERMINAL_RECEIPT_PATH);
    validate_contract(&contract, &inventory, &terminal).expect("valid Unicode table contract");
}

#[test]
fn contract_rejects_version_table_feature_and_cutover_drift() {
    let contract = parse_repo_json(CONTRACT_PATH);
    let inventory = parse_repo_json(INVENTORY_PATH);
    let terminal = parse_repo_json(TERMINAL_RECEIPT_PATH);

    let mut version_drift = contract.clone();
    version_drift["unicode_source"]["version"] = Value::String("15.1.0".to_owned());
    assert!(validate_contract(&version_drift, &inventory, &terminal).is_err());

    let mut missing_input = contract.clone();
    missing_input["unicode_source"]["consumed_files"]
        .as_array_mut()
        .expect("consumed files")
        .pop();
    assert!(validate_contract(&missing_input, &inventory, &terminal).is_err());

    let mut checksum_drift = contract.clone();
    checksum_drift["generator"]["generated_tables"][0]["sha256"] = Value::String("0".repeat(64));
    assert!(validate_contract(&checksum_drift, &inventory, &terminal).is_err());

    let mut missing_feature = contract.clone();
    missing_feature["feature_surface"]
        .as_array_mut()
        .expect("feature surface")
        .pop();
    assert!(validate_contract(&missing_feature, &inventory, &terminal).is_err());

    let mut blocked_regeneration_cutover = contract.clone();
    blocked_regeneration_cutover["decision"]["cutover_eligible"] = Value::Bool(true);
    assert!(validate_contract(&blocked_regeneration_cutover, &inventory, &terminal).is_err());

    let mut missing_binary_cutover = contract.clone();
    missing_binary_cutover["decision"]["cutover_eligible"] = Value::Bool(true);
    missing_binary_cutover["generator"]["regeneration_probe"]["admissible_as_regeneration_proof"] =
        Value::Bool(true);
    assert!(validate_contract(&missing_binary_cutover, &inventory, &terminal).is_err());
}

#[test]
fn operator_document_tracks_the_machine_boundary() {
    let doc = read_repo_file(DOC_PATH);
    for required in [
        "<!-- BEGIN REGEX UNICODE TABLE CONTRACT -->",
        "<!-- END REGEX UNICODE TABLE CONTRACT -->",
        "KEEP_INCUMBENT_DEFER",
        "Unicode Character Database 16.0.0",
        "ucd-generate@0.3.1",
        "BLOCKED_RCH_PREFLIGHT",
        "788,324",
        "29947326818680879",
        "No local Cargo fallback is approved.",
        "does not authorize removing `regex` or `regex-syntax`",
    ] {
        assert!(
            doc.contains(required),
            "operator document lost required marker: {required}"
        );
    }
}

#[cfg(feature = "metrics")]
#[test]
fn pinned_incumbent_independently_exercises_every_unicode_table_family() {
    use regex::Regex;

    let matches = |pattern: &str, haystack: &str| {
        Regex::new(pattern)
            .unwrap_or_else(|error| panic!("failed to compile {pattern:?}: {error}"))
            .is_match(haystack)
    };

    let age_16 = [r"^\p", "{Age:16.0}", "$"].concat();
    let hiragana_script_extension = [r"^\p", "{scx:Hira}", "$"].concat();
    let unknown_property = [r"\p", "{DefinitelyNotAProperty}"].concat();

    assert!(matches(&age_16, "\u{1C89}"));
    assert!(matches(r"^\p{Extended_Pictographic}$", "😀"));
    assert!(matches(r"(?i)^σ$", "Σ"));
    assert!(matches(r"(?i)^σ$", "ς"));
    assert!(!matches(r"(?i)^ß$", "SS"));
    assert!(matches(r"^\p{Letter}+$", "κρυφό"));
    assert!(matches(r"^\d+$", "١٢٣٤"));
    assert!(matches(r"^\s$", "\u{00A0}"));
    assert!(matches(r"^\w$", "\u{200C}"));
    assert!(matches(r"^\p{Greek}+$", "κρυφό"));
    assert!(matches(&hiragana_script_extension, "ー"));
    assert!(matches(r"^\p{gcb=Extend}$", "\u{0301}"));
    assert!(matches(r"^\p{wb=Katakana}$", "カ"));
    assert!(matches(r"^\p{sb=ATerm}$", "."));
    assert!(matches(r"\bκόσμος\b", "ο κόσμος εδώ"));
    assert!(matches(r"(?-u:\b)secret(?-u:\b)", "$$secret$$"));
    assert!(Regex::new(&unknown_property).is_err());
}

#[cfg(feature = "metrics")]
#[test]
fn frozen_r1_unicode_rows_replay_against_the_pinned_incumbent() {
    use regex::Regex;

    let inventory = parse_repo_json(INVENTORY_PATH);
    let required = exact_set(&[
        "RGX-SYN-010",
        "RGX-SYN-011",
        "RGX-SYN-013",
        "RGX-SYN-014",
        "RGX-SYN-019",
        "RGX-SYN-020",
        "RGX-SYN-021",
    ]);
    let rows = array(&inventory, "syntax_corpus").expect("syntax corpus");
    let mut observed = BTreeSet::new();
    for row in rows {
        let case_id = text(row, "case_id").expect("case id");
        if !required.contains(case_id) {
            continue;
        }
        let pattern = text(row, "pattern").expect("pattern");
        let haystack = text(row, "haystack").expect("haystack");
        let regex = Regex::new(pattern)
            .unwrap_or_else(|error| panic!("{case_id} failed to compile: {error}"));
        assert_eq!(
            regex.is_match(haystack),
            boolean(row, "matches").expect("expected match"),
            "{case_id} changed incumbent behavior"
        );
        observed.insert(case_id.to_owned());
    }
    assert_eq!(observed, required);
}
