#![allow(missing_docs)]

use asupersync::atp::manifest::Manifest;
use asupersync::atp::object::{
    MetadataPolicy, Object, ObjectEdge, ObjectGraph, ObjectGraphError, ObjectId, ObjectKind,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathDecision {
    Include,
    DenyLink,
    RejectTraversal,
}

#[derive(Debug, Clone)]
struct MaterializedObject {
    relative_path: String,
    object_id: ObjectId,
    kind: ObjectKind,
    size_bytes: Option<u64>,
}

#[derive(Debug)]
struct DirectoryTransferProof {
    source_root: PathBuf,
    receive_root: PathBuf,
    journal_path: PathBuf,
    proof_path: PathBuf,
    log_path: PathBuf,
    graph: ObjectGraph,
    root_id: ObjectId,
    materialized: Vec<MaterializedObject>,
    events: Vec<Value>,
    source_hash: [u8; 32],
    receive_hash: [u8; 32],
}

#[test]
fn directory_object_graph_matrix_transfers_real_tree_with_proof_logs()
-> Result<(), Box<dyn std::error::Error>> {
    let run_root = unique_run_root("directory_matrix");
    let source_root = build_directory_fixture(&run_root)?;
    let receive_root = run_root.join("received");
    let journal_path = run_root.join("journal").join("directory_journal.jsonl");
    let proof_path = run_root.join("proof").join("directory_proof.json");
    let log_path = run_root.join("logs").join("directory_events.jsonl");

    let proof = transfer_directory_object_graph(
        source_root,
        receive_root,
        journal_path,
        proof_path,
        log_path,
        MetadataPolicy::portable(),
    )?;

    let manifest = Manifest::from_graph(&proof.graph, MetadataPolicy::portable())?;
    manifest.validate()?;

    assert_eq!(proof.source_hash, proof.receive_hash);
    assert_eq!(manifest.object_count(), proof.graph.object_count());
    assert_eq!(proof.materialized.len(), proof.graph.object_count());
    assert_eq!(proof.graph.roots().count(), 1);
    assert!(proof.graph.contains_object(&proof.root_id));
    assert!(proof.source_root.join("README.txt").is_file());
    assert!(proof.receive_root.join("README.txt").is_file());
    assert_eq!(count_kind(&proof.graph, ObjectKind::FileObject), 4);
    assert_eq!(count_kind(&proof.graph, ObjectKind::DirectoryObject), 7);

    let rejected_traversal = classify_path(
        Path::new("../escape.txt"),
        false,
        &MetadataPolicy::portable(),
    );
    assert_eq!(rejected_traversal, PathDecision::RejectTraversal);

    let denied_link = proof
        .events
        .iter()
        .any(|event| event.get("event") == Some(&json!("path_policy_denied_link")));
    assert!(denied_link || cfg!(not(unix)));

    let final_event = proof
        .events
        .iter()
        .find(|event| event.get("event") == Some(&json!("final_commit")))
        .expect("final commit event must be present");
    assert_eq!(
        final_event["journal_path"],
        json!(proof.journal_path.display().to_string())
    );
    assert_eq!(
        final_event["proof_path"],
        json!(proof.proof_path.display().to_string())
    );
    assert_eq!(
        final_event["replay_pointer"],
        json!(proof.log_path.display().to_string())
    );
    assert_eq!(
        final_event["source_hash"],
        json!(hex_hash(proof.source_hash))
    );
    assert_eq!(
        final_event["received_hash"],
        json!(hex_hash(proof.receive_hash))
    );
    assert!(final_event.get("object_graph_shape").is_some());
    assert!(final_event.get("chunking_profile").is_some());
    assert!(final_event.get("dedupe_reuse_decisions").is_some());
    assert!(final_event.get("final_commit_record").is_some());

    let proof_json: Value = serde_json::from_slice(&fs::read(&proof.proof_path)?)?;
    assert_eq!(
        proof_json["manifest_root"],
        json!(hex_hash(*manifest.merkle_root.hash()))
    );
    assert_eq!(
        proof_json["object_count"],
        json!(proof.graph.object_count())
    );
    assert_eq!(proof_json["root_id"], json!(proof.root_id.to_string()));

    let replayed_events = read_jsonl(&proof.log_path)?;
    assert_eq!(replayed_events, proof.events);

    Ok(())
}

fn transfer_directory_object_graph(
    source_root: PathBuf,
    receive_root: PathBuf,
    journal_path: PathBuf,
    proof_path: PathBuf,
    log_path: PathBuf,
    metadata_policy: MetadataPolicy,
) -> Result<DirectoryTransferProof, Box<dyn std::error::Error>> {
    let mut graph = ObjectGraph::new();
    let mut materialized = Vec::new();
    let mut events = Vec::new();

    let root_id = materialize_directory_entry(
        &source_root,
        Path::new(""),
        &metadata_policy,
        &mut graph,
        &mut materialized,
        &mut events,
    )?
    .expect("fixture root must be included");
    graph.validate()?;

    fs::create_dir_all(journal_path.parent().expect("journal parent"))?;
    fs::create_dir_all(proof_path.parent().expect("proof parent"))?;
    fs::create_dir_all(log_path.parent().expect("log parent"))?;
    write_journal(&journal_path, &materialized)?;

    write_received_tree(&graph, &root_id, &receive_root)?;
    let source_hash = hash_tree(&source_root, &metadata_policy)?;
    let receive_hash = hash_tree(&receive_root, &metadata_policy)?;
    assert_eq!(source_hash, receive_hash);

    let manifest = Manifest::from_graph(&graph, metadata_policy.clone())?;
    manifest.validate()?;
    write_proof_bundle(
        &proof_path,
        &manifest,
        &root_id,
        graph.object_count(),
        source_hash,
        receive_hash,
    )?;

    events.push(json!({
        "event": "manifest_written",
        "manifest_root": hex_hash(*manifest.merkle_root.hash()),
        "object_graph_shape": graph_shape(&graph),
        "journal_path": journal_path.display().to_string(),
        "proof_path": proof_path.display().to_string(),
    }));
    events.push(json!({
        "event": "final_commit",
        "object_graph_shape": graph_shape(&graph),
        "chunking_profile": {
            "strategy": "fixed-size",
            "target_chunk_size": 4096,
            "selected_path": "directory-object-metadata-first-small-file-first",
        },
        "dedupe_reuse_decisions": {
            "inserted_objects": graph.object_count(),
            "reused_objects": 0,
        },
        "journal_path": journal_path.display().to_string(),
        "proof_path": proof_path.display().to_string(),
        "selected_path": "directory-object",
        "final_commit_record": format!("directory-root:{}:{}", root_id, hex_hash(receive_hash)),
        "replay_pointer": log_path.display().to_string(),
        "source_hash": hex_hash(source_hash),
        "received_hash": hex_hash(receive_hash),
    }));
    write_jsonl(&log_path, &events)?;

    Ok(DirectoryTransferProof {
        source_root,
        receive_root,
        journal_path,
        proof_path,
        log_path,
        graph,
        root_id,
        materialized,
        events,
        source_hash,
        receive_hash,
    })
}

fn unique_run_root(name: &str) -> PathBuf {
    let sequence = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "asupersync_vk4kcf8_{name}_{}_{}",
        std::process::id(),
        sequence
    ))
}

fn build_directory_fixture(run_root: &Path) -> std::io::Result<PathBuf> {
    let source_root = run_root.join("source");
    fs::create_dir_all(source_root.join("empty"))?;
    fs::create_dir_all(source_root.join("small"))?;
    fs::create_dir_all(source_root.join("deep").join("a").join("b").join("c"))?;

    fs::write(
        source_root.join("README.txt"),
        b"ATP directory graph proof\n",
    )?;
    fs::write(source_root.join("small").join("a.txt"), b"alpha\n")?;
    fs::write(source_root.join("small").join("b.txt"), b"beta\n")?;
    fs::write(
        source_root
            .join("deep")
            .join("a")
            .join("b")
            .join("c")
            .join("final.txt"),
        b"deep directory payload\n",
    )?;

    #[cfg(unix)]
    std::os::unix::fs::symlink("README.txt", source_root.join("readme-link"))?;

    Ok(source_root)
}

fn materialize_directory_entry(
    absolute_path: &Path,
    relative_path: &Path,
    metadata_policy: &MetadataPolicy,
    graph: &mut ObjectGraph,
    materialized: &mut Vec<MaterializedObject>,
    events: &mut Vec<Value>,
) -> Result<Option<ObjectId>, Box<dyn std::error::Error>> {
    let file_type = fs::symlink_metadata(absolute_path)?.file_type();
    let is_symlink = file_type.is_symlink();
    match classify_path(relative_path, is_symlink, metadata_policy) {
        PathDecision::RejectTraversal => {
            events.push(json!({
                "event": "path_policy_rejected_traversal",
                "path": relative_path.display().to_string(),
            }));
            return Ok(None);
        }
        PathDecision::DenyLink => {
            events.push(json!({
                "event": "path_policy_denied_link",
                "path": relative_path.display().to_string(),
                "target": fs::read_link(absolute_path)?.display().to_string(),
            }));
            return Ok(None);
        }
        PathDecision::Include => {}
    }

    if file_type.is_file() {
        let content = fs::read(absolute_path)?;
        let object = Object::file(content);
        let object_id = object.id.clone();
        let size_bytes = object.metadata.size_bytes;
        graph.add_object(object)?;
        materialized.push(MaterializedObject {
            relative_path: display_relative_path(relative_path),
            object_id: object_id.clone(),
            kind: ObjectKind::FileObject,
            size_bytes,
        });
        return Ok(Some(object_id));
    }

    if file_type.is_dir() {
        let mut child_paths = fs::read_dir(absolute_path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        child_paths.sort();

        let mut edges = Vec::new();
        for child_path in child_paths {
            let child_name = child_path
                .file_name()
                .expect("read_dir entries have names")
                .to_string_lossy()
                .into_owned();
            let child_relative = if relative_path.as_os_str().is_empty() {
                PathBuf::from(&child_name)
            } else {
                relative_path.join(&child_name)
            };
            if let Some(child_id) = materialize_directory_entry(
                &child_path,
                &child_relative,
                metadata_policy,
                graph,
                materialized,
                events,
            )? {
                edges.push(ObjectEdge::new(child_id, child_name));
            }
        }

        let object = Object::directory(edges);
        let object_id = object.id.clone();
        graph.add_object(object)?;
        materialized.push(MaterializedObject {
            relative_path: display_relative_path(relative_path),
            object_id: object_id.clone(),
            kind: ObjectKind::DirectoryObject,
            size_bytes: None,
        });
        return Ok(Some(object_id));
    }

    Ok(None)
}

fn classify_path(path: &Path, is_symlink: bool, metadata_policy: &MetadataPolicy) -> PathDecision {
    for component in path.components() {
        match component {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return PathDecision::RejectTraversal;
            }
            Component::CurDir | Component::Normal(_) => {}
        }
    }

    if is_symlink && !metadata_policy.preserve_symlinks {
        return PathDecision::DenyLink;
    }

    PathDecision::Include
}

fn write_received_tree(
    graph: &ObjectGraph,
    object_id: &ObjectId,
    output_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let object = graph
        .get_object(object_id)
        .ok_or_else(|| ObjectGraphError::ObjectNotFound(object_id.clone()))?;

    match object.metadata.kind {
        ObjectKind::FileObject => {
            let content = object.content.as_ref().expect("file object has content");
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(output_path, content)?;
        }
        ObjectKind::DirectoryObject => {
            fs::create_dir_all(output_path)?;
            for edge in &object.children {
                write_received_tree(graph, &edge.child_id, &output_path.join(&edge.name))?;
            }
        }
        other => panic!("unexpected object kind in directory matrix: {other:?}"),
    }

    Ok(())
}

fn write_journal(path: &Path, materialized: &[MaterializedObject]) -> std::io::Result<()> {
    let events = materialized
        .iter()
        .map(|object| {
            json!({
                "event": "materialized_object",
                "path": object.relative_path,
                "object_id": object.object_id.to_string(),
                "kind": object.kind.to_string(),
                "size_bytes": object.size_bytes,
            })
        })
        .collect::<Vec<_>>();
    write_jsonl(path, &events)
}

fn write_proof_bundle(
    path: &Path,
    manifest: &Manifest,
    root_id: &ObjectId,
    object_count: usize,
    source_hash: [u8; 32],
    receive_hash: [u8; 32],
) -> std::io::Result<()> {
    let proof = json!({
        "manifest_root": hex_hash(*manifest.merkle_root.hash()),
        "root_id": root_id.to_string(),
        "object_count": object_count,
        "source_hash": hex_hash(source_hash),
        "received_hash": hex_hash(receive_hash),
        "verification": "source-tree-equals-received-tree",
    });
    fs::write(path, serde_json::to_vec_pretty(&proof)?)
}

fn write_jsonl(path: &Path, events: &[Value]) -> std::io::Result<()> {
    let mut output = String::new();
    for event in events {
        output.push_str(&serde_json::to_string(event)?);
        output.push('\n');
    }
    fs::write(path, output)
}

fn read_jsonl(path: &Path) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    fs::read_to_string(path)?
        .lines()
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

fn hash_tree(path: &Path, metadata_policy: &MetadataPolicy) -> std::io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hash_tree_entry(path, Path::new(""), metadata_policy, &mut hasher)?;
    Ok(hasher.finalize().into())
}

fn hash_tree_entry(
    absolute_path: &Path,
    relative_path: &Path,
    metadata_policy: &MetadataPolicy,
    hasher: &mut Sha256,
) -> std::io::Result<()> {
    let file_type = fs::symlink_metadata(absolute_path)?.file_type();
    if classify_path(relative_path, file_type.is_symlink(), metadata_policy)
        != PathDecision::Include
    {
        return Ok(());
    }

    hasher.update(display_relative_path(relative_path).as_bytes());
    if file_type.is_file() {
        hasher.update(b"file");
        hasher.update(fs::read(absolute_path)?);
    } else if file_type.is_dir() {
        hasher.update(b"dir");
        let mut child_paths = fs::read_dir(absolute_path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        child_paths.sort();
        for child_path in child_paths {
            let child_name = child_path
                .file_name()
                .expect("read_dir entries have names")
                .to_string_lossy()
                .into_owned();
            let child_relative = if relative_path.as_os_str().is_empty() {
                PathBuf::from(&child_name)
            } else {
                relative_path.join(&child_name)
            };
            hash_tree_entry(&child_path, &child_relative, metadata_policy, hasher)?;
        }
    }

    Ok(())
}

fn count_kind(graph: &ObjectGraph, kind: ObjectKind) -> usize {
    graph
        .objects()
        .filter(|(_, object)| object.metadata.kind == kind)
        .count()
}

fn graph_shape(graph: &ObjectGraph) -> Vec<Value> {
    graph
        .objects()
        .map(|(id, object)| {
            json!({
                "id": id.to_string(),
                "kind": object.metadata.kind.to_string(),
                "children": object.children.len(),
                "size_bytes": object.metadata.size_bytes,
            })
        })
        .collect()
}

fn display_relative_path(path: &Path) -> String {
    if path.as_os_str().is_empty() {
        ".".to_string()
    } else {
        path.display().to_string()
    }
}

fn hex_hash(hash: [u8; 32]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}
