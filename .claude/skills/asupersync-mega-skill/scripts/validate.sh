#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VALIDATOR="$SCRIPT_DIR/../../sw/scripts/validate-skill.py"

if [[ ! -f "$VALIDATOR" ]]; then
  echo "error: validator not found: $VALIDATOR" >&2
  exit 1
fi

python3 "$VALIDATOR" "$SKILL_DIR" "$@"

# Validate progressive-disclosure structure and every relative Markdown link.
# GitHub-style anchor validation catches hand-written TOCs that silently drift
# when a heading changes.
python3 - "$SKILL_DIR" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1]).resolve()
markdown = sorted(root.rglob("*.md"))
errors: list[str] = []


def github_slug(heading: str) -> str:
    heading = re.sub(r"<[^>]*>", "", heading)
    heading = re.sub(r"[`*~]", "", heading).strip().lower()
    heading = "".join(ch for ch in heading if ch.isalnum() or ch in " _-")
    return re.sub(r"\s", "-", heading)


def anchors(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return {
        github_slug(match.group(1))
        for match in re.finditer(r"^#{1,6}\s+(.+?)\s*$", text, re.MULTILINE)
    }


anchor_cache = {path: anchors(path) for path in markdown}
for path in markdown:
    text = path.read_text(encoding="utf-8")
    if path.parent.name == "references" and len(text.splitlines()) > 100:
        if not re.search(r"^## (?:Table of )?Contents$", text, re.MULTILINE):
            errors.append(f"{path.relative_to(root)}: reference over 100 lines lacks a TOC")

    for match in re.finditer(r"\[[^\]]+\]\(([^)]+)\)", text):
        target = match.group(1).strip()
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        target_path_text, _, anchor = target.partition("#")
        target_path = path if not target_path_text else (path.parent / target_path_text).resolve()
        if not target_path.exists():
            errors.append(f"{path.relative_to(root)}: missing link target {target}")
            continue
        if anchor and target_path.suffix == ".md":
            known = anchor_cache.get(target_path)
            if known is None:
                known = anchors(target_path)
                anchor_cache[target_path] = known
            if anchor not in known:
                errors.append(f"{path.relative_to(root)}: missing Markdown anchor {target}")

if errors:
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    raise SystemExit(1)
PY

require_text() {
  local pattern="$1"
  local path="$2"
  local message="$3"

  if ! rg -q --fixed-strings "$pattern" "$path"; then
    echo "error: $message" >&2
    exit 1
  fi
}

reject_docs() {
  local pattern="$1"
  local message="$2"

  if rg -q --fixed-strings "$pattern" \
    "$SKILL_DIR/SKILL.md" "$SKILL_DIR/SELF-TEST.md" "$SKILL_DIR/references"; then
    echo "error: $message" >&2
    exit 1
  fi
}

# Entrypoint routing and centralized release-boundary sentinels.
require_text "Release and Live-HEAD Status" \
  "$SKILL_DIR/references/SOURCE-MAP.md" \
  "source map must contain the one current release/status card"
require_text "v0.4.9 is the functional baseline" \
  "$SKILL_DIR/references/SOURCE-MAP.md" \
  "status card must name the published source baseline"
require_text "3c73a334c" \
  "$SKILL_DIR/references/SOURCE-MAP.md" \
  "status card must identify the current post-v0.4.9 gRPC delta"
require_text '`Cx::spawn_local` requires a worker-local lane' \
  "$SKILL_DIR/SKILL.md" \
  "entrypoint must route local tasks through a real owner-worker lane"
require_text "does not install a Tokio runtime" \
  "$SKILL_DIR/SKILL.md" \
  "entrypoint must not overclaim the Tokio compatibility bridge"
require_text "zero admissible executed tests" \
  "$SKILL_DIR/SKILL.md" \
  "entrypoint must classify RCH pre-admission refusal as zero test evidence"
require_text "preserve the v0.4.3 public" \
  "$SKILL_DIR/SKILL.md" \
  "entrypoint must retain the 0.4.x compatibility floor"
require_text '`RuntimeHandle::try_request_cx_with_budget(budget)`' \
  "$SKILL_DIR/references/RUNTIME-CONTROLS.md" \
  "runtime card must expose the additive fallible handle request-context API"
require_text "Cx::with_blocking_pool_handle" \
  "$SKILL_DIR/references/RUNTIME-CONTROLS.md" \
  "runtime card must expose additive caller-owned blocking-pool wiring"
require_text "run the closure inline on" \
  "$SKILL_DIR/references/RUNTIME-CONTROLS.md" \
  "runtime card must state the exact pool-less Cx blocking fallback"
require_text "manifest = command/claim/envelope" \
  "$SKILL_DIR/SKILL.md" \
  "entrypoint must retain the three-layer proof evidence model"
require_text "CASS for rationale" \
  "$SKILL_DIR/SKILL.md" \
  "entrypoint must treat session history as rationale rather than current proof"
require_text "maintain Asupersync" \
  "$SKILL_DIR/SKILL.md" \
  "entrypoint must route repository maintenance as well as downstream use"
if rg -q --fixed-strings 'Published v0.4.9' "$SKILL_DIR/SKILL.md"; then
  echo "error: volatile release status must stay in SOURCE-MAP, not the entrypoint" >&2
  exit 1
fi

reject_docs "published v0.4.8 source" \
  "stale published-v0.4.8 baseline returned"
reject_docs 'Current `main` after v0.4.8' \
  "shipped v0.4.9 work is still labeled current-main-only"
reject_docs "post-v0.4.8" \
  "shipped v0.4.9 work is still labeled post-v0.4.8"
reject_docs "A6-A9" \
  "stale OTLP A6-A9 frontier returned; the open frontier is A6-A11"
reject_docs "workspace version 0.4.8" \
  "stale browser or workspace package version returned"

# Semantic regression sentinels for previously escaped documentation drift.
require_text "does not install a Tokio runtime handle" \
  "$SKILL_DIR/references/COMPAT-BOUNDARY.md" \
  "compat boundary must deny a Tokio-runtime/Handle::current guarantee"
require_text "pooled HTTP/1" \
  "$SKILL_DIR/references/STACK-SURFACES.md" \
  "support matrix must classify the high-level client pool as HTTP/1"
require_text "has an asynchronous capacity reservation" \
  "$SKILL_DIR/references/PRIMITIVES-AND-ORCHESTRATION-CHOOSER.md" \
  "primitive chooser must distinguish reserve shapes"
require_text "discounted UCB1" \
  "$SKILL_DIR/references/SCHEDULER-INTERNALS.md" \
  "scheduler reference must retain the current controller classification"
require_text "shard B is dormant" \
  "$SKILL_DIR/references/PERFORMANCE-AND-SCHEDULING.md" \
  "performance guidance must not overclaim live region-shard routing"
require_text "Fairness and starvation governors may temporarily choose another eligible lane" \
  "$SKILL_DIR/references/PERFORMANCE-AND-SCHEDULING.md" \
  "scheduler summary must qualify ordinary lane precedence with fairness overrides"
require_text "zero admissible executed tests" \
  "$SKILL_DIR/references/TESTING-FORENSICS.md" \
  "remote admission metadata and exit 103 must not be represented as test evidence"
require_text "Do not key source or evidence authority to a checkout prefix" \
  "$SKILL_DIR/references/REPO-CONTRIBUTOR-GUIDE.md" \
  "repository identity must not depend on /dp, /data/projects, or RCH checkout paths"
require_text "Many modules include inline" \
  "$SKILL_DIR/references/REPO-CONTRIBUTOR-GUIDE.md" \
  "repository testing guidance must not claim every module has inline tests"
require_text "OnceCell -- cancel-awareness" \
  "$SKILL_DIR/references/REPO-CONTRIBUTOR-GUIDE.md" \
  "repository module table must name the current OnceCell primitive"
require_text "selected, non-exhaustive inventory" \
  "$SKILL_DIR/references/REPO-CONTRIBUTOR-GUIDE.md" \
  "feature table must not present its selected rows as a complete inventory"
require_text "Feature-gated native FABRIC lane" \
  "$SKILL_DIR/references/REPO-CONTRIBUTOR-GUIDE.md" \
  "repository guide must retain the current native FABRIC feature boundary"
reject_docs "Every module includes inline" \
  "repository testing guidance again claimed universal inline-test coverage"
reject_docs "OnceLock -- cancel-awareness" \
  "stale OnceLock module-table label returned"
reject_docs "module wiring not fully gated yet" \
  "stale FABRIC module-gating claim returned"
require_text "never invoke a waker" \
  "$SKILL_DIR/references/LOCK-ORDERING.md" \
  "runtime-lock guidance must keep wakers, hooks, and callbacks outside locks"
require_text "asupersync-909482" \
  "$SKILL_DIR/references/LOCK-ORDERING.md" \
  "the active callback-under-lock P0 must remain labeled as an unshipped boundary"
require_text "asupersync-2qas9c" \
  "$SKILL_DIR/references/NETWORKING-PROTOCOL-STACK.md" \
  "the ATP receive-watchdog acceptance boundary must remain explicit"
require_text "asupersync-dax0vn" \
  "$SKILL_DIR/references/NETWORKING-PROTOCOL-STACK.md" \
  "the shipped ATP secret-delivery boundary must remain explicit"
require_text "515d96e7f" \
  "$SKILL_DIR/references/NETWORKING-PROTOCOL-STACK.md" \
  "the focused-gate-proven ATP secret-delivery repair must remain source-bound"
require_text "OwnedOtlpMetrics" \
  "$SKILL_DIR/references/OBSERVABILITY-FORENSICS.md" \
  "observability guidance must include the current finite owned metrics mapper"
require_text "OwnedOtlpTraces" \
  "$SKILL_DIR/references/OBSERVABILITY-FORENSICS.md" \
  "observability guidance must include the current finite owned trace mapper"
require_text "OwnedOtlpLogs" \
  "$SKILL_DIR/references/OBSERVABILITY-FORENSICS.md" \
  "observability guidance must include the current finite owned log mapper"
require_text "A6-A11" \
  "$SKILL_DIR/references/OBSERVABILITY-FORENSICS.md" \
  "observability guidance must retain the open post-mapping OTLP boundary"
require_text "lexical root-export inventory" \
  "$SKILL_DIR/references/SOURCE-MAP.md" \
  "source map must not promote API-map counts into support or behavior proof"
require_text "ProtoMessage" \
  "$SKILL_DIR/references/SOURCE-MAP.md" \
  "source map must include the protobuf proc-macro derives"
require_text 'proc_macros::session_protocol!' \
  "$SKILL_DIR/references/SOURCE-MAP.md" \
  "source map must retain the explicit-path-only session protocol macro"
require_text "Adaptive layouts, anti-entropy, assignment, runtime bridge" \
  "$SKILL_DIR/references/SOURCE-MAP.md" \
  "source map must retain the current distributed subsystem breadth"
require_text 'AsyncCxFnHandler1::<_, State<Db>>::new' \
  "$SKILL_DIR/references/GREENFIELD-PATTERNS.md" \
  "greenfield web example must explicitly adapt an async Cx handler"
require_text 'AsyncCxFnHandler2::<_, State<Db>, JsonExtract<CreateUser>>::new' \
  "$SKILL_DIR/references/GREENFIELD-PATTERNS.md" \
  "greenfield web example must explicitly adapt both request extractors"
require_text 'async fn list_users(cx: Cx' \
  "$SKILL_DIR/references/GREENFIELD-PATTERNS.md" \
  "greenfield web example must receive the runtime-owned Cx"
reject_docs 'async fn list_users(State' \
  "raw async web handler example without a Cx adapter returned"
require_text 'The production `transport_rq` transport is fail-closed' \
  "$SKILL_DIR/references/RAPTORQ-DISTRIBUTED.md" \
  "RaptorQ guidance must scope the fail-closed claim to production transport"
if rg -q --fixed-strings 'NO_PREFLIGHT=1' \
  "$SKILL_DIR/references/RAPTORQ-DISTRIBUTED.md"; then
  echo "error: proof-bypassing RaptorQ command returned" >&2
  exit 1
fi
require_text '`metrics,test-internals` focused' \
  "$SKILL_DIR/references/OBSERVABILITY-FORENSICS.md" \
  "observability guidance must bind feature-gated mapping evidence to its exact lane"
require_text 'explicitly `#[ignore]`' \
  "$SKILL_DIR/references/OBSERVABILITY-FORENSICS.md" \
  "observability guidance must not overclaim routine external Collector execution"
require_text 'explicitly named `*_unchecked` compatibility escape hatches' \
  "$SKILL_DIR/references/DB-MESSAGING-FS-PROCESS.md" \
  "database guidance must distinguish checked SQLite defaults from explicit escape hatches"
require_text '`validate_checked_sql_statement`' \
  "$SKILL_DIR/references/DB-MESSAGING-FS-PROCESS.md" \
  "database guidance must include the current public checked-SQL validator"
require_text '`SqliteOperationError`' \
  "$SKILL_DIR/references/DB-MESSAGING-FS-PROCESS.md" \
  "database guidance must include the additive SQLite diagnosed-error family"
require_text '`SqliteErrorDiagnostic` are non-exhaustive, engine-neutral public types' \
  "$SKILL_DIR/references/DB-MESSAGING-FS-PROCESS.md" \
  "database guidance must retain the exact non-exhaustive SQLite diagnostic component boundary"
require_text '`SqliteOperationError` is their private-field wrapper' \
  "$SKILL_DIR/references/DB-MESSAGING-FS-PROCESS.md" \
  "database guidance must distinguish the private-field wrapper from its non-exhaustive components"
require_text '`SqliteOperationError` itself is the' \
  "$SKILL_DIR/SELF-TEST.md" \
  "self-test must reject classifying the SQLite operation wrapper as a non-exhaustive enum"
require_text 'wrap them with the matching `AsyncCxFnHandler*` arity' \
  "$SKILL_DIR/SELF-TEST.md" \
  "self-test must retain the high-level async Cx web-handler contract"
require_text '`Server::bind_registered_http2`' \
  "$SKILL_DIR/references/WEB-GRPC-HTTP.md" \
  "web/gRPC guidance must include registered-service native H2 binding"
require_text '`Server::serve_http2`' \
  "$SKILL_DIR/references/WEB-GRPC-HTTP.md" \
  "web/gRPC guidance must include registered-service native H2 serving"
require_text '`Server::dispatch_registered_unary_with_trailers`' \
  "$SKILL_DIR/references/WEB-GRPC-HTTP.md" \
  "web/gRPC guidance must distinguish in-process trailer-aware dispatch"
require_text '`ServiceHandlerFuture`' \
  "$SKILL_DIR/references/WEB-GRPC-HTTP.md" \
  "web/gRPC guidance must name the callable handler return alias"
require_text 'not part of the published' \
  "$SKILL_DIR/references/WEB-GRPC-HTTP.md" \
  "web/gRPC guidance must distinguish live HEAD from the published crate"
reject_docs 'non-exhaustive `SqliteOperationError`' \
  "SQLite operation wrapper was incorrectly classified as non-exhaustive"
require_text '`rusqlite::Error::SqlInputError`' \
  "$SKILL_DIR/references/DB-MESSAGING-FS-PROCESS.md" \
  "database guidance must retain structured parser-error classification"
require_text '47 common public-surface cases' \
  "$SKILL_DIR/references/DB-MESSAGING-FS-PROCESS.md" \
  "database guidance must retain the terminal cross-engine aggregate count"
require_text 'eight native-only P5 cancellation cases' \
  "$SKILL_DIR/references/DB-MESSAGING-FS-PROCESS.md" \
  "database guidance must retain the native-only cancellation boundary"
require_text '`KEEP_CURRENT_RUSQLITE_AND_SQLPARSER`' \
  "$SKILL_DIR/references/DB-MESSAGING-FS-PROCESS.md" \
  "database guidance must retain the no-cutover decision"
require_text '`SqliteRow::{column_names_in_order,column_name,column_index}`' \
  "$SKILL_DIR/references/DB-MESSAGING-FS-PROCESS.md" \
  "database guidance must preserve the additive ordered duplicate-column surface"
require_text '`as_real_strict` or `get_f64_strict`' \
  "$SKILL_DIR/references/DB-MESSAGING-FS-PROCESS.md" \
  "database guidance must distinguish strict REAL reads from legacy integer widening"
require_text 'poll rollback inside a bounded,' \
  "$SKILL_DIR/references/DB-MESSAGING-FS-PROCESS.md" \
  "database guidance must state the transaction-helper terminal rollback boundary"
require_text 'cannot enable the SHA-1 plugin' \
  "$SKILL_DIR/references/DB-MESSAGING-FS-PROCESS.md" \
  "database guidance must not present MySQL compatibility fields as legacy-auth escape hatches"
require_text 'surplus bind' \
  "$SKILL_DIR/references/DB-MESSAGING-FS-PROCESS.md" \
  "database guidance must retain the prepared-statement surplus-bind difference"
require_text '`runtime::yield_now().await` after each batch of eight' \
  "$SKILL_DIR/references/SUPERVISION-OTP.md" \
  "supervision guidance must retain the real actor and GenServer mailbox yield point"
require_text 'including `Duration::MAX`' \
  "$SKILL_DIR/references/SUPERVISION-OTP.md" \
  "supervision guidance must retain extreme restart-backoff saturation"
require_text '`Ok(Err(LockError::Cancelled))`' \
  "$SKILL_DIR/SELF-TEST.md" \
  "self-test must retain the escaped parked-mutex exact nested outcome"
require_text 'waiter-count' \
  "$SKILL_DIR/SELF-TEST.md" \
  "self-test must retain the native parked-state witness and cleanup oracle"
require_text 'A2-A5' \
  "$SKILL_DIR/SELF-TEST.md" \
  "self-test must retain the closed OTLP tranche boundary"
require_text 'A6-A11 still open' \
  "$SKILL_DIR/SELF-TEST.md" \
  "self-test must retain the open OTLP program boundary"
require_text 'tokio_util|tokio_stream|tokio_postgres|tokio_rustls' \
  "$SKILL_DIR/scripts/audit-target.sh" \
  "source inventory must recognize Rust underscore spellings for ecosystem crates"
require_text 'tonic_web|hyper_util|async_std|sea_orm' \
  "$SKILL_DIR/scripts/audit-target.sh" \
  "source inventory must cover common Tokio-boundary ecosystem crates"
require_text 'runtime.block_on(runtime.handle().spawn(async { ... }))' \
  "$SKILL_DIR/references/RUNTIME-CONTROLS.md" \
  "runtime card must teach how to enter the owning worker-local lane"
require_text 'Classification, explanation, diagnosis, and review requests are read-only' \
  "$SKILL_DIR/references/REPO-CONTRIBUTOR-GUIDE.md" \
  "repository card must gate mutations behind user authorization"

# Parse the routing cases as a contract instead of treating SELF-TEST.md as
# unstructured prose. Actual model selection is still forward-tested separately.
python3 - "$SKILL_DIR" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
text = (root / "SELF-TEST.md").read_text(encoding="utf-8")
entrypoint = (root / "SKILL.md").read_text(encoding="utf-8")
if "## Choose One Lane" not in entrypoint or "## Non-Negotiables" not in entrypoint:
    raise SystemExit("error: SKILL.md lacks bounded primary routing section")
primary_routes = entrypoint.split("## Choose One Lane", 1)[1].split("## Non-Negotiables", 1)[0]
start = "<!-- ROUTING_CASES_START -->"
end = "<!-- ROUTING_CASES_END -->"
if text.count(start) != 1 or text.count(end) != 1:
    raise SystemExit("error: SELF-TEST routing markers must appear exactly once")
body = text.split(start, 1)[1].split(end, 1)[0]
rows = []
for line in body.splitlines():
    if not line.startswith("|") or line.startswith("|---") or line.startswith("| ID "):
        continue
    cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
    if len(cells) != 6:
        raise SystemExit(f"error: malformed SELF-TEST routing row: {line}")
    rows.append(cells)

ids = [row[0] for row in rows]
if len(ids) != len(set(ids)):
    raise SystemExit("error: duplicate SELF-TEST routing case id")
positive = negative = 0
for case_id, select, prompt, first_ref, must_do, must_not in rows:
    if select not in {"yes", "no"}:
        raise SystemExit(f"error: routing case {case_id} has invalid Select={select!r}")
    if not (prompt.startswith("`") and prompt.endswith("`")):
        raise SystemExit(f"error: routing case {case_id} prompt is not code-delimited")
    if not must_do or not must_not:
        raise SystemExit(f"error: routing case {case_id} lacks must/must-not behavior")
    if select == "yes":
        positive += 1
        if not (first_ref.startswith("`references/") and first_ref.endswith(".md`")):
            raise SystemExit(f"error: positive routing case {case_id} lacks one first reference")
        target = root / first_ref.strip("`")
        if not target.is_file():
            raise SystemExit(f"error: routing case {case_id} references missing {target}")
        route = first_ref.strip("`")
        if f"]({route})" not in primary_routes:
            raise SystemExit(f"error: routing case {case_id} first reference is not a primary route")
    else:
        negative += 1
        if first_ref != "-":
            raise SystemExit(f"error: negative routing case {case_id} must not route to a reference")
if positive < 10 or negative < 4:
    raise SystemExit(f"error: routing matrix too small: positive={positive}, negative={negative}")
print(f"routing contract passed: {positive} positive, {negative} negative")
PY

"$SCRIPT_DIR/audit-target.sh" --self-test

# Optional live-source binding. The skill package remains portable, while a
# maintainer refreshing it against a checkout can require the key public and
# behavioral anchors used by release-sensitive cards.
if [[ -n "${ASUPERSYNC_SOURCE_ROOT:-}" ]]; then
  if [[ ! -d "$ASUPERSYNC_SOURCE_ROOT/src" ]]; then
    echo "error: ASUPERSYNC_SOURCE_ROOT has no src directory: $ASUPERSYNC_SOURCE_ROOT" >&2
    exit 1
  fi
  if ! git -C "$ASUPERSYNC_SOURCE_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    echo "error: live status validation requires an Asupersync Git checkout" >&2
    exit 1
  fi
  grpc_delta=3c73a334c02e9976bda712c19b07221360bc7f3e
  if ! git -C "$ASUPERSYNC_SOURCE_ROOT" merge-base --is-ancestor "$grpc_delta" HEAD; then
    echo "error: documented post-v0.4.9 gRPC delta is not contained in live HEAD" >&2
    exit 1
  fi
  if ! git -C "$ASUPERSYNC_SOURCE_ROOT" rev-parse --verify 'v0.4.9^{commit}' >/dev/null 2>&1; then
    echo "error: live checkout lacks the documented v0.4.9 baseline tag" >&2
    exit 1
  fi
  if git -C "$ASUPERSYNC_SOURCE_ROOT" merge-base --is-ancestor "$grpc_delta" v0.4.9; then
    echo "error: gRPC delta is now included in v0.4.9; release boundary is stale" >&2
    exit 1
  fi
  python3 - "$ASUPERSYNC_SOURCE_ROOT/.beads/issues.jsonl" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
if not path.is_file():
    raise SystemExit("error: live status validation requires .beads/issues.jsonl")
wanted = {"asupersync-909482", "asupersync-2qas9c"}
statuses = {}
for line in path.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    row = json.loads(line)
    if row.get("id") in wanted:
        statuses[row["id"]] = row.get("status")
missing = wanted - statuses.keys()
if missing:
    raise SystemExit(f"error: live tracker lacks status-card rows: {sorted(missing)}")
stale = {issue: status for issue, status in statuses.items() if status not in {"open", "in_progress"}}
if stale:
    raise SystemExit(f"error: status card names rows no longer open: {stale}")
print("live release/tag/tracker relationships passed")
PY
  # Exact repo-relative code spans must resolve against the live checkout.
  # Dynamic templates/globs are excluded; they require lane-specific runtime
  # validation rather than a misleading existence check.
  python3 - "$SKILL_DIR" "$ASUPERSYNC_SOURCE_ROOT" <<'PY'
from pathlib import Path
import re
import sys

skill = Path(sys.argv[1]).resolve()
source = Path(sys.argv[2]).resolve()
prefixes = (
    "src/", "tests/", "artifacts/", "scripts/", "docs/", "examples/",
    "packages/", "benches/", "formal/", "asupersync-macros/",
    "asupersync-tokio-compat/", "conformance/",
)
standalone = {"AGENTS.md", "README.md", "CHANGELOG.md", "CHANGELOG_RESEARCH.md", "TESTING_FOR_AGENTS.md", "Cargo.toml"}
missing = []
for doc in sorted(skill.rglob("*.md")):
    text = doc.read_text(encoding="utf-8")
    for code in re.findall(r"`([^`\n]+)`", text):
        if any(marker in code for marker in ("<", ">", "{", "}", "*", "$")):
            continue
        for token in re.split(r"[\s,;()]+", code):
            token = token.strip("'\"[]:.")
            if not token:
                continue
            if token in standalone or token.startswith(prefixes):
                token = token.split("#", 1)[0]
                if (doc.parent / token).exists() or (skill / token).exists():
                    continue
                candidate = source / token
                if not candidate.exists():
                    missing.append(f"{doc.relative_to(skill)}: {token}")
if missing:
    for item in sorted(set(missing)):
        print(f"error: missing live repository path: {item}", file=sys.stderr)
    raise SystemExit(1)
print("live repository path references passed")
PY
  require_text 'version = "0.4.9"' \
    "$ASUPERSYNC_SOURCE_ROOT/Cargo.toml" \
    "live source does not match the documented v0.4.9 workspace baseline"
  require_text 'ProtoMessage, ProtoOneof' \
    "$ASUPERSYNC_SOURCE_ROOT/src/lib.rs" \
    "live source lacks the documented protobuf proc-macro derives"
  require_text 'session_protocol' \
    "$ASUPERSYNC_SOURCE_ROOT/src/lib.rs" \
    "live source lacks the documented explicit-path session protocol macro"
  require_text '"entry_points": 19' \
    "$ASUPERSYNC_SOURCE_ROOT/artifacts/api_surface_map_v1.json" \
    "live API map no longer matches the documented entry-point count"
  require_text '"modules": 120' \
    "$ASUPERSYNC_SOURCE_ROOT/artifacts/api_surface_map_v1.json" \
    "live API map no longer matches the documented module count"
  require_text '"root_exports": 315' \
    "$ASUPERSYNC_SOURCE_ROOT/artifacts/api_surface_map_v1.json" \
    "live API map no longer matches the documented root-export count"
  for browser_package in browser-core browser react next; do
    require_text '"version": "0.4.9"' \
      "$ASUPERSYNC_SOURCE_ROOT/packages/$browser_package/package.json" \
      "live browser package version no longer matches the documented v0.4.9 baseline"
  done
  require_text 'pub fn with_blocking_pool_handle' \
    "$ASUPERSYNC_SOURCE_ROOT/src/cx/cx.rs" \
    "live source lacks the documented embedder blocking-pool API"
  require_text 'pub fn try_request_cx_with_budget' \
    "$ASUPERSYNC_SOURCE_ROOT/src/runtime/builder.rs" \
    "live source lacks the documented fallible RuntimeHandle request-Cx API"
  require_text 'pub struct AsyncCxFnHandler1' \
    "$ASUPERSYNC_SOURCE_ROOT/src/web/handler.rs" \
    "live source lacks the async Cx web-handler adapter used by the skill"
  require_text 'AsyncCxFnHandler1::<_, State<Db>>::new' \
    "$ASUPERSYNC_SOURCE_ROOT/src/web/mod.rs" \
    "live web quick-start does not use the required async Cx handler adapter"
  if rg -q --fixed-strings 'async fn list_users(State' \
    "$ASUPERSYNC_SOURCE_ROOT/src/web/mod.rs"; then
    echo "error: live web quick-start again passes a raw async function to the router" >&2
    exit 1
  fi
  require_text 'pub type ServiceHandlerFuture' \
    "$ASUPERSYNC_SOURCE_ROOT/src/grpc/service.rs" \
    "live source lacks the documented registered unary handler future"
  require_text "fn call_unary<'a>" \
    "$ASUPERSYNC_SOURCE_ROOT/src/grpc/service.rs" \
    "live source lacks the documented additive registered unary hook"
  require_text 'pub async fn bind_registered_http2' \
    "$ASUPERSYNC_SOURCE_ROOT/src/grpc/server.rs" \
    "live source lacks registered-service native H2 binding"
  require_text 'pub async fn serve_http2' \
    "$ASUPERSYNC_SOURCE_ROOT/src/grpc/server.rs" \
    "live source lacks registered-service native H2 serving"
  require_text 'pub async fn dispatch_registered_unary_with_trailers' \
    "$ASUPERSYNC_SOURCE_ROOT/src/grpc/server.rs" \
    "live source lacks trailer-aware registered unary dispatch"
  require_text '#[cfg(feature = "messaging-fabric")]' \
    "$ASUPERSYNC_SOURCE_ROOT/src/messaging/mod.rs" \
    "live source lacks the documented native FABRIC feature gate"
  require_text 'pub struct OwnedOtlpMetrics' \
    "$ASUPERSYNC_SOURCE_ROOT/src/observability/otel.rs" \
    "live source lacks the documented owned OTLP metrics mapper"
  require_text 'pub struct OwnedOtlpTraces' \
    "$ASUPERSYNC_SOURCE_ROOT/src/observability/otel.rs" \
    "live source lacks the documented owned OTLP trace mapper"
  require_text 'pub struct OwnedOtlpLogs' \
    "$ASUPERSYNC_SOURCE_ROOT/src/observability/otel.rs" \
    "live source lacks the documented owned OTLP log mapper"
  require_text '#[cfg(all(feature = "metrics", not(target_arch = "wasm32")))]' \
    "$ASUPERSYNC_SOURCE_ROOT/src/observability/mod.rs" \
    "live source lacks the documented native-only owned OTLP re-export gate"
  require_text 'pub fn validate_checked_sql_statement' \
    "$ASUPERSYNC_SOURCE_ROOT/src/database/sqlite.rs" \
    "live source lacks the documented checked-SQL validator"
  require_text 'pub struct SqliteOperationError' \
    "$ASUPERSYNC_SOURCE_ROOT/src/database/sqlite.rs" \
    "live source lacks the documented structured SQLite error wrapper"
  require_text 'rusqlite::Error::SqlInputError' \
    "$ASUPERSYNC_SOURCE_ROOT/src/database/sqlite.rs" \
    "live source lacks the documented parser-error preservation path"
  require_text 'pub async fn open_diagnosed' \
    "$ASUPERSYNC_SOURCE_ROOT/src/database/sqlite.rs" \
    "live source lacks the documented diagnosed SQLite API family"
  require_text 'pub fn column_names_in_order' \
    "$ASUPERSYNC_SOURCE_ROOT/src/database/sqlite.rs" \
    "live source lacks the documented ordered SQLite metadata API"
  require_text 'actor::yield_after_ready_batch' \
    "$ASUPERSYNC_SOURCE_ROOT/src/actor.rs" \
    "live actor loop lacks the documented real fairness-yield anchor"
  require_text 'gen_server::yield_after_ready_batch' \
    "$ASUPERSYNC_SOURCE_ROOT/src/gen_server.rs" \
    "live GenServer loop lacks the documented real fairness-yield anchor"
  require_text 'Duration::try_from_secs_f64' \
    "$ASUPERSYNC_SOURCE_ROOT/src/supervision.rs" \
    "live supervision source lacks the documented saturating backoff conversion"
  require_text '"directly_compared_cases": 47' \
    "$ASUPERSYNC_SOURCE_ROOT/artifacts/sqlite_parity_harness_v1.json" \
    "live SQLite aggregate lacks the documented 47 common cases"
  require_text '"native_p5_cases": 8' \
    "$ASUPERSYNC_SOURCE_ROOT/artifacts/sqlite_parity_harness_v1.json" \
    "live SQLite aggregate lacks the documented eight native-only cases"
  require_text '"sqlite_dependency": "KEEP_CURRENT_RUSQLITE_AND_SQLPARSER"' \
    "$ASUPERSYNC_SOURCE_ROOT/artifacts/sqlite_parity_harness_v1.json" \
    "live SQLite aggregate lacks the documented KEEP-incumbent decision"
fi
