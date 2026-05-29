# Provider Audit Log

This log records source-backed checks for volatile README/AGENTS facts. It is
not a frozen source of truth; rerun the commands when auditing future claims.

## 2026-05-29 - asupersync-dgu59f

Scope: `README.md` and `AGENTS.md` claims about LOC, file counts, workspace
membership, conformance registry counts, roadmap status, and legacy branch
wording.

| Claim area | Live evidence | Verdict | Action |
| --- | --- | --- | --- |
| Historical README `310K+ LOC` claim | `rg -n "310K|310 K|310,000|1\\.72M|1\\.72 M|1720000|1,720,000" README.md AGENTS.md` returned no matches. | No current README/AGENTS claim found. | No README numeric LOC replacement was needed. |
| Repository file count | `git ls-files \| wc -l` returned `17203`. | Count is volatile and should not be copied into README prose. | Logged evidence only. |
| Tracked line count | `git ls-files -z \| xargs -0 wc -l \| awk '/ total$/ {sum += $1} END {print sum}'` returned `3479106`. | Count is volatile and depends on tracked generated/test/docs surfaces. | Logged evidence only. |
| Rust line count | `git ls-files -z '*.rs' \| xargs -0 wc -l \| awk '/ total$/ {sum += $1} END {print sum}'` returned `2978803`. | Count is volatile and should be regenerated, not embedded as prose. | Logged evidence only. |
| `src/` Rust surface | `git ls-files src \| rg '\\.rs$' \| wc -l` returned `1343`; the matching LOC summation returned `1724636`. | This explains the older ~1.72M figure as a live `src/` Rust-surface count, not a whole-repository-with-tests count. | Logged evidence only. |
| Workspace members | `cargo metadata --no-deps --format-version 1 \| jq -r '.workspace_members \| length'` returned `10`. The member list matches the AGENTS workspace-member table, with `asupersync-wasm` and `fuzz` excluded from the workspace. | Current README/AGENTS workspace-member claims are consistent with `Cargo.toml`. | Logged evidence only. |
| Cargo manifests vs workspace members | `find . -name Cargo.toml -not -path './target/*' -not -path './.git/*' \| sort` found `28` manifests, while cargo metadata reports `10` workspace members. | Manifest count is not the same as workspace-member count because fixtures, fuzz crates, and excluded crates carry manifests. | Logged evidence only. |
| Conformance registry counts | README already says not to copy conformance registry counts into prose and points to `artifacts/conformance_registry_contract_v1.json` plus `tests/conformance_registry_contract.rs`. | Current README avoids stale active/dormant module counts. | Logged evidence only. |
| Roadmap phase status | README Roadmap currently marks Phase 0, Phase 1, and Phase 3 complete; Phase 2 and Phase 5 partial; Phase 4 core primitives complete with remote adapters scoped; Phase 6 continuous. | `AGENTS.md` had a stale summary saying Phases 0-5 were complete. | Updated `AGENTS.md` to match README's current roadmap posture. |
| Legacy `master` wording | `README.md` and `AGENTS.md` reference `master` only as the legacy compatibility ref that must mirror `main`, plus code examples containing `main`. | Wording is intentional under the repository workflow. | No edit needed. |
