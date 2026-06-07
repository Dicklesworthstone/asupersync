# asupersync repo-janitor handoff — 2026-05-13

## Outcome
Cleaned up 12 root-level files (8 moves, 3 deletes, 1 surfaced-and-kept) and
hardened `.gitignore` with 6 root-anchored patterns to prevent re-accretion.
**8.0 MB of unused tracked artifacts removed from the working tree.**

All 6 cleanup commits live directly on `main` (per AGENTS.md RULE 2: no
branches, no worktrees). No reference rewrites were necessary in source code;
the one historical artifact reference in `tests/artifacts/perf/asupersync-yvmiat-fingerprint.json`
was left as-is (it's a frozen `git status` snapshot, not a live link).

## Commit log (6 commits on main, branching from 43fd4c8f8)

| SHA | Subject | Net diff |
|-----|---------|---------|
| `b247b5533` | Move architectural design docs from root to docs/ | 2 renames, 0 bytes |
| `bfed7f749` | Move bead-specific notes to docs/beads/ | 2 renames, 0 bytes |
| `4d89ad631` | Move uring user_data collision bug report to docs/audits/ | 1 rename, 0 bytes |
| `6decb6f2a` | Move modes-of-reasoning analysis + perf scenario to docs/ | 3 renames, 0 bytes |
| `349075641` | Remove tracked debug binary + unused PNG illustration duplicates | -8 MB |
| `417354433` | Add root-anchored .gitignore patterns to prevent re-accretion | +17 lines |

## What moved (8 files)

| From (root) | To |
|-------------|----|
| `CROSS_MODULE_LOCK_ORDERING.md` | `docs/CROSS_MODULE_LOCK_ORDERING.md` |
| `MEMORY_ORDERING_OPTIMIZATION.md` | `docs/MEMORY_ORDERING_OPTIMIZATION_REPORT.md` (renamed; docs/ already had an `_AUDIT` companion) |
| `bead_1qfd0.620.md` | `docs/beads/bead_1qfd0.620.md` |
| `bead_metamorphic_analysis.md` | `docs/beads/bead_metamorphic_analysis.md` |
| `bug_report_uring_user_data_collision.md` | `docs/audits/bug_report_uring_user_data_collision.md` |
| `MODES_ANALYSIS_PROGRESS.md` | `docs/analysis/MODES_ANALYSIS_PROGRESS.md` |
| `MODES_OF_REASONING_REPORT_AND_ANALYSIS_OF_PROJECT.md` | `docs/analysis/MODES_OF_REASONING_REPORT_AND_ANALYSIS_OF_PROJECT.md` |
| `perf_scenario_definition.md` | `docs/perf/perf_scenario_definition.md` |

All 8 moves recorded as 100% similarity renames by git (preserves blame/log
across the move).

## What was deleted (3 files, 8.0 MB)

| Path | Size | Why |
|------|------|-----|
| `cx_optimization_benchmark` | 4.2 MB | ELF debug binary; no [[bin]] entry; accidentally committed in d006b5302 |
| `asupersync_diagram.png` | 1.7 MB | README uses the .webp variant; .png was an unused larger duplicate |
| `asupersync_illustration.png` | 2.2 MB | README uses the .webp variant; .png was an unused larger duplicate |

## What was surfaced and kept

| Path | Size | Why kept |
|------|------|----------|
| `gh_og_share_image.png` | 323 KB | Intentional GitHub social-preview asset (per user) |

## What was hardened (.gitignore additions)

Six new root-anchored patterns added to `.gitignore`:

    /cx_*_benchmark      -> belongs in target/, not at root
    /asupersync_*.png    -> README uses .webp variants
    /bead_*.md           -> belongs under docs/beads/
    /MODES_*.md          -> belongs under docs/analysis/
    /perf_scenario_*.md  -> belongs under docs/perf/
    /bug_report_*.md     -> belongs under docs/audits/

Shadowing audit: all 6 patterns are root-anchored (leading `/`), so the moved
files at `docs/beads/bead_*.md`, `docs/analysis/MODES_*.md`, etc. remain
tracked normally. `gh_og_share_image.png`, `asupersync_*.webp`, and
`asupersync_plan_v4.md` are explicitly NOT ignored (verified via
`git check-ignore`).

## Recovery

If anything needs to come back:

    # Backup ref (saved before any cleanup commit):
    git checkout refs/repo-janitor-backup/2026-05-13-pre-cleanup -- <path>

    # Or revert specific commits:
    git revert 417354433   # the .gitignore
    git revert 349075641   # the deletes
    git revert 6decb6f2a 4d89ad631 bfed7f749 b247b5533   # the moves

    # Or restore from the bundle (byte-identical copies):
    cp /data/projects/asupersync-repo-archive-2026-05-13/working-tree-copies/<path> .

## Quality gate

    rch exec -- cargo check --all-targets   # exit=0 in 6m 48s on ts2

No errors, no warnings introduced.

## Concurrent-agent work I did NOT touch

Per AGENTS.md, concurrent agents' working-tree changes belong to them:

    M  .beads/issues.jsonl
    M  src/observability/otel_conformance_tests.rs

(The other concurrent-agent file `src/observability/w3c_trace_id_randomness_audit_test.rs`
was committed by another agent during my work as `771892200`.)

I committed only the files in my categorized plan, using scoped `git add` /
`git mv` / `git rm` so I never accidentally bundled concurrent agents' work
into my commits.

## Push plan (AGENTS.md branch policy)

    git push origin main           # land cleanup on main
    git push origin main:master    # keep master synchronized (legacy URL compat)

I have NOT pushed yet; awaiting user authorization before push (shared-state
action per Claude Code default policy).
