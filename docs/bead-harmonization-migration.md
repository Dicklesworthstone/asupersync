# Bead Harmonization Migration Plan

**Date**: 2026-01-22
**Tracking EPIC**: bd-zs64
**Status**: In progress

## Executive Summary

This migration harmonizes the asupersync bead hierarchy to eliminate duplicates, fix priority misalignments, and establish consistent naming conventions. All changes preserve functionality while improving the coherence of the agent "robot mode" interface.

## Changes Executed

### 1. I/O EPIC Consolidation (bd-q0om)

**Problem**: Two overlapping Phase 2 I/O EPICs existed:
- `asupersync-90l9` (P0): "[EPIC] Phase 2: Production I/O"
- `asupersync-ds8` (P2): "EPIC: Phase 2 - Production I/O Foundation"

**Resolution**:
- Linked 90l9's sub-EPICs to ds8 hierarchy:
  - `asupersync-56fs` (Epoll Reactor) → now depends on ds8
  - `asupersync-5w2z` (Cancel-Safe File I/O) → now depends on ds8
  - `asupersync-8jx5` (TCP/UDP Networking) → now depends on ds8
- Closed `asupersync-90l9` with migration note
- Canonical EPIC: **asupersync-ds8**

### 2. Parallel Runtime EPIC Consolidation (bd-hzrb)

**Problem**: Two overlapping parallel runtime EPICs existed:
- `asupersync-n5o` (P1): "[SUB-EPIC] Parallel Runtime"
- `asupersync-xrc` (P2): "EPIC: Parallel Runtime Execution"

**Resolution**:
- Made `asupersync-n5o` depend on `asupersync-xrc`
- Updated n5o description to note it's a tokio-equivalence alias
- Canonical EPIC: **asupersync-xrc**

### 3. Priority Alignment (bd-4rpn)

**Problem**: xrc EPIC and sub-tasks had P2 priority but parallel runtime is critical.

**Resolution**: Updated to P1:
- `asupersync-xrc` (EPIC)
- `asupersync-xrc.1` through `asupersync-xrc.12` (all sub-tasks)

### 4. Duplicate Dependency Cleanup (asupersync-14o)

**Problem**: asupersync-14o had duplicate dependencies pointing to both canonical and duplicate versions of the same modules.

**Duplicates Removed** (with canonical versions):
| Removed | Canonical | Module |
|---------|-----------|--------|
| asupersync-emz | asupersync-a4th | Signal Handling |
| asupersync-4ue | asupersync-ewm6 | Process Spawning |
| asupersync-uqw | asupersync-5wao | DNS Resolution |
| asupersync-8vy | asupersync-52ug | TLS |
| asupersync-nid | asupersync-zj8r | Bytes/Buffer |

**Resolution**:
- Removed duplicate dependencies from 14o
- Updated duplicate beads with "DUPLICATE: Superseded by X" notes

### 5. Naming Standardization (bd-kh65)

### 6. Orphan Sub-task Migration (bd-3p6e)

**Problem**: Legacy runtime tasks (8z9, ior, 9d3, c61) were floating without a Phase 1 parent.

**Resolution**:
- Re-parented to the Phase 1 hierarchy:
  - `asupersync-9d3` → parent `asupersync-xrc.1` (Work-Stealing Scheduler)
  - `asupersync-c61` → parent `asupersync-xrc.1` (Work-Stealing Scheduler)
  - `asupersync-ior` → parent `asupersync-xrc.2` (Region Heap + Send Task Model)
  - `asupersync-8z9` → parent `asupersync-xrc.2` (Region Heap + Send Task Model)
- Legacy IDs remain for traceability; canonical hierarchy is now `xrc.*`.

**Status**: Tracked for future standardization

**Current inconsistencies identified**:
- `[EPIC]` prefix format
- `EPIC:` prefix format
- `Epic #N` format
- `[SUB-EPIC]` prefix format

**Recommended standard**: `EPIC: Title` for top-level, `SUB-EPIC: Title` for children

## Tracking Beads Created

| ID | Purpose |
|----|---------|
| bd-zs64 | Master harmonization tracking EPIC |
| bd-q0om | I/O EPIC merge tracking |
| bd-hzrb | Parallel runtime merge tracking |
| bd-kh65 | Naming standardization tracking |
| bd-4rpn | Priority alignment tracking |
| bd-3p6e | Orphan migration tracking |

## Verification Commands

```bash
# List all open beads
br list

# Robot-mode triage (for agents)
bv --robot-triage

# Check specific EPIC hierarchies
br show asupersync-ds8
br show asupersync-xrc

# Verify no orphan tasks
bv --orphans
```

## Rollback Procedure

If issues are discovered:

1. Re-open closed beads:
   ```bash
   br update asupersync-90l9 --status open
   ```

2. Restore original dependencies:
   ```bash
   br dep add asupersync-14o asupersync-emz
   br dep add asupersync-14o asupersync-4ue
   # etc.
   ```

3. Restore original priorities:
   ```bash
   br update asupersync-xrc -p 2
   ```

## No Features Lost

All functionality preserved:
- All sub-EPICs and tasks remain accessible
- Dependency relationships maintained via new canonical parents
- Priority increases (P2→P1) only make items more visible
- Closed duplicates have migration notes for traceability

## Next Steps

1. Complete naming standardization (asupersync-kh65)
2. Regular `bv --robot-triage` audits
3. Consider closing remaining duplicate beads after verification period
