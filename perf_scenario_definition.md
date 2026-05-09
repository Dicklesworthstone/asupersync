# Performance Profiling Scenario - Round 2 Post-yvmiat

**Scenario**: Runtime scheduler, context, and channel performance optimization
**Workload**: artifacts/runtime_workload_corpus_v1.json (AA01-WL-CPU-001 primary target)
**Metric**: CPU hotspots with >5% impact evidence via samply profiling
**Success Criteria**: Ranked hotspot table with concrete evidence, ship measurable wins only

**Target Directories**:
- src/runtime/scheduler/ (wake path, scheduling primitives)  
- src/cx/ (capability context building)
- src/channel/ (two-phase reserve/send operations)

**Previous Context**: yvmiat optimization delivered 71.8% → ~20% improvement in schedule_local_push
**This Round**: Find next >5% targets with hard profiling evidence

**Budget**: 60 minutes ship-or-surface
**Evidence Standard**: samply flame graphs + quantified impact per function