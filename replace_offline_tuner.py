import os

file_path = "src/raptorq/offline_tuner.rs"

with open(file_path, "r") as f:
    content = f.read()

old_call = """        // Extract optimized thresholds from selected candidate
        let (mul_min_total, mul_max_total, addmul_min_total, addmul_max_total, addmul_min_lane) =
            Self::derive_thresholds_from_candidate(selected);"""

new_call = """        // Extract optimized thresholds from selected candidate
        let (
            mul_min_total,
            mul_max_total,
            addmul_min_total,
            addmul_max_total,
            addmul_min_lane,
            max_lane_ratio,
        ) = Self::derive_thresholds_from_candidate(selected);"""

content = content.replace(old_call, new_call)

old_struct_init = """            addmul_min_lane,
            max_lane_ratio: 4, // TODO: Derive from candidate"""

new_struct_init = """            addmul_min_lane,
            max_lane_ratio,"""

content = content.replace(old_struct_init, new_struct_init)

old_fn = """    fn derive_thresholds_from_candidate(
        candidate: &KernelCandidate,
    ) -> (usize, usize, usize, usize, usize) {
        match candidate.fusion_shape {
            FusionShape::Fused => {
                // Fused kernels benefit from larger working sets
                (
                    candidate.tile_bytes * 4,
                    candidate.tile_bytes * 16,
                    candidate.tile_bytes * 2,
                    candidate.tile_bytes * 8,
                    candidate.tile_bytes,
                )
            }
            FusionShape::Split => {
                // Split kernels prefer smaller, more predictable working sets
                (
                    usize::MAX,
                    0,
                    candidate.tile_bytes,
                    candidate.tile_bytes * 4,
                    candidate.tile_bytes / 2,
                )
            }
            FusionShape::Balanced => {
                // Balanced approach based on tile size
                (
                    candidate.tile_bytes * 2,
                    candidate.tile_bytes * 8,
                    candidate.tile_bytes,
                    candidate.tile_bytes * 6,
                    candidate.tile_bytes / 2,
                )
            }
        }
    }"""

new_fn = """    fn derive_thresholds_from_candidate(
        candidate: &KernelCandidate,
    ) -> (usize, usize, usize, usize, usize, usize) {
        let max_lane_ratio = candidate.unroll.max(1);
        match candidate.fusion_shape {
            FusionShape::Fused => {
                // Fused kernels benefit from larger working sets
                (
                    candidate.tile_bytes * 4,
                    candidate.tile_bytes * 16,
                    candidate.tile_bytes * 2,
                    candidate.tile_bytes * 8,
                    candidate.tile_bytes,
                    max_lane_ratio,
                )
            }
            FusionShape::Split => {
                // Split kernels prefer smaller, more predictable working sets
                (
                    usize::MAX,
                    0,
                    candidate.tile_bytes,
                    candidate.tile_bytes * 4,
                    candidate.tile_bytes / 2,
                    max_lane_ratio,
                )
            }
            FusionShape::Balanced => {
                // Balanced approach based on tile size
                (
                    candidate.tile_bytes * 2,
                    candidate.tile_bytes * 8,
                    candidate.tile_bytes,
                    candidate.tile_bytes * 6,
                    candidate.tile_bytes / 2,
                    max_lane_ratio,
                )
            }
        }
    }"""

content = content.replace(old_fn, new_fn)

with open(file_path, "w") as f:
    f.write(content)

print("Applied offline_tuner fix.")
