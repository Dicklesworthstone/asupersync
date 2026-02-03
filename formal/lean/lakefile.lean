import Lake
open Lake DSL

package asupersync_semantics where
  -- Self-contained semantics mechanization; no extra deps beyond Std.

@[default_target]
lean_lib Asupersync where
  srcDir := "."
