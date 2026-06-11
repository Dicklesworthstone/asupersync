//! A Cx without the HasSpawn capability cannot spawn: the v2 surface is
//! gated at the type level, not by a runtime check.

use asupersync::cx::Cx;
use asupersync::cx::cap;

fn main() {
    let cx: Cx<cap::None> = Cx::detached_cancel_context();
    let _ = cx.spawn(|_cx| async move { 42_u32 });
}
