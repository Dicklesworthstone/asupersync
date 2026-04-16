import sys

content = open("src/runtime/scheduler/priority.rs").read()

def replace_func(content, func_name, entry_type, priority_field):
    old_str = f"""    fn {func_name}(
        lane: &mut BinaryHeap<{entry_type}>,
        rng_hint: u64,
        scratch: &mut Vec<{entry_type}>,
    ) -> Option<{entry_type}> {{
        let first = lane.pop()?;
        if lane.is_empty() {{
            return Some(first);
        }}
        let {priority_field} = first.{priority_field};
        if lane.peek().is_some_and(|peek| peek.{priority_field} != {priority_field}) {{
            return Some(first);
        }}
        scratch.clear();
        scratch.push(first);

        while let Some(peek) = lane.peek() {{
            if peek.{priority_field} != {priority_field} || scratch.len() >= scratch.capacity() {{
                break;
            }}
            // `peek` guarantees the next `pop` is `Some`.
            scratch.push(lane.pop().expect("popped after peek"));
        }}

        let idx = Self::tie_break_index(rng_hint, scratch.len());
        let chosen = scratch.swap_remove(idx);
        for entry in scratch.drain(..) {{
            lane.push(entry);
        }}
        Some(chosen)
    }}"""

    new_str = f"""    fn {func_name}(
        lane: &mut BinaryHeap<{entry_type}>,
        rng_hint: u64,
        _scratch: &mut Vec<{entry_type}>,
    ) -> Option<{entry_type}> {{
        let first = lane.pop()?;
        if lane.is_empty() {{
            return Some(first);
        }}
        let {priority_field} = first.{priority_field};
        if lane.peek().is_some_and(|peek| peek.{priority_field} != {priority_field}) {{
            return Some(first);
        }}
        
        // Optimize tie-breaking to avoid O(K log N) pops:
        // Just pick between the top 2 elements. This provides sufficient 
        // scheduling jitter for DPOR without DOS-ing the production scheduler.
        if (rng_hint & 1) == 1 {{
            let second = lane.pop().unwrap();
            lane.push(first);
            Some(second)
        }} else {{
            Some(first)
        }}
    }}"""
    
    if old_str in content:
        return content.replace(old_str, new_str)
    else:
        print(f"Could not find {func_name} in content.")
        return content

content = replace_func(content, "pop_entry_with_rng", "SchedulerEntry", "priority")
content = replace_func(content, "pop_timed_with_rng", "TimedEntry", "deadline")

open("src/runtime/scheduler/priority.rs", "w").write(content)
