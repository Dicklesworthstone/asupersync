import re

with open('src/supervision.rs', 'r') as f:
    content = f.read()

# 1. Update signature of decide_err_with_budget
content = content.replace(
    'now: u64,\n        budget: Option<&Budget>,',
    'now: u64,\n        mut budget: Option<&mut Budget>,'
)

# 2. Update signature of on_failure_with_budget
content = content.replace(
    'now: u64,\n        budget: Option<&Budget>,',
    'now: u64,\n        budget: Option<&mut Budget>,'
)

# 3. Update the consumption logic
old_logic = """                // Check budget constraints if a budget is provided.
                if let Some(budget) = budget {
                    if let Err(refusal) = history.can_restart_with_budget(now, budget) {"""
new_logic = """                // Check budget constraints if a budget is provided.
                if let Some(ref mut b) = budget {
                    if let Err(refusal) = history.can_restart_with_budget(now, b) {"""
content = content.replace(old_logic, new_logic)

old_logic_2 = """                        return (decision, constraint);
                    }
                } else if !history.can_restart(now) {"""
new_logic_2 = """                        return (decision, constraint);
                    }
                    if config.restart_cost > 0 {
                        b.consume_cost(config.restart_cost);
                    }
                } else if !history.can_restart(now) {"""
content = content.replace(old_logic_2, new_logic_2)

# 4. Fix tests
content = re.sub(r'Some\(&budget\)', 'Some(&mut budget)', content)

# Fix Some(&Budget::INFINITE)
content = re.sub(r'Some\(&Budget::INFINITE\)', '{ let mut b = Budget::INFINITE; Some(&mut b) }', content)

with open('src/supervision.rs', 'w') as f:
    f.write(content)
