import os

def dedup_file(filepath):
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    new_lines = []
    seen_allow = False
    modified = False
    
    for line in lines:
        if line.startswith('#![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap'):
            if seen_allow:
                modified = True
                continue
            seen_allow = True
        
        # also deduplicate the #[cfg(test)] inner allow
        if line.strip().startswith('#![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap'):
            if seen_allow:
                modified = True
                continue
            seen_allow = True

        new_lines.append(line)

    if modified:
        with open(filepath, 'w') as f:
            f.writelines(new_lines)
        print(f"Fixed {filepath}")

for root, _, files in os.walk('tests'):
    for file in files:
        if file.endswith('.rs'):
            dedup_file(os.path.join(root, file))

for root, _, files in os.walk('src'):
    for file in files:
        if file.endswith('.rs'):
            dedup_file(os.path.join(root, file))
