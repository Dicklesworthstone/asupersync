import os
import re

ALLOW_ATTR = "#![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]\n"

def process_file(filepath):
    if not filepath.endswith('.rs'):
        return

    with open(filepath, 'r') as f:
        content = f.read()

    # Add to integration tests
    if 'tests/' in filepath:
        if ALLOW_ATTR not in content:
            content = ALLOW_ATTR + content

    # Add to #[cfg(test)] modules in src/
    if 'src/' in filepath:
        if '#[cfg(test)]\nmod tests {' in content:
            content = content.replace(
                '#[cfg(test)]\nmod tests {\n',
                f'#[cfg(test)]\nmod tests {{\n    {ALLOW_ATTR}'
            )

    with open(filepath, 'w') as f:
        f.write(content)

for root, _, files in os.walk('tests'):
    for file in files:
        process_file(os.path.join(root, file))

for root, _, files in os.walk('src'):
    for file in files:
        process_file(os.path.join(root, file))

print("Applied allow attributes to test modules.")
