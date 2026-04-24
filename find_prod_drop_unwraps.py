import os
import glob
import re

def check_file(filepath):
    if "test" in filepath or "tests/" in filepath:
        return
    with open(filepath, "r") as f:
        lines = f.readlines()
        
    in_drop = False
    brace_depth = 0
    for i, line in enumerate(lines):
        # Very simple heuristic
        if "impl Drop for" in line and "#[cfg(test)]" not in "".join(lines[max(0, i-5):i]):
            in_drop = True
            brace_depth = 0
        if in_drop:
            brace_depth += line.count("{") - line.count("}")
            if "unwrap()" in line or "expect(" in line:
                # ignore assert, and ubs:ignore
                if "ubs:ignore" not in line and "assert" not in line:
                    print(f"{filepath}:{i+1}: {line.strip()}")
            if brace_depth <= 0 and "}" in line:
                in_drop = False

for root, _, files in os.walk("src"):
    for file in files:
        if file.endswith(".rs"):
            check_file(os.path.join(root, file))
