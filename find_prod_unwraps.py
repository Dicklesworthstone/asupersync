import os

def check_file(filepath):
    if "test" in filepath or "tests/" in filepath:
        return
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
        
    in_test = False
    brace_depth = 0
    for i, line in enumerate(lines):
        if "#[cfg(test)]" in line or "#[test]" in line:
            in_test = True
            brace_depth = 0
        if in_test:
            brace_depth += line.count("{") - line.count("}")
        
        if not in_test:
            if "unwrap()" in line or "expect(" in line:
                if "assert" not in line and "ubs:ignore" not in line and "test_utils" not in line:
                    # Ignore a few false positives
                    if "thread::spawn" not in line and "Mutex" not in line and "RwLock" not in line:
                        print(f"{filepath}:{i+1}: {line.strip()}")
                        
        if in_test and brace_depth <= 0 and "}" in line:
            in_test = False

for root, _, files in os.walk("src"):
    for file in files:
        if file.endswith(".rs"):
            check_file(os.path.join(root, file))
