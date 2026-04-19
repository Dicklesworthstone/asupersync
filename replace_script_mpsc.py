import re

with open('src/channel/mpsc.rs', 'r') as f:
    content = f.read()

pattern = r'std::thread::spawn\(async move \{'
replacement = r'''std::thread::spawn(move || {
                    futures_lite::future::block_on(async move {'''

content = re.sub(pattern, replacement, content)

# I also need to replace `send_handle.await.unwrap()` or similar to `.join().unwrap()`
# and the closing brace `});` for the thread
# Since this is tricky with regex, let's just do it directly.
# Wait, replacing `});` with `})});` is required for the new block.

with open('src/channel/mpsc.rs', 'w') as f:
    f.write(content)
