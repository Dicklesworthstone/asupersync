import re
import sys

with open('src/sync/rwlock.rs', 'r') as f:
    content = f.read()

# Replace vec push_back with slab push_back_tagged
content = re.sub(
    r'state\.reader_waiters\.push_back\(Waiter \{\s*waker: context\.waker\(\)\.clone\(\),\s*id,\s*\}\);',
    r'let slab_index = state.reader_waiters.push_back_tagged(context.waker().clone(), id);',
    content
)

# And waiter_id = Some(id) -> Some(slab_index)
content = re.sub(
    r'let id = state\.next_waiter_id;[\s\S]*?this\.waiter_id = Some\(id\);',
    r'''let id = state.next_waiter_id;
        state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
        let slab_index = state.reader_waiters.push_back_tagged(context.waker().clone(), id);
        drop(state);
        this.waiter_id = Some(slab_index);''',
    content
)

with open('src/sync/rwlock.rs', 'w') as f:
    f.write(content)
