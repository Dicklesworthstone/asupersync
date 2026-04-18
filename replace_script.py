import sys

def modify_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    # Replacement 1: drain_nodes -> take_all in TimerSlot
    old_drain_nodes = """    /// Drains all nodes from the slot without consuming their wakers.
    ///
    /// # Safety
    ///
    /// All nodes in the slot must be valid.
    unsafe fn drain_nodes(&self) -> Vec<NonNull<TimerNode>> {
        let mut nodes = Vec::with_capacity(self.count.get());

        while let Some(node) = self.pop_front() {
            nodes.push(node);
        }

        nodes
    }"""
    
    new_take_all = """    /// Extracts all nodes from the slot in O(1) time.
    ///
    /// # Safety
    ///
    /// Extracted nodes remain linked=true internally and must be unlinked manually.
    unsafe fn take_all(&self) -> Option<NonNull<TimerNode>> {
        let head = self.head.get();
        self.head.set(None);
        self.tail.set(None);
        self.count.set(0);
        head
    }"""

    # Replacement 2: collect_expired without extra allocation
    old_collect_expired = """    unsafe fn collect_expired(&self, now: Instant) -> (Vec<Waker>, usize) {
        let mut wakers = Vec::with_capacity(self.count.get());
        let mut expired = Vec::with_capacity(self.count.get());

        // First pass: identify expired nodes
        let mut current = self.head.get();
        while let Some(node_ptr) = current {
            let node_ref = node_ptr.as_ref();
            let next = node_ref.next.get();

            if node_ref.deadline() <= now {
                expired.push(node_ptr);
            }

            current = next;
        }

        let removed_count = expired.len();
        // Second pass: remove expired and collect wakers
        for node_ptr in expired {
            self.remove(node_ptr);
            if let Some(waker) = node_ptr.as_ref().take_waker() {
                wakers.push(waker);
            }
        }

        (wakers, removed_count)
    }"""

    new_collect_expired = """    unsafe fn collect_expired(&self, now: Instant) -> (Vec<Waker>, usize) {
        let mut wakers = Vec::new();
        let mut removed_count = 0;

        let mut current = self.head.get();
        while let Some(node_ptr) = current {
            let node_ref = node_ptr.as_ref();
            let next = node_ref.next.get();

            if node_ref.deadline() <= now {
                self.remove(node_ptr);
                if let Some(waker) = node_ref.take_waker() {
                    wakers.push(waker);
                }
                removed_count += 1;
            }

            current = next;
        }

        (wakers, removed_count)
    }"""

    # Replacement 3: advance_to fast-forward drain_level! macro
    old_drain_level = """            macro_rules! drain_level {
                ($level:expr) => {
                    for slot in &mut $level.slots {
                        let nodes = slot.drain_nodes();
                        for node in nodes {
                            let node_ref = node.as_ref();
                            if node_ref.deadline() <= now {
                                if let Some(w) = node_ref.take_waker() {
                                    wakers.push(w);
                                }
                            } else {
                                remaining.push(node);
                            }
                        }
                    }
                };
            }"""

    new_drain_level = """            macro_rules! drain_level {
                ($level:expr) => {
                    for slot in &mut $level.slots {
                        let mut current_node = slot.take_all();
                        while let Some(node_ptr) = current_node {
                            let node_ref = node_ptr.as_ref();
                            let next = node_ref.next.get();

                            node_ref.linked.set(false);
                            node_ref.prev.set(None);
                            node_ref.next.set(None);

                            if node_ref.deadline() <= now {
                                if let Some(w) = node_ref.take_waker() {
                                    wakers.push(w);
                                }
                            } else {
                                remaining.push(node_ptr);
                            }

                            current_node = next;
                        }
                    }
                };
            }"""

    # Replacement 4: cascade
    old_cascade = """    #[allow(clippy::only_used_in_recursion)]
    fn cascade(&mut self, level_index: u8, now: Instant, wakers: &mut Vec<Waker>) {
        let (bucket, wrapped) = match level_index {
            1 => self.level1.advance_and_drain(),
            2 => self.level2.advance_and_drain(),
            3 => self.level3.advance_and_drain(),
            _ => return,
        };

        for node in bucket {
            let node_ref = unsafe { node.as_ref() };
            if node_ref.deadline() <= now {
                if let Some(waker) = node_ref.take_waker() {
                    wakers.push(waker);
                }
                self.count = self.count.saturating_sub(1);
                continue;
            }
            if !node_ref.is_linked() {
                let (new_level, new_slot) = self.slot_for(node_ref.deadline());
                node_ref.update_slot_level(new_slot, new_level);
                self.push_node(new_level, new_slot, node);
            }
        }

        if wrapped {
            self.cascade(level_index + 1, now, wakers);
        }
    }"""

    new_cascade = """    #[allow(clippy::only_used_in_recursion)]
    fn cascade(&mut self, level_index: u8, now: Instant, wakers: &mut Vec<Waker>) {
        let (mut current_node, wrapped) = match level_index {
            1 => self.level1.advance_and_take(),
            2 => self.level2.advance_and_take(),
            3 => self.level3.advance_and_take(),
            _ => return,
        };

        while let Some(node_ptr) = current_node {
            let node_ref = unsafe { node_ptr.as_ref() };
            let next = node_ref.next.get();

            node_ref.linked.set(false);
            node_ref.prev.set(None);
            node_ref.next.set(None);

            if node_ref.deadline() <= now {
                if let Some(waker) = node_ref.take_waker() {
                    wakers.push(waker);
                }
                self.count = self.count.saturating_sub(1);
            } else {
                let (new_level, new_slot) = self.slot_for(node_ref.deadline());
                node_ref.update_slot_level(new_slot, new_level);
                self.push_node(new_level, new_slot, node_ptr);
            }

            current_node = next;
        }

        if wrapped {
            self.cascade(level_index + 1, now, wakers);
        }
    }"""

    # Replacement 5: advance_and_drain
    old_advance_and_drain = """    /// Advances cursor by one and drains the slot at the new cursor position.
    ///
    /// Returns the nodes from the drained slot and whether the cursor wrapped around.
    fn advance_and_drain(&mut self) -> (Vec<NonNull<TimerNode>>, bool) {
        self.cursor = (self.cursor + 1) % SLOTS;
        let wrapped = self.cursor == 0;
        let nodes = unsafe { self.slots[self.cursor].drain_nodes() };
        (nodes, wrapped)
    }"""

    new_advance_and_take = """    /// Advances cursor by one and takes the slot at the new cursor position.
    ///
    /// Returns the head of the extracted list and whether the cursor wrapped around.
    fn advance_and_take(&mut self) -> (Option<NonNull<TimerNode>>, bool) {
        self.cursor = (self.cursor + 1) % SLOTS;
        let wrapped = self.cursor == 0;
        let head = unsafe { self.slots[self.cursor].take_all() };
        (head, wrapped)
    }"""

    content = content.replace(old_drain_nodes, new_take_all)
    content = content.replace(old_collect_expired, new_collect_expired)
    content = content.replace(old_drain_level, new_drain_level)
    content = content.replace(old_cascade, new_cascade)
    content = content.replace(old_advance_and_drain, new_advance_and_take)

    with open(filepath, 'w') as f:
        f.write(content)

modify_file('src/time/intrusive_wheel.rs')
