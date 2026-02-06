use std::cell::RefCell;
use std::collections::HashMap;

// PART 1: Data Structures & Logic

/// Core Permission Types matching Rust's Borrow Checker
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Perm {
    Shared,  // &T
    Mutable, // &mut T
}

/// A node in the Borrow Tree representing a specific pointer/reference
#[derive(Debug, Clone)]
struct Node {
    id: usize,
    parent: Option<usize>,
    children: Vec<usize>,
    active: bool,
}

struct BorrowTree {
    nodes: Vec<Node>,
}

impl BorrowTree {
    fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    fn spawn_root(&mut self) -> usize {
        let id = self.nodes.len();
        self.nodes.push(Node {
            id,
            parent: None,
            children: Vec::new(),
            active: true,
        });
        id
    }

    fn spawn_child(&mut self, parent_id: usize) -> Option<usize> {
        if parent_id >= self.nodes.len() || !self.nodes[parent_id].active {
            return None;
        }
        let id = self.nodes.len();
        self.nodes.push(Node {
            id,
            parent: Some(parent_id),
            children: Vec::new(),
            active: true,
        });
        self.nodes[parent_id].children.push(id);
        Some(id)
    }

    ///  Invalidates a node and everything derived from it.
    fn deep_revoke(&mut self, id: usize) {
        if id >= self.nodes.len() {
            return;
        }
        let mut stack = vec![id];
        while let Some(curr) = stack.pop() {
            if let Some(node) = self.nodes.get_mut(curr) {
                if node.active {
                    node.active = false;
                    stack.extend_from_slice(&node.children);
                }
            }
        }
    }

    /// Sibling Revocation Logic
    /// Used when a Mutable borrow claims exclusivity at a specific level.
    fn revoke_children_of(&mut self, parent_id: usize) {
        if parent_id >= self.nodes.len() {
            return;
        }
        // Copy children IDs to avoid borrowing conflicts during iteration
        let siblings = self.nodes[parent_id].children.clone();
        for sib in siblings {
            self.deep_revoke(sib);
        }
        // Clean up the parent's list since they are all dead
        self.nodes[parent_id].children.clear();
    }

    fn is_valid(&self, id: usize) -> bool {
        let mut curr = Some(id);
        while let Some(idx) = curr {
            let node = match self.nodes.get(idx) {
                Some(n) => n,
                None => return false,
            };
            if !node.active {
                return false;
            }
            curr = node.parent;
        }
        true
    }
}

// PART 2: The Runtime State

pub struct Runtime {
    tree: BorrowTree,
    shadow_map: HashMap<usize, usize>,
}

thread_local! {
    pub static RT: RefCell<Runtime> = RefCell::new(Runtime::new());
}

impl Runtime {
    pub fn new() -> Self {
        Self {
            tree: BorrowTree::new(),
            shadow_map: HashMap::new(),
        }
    }

    /// Called on `let x = Box::new(...)` or stack allocation
    pub fn handle_alloc(&mut self, addr: usize) {
        let root_id = self.tree.spawn_root();
        self.shadow_map.insert(addr, root_id);
    }

    /// Called on `let y = &x` or `let y = &mut x`
    pub fn handle_reborrow(&mut self, parent_addr: usize, new_addr: usize, perm: Perm) {
        let parent_id = match self.shadow_map.get(&parent_addr) {
            Some(&id) => id,
            None => panic!(
                "[Security Violation] Reborrowing from invalid/untracked address 0x{:x}",
                parent_addr
            ),
        };

        if perm == Perm::Mutable {
            self.tree.revoke_children_of(parent_id);
        }

        match self.tree.spawn_child(parent_id) {
            Some(child_id) => {
                self.shadow_map.insert(new_addr, child_id);
            }
            None => panic!(
                "[Security Violation] Parent 0x{:x} is already invalidated.",
                parent_addr
            ),
        }
    }

    /// Called on `*ptr = ...` or `val = *ptr`
    pub fn handle_access(&self, addr: usize) {
        let id = match self.shadow_map.get(&addr) {
            Some(&id) => id,
            None => return, // Untracked memory (e.g., raw FFI) is ignored in this demo
        };

        if !self.tree.is_valid(id) {
            panic!(
                "[Security Violation] Use-After-Free/Revocation at address 0x{:x}",
                addr
            );
        }
    }
}

// PART 3: Public Helpers (API)

pub fn track_alloc<T>(ptr: *const T) {
    RT.with(|rt| rt.borrow_mut().handle_alloc(ptr as usize));
}

pub fn track_borrow<T>(parent: *const T, derived: *const T, perm: Perm) {
    RT.with(|rt| {
        rt.borrow_mut()
            .handle_reborrow(parent as usize, derived as usize, perm)
    });
}

pub fn check_access<T>(ptr: *const T) {
    RT.with(|rt| rt.borrow().handle_access(ptr as usize));
}
