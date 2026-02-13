use std::cell::RefCell;
use std::collections::HashMap;

/// Represents the permission level of a pointer, derived from Rust's ownership model.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Perm {
    /// Shared (Read-Only) access. Multiple Shared pointers can coexist.
    Shared,
    /// Mutable (Unique) access. Must be exclusive (XOR Aliasing).
    Mutable,
}

/// A node in the Borrow Tree representing a specific pointer derivation.
/// Tracks lineage (parent/children) and current validity (active status).
#[derive(Debug, Clone)]
struct Node {
    id: usize,
    parent: Option<usize>,
    children: Vec<usize>,
    permission: Perm, 
    /// If false, this pointer has been revoked and cannot be used.
    active: bool,
}

/// The core data structure enforcing the Aliasing Model.
/// It maintains the hierarchy of borrows to track pointer provenance.
struct BorrowTree {
    nodes: Vec<Node>,
}

impl BorrowTree {
    fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Creates a new root node for a fresh allocation.
    /// Roots are implicitly Mutable (Owners).
    fn spawn_root(&mut self) -> usize {
        let id = self.nodes.len();
        self.nodes.push(Node {
            id,
            parent: None,
            children: Vec::new(),
            permission: Perm::Mutable, 
            active: true,
        });
        id
    }

    /// Derives a child pointer from a valid parent.
    /// Returns None if the parent is already invalid.
    fn spawn_child(&mut self, parent_id: usize, perm: Perm) -> Option<usize> {
        if parent_id >= self.nodes.len() || !self.nodes[parent_id].active {
            return None;
        }
        let id = self.nodes.len();
        self.nodes.push(Node {
            id,
            parent: Some(parent_id),
            children: Vec::new(),
            permission: perm,
            active: true,
        });
        self.nodes[parent_id].children.push(id);
        Some(id)
    }

    /// Recursively invalidates a node and its entire subtree (descendants).
    /// Uses an iterative stack approach to prevent stack overflow on deep trees.
    fn deep_revoke(&mut self, id: usize) {
        if id >= self.nodes.len() { return; }
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

    /// Revokes all children of a specific node.
    /// This enforces "Freezing": If a parent writes, all derived pointers must be invalidated.
    fn revoke_all_children(&mut self, id: usize) {
        if id >= self.nodes.len() { return; }
        
        // Clone children list to safely iterate while modifying the tree
        let children = self.nodes[id].children.clone();
        for child in children {
            self.deep_revoke(child);
        }
        self.nodes[id].children.clear();
    }

    /// Enforces "Aliasing XOR Mutability" for Write Access.
    /// Invalidates all sibling nodes except the survivor (the one being used).
    fn revoke_siblings_except(&mut self, parent_id: usize, survivor_id: usize) {
        if parent_id >= self.nodes.len() { return; }
        
        let siblings = self.nodes[parent_id].children.clone();
        for sib in siblings {
            if sib != survivor_id {
                self.deep_revoke(sib);
            }
        }
        
        // Update the parent's child list to reflect that only the survivor remains
        if let Some(parent) = self.nodes.get_mut(parent_id) {
            parent.children.retain(|&x| x == survivor_id);
        }
    }

    /// Enforces "Reader-Writer Lock" for Read Access.
    /// Invalidates only MUTABLE siblings, allowing other Shared siblings to survive.
    fn revoke_mutable_siblings(&mut self, parent_id: usize, survivor_id: usize) {
        if parent_id >= self.nodes.len() { return; }
        
        let siblings = self.nodes[parent_id].children.clone();
        for sib in siblings {
            // If sibling is Mutable, it conflicts with our Shared access -> Revoke it.
            if sib != survivor_id && self.nodes[sib].permission == Perm::Mutable {
                self.deep_revoke(sib);
            }
        }
        // Note: We do not remove them from the parent's list here; 
        // they are just marked inactive and filtered out during validity checks.
    }

    /// Checks if a pointer is valid by verifying the entire path to the root.
    fn is_valid(&self, id: usize) -> bool {
        let mut curr = Some(id);
        while let Some(idx) = curr {
            match self.nodes.get(idx) {
                Some(node) => {
                    if !node.active { return false; }
                    curr = node.parent;
                }
                None => return false,
            }
        }
        true
    }

    fn get_perm(&self, id: usize) -> Perm {
        self.nodes[id].permission
    }

    fn get_parent(&self, id: usize) -> Option<usize> {
        self.nodes[id].parent
    }
}

/// The Runtime Monitor state.
/// Holds the BorrowTree (Logical Model) and Shadow Map (Address -> Tree Node mapping).
pub struct Runtime {
    tree: BorrowTree,
    shadow_map: HashMap<usize, usize>,
}

thread_local! {
    /// Thread-local singleton for the runtime monitor.
    pub static RT: RefCell<Runtime> = RefCell::new(Runtime::new());
}

impl Runtime {
    pub fn new() -> Self {
        Self {
            tree: BorrowTree::new(),
            shadow_map: HashMap::new(),
        }
    }

    /// Tracks a new memory allocation (Root).
    pub fn handle_alloc(&mut self, addr: usize) {
        let root_id = self.tree.spawn_root();
        self.shadow_map.insert(addr, root_id);
    }

    /// Tracks a reborrow (derivation of a new pointer from an existing one).
    /// Implements Lazy Revocation: No invalidation happens here, only tree insertion.
    pub fn handle_reborrow(&mut self, parent_addr: usize, new_addr: usize, perm: Perm) {
        let parent_id = match self.shadow_map.get(&parent_addr) {
            Some(id) => *id, 
            None => panic!("[Security] Reborrow from untracked address 0x{:x}", parent_addr),
        };

        match self.tree.spawn_child(parent_id, perm) {
            Some(child_id) => {
                self.shadow_map.insert(new_addr, child_id);
            }
            None => panic!("[Security] Parent at 0x{:x} is already invalidated.", parent_addr),
        }
    }

    /// Validates access and triggers Revoke-on-Use logic.
    /// This function acts as the Reference Monitor barrier.
    pub fn handle_access(&mut self, addr: usize) {
        let id = match self.shadow_map.get(&addr) {
            Some(id) => *id, 
            None => return, // Ignore untracked memory (e.g., stack vars not monitored)
        };

        // 1. Validate Provenance (Is the pointer still alive?)
        if !self.tree.is_valid(id) {
            panic!("[Security Violation] Use-After-Free/Revocation at 0x{:x}", addr);
        }

        let perm = self.tree.get_perm(id);

        // 2. Vertical Enforcement: Writer kills Children (Freezing)
        // If we are Writing, we assert uniqueness, so all derived pointers must die.
        if perm == Perm::Mutable {
            self.tree.revoke_all_children(id);
        }

        // 3. Horizontal Enforcement: Sibling Conflicts
        if let Some(parent) = self.tree.get_parent(id) {
            if perm == Perm::Mutable {
                // WRITE Access: Exclusive. Kill ALL siblings.
                self.tree.revoke_siblings_except(parent, id);
            } else if perm == Perm::Shared {
                // READ Access: Shared. Kill only MUTABLE siblings.
                self.tree.revoke_mutable_siblings(parent, id);
            }
        }
    }
}

// --- Public API (Exposed to FFI / Instrumentation) ---

pub fn track_alloc<T>(ptr: *const T) {
    RT.with(|rt| rt.borrow_mut().handle_alloc(ptr as usize));
}

pub fn track_borrow<T>(parent: *const T, derived: *const T, perm: Perm) {
    RT.with(|rt| rt.borrow_mut().handle_reborrow(parent as usize, derived as usize, perm));
}

pub fn check_access<T>(ptr: *const T) {
    RT.with(|rt| rt.borrow_mut().handle_access(ptr as usize));
}