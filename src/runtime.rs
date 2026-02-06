use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

// Type alias for Node Index to make code clearer
type NodeId = usize;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Permission {
    Shared,
    Mutable,
}

#[derive(Debug)]
pub struct BorrowNode {
    id: NodeId,
    parent: Option<NodeId>,
    children: Vec<NodeId>,
    permission: Permission,
    active: bool,
}

impl BorrowNode {
    fn new(id: NodeId, parent: Option<NodeId>, permission: Permission) -> Self {
        Self {
            id,
            parent,
            children: Vec::new(),
            permission,
            active: true,
        }
    }
}

pub struct BorrowTree {
    nodes: Vec<BorrowNode>,
}

impl BorrowTree {
    fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    fn new_root(&mut self) -> NodeId {
        let id = self.nodes.len();
        let node = BorrowNode::new(id, None, Permission::Mutable);
        self.nodes.push(node);
        id
    }

    fn add_child(&mut self, parent_id: NodeId, perm: Permission) -> Option<NodeId> {
        if parent_id >= self.nodes.len() || !self.nodes[parent_id].active {
            return None; 
        }

        let child_id = self.nodes.len();
        let child_node = BorrowNode::new(child_id, Some(parent_id), perm);
        self.nodes.push(child_node);

        // Link parent to child
        self.nodes[parent_id].children.push(child_id);
        Some(child_id)
    }

    fn get_node(&self, id: NodeId) -> Option<&BorrowNode> {
        self.nodes.get(id)
    }

    fn get_node_mut(&mut self, id: NodeId) -> Option<&mut BorrowNode> {
        self.nodes.get_mut(id)
    }

    // REVOCATION LOGIC:
    // When we access a node for writing, we must ensure:
    // 1. The node itself is active.
    // 2. Its ancestors are active.
    // 3. This access might revoke siblings (if they are incompatible).
    fn on_write_access(&mut self, access_id: NodeId) -> Result<(), String> {
        if access_id >= self.nodes.len() {
            return Err("Node ID out of bounds".to_string());
        }

        // 1. Check validity up the tree
        let mut curr = Some(access_id);
        while let Some(id) = curr {
            if !self.nodes[id].active {
                return Err(format!("Access Violation: Node {} (or ancestor) is already revoked.", access_id));
            }
            curr = self.nodes[id].parent;
        }

        // 2. Sibling Revocation Logic
        // If we write to 'access_id', other children of the same parent 
        // (which are siblings to this node) are effectively invalidated 
        // because we are claiming exclusive access.
        if let Some(parent_id) = self.nodes[access_id].parent {
            // We need to collect siblings to revoke to avoid borrowing issues
            let mut siblings_to_revoke = Vec::new();
            
            let parent = &self.nodes[parent_id];
            for &sibling_id in &parent.children {
                if sibling_id != access_id {
                    siblings_to_revoke.push(sibling_id);
                }
            }

            // Perform revocation
            for sibling_id in siblings_to_revoke {
                self.deep_revoke(sibling_id);
            }
        }

        Ok(())
    }

    // Recursively set a node and all its children to inactive
    fn deep_revoke(&mut self, id: NodeId) {
        if id >= self.nodes.len() { return; }
        
        // Use a stack to avoid recursion limit issues, though recursion is fine for shallow trees
        let mut stack = vec![id];
        while let Some(curr_id) = stack.pop() {
            if let Some(node) = self.nodes.get_mut(curr_id) {
                if node.active {
                    node.active = false;
                    // Add children to stack
                    stack.extend_from_slice(&node.children);
                    // println!("DEBUG: Revoked Node {}", curr_id);
                }
            }
        }
    }
}

pub struct Runtime {
    // Provenance Layer: Maps a raw memory address to a Node in the tree.
    provenance_map: HashMap<usize, NodeId>,
    // Alias Analysis Layer: The actual tree structure.
    borrow_tree: BorrowTree,
}

// Thread-local singleton for the runtime
thread_local! {
    pub static RUNTIME: RefCell<Runtime> = RefCell::new(Runtime::new());
}

impl Runtime {
    pub fn new() -> Self {
        Self {
            provenance_map: HashMap::new(),
            borrow_tree: BorrowTree::new(),
        }
    }

    // --- Interface Methods ---

    /// Start tracking a new allocation (Roots the tree)
    pub fn track_alloc(&mut self, addr: usize, _size: usize) {
        let root_id = self.borrow_tree.new_root();
        self.provenance_map.insert(addr, root_id);
        // println!("RUNTIME: Tracking alloc at 0x{:x} -> Node {}", addr, root_id);
    }

    /// Handle a reborrow: Create a new node derived from parent_addr
    pub fn track_reborrow(&mut self, parent_addr: usize, new_addr: usize, perm: Permission) {
        // 1. Find parent node
        let parent_node_id = match self.provenance_map.get(&parent_addr) {
            Some(&id) => id,
            None => {
                // If parent isn't tracked, we might panic or just ignore. 
                // For this demo, we assume tracked.
                panic!("RUNTIME ERROR: Reborrowing from untracked address 0x{:x}", parent_addr);
            }
        };

        // 2. Add child to tree
        if let Some(child_id) = self.borrow_tree.add_child(parent_node_id, perm) {
            // 3. Update Provenance Map
            self.provenance_map.insert(new_addr, child_id);
            // println!("RUNTIME: Reborrow 0x{:x} (Node {}) -> 0x{:x} (Node {})", parent_addr, parent_node_id, new_addr, child_id);
        } else {
            panic!("RUNTIME ERROR: Parent Node {} is invalid, cannot reborrow.", parent_node_id);
        }
    }

    /// "Invalidate" (Renamed from revoke): Removes from provenance map.
    /// Used when memory is freed.
    pub fn invalidate(&mut self, addr: usize) {
        if let Some(id) = self.provenance_map.remove(&addr) {
            // Optionally, we could also mark the node as inactive in the tree
            self.borrow_tree.deep_revoke(id);
            // println!("RUNTIME: Invalidated pointer 0x{:x}", addr);
        }
    }

    /// Check access validity
    pub fn check_access(&mut self, addr: usize) {
        let node_id = match self.provenance_map.get(&addr) {
            Some(&id) => id,
            None => {
                // Address not tracked, assume safe for now or panic depending on strictness
                return;
            }
        };

        // Delegate to tree logic
        match self.borrow_tree.on_write_access(node_id) {
            Ok(_) => { /* Access Allowed */ },
            Err(e) => {
                panic!("RUNTIME VIOLATION at address 0x{:x}: {}", addr, e);
            }
        }
    }
}

// --- FFI / Helpers for instrumentation ---

pub fn instrumentation_alloc(ptr: *const u8, size: usize) {
    RUNTIME.with(|rt| {
        rt.borrow_mut().track_alloc(ptr as usize, size);
    });
}

pub fn instrumentation_reborrow(parent: *const u8, derived: *const u8) {
    RUNTIME.with(|rt| {
        // Assuming Mutable for demo purposes, can be extended to take permission arg
        rt.borrow_mut().track_reborrow(parent as usize, derived as usize, Permission::Mutable);
    });
}

pub fn instrumentation_write(ptr: *const u8) {
    RUNTIME.with(|rt| {
        rt.borrow_mut().check_access(ptr as usize);
    });
}

pub fn instrumentation_free(ptr: *const u8) {
    RUNTIME.with(|rt| {
        rt.borrow_mut().invalidate(ptr as usize);
    });
}