use std::cell::RefCell;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Perm {
    Shared,
    Mutable,
}

#[derive(Debug, Clone)]
struct Node {
    id: usize,
    parent: Option<usize>,
    children: Vec<usize>,
    permission: Perm, 
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
            permission: Perm::Mutable, // Roots are implicitly owners
            active: true,
        });
        id
    }

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

    /// Recursively invalidates a node and its entire subtree.
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

    /// Invalidates all descendants of a node.
    fn revoke_all_children(&mut self, id: usize) {
        if id >= self.nodes.len() { return; }
        
        let children = self.nodes[id].children.clone();
        for child in children {
            self.deep_revoke(child);
        }
        self.nodes[id].children.clear();
    }

    /// Enforces exclusivity: invalidates all sibling nodes except the survivor.
    fn revoke_siblings_except(&mut self, parent_id: usize, survivor_id: usize) {
        if parent_id >= self.nodes.len() { return; }
        
        let siblings = self.nodes[parent_id].children.clone();
        for sib in siblings {
            if sib != survivor_id {
                self.deep_revoke(sib);
            }
        }
        
        if let Some(parent) = self.nodes.get_mut(parent_id) {
            parent.children.retain(|&x| x == survivor_id);
        }
    }

    /// Invalidates only MUTABLE siblings. 
    fn revoke_mutable_siblings(&mut self, parent_id: usize, survivor_id: usize) {
        if parent_id >= self.nodes.len() { return; }
        
        let siblings = self.nodes[parent_id].children.clone();
        for sib in siblings {
            if sib != survivor_id && self.nodes[sib].permission == Perm::Mutable {
                self.deep_revoke(sib);
            }
        }
    }

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

    pub fn handle_alloc(&mut self, addr: usize) {
        let root_id = self.tree.spawn_root();
        self.shadow_map.insert(addr, root_id);
    }

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

    pub fn handle_access(&mut self, addr: usize) {
        let id = match self.shadow_map.get(&addr) {
            Some(id) => *id, 
            None => return, 
        };

        if !self.tree.is_valid(id) {
            panic!("[Security Violation] Use-After-Free/Revocation at 0x{:x}", addr);
        }

        let perm = self.tree.get_perm(id);

        // 1. Vertical Enforcement (Writer kills Children)
        if perm == Perm::Mutable {
            self.tree.revoke_all_children(id);
        }

        // 2. Horizontal Enforcement (Siblings)
        if let Some(parent) = self.tree.get_parent(id) {
            if perm == Perm::Mutable {
                self.tree.revoke_siblings_except(parent, id);
            } else if perm == Perm::Shared {
                self.tree.revoke_mutable_siblings(parent, id);
            }
        }
    }
}

pub fn track_alloc<T>(ptr: *const T) {
    RT.with(|rt| rt.borrow_mut().handle_alloc(ptr as usize));
}

pub fn track_borrow<T>(parent: *const T, derived: *const T, perm: Perm) {
    RT.with(|rt| rt.borrow_mut().handle_reborrow(parent as usize, derived as usize, perm));
}

pub fn check_access<T>(ptr: *const T) {
    RT.with(|rt| rt.borrow_mut().handle_access(ptr as usize));
}