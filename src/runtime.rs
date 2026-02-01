use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::RwLock;

/// A unique identifier for a specific memory allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag(pub u64);

/// Metadata tracked for each allocation.
///
///We track allocations by their Base Address
/// rather than using a full Shadow Register File, providing O(1) lookup.
#[derive(Debug, Clone)]
pub struct AllocationMetadata {
    pub base_addr: usize,
    pub size: usize,
    pub active_tag: Tag,
}

// --- Global State ---

lazy_static! {
    /// The Global Shadow Map.
    /// Maps Base Address (usize) -> Metadata.
    static ref GLOBAL_SHADOW_MAP: RwLock<HashMap<usize, AllocationMetadata>> = {
        RwLock::new(HashMap::new())
    };
}

// --- FFI Interface ---

/// Registers a new allocation in the shadow map.
/// Returns a new unique Tag for this memory.
#[no_mangle]
pub extern "C" fn capslock_register(base: usize, size: usize) -> u64 {
    let mut map = GLOBAL_SHADOW_MAP.write().unwrap();

    // In a full implementation, this would be a random ID.
    // For this prototype, using the base address as the ID is sufficient.
    let tag = Tag(base as u64);

    let meta = AllocationMetadata {
        base_addr: base,
        size,
        active_tag: tag,
    };

    map.insert(base, meta);

    // Log for demonstration purposes
    println!(
        "[Runtime] ALLOC: Registered {:p} (Size: {}) with Tag {:?}",
        base as *const (), size, tag
    );

    tag.0
}

/// Verifies that the pointer is still valid for the given Tag.
/// Panics if the memory has been revoked (Use-After-Free / Aliasing Violation).
#[no_mangle]
pub extern "C" fn capslock_check(base: usize, expected_tag: u64) {
    let map = GLOBAL_SHADOW_MAP.read().unwrap();

    if let Some(meta) = map.get(&base) {
        if meta.active_tag.0 != expected_tag {
            // CRITICAL FAILURE
            panic!(
                "\n[Runtime] *** SECURITY VIOLATION ***\n    Address: {:p}\n    Expected Tag: {:?}\n    Actual Tag:   {:?}\n    Reason: Memory was revoked/modified by foreign code.\n",
                base as *const (), expected_tag, meta.active_tag
            );
        }
    } else {
        println!(
            "[Runtime] WARNING: Accessing untracked memory at {:p}",
            base as *const ()
        );
    }
}

/// Called by foreign code (C/C++) when it modifies a pointer.
/// This invalidates the old tag, effectively "revoking" the Rust pointer.
#[no_mangle]
pub extern "C" fn capslock_revoke(base: usize) {
    let mut map = GLOBAL_SHADOW_MAP.write().unwrap();

    if let Some(meta) = map.get_mut(&base) {
        // Rotate the tag to a new invalid value.
        // Any Rust code holding the old tag will now fail the check.
        let new_tag = Tag(0xDEAD_BEEF);
        meta.active_tag = new_tag;

        println!(
            "[Runtime] REVOKE: Foreign write detected at {:p}. Tag rotated to {:?}",
            base as *const (), new_tag
        );
    }
}
