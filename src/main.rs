mod runtime; // Integrate the runtime module

use runtime::{capslock_register, capslock_check, capslock_revoke};

// Define the foreign function interface
unsafe extern "C" {
    fn c_write_access(ptr: *mut i32);
}

fn main() {
    // Force the linker to keep 'capslock_revoke' by creating a dummy reference to it.
    // This prevents the compiler from optimizing it away since Rust code doesn't call it directly.
    let _keep_alive = capslock_revoke as *const ();

    println!("=== CapsLock-lite: Revocation Demo ===\n");

    // We use a Box to get heap memory.
    let mut data = Box::new(42);
    let ptr = &mut *data as *mut i32;
    let base_addr = ptr as usize;

    // We manually register the pointer to simulate what the compiler pass would do.
    let tag = capslock_register(base_addr, 4);

    // Ensure the pointer is valid before we hand it off.
    capslock_check(base_addr, tag);
    println!("[Rust]   State: Valid. Value: {}", unsafe { *ptr });

    println!("[Rust]   -> Passing ownership to C...");
    unsafe { c_write_access(ptr) };

    // The C code has modified/freed the memory. Our tag should now be invalid.
    println!("[Rust]   <- C returned. Checking integrity...");
    
    // This MUST panic if the protection is working.
    capslock_check(base_addr, tag); 

    // Unreachable if successful
    println!("[Rust]   ERROR: Security check failed to catch the violation!");
}