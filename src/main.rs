mod runtime;
use runtime::{track_alloc, track_borrow, check_access, Perm};

fn main() {
    println!(":: CapsLock-lite: Reference Monitor Test (Lazy Revocation) ::\n");

    let mut data = 100;
    let root_ptr = &mut data as *mut i32;
    
    // 1. Allocation
    track_alloc(root_ptr);
    println!("[1] Allocated Root Owner.");

    // 2. Shared Borrow A
    let ref_a = unsafe { root_ptr.add(1) }; 
    track_borrow(root_ptr, ref_a, Perm::Shared);
    println!("[2] Created ref_a (Shared).");

    // 3. Mutable Borrow C (Lazy Trigger)
    // Creation does not invalidate ref_a immediately (supports unused branches).
    let mut_c = unsafe { root_ptr.add(2) }; 
    track_borrow(root_ptr, mut_c, Perm::Mutable);
    println!("[3] Created mut_c (Mutable).");

    // 4. Access ref_a (Valid)
    // Proves ref_a coexists with unused mut_c.
    print!("[4] Accessing ref_a (Pre-Mutation)... "); 
    check_access(ref_a); 
    println!("Success.");

    // 5. Access mut_c (Revocation Event)
    // Usage asserts exclusivity, invalidating siblings.
    print!("[5] Accessing mut_c... "); 
    check_access(mut_c);
    println!("Success. Siblings invalidated.");

    // 6. Access ref_a (Invalid)
    println!("[6] Accessing ref_a (Post-Mutation)... Expecting Panic.");
    
    let result = std::panic::catch_unwind(|| {
        check_access(ref_a);
    });

    match result {
        Ok(_) => println!("FAILURE: Revocation failed!"),
        Err(_) => println!("SUCCESS: Violation caught."),
    }
}