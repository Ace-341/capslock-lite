mod runtime;
use runtime::{check_access, track_alloc, track_borrow, Perm};

fn main() {
    println!(":: CapsLock-lite Reference Monitor ::");
    println!(":: Scenario: Sibling Revocation (Aliasing XOR Mutability) ::\n");

    let mut data = 100;
    let root_ptr = &mut data as *mut i32;

    // 1. Initial Allocation
    track_alloc(root_ptr);
    println!("[1] Allocated Root Owner (ptr: {:p})", root_ptr);

    // 2. Shared Borrow A
    // We use pointer offsets to simulate distinct pointer identities for the map.
    let ref_a = unsafe { root_ptr.add(1) };
    track_borrow(root_ptr, ref_a, Perm::Shared);
    println!("[2] Created ref_a (Shared Sibling A). Status: Active.");

    // 3. Shared Borrow B
    // Multiple shared borrows are allowed to coexist (no revocation yet).
    let ref_b = unsafe { root_ptr.add(2) };
    track_borrow(root_ptr, ref_b, Perm::Shared);
    println!("[3] Created ref_b (Shared Sibling B). Status: Active.");

    // Verify liveness
    print!("    Checking ref_a... ");
    check_access(ref_a);
    println!("OK.");
    print!("    Checking ref_b... ");
    check_access(ref_b);
    println!("OK.");

    // 4. Mutable Borrow C (The Trigger)
    // A mutable borrow demands exclusivity, so this must revoke all previous siblings.
    let mut_c = unsafe { root_ptr.add(3) };
    println!("\n[4] Creating mut_c (Mutable Sibling C)...");
    track_borrow(root_ptr, mut_c, Perm::Mutable);
    println!("    -> Sibling Revocation Triggered: ref_a and ref_b should be invalidated.");

    // 5. Verify Revocation
    // Accessing ref_a should now trigger a security violation.
    println!("\n[5] Attempting to access ref_a (Expect Panic)...");

    let result = std::panic::catch_unwind(|| {
        check_access(ref_a);
    });

    match result {
        Ok(_) => println!(" FAILURE: Security bypass detected!"),
        Err(_) => println!(" SUCCESS: CapsLock caught the illegal access."),
    }

    // 6. Verify Exclusivity
    // The new mutable borrow should remain valid.
    print!("\n[6] Checking mut_c ... ");
    check_access(mut_c);
    println!("OK.");
}
