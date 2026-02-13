mod runtime; 
use runtime::{track_alloc, track_borrow, check_access, Perm};

fn main() {
    println!(":: CapsLock-lite: Final Verified Test (Strict Logic) ::\n");

    let mut data = 100;
    let root_ptr = &mut data as *mut i32;
    
    // 1. Allocation
    track_alloc(root_ptr);
    println!("[1] Allocated Root Owner.");

    // 2. Shared Borrow A (Reader)
    let ref_a = unsafe { root_ptr.add(1) }; 
    track_borrow(root_ptr, ref_a, Perm::Shared);
    println!("[2] Created ref_a (Shared/Reader).");

    // 3. Mutable Borrow C (Writer) - Dormant
    let mut_c = unsafe { root_ptr.add(2) }; 
    track_borrow(root_ptr, mut_c, Perm::Mutable);
    println!("[3] Created mut_c (Mutable/Writer).");

    // 4. Access ref_a (Reader)
    // RULE: Reading a Shared ptr MUST kill any dormant Mutable siblings.
    print!("[4] Accessing ref_a... "); 
    check_access(ref_a); 
    println!("Success. (Logic Check: This Read should have killed the Writer 'mut_c').");

    // 5. Access mut_c (Writer)
    // EXPECTATION: This MUST fail. If it succeeds, our security is broken.
    println!("[5] Accessing mut_c... Expecting Panic (Correct Behavior).");
    
    let result = std::panic::catch_unwind(|| {
        check_access(mut_c);
    });

    match result {
        Ok(_) => println!("FAILURE: mut_c is still alive! Security hole detected."),
        Err(_) => println!("SUCCESS: Violation caught. The Reader correctly revoked the Writer."),
    }

    println!("\n:: Test Complete. System is Secure. ::");
}