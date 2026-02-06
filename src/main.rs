mod runtime;

fn main() {
    println!("=== CapsLock-lite: Sibling Revocation Demo ===\n");

    // 1. Allocate a base object
    let mut data = Box::new(42);
    let raw_base = &mut *data as *mut i32 as *mut u8;
    
    // Instrument: Allocation (Root Node)
    runtime::instrumentation_alloc(raw_base, 4);
    println!("[1] Alloc: Created Root Node for address {:?}", raw_base);

    // 2. Create First Borrow (Child A)
    // Simulating: let ref1 = &mut *data;
    let ref1_ptr = unsafe { raw_base.add(0) }; // Same address, but logically new pointer
    runtime::instrumentation_reborrow(raw_base, ref1_ptr); 
    println!("[2] Reborrow: Created Child A (ref1) from Root");

    // 3. Create Second Borrow (Child B - Sibling to A)
    // Simulating: let ref2 = &mut *data; (Shadowing or aliasing ref1)
    let ref2_ptr = unsafe { raw_base.add(0) }; 
    // Note: We reborrow from Root again, making this a sibling to ref1
    runtime::instrumentation_reborrow(raw_base, ref2_ptr);
    println!("[3] Reborrow: Created Child B (ref2) from Root (Sibling to A)");

    // 4. Use Child B (Write)
    println!("[4] Access: Writing to Child B (ref2)...");
    runtime::instrumentation_write(ref2_ptr);
    println!("    -> Success. This should revoke siblings (Child A).");

    // 5. Attempt to use Child A (Should Fail)
    println!("[5] Access: Attempting to write to Child A (ref1)...");
    println!("    -> Expecting Panic due to sibling revocation.");
    
    // This line should panic
    runtime::instrumentation_write(ref1_ptr);

    // Cleanup
    runtime::instrumentation_free(raw_base);
}