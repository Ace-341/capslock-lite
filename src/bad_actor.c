#include <stdio.h>
#include <stdint.h>

// Declare the external Rust function we need to call.
// This notifies the runtime that we are touching the memory.
extern void capslock_revoke(uintptr_t base);

// A C function that receives a raw pointer from Rust.
// It modifies the data and triggers a revocation.
void c_write_access(int* ptr) {
    printf("[C-Code] Received pointer %p. Performing unsafe write...\n", (void*)ptr);
    
    // 1. Perform the Write
    *ptr = 9999; 
    
    // 2. Trigger Revocation
    // In a full system, this would be injected via compiler instrumentation 
    // or an LD_PRELOAD allocator shim. For this demo, we call it explicit.
    capslock_revoke((uintptr_t)ptr);
}