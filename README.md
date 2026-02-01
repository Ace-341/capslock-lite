# CapsLock-lite Prototype

## Overview

This repository contains the initial prototype for **CapsLock-lite**, focusing on the runtime metadata storage and revocation logic.

As per the revised design plan, this implementation replaces the complex Shadow Register File structure with a global **Hash Map** (`HashMap<usize, AllocationMetadata>`). This allows for O(1) tracking of allocation bounds and ownership tags without the overhead of full hardware emulation.

## Project Structure

- `src/runtime.rs`: Implements the `GLOBAL_SHADOW_MAP` and the logic for `register`, `check`, and `revoke`.
- `src/bad_actor.c`: A C simulation of unsafe code that modifies a pointer and triggers a revocation event.
- `src/main.rs`: The driver program that demonstrates the "Revoke-on-Write" behavior.

## The Demo Scenario

1. **Rust** allocates memory (`Box::new`) and registers it, receiving a unique `Tag`.
2. **Rust** passes the raw pointer to **C**.
3. **C** modifies the memory and triggers a revocation (simulating a `free` or an instrumented write).
4. **Rust** attempts to access the memory again using the original `Tag`.
5. **The Runtime** detects the tag mismatch and panics with a security violation.

## How to Run

Ensure you have a C compiler installed (MSVC on Windows, GCC/Clang on Linux/Mac).

```bash
cargo run
```