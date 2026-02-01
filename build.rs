fn main() {
    // Tell Cargo to re-run this script if the C file changes
    println!("cargo:rerun-if-changed=src/bad_actor.c");

    // Compile the C code into a static library
    cc::Build::new()
        .file("src/bad_actor.c")
        .compile("bad_actor");
}