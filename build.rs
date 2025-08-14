// Cargo build script to compile the assembly code.

use std::env; // To access environment variables.

fn main() {
    // Gets the TARGET environment variable, which specifies the target architecture.
    let target = env::var("TARGET").expect("Missing TARGET environment variable");
    // Gets the OUT_DIR environment variable, which is the directory where build artifacts will be stored.
    let out_dir = env::var("OUT_DIR").expect("Missing OUT_DIR environment variable");

    // This build script is only compatible with x86_64 architecture.
    if !target.contains("x86_64") {
        panic!("This build script is only compatible with x86_64 targets.");
    }

    // Path to the assembly file.
    let asm_file = "src/hellsgate.asm";

    // Checks the target toolchain (MSVC or GNU) to use the appropriate compiler.
    if target.contains("msvc") {
        // If MSVC, use the `cc` crate to compile the .asm file.
        cc::Build::new()
            .file(asm_file)
            .compile("TartarusGate");
    } else if target.contains("gnu") {
        // If GNU, use the `nasm-rs` crate to compile with NASM.
        // Note: The assembly syntax may need adjustments for NASM.
        if let Err(e) = nasm_rs::compile_library("TartarusGate", &[asm_file]) {
            panic!("NASM compilation failed [TartarusGate]: {}", e);
        }
    // Tells rustc to look for native libraries in the output directory.
    println!("cargo:rustc-link-search=native={}", out_dir);
    // Tells rustc to statically link the compiled library.
    println!("cargo:rustc-link-lib=static=TartarusGate");
    } else {
        // If the toolchain is not compatible, panic.
        panic!("Unsupported target toolchain: {}", target);
    }

    // Tells Cargo to rerun this script if the assembly file changes.
    println!("cargo:rerun-if-changed={}", asm_file);
}