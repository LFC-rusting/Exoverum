// Passa o linker.ld para o linker apenas quando o alvo for bare-metal.
// Evita quebrar builds de host (testes futuros).

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if target == "x86_64-unknown-none" {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        println!("cargo:rustc-link-arg-bins=-T{}/linker.ld", dir);
        println!("cargo:rustc-link-arg-bins=-zmax-page-size=0x1000");
        println!("cargo:rustc-link-arg-bins=-znoexecstack");
        println!("cargo:rustc-link-arg-bins=--gc-sections");
        println!("cargo:rerun-if-changed=linker.ld");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
