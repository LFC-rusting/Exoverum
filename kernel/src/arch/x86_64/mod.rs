//! Modulo arch::x86_64: concentra todo o `unsafe` do kernel.
//!
//! Regra: nenhum outro modulo do kernel pode conter `unsafe`. Cada submodulo
//! aqui expoe API safe e documenta invariantes em comentarios SAFETY.

pub mod cpu;
pub mod gdt;
pub mod idt;
pub mod serial;
