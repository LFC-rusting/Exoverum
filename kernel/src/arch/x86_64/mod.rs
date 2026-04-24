//! Modulo arch::x86_64: concentra o `unsafe` de hardware do kernel.
//!
//! Regra de encapsulamento: `unsafe` so e permitido em tres sitios no kernel:
//!   - `arch::x86_64::*` (este modulo) — asm inline, GDT/IDT, portas I/O.
//!   - `mm::mod` — fronteira do alocador global (`UnsafeCell` + `static`).
//!   - `main.rs::entry` — chamada de `kmain::start` (unsafe fn do bootloader).
//!
//! Qualquer outro modulo deve declarar `#![forbid(unsafe_code)]`. Cada bloco
//! unsafe traz comentario `SAFETY:` explicando a invariante que o justifica.

pub mod cpu;
pub mod gdt;
pub mod idt;
pub mod serial;
