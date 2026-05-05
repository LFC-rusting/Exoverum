//! Modulo arch::x86_64: concentra o `unsafe` de hardware do kernel.
//!
//! Regra de encapsulamento: `unsafe` so e permitido em quatro sitios:
//!   - `arch::x86_64::*` (este modulo) — asm inline, GDT/IDT, portas I/O, MMIO.
//!   - `mm::mod`       — fronteira do alocador global (`UnsafeCell` + `static`).
//!   - `kobj::domain`  — tabela mutavel de dominios + ctx save/restore unsafe.
//!   - `main.rs::entry` — chamada de `kmain::start` (unsafe fn do bootloader).
//!
//! Qualquer outro modulo declara `#![forbid(unsafe_code)]`. Cada bloco
//! unsafe traz comentario `SAFETY:` com a invariante que o justifica.

pub mod cpu;
pub mod gdt;
pub mod idt;
pub mod lapic;
pub mod serial;
pub mod userland;
