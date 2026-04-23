//! Biblioteca do kernel Exoverum.
//!
//! Expoe modulos em camadas:
//!   - `arch::x86_64` concentra todo o `unsafe` (portas I/O, GDT/IDT, MSR).
//!   - `log`, `panic`, `kmain` sao logica safe.
//!
//! O binario (`src/main.rs`) apenas chama `kmain::start`. O panic handler
//! vive aqui para ser compartilhado com o bin via link.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod arch;
pub mod kmain;
pub mod log;
mod panic;
