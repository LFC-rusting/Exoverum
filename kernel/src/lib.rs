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

// Modulos especificos de arquitetura so compilam em bare-metal. Em builds
// de host-test (linux-gnu) eles seriam rejeitados por usarem asm inline.
#[cfg(target_os = "none")]
pub mod arch;
#[cfg(target_os = "none")]
pub mod log;
#[cfg(target_os = "none")]
pub mod kmain;

// `mm` e target-agnostico (logica pura; so manipula bytes), entao
// pode ser compilado e testado em host.
pub mod mm;

mod panic;
