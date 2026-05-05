//! Biblioteca do kernel Exoverum.
//!
//! Organizacao:
//!   - `arch::x86_64` — unsafe de hardware (portas I/O, GDT/IDT, MSR, LAPIC).
//!   - `mm`           — frame allocator + paging (target-agnostic).
//!   - `kobj`         — cap, domain, notification, timer (objetos de kernel).
//!   - `fb`, `kmain`  — bare-metal glue.
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
pub mod kmain;
// Renderer minimo do framebuffer UEFI. Bare-metal-only (depende de
// mm::map_kernel_page e Perm::Mmio).
#[cfg(target_os = "none")]
pub mod fb;

// `mm` e target-agnostico (logica pura; so manipula bytes); host-testavel.
pub mod mm;

// `kobj`: capabilities + dominio + notification + timer. Host-testavel
// exceto `domain` (gated em target_os = none).
pub mod kobj;

// Panic handler bare-metal. Nao entra em host tests.
#[cfg(all(target_os = "none", not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    crate::arch::x86_64::serial::write_str("[kernel] PANIC\n");
    crate::arch::x86_64::cpu::halt_forever();
}
