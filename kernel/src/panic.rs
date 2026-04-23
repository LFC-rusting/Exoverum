//! Panic handler do kernel: loga pela serial (se presente) e halta.
//!
//! So entra em builds bare-metal (`target_os = "none"`) para nao colidir com
//! o `panic_impl` fornecido por `std` em builds de host/test.

#![forbid(unsafe_code)]

#[cfg(all(target_os = "none", not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    crate::arch::x86_64::serial::write_str("[kernel] PANIC\n");
    crate::arch::x86_64::cpu::halt_forever();
}
