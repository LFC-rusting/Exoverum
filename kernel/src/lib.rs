//! Esqueleto do kernel Exoverum.
//!
//! Mantenho apenas o entry `kernel_start` e um panic handler mínimo. `forbid`
//! não é usado no crate raiz porque `#[no_mangle]` é classificado como atributo
//! unsafe a partir de edições recentes do Rust; isolo a exceção via `#[allow]`
//! local. Assim que o kernel crescer, a ABI será movida para um módulo dedicado.

#![no_std]
#![deny(unsafe_code)]

use bootinfo::BootInfo;

#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn kernel_start(_bootinfo: &BootInfo) -> ! {
    loop {}
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
