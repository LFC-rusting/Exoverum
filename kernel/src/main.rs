//! Binario do kernel Exoverum.
//!
//! Apenas o entry `kernel_start`; toda a logica vive na biblioteca `kernel`
//! (src/lib.rs). Isso permite testar modulos safe no host sem precisar do
//! entry bare-metal.

#![no_std]
#![no_main]

use bootinfo::BootInfo;

/// Entry point chamado pelo bootloader (convencao `extern "C"`).
///
/// O bootloader transfere execucao apos copiar os segmentos PT_LOAD aos
/// enderecos fisicos definidos em `linker.ld` (2 MiB). `bootinfo` aponta
/// para estrutura alocada na pool UEFI; permanece valida enquanto nao
/// reusarmos aquela faixa de memoria.
#[no_mangle]
pub extern "C" fn kernel_start(bootinfo: *const BootInfo) -> ! {
    kernel::kmain::start(bootinfo)
}
