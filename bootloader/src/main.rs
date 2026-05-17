#![no_std]
#![no_main]

use bootloader::platform::uefi::{efi_entry, EfiHandle, EfiSystemTable};

/// Entry point UEFI exportado no binário final. Chamado pela firmware
/// UEFI; argumentos vêm direto dela e o ponteiro `system_table` é
/// confiável por contrato (ou nulo, tratado em `efi_entry`).
///
/// # Safety
///
/// Chamado apenas pela firmware UEFI. `image` e `system_table` valem
/// por contrato UEFI; nulo é tolerado e tratado em `efi_entry`.
// Sem `pub`: `#[unsafe(no_mangle)]` ja exporta o simbolo para o linker
// UEFI. Marcar `pub` faria clippy disparar `not_unsafe_ptr_arg_deref`
// (regressao em 1.95: o lint ignora `unsafe` em fn com `extern "ABI"`).
#[unsafe(no_mangle)]
unsafe extern "efiapi" fn efi_main(image: EfiHandle, system_table: *mut EfiSystemTable) -> ! {
    // SAFETY: argumentos via firmware UEFI. `efi_entry` valida null.
    unsafe { efi_entry(image, system_table) }
}
