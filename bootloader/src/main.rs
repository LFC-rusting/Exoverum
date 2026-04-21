#![no_std]
#![no_main]

use bootloader::platform::uefi::{efi_entry, EfiHandle, EfiSystemTable};

/// Entry point UEFI exportado no binário final.
#[no_mangle]
pub extern "efiapi" fn efi_main(image: EfiHandle, system_table: *mut EfiSystemTable) -> ! {
    efi_entry(image, system_table)
}
