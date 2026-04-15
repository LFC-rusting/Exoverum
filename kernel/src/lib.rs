#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use bootinfo::BootInfo;

#[no_mangle]
pub extern "C" fn kernel_start(_bootinfo: &BootInfo) -> ! {
    loop {}
}
