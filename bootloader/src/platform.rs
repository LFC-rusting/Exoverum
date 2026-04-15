use bootinfo::{FramebufferInfo, MemoryMap};

use crate::{BootError, PlatformInfo, PhysRange};

pub mod uefi;

/// Stub de plataforma; implementação concreta (ex.: UEFI) deve fornecer estes métodos.
pub trait Platform {
    fn memory_map(&self) -> Option<MemoryMap>;
    fn framebuffer(&self) -> Option<FramebufferInfo>;
    fn rsdp(&self) -> Option<u64>;
    fn smbios(&self) -> Option<u64>;
    fn page_table_root(&self) -> Option<u64>;
}

/// Coleta informações mínimas da plataforma antes do ExitBootServices.
pub fn collect_platform_info<P: Platform>(
    platform: &P,
    kernel_phys_range: PhysRange,
) -> Result<PlatformInfo, BootError> {
    let memory_map = platform.memory_map().ok_or(BootError::MemoryMapUnavailable)?;
    let page_table_root = platform.page_table_root().ok_or(BootError::PageTableUnavailable)?;
    Ok(PlatformInfo {
        memory_map,
        framebuffer: platform.framebuffer(),
        rsdp: platform.rsdp(),
        smbios: platform.smbios(),
        page_table_root,
        kernel_phys_range,
    })
}
