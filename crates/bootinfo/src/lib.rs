#![no_std]
#![forbid(unsafe_code)]

/// Informações mínimas passadas do bootloader para o kernel.
/// Mantemos apenas o necessário para reduzir TCB e superfície.
#[derive(Debug, Copy, Clone)]
pub struct BootInfo {
    pub memory_map: MemoryMap,
    pub framebuffer: Option<FramebufferInfo>,
    pub rsdp: Option<u64>,
    pub smbios: Option<u64>,
    pub page_table_root: u64,
    pub kernel_phys_range: PhysRange,
}

#[derive(Debug, Copy, Clone)]
pub struct MemoryMap {
    pub ptr: u64,
    pub len: u64,
}

#[derive(Debug, Copy, Clone)]
pub struct FramebufferInfo {
    pub base: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u32,
}

#[derive(Debug, Copy, Clone)]
pub struct PhysRange {
    pub start: u64,
    pub end: u64,
}
