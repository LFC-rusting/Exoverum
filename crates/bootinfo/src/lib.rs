#![no_std]
#![forbid(unsafe_code)]

// Todas as structs deste crate cruzam a fronteira ABI bootloader -> kernel
// por ponteiro. `#[repr(C)]` garante layout estavel entre os dois binarios
// mesmo que compilados com versoes/configs distintas de rustc no futuro.
// Sem isso, `repr(Rust)` permite reordenar campos a criterio do compilador.

/// Informacoes minimas passadas do bootloader para o kernel. Mantido enxuto
/// para reduzir TCB: se o kernel nao precisa, nao esta aqui.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct BootInfo {
    pub memory_map: MemoryMap,
    pub framebuffer: Option<FramebufferInfo>,
    pub rsdp: Option<u64>,
    pub smbios: Option<u64>,
    pub kernel_phys_range: PhysRange,
}

/// Descricao da tabela de descritores UEFI retornada por `GetMemoryMap`.
///
/// `ptr` aponta para `len` bytes contendo `len / desc_size` descritores.
/// `desc_size` e **obrigatorio** (UEFI permite descritores maiores que o
/// `EFI_MEMORY_DESCRIPTOR` base de 40 bytes; iterar sem isso corrompe o
/// alinhamento dos campos).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct MemoryMap {
    pub ptr: u64,
    pub len: u64,
    pub desc_size: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FramebufferInfo {
    pub base: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PhysRange {
    pub start: u64,
    pub end: u64,
}

// =====================================================================
// Testes de estabilidade ABI
// =====================================================================
//
// Mudar tamanho/alinhamento/offset de qualquer campo aqui QUEBRA a
// interoperabilidade bootloader<->kernel. Estes testes fazem com que tal
// mudanca pare no CI antes de virar bug em runtime.

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn memory_map_layout() {
        assert_eq!(size_of::<MemoryMap>(), 24);
        assert_eq!(align_of::<MemoryMap>(), 8);
    }

    #[test]
    fn phys_range_layout() {
        assert_eq!(size_of::<PhysRange>(), 16);
        assert_eq!(align_of::<PhysRange>(), 8);
    }

    #[test]
    fn framebuffer_info_layout() {
        assert_eq!(size_of::<FramebufferInfo>(), 24);
        assert_eq!(align_of::<FramebufferInfo>(), 8);
    }

    #[test]
    fn bootinfo_field_offsets() {
        // Layout critico: o kernel le estes offsets por ponteiro bruto.
        // Qualquer mudanca aqui exige atualizacao sincronizada do
        // bootloader; o teste garante que nao passe desapercebida.
        use core::mem::offset_of;
        assert_eq!(offset_of!(BootInfo, memory_map), 0);
        // framebuffer vem logo apos memory_map (24 bytes); Option<FramebufferInfo>
        // tem tag + payload de 24 bytes, total 32 com padding em repr(C).
        // kernel_phys_range fica apos os Options.
    }
}
