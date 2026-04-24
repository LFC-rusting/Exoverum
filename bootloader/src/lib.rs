//! Núcleo lógico do bootloader UEFI do Exoverum.
//!
//! Este crate contém tudo o que pode ser `safe`: parser ELF, SHA-256, montagem
//! de `BootInfo` e tipos compartilhados. Todo código `unsafe` (FFI UEFI, acesso
//! a portas, asm) fica isolado em `platform::*`, respeitando a regra de que
//! `unsafe` não atravessa fronteiras de módulo.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

// `forbid(unsafe_code)` e aplicado em cada modulo safe individualmente
// (elf, crypto). `platform::*` e a unica porta de entrada de unsafe,
// por isso o crate raiz não pode declarar forbid global.

use bootinfo::{BootInfo, FramebufferInfo, MemoryMap, PhysRange};

pub mod elf;
pub mod crypto;
pub mod platform;

pub use elf::{kernel_entry_from_elf, kernel_phys_range_from_elf, validate_kernel_elf};

/// Panic handler: tenta logar via serial antes de parar. `serial::write_str`
/// e idempotente e silenciosa se o UART nao respondeu ao probe, entao nunca
/// piora a situacao. Em seguida entra em loop, ja que `panic = "abort"` esta
/// ativo. Gated em `target_os = "uefi"` para nao colidir com `std::panic_impl`
/// em builds de host-test (linux-gnu).
#[cfg(all(target_os = "uefi", not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    platform::serial::write_str("[boot] PANIC\n");
    loop {}
}

/// Erros do pipeline de boot. Mantidos enxutos: cada variante corresponde a um
/// ponto de falha distinto para que o log serial identifique a causa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootError {
    InvalidElf,
    InvalidElfOverlap,
    InvalidElfEntry,
    InvalidElfAlign,
    HashMismatch,
    MissingKernel,
    MemoryMapUnavailable,
    PageTableUnavailable,
}

/// Imagem do kernel em memória, com hash opcional para verificação.
pub struct KernelImage<'a> {
    pub elf: &'a [u8],
    pub expected_sha256: Option<[u8; 32]>,
}

/// Informações coletadas da plataforma antes do ExitBootServices.
pub struct PlatformInfo {
    pub memory_map: MemoryMap,
    pub framebuffer: Option<FramebufferInfo>,
    pub rsdp: Option<u64>,
    pub smbios: Option<u64>,
    pub kernel_phys_range: PhysRange,
}

/// Verifica SHA-256 do ELF se um hash esperado foi embutido na imagem.
pub fn verify_sha256(elf: &[u8], expected: Option<[u8; 32]>) -> Result<(), BootError> {
    if let Some(hash) = expected {
        if crypto::sha256::sha256(elf) != hash {
            return Err(BootError::HashMismatch);
        }
    }
    Ok(())
}

/// Processa a imagem do kernel: valida ELF e verifica hash.
pub fn process_kernel_image(img: &KernelImage<'_>) -> Result<(), BootError> {
    validate_kernel_elf(img.elf)?;
    verify_sha256(img.elf, img.expected_sha256)?;
    Ok(())
}

/// Monta `BootInfo` a partir dos campos coletados.
pub fn build_bootinfo(
    memory_map: MemoryMap,
    framebuffer: Option<FramebufferInfo>,
    rsdp: Option<u64>,
    smbios: Option<u64>,
    kernel_phys_range: PhysRange,
) -> BootInfo {
    BootInfo {
        memory_map,
        framebuffer,
        rsdp,
        smbios,
        kernel_phys_range,
    }
}
