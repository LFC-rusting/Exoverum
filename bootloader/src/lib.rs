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

/// Imagem do kernel em memória, com hash esperado obrigatório.
pub struct KernelImage<'a> {
    pub elf: &'a [u8],
    pub expected_sha256: [u8; 32],
}

/// Informações coletadas da plataforma antes do ExitBootServices.
pub struct PlatformInfo {
    pub memory_map: MemoryMap,
    pub framebuffer: Option<FramebufferInfo>,
    pub rsdp: Option<u64>,
    pub smbios: Option<u64>,
    pub kernel_phys_range: PhysRange,
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_sha256_hex(hex: &str) -> Result<[u8; 32], BootError> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return Err(BootError::HashMismatch);
    }
    let mut out = [0u8; 32];
    let mut i = 0usize;
    while i < 32 {
        let hi = hex_nibble(bytes[i * 2]).ok_or(BootError::HashMismatch)?;
        let lo = hex_nibble(bytes[i * 2 + 1]).ok_or(BootError::HashMismatch)?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Ok(out)
}

/// Hash SHA-256 do `kernel.elf` embutido no build do bootloader.
///
/// Preenchido em tempo de compilação via variável de ambiente
/// `EXOVERUM_KERNEL_SHA256` (hex com 64 caracteres).
pub fn embedded_kernel_sha256() -> Result<[u8; 32], BootError> {
    let hex = option_env!("EXOVERUM_KERNEL_SHA256")
        .ok_or(BootError::HashMismatch)?;
    parse_sha256_hex(hex)
}

/// Verifica SHA-256 do ELF contra hash esperado obrigatório.
pub fn verify_sha256(elf: &[u8], expected: [u8; 32]) -> Result<(), BootError> {
    if crypto::sha256::sha256(elf) != expected {
        return Err(BootError::HashMismatch);
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
