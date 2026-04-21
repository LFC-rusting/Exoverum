//! Parser ELF64 minimalista (somente leitura, sem alocação).
//!
//! Escopo: validar e extrair o necessário para carregar o kernel x86_64:
//! cabeçalho ELF, program headers do tipo LOAD, entrypoint, faixa física.
//! Sem suporte a relocation, symbols, debug info ou qualquer coisa fora desse alvo.
//! Ausência de `unsafe` é proposital: todo o parsing é feito com slice bounds-checks.

#![forbid(unsafe_code)]

use bootinfo::PhysRange;
use core::convert::TryInto;

use crate::BootError;

pub const PT_LOAD: u32 = 1;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;

/// Cabeçalho ELF64 (somente campos usados).
pub struct ElfHeader {
    pub entry: u64,
    pub phoff: u64,
    pub phentsize: u16,
    pub phnum: u16,
    pub e_type: u16,
    pub machine: u16,
}

/// Program header ELF64 (apenas campos necessários).
pub struct ProgramHeader {
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

/// Obtém entrypoint do ELF (endereço virtual conforme header).
pub fn kernel_entry_from_elf(elf: &[u8]) -> Result<u64, BootError> {
    let hdr = parse_elf_header(elf)?;
    Ok(hdr.entry)
}

/// Calcula faixa física do kernel com base em paddr dos LOAD.
pub fn kernel_phys_range_from_elf(elf: &[u8]) -> Result<PhysRange, BootError> {
    let hdr = parse_elf_header(elf)?;
    let mut min: Option<u64> = None;
    let mut max: Option<u64> = None;
    for i in 0..hdr.phnum {
        let ph = parse_ph(elf, hdr.phoff, hdr.phentsize, i)?;
        if ph.p_type != PT_LOAD {
            continue;
        }
        let start = ph.paddr;
        let end = start.checked_add(ph.memsz).ok_or(BootError::InvalidElf)?;
        min = Some(match min { Some(v) => v.min(start), None => start });
        max = Some(match max { Some(v) => v.max(end), None => end });
    }
    match (min, max) {
        (Some(start), Some(end)) => Ok(PhysRange { start, end }),
        _ => Err(BootError::InvalidElf),
    }
}

/// Valida cabeçalho ELF64 e segmentos LOAD.
///
/// Regras aplicadas (todas pensadas para reduzir superfície de ataque):
/// - magic number e classe ELF64 little-endian corretos;
/// - `e_type = ET_EXEC` e `e_machine = EM_X86_64`;
/// - `phentsize` exatamente 56;
/// - para cada LOAD: `filesz <= memsz`, alinhamento potência de dois e coerente,
///   sem sobreposição entre LOADs;
/// - entry cai dentro de um LOAD executável e não-writable (W^X).
pub fn validate_kernel_elf(elf: &[u8]) -> Result<(), BootError> {
    const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
    if elf.len() < 64 {
        return Err(BootError::InvalidElf);
    }
    if &elf[0..4] != ELF_MAGIC {
        return Err(BootError::InvalidElf);
    }
    let class = elf[4];
    let endianness = elf[5];
    if class != 2 || endianness != 1 {
        return Err(BootError::InvalidElf);
    }

    let hdr = parse_elf_header(elf)?;
    if hdr.e_type != 2 || hdr.machine != 0x3E {
        return Err(BootError::InvalidElf);
    }
    if hdr.phentsize as usize != 56 {
        return Err(BootError::InvalidElf);
    }

    for i in 0..hdr.phnum {
        let ph_i = parse_ph(elf, hdr.phoff, hdr.phentsize, i)?;
        if ph_i.p_type != PT_LOAD {
            continue;
        }
        if ph_i.filesz > ph_i.memsz {
            return Err(BootError::InvalidElf);
        }
        if ph_i.align != 0 {
            if !ph_i.align.is_power_of_two() {
                return Err(BootError::InvalidElfAlign);
            }
            if (ph_i.vaddr % ph_i.align) != (ph_i.offset % ph_i.align) {
                return Err(BootError::InvalidElfAlign);
            }
        }
        let start_i = ph_i.vaddr;
        let end_i = start_i.checked_add(ph_i.memsz).ok_or(BootError::InvalidElfOverlap)?;
        for j in 0..hdr.phnum {
            if i == j {
                continue;
            }
            let ph_j = parse_ph(elf, hdr.phoff, hdr.phentsize, j)?;
            if ph_j.p_type != PT_LOAD {
                continue;
            }
            let start_j = ph_j.vaddr;
            let end_j = start_j.checked_add(ph_j.memsz).ok_or(BootError::InvalidElfOverlap)?;
            if ranges_overlap(start_i, end_i, start_j, end_j) {
                return Err(BootError::InvalidElfOverlap);
            }
        }
    }

    if !entry_in_executable_segment(elf, &hdr)? {
        return Err(BootError::InvalidElfEntry);
    }

    Ok(())
}

pub fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    !(a_end <= b_start || b_end <= a_start)
}

pub fn parse_elf_header(elf: &[u8]) -> Result<ElfHeader, BootError> {
    if elf.len() < 64 {
        return Err(BootError::InvalidElf);
    }
    Ok(ElfHeader {
        entry: u64::from_le_bytes(elf[24..32].try_into().unwrap()),
        phoff: u64::from_le_bytes(elf[32..40].try_into().unwrap()),
        phentsize: u16::from_le_bytes(elf[54..56].try_into().unwrap()),
        phnum: u16::from_le_bytes(elf[56..58].try_into().unwrap()),
        e_type: u16::from_le_bytes(elf[16..18].try_into().unwrap()),
        machine: u16::from_le_bytes(elf[18..20].try_into().unwrap()),
    })
}

pub fn parse_ph(elf: &[u8], phoff: u64, entsize: u16, idx: u16) -> Result<ProgramHeader, BootError> {
    let start = phoff
        .checked_add((entsize as u64) * (idx as u64))
        .ok_or(BootError::InvalidElf)? as usize;
    let end = start
        .checked_add(entsize as usize)
        .ok_or(BootError::InvalidElf)?;
    if end > elf.len() || entsize as usize != 56 {
        return Err(BootError::InvalidElf);
    }
    let chunk: &[u8] = &elf[start..end];
    Ok(ProgramHeader {
        p_type: u32::from_le_bytes(chunk[0..4].try_into().unwrap()),
        flags: u32::from_le_bytes(chunk[4..8].try_into().unwrap()),
        offset: u64::from_le_bytes(chunk[8..16].try_into().unwrap()),
        vaddr: u64::from_le_bytes(chunk[16..24].try_into().unwrap()),
        paddr: u64::from_le_bytes(chunk[24..32].try_into().unwrap()),
        filesz: u64::from_le_bytes(chunk[32..40].try_into().unwrap()),
        memsz: u64::from_le_bytes(chunk[40..48].try_into().unwrap()),
        align: u64::from_le_bytes(chunk[48..56].try_into().unwrap()),
    })
}

fn entry_in_executable_segment(elf: &[u8], hdr: &ElfHeader) -> Result<bool, BootError> {
    for i in 0..hdr.phnum {
        let ph = parse_ph(elf, hdr.phoff, hdr.phentsize, i)?;
        if ph.p_type != PT_LOAD {
            continue;
        }
        let start = ph.vaddr;
        let end = start.checked_add(ph.memsz).ok_or(BootError::InvalidElfEntry)?;
        if hdr.entry >= start && hdr.entry < end {
            let exec = (ph.flags & PF_X) != 0;
            let writable = (ph.flags & PF_W) != 0;
            return Ok(exec && !writable);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_overlap_casos() {
        assert!(ranges_overlap(0, 10, 5, 15));
        assert!(ranges_overlap(5, 15, 0, 10));
        assert!(ranges_overlap(0, 10, 0, 10));
        assert!(!ranges_overlap(0, 10, 10, 20));
        assert!(!ranges_overlap(10, 20, 0, 10));
    }

    #[test]
    fn parse_header_rejeita_truncado() {
        let buf = [0u8; 10];
        assert!(parse_elf_header(&buf).is_err());
    }

    #[test]
    fn validate_rejeita_magic_invalido() {
        let mut buf = [0u8; 64];
        buf[0] = 0xAA;
        assert!(validate_kernel_elf(&buf).is_err());
    }
}
