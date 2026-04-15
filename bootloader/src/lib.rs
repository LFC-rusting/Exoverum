#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use bootinfo::{BootInfo, FramebufferInfo, MemoryMap, PhysRange};

#[allow(unsafe_code)]
pub mod platform;
pub use platform::{collect_platform_info, Platform};

pub mod mapping;

use core::convert::TryInto;
#[cfg(not(test))]
use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

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

/// Estrutura mínima para representar a imagem do kernel em memória.
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
    pub page_table_root: u64,
    pub kernel_phys_range: PhysRange,
}

/// Header ELF64 (somente campos usados).
pub(crate) struct ElfHeader {
    entry: u64,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
    e_type: u16,
    machine: u16,
}

/// Program header ELF64 (apenas campos necessários).
pub(crate) struct ProgramHeader {
    p_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

/// Valida cabeçalho ELF64 e segmentos LOAD.
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

    // Validar cada LOAD e checar sobreposição (O(n^2) sem alocação, n pequeno).
    for i in 0..hdr.phnum {
        let ph_i = parse_ph(elf, hdr.phoff, hdr.phentsize, i)?;
        if ph_i.p_type != PT_LOAD {
            continue;
        }
        // filesz <= memsz
        if ph_i.filesz > ph_i.memsz {
            return Err(BootError::InvalidElf);
        }
        // alinhamento: power of two e coerência offset/vaddr
        if ph_i.align != 0 {
            if !ph_i.align.is_power_of_two() {
                return Err(BootError::InvalidElfAlign);
            }
            if (ph_i.vaddr % ph_i.align) != (ph_i.offset % ph_i.align) {
                return Err(BootError::InvalidElfAlign);
            }
        }
        // sobreposição com outros LOAD
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

    // entry deve cair em um LOAD executável e não-writable.
    if !entry_in_executable_segment(elf, &hdr)? {
        return Err(BootError::InvalidElfEntry);
    }

    Ok(())
}

fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    !(a_end <= b_start || b_end <= a_start)
}

pub(crate) fn parse_elf_header(elf: &[u8]) -> Result<ElfHeader, BootError> {
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

pub(crate) fn parse_ph(elf: &[u8], phoff: u64, entsize: u16, idx: u16) -> Result<ProgramHeader, BootError> {
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

/// SHA-256 minimalista (sem deps, no_std).
pub fn verify_sha256(elf: &[u8], expected: Option<[u8; 32]>) -> Result<(), BootError> {
    if let Some(hash) = expected {
        let computed = sha256(elf);
        if computed != hash {
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

fn sha256(data: &[u8]) -> [u8; 32] {
    const H0: [u32; 8] = [
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut buffer = [0u8; 64];
    let mut h = H0;

    let mut chunks = data.chunks(64);
    while let Some(chunk) = chunks.next() {
        if chunk.len() == 64 {
            buffer.copy_from_slice(chunk);
            compress(&mut h, &buffer);
        } else {
            // Padding
            let mut last = [0u8; 128];
            let mut idx = 0;
            for &b in chunk {
                last[idx] = b;
                idx += 1;
            }
            last[idx] = 0x80;
            idx += 1;

            let len_pos = if idx > 56 { 120 } else { 56 };
            last[len_pos..len_pos + 8].copy_from_slice(&bit_len.to_be_bytes());

            let total = if idx > 56 { 128 } else { 64 };
            let mut processed = 0;
            while processed < total {
                buffer.copy_from_slice(&last[processed..processed + 64]);
                compress(&mut h, &buffer);
                processed += 64;
            }
        }
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for t in 0..16 {
        let start = t * 4;
        w[t] = u32::from_be_bytes(block[start..start + 4].try_into().unwrap());
    }
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for t in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Monta BootInfo mínimo.
pub fn build_bootinfo(
    memory_map: MemoryMap,
    framebuffer: Option<FramebufferInfo>,
    rsdp: Option<u64>,
    smbios: Option<u64>,
    page_table_root: u64,
    kernel_phys_range: PhysRange,
) -> BootInfo {
    BootInfo {
        memory_map,
        framebuffer,
        rsdp,
        smbios,
        page_table_root,
        kernel_phys_range,
    }
}

/// Constrói BootInfo a partir do agregado de plataforma.
pub fn build_bootinfo_from(info: PlatformInfo) -> BootInfo {
    BootInfo {
        memory_map: info.memory_map,
        framebuffer: info.framebuffer,
        rsdp: info.rsdp,
        smbios: info.smbios,
        page_table_root: info.page_table_root,
        kernel_phys_range: info.kernel_phys_range,
    }
}

/// Fluxo de alto nível: processa imagem do kernel, coleta info da plataforma e retorna BootInfo.
pub fn boot_flow<P: Platform>(
    platform: &P,
    image: &KernelImage<'_>,
    kernel_phys_range: PhysRange,
) -> Result<BootInfo, BootError> {
    process_kernel_image(image)?;
    let plat = collect_platform_info(platform, kernel_phys_range)?;
    Ok(build_bootinfo_from(plat))
}
