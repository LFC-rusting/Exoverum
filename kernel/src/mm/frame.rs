//! Alocador de frames fisicos (4 KiB) baseado em bitmap.
//!
//! # Design
//!
//! - Um bitmap estatico `[u64; BITMAP_WORDS]` em `.bss` cobrindo ate
//!   `MAX_MANAGED_FRAMES` frames. Bit = 1 significa livre, bit = 0 ocupado.
//! - `init` parseia a UEFI MemoryMap: cada descritor `EfiConventionalMemory`
//!   vira uma regiao de frames livres (dentro de `MAX_MANAGED_FRAMES`).
//!   Reservados (kernel, stack, page tables, memory map buffer) seguem como
//!   EfiLoaderCode/Data na propria MemoryMap, entao nao sao marcados livres.
//! - `alloc` usa `next_hint` para first-fit com retomada; `free` apenas
//!   seta o bit.
//!
//! # Seguranca / TCB
//!
//! Este modulo e `#![forbid(unsafe_code)]`. Toda leitura da memoria fisica
//! bruta (memory map) acontece em `mm/mod.rs` via `slice::from_raw_parts`.
//! Aqui manipulamos apenas `&[u8]` e arrays fixos: superficie de ataque
//! minima, trivialmente testavel em host.

#![forbid(unsafe_code)]

use bootinfo::PhysRange;

/// Tamanho de um frame fisico em bytes (x86_64 4 KiB).
pub const FRAME_SIZE: u64 = 4096;

/// Quantidade maxima de frames gerenciados. 131_072 frames * 4 KiB = 512 MiB
/// de memoria fisica coberta. Suficiente para Fase 2 em QEMU com `-m 256M`.
/// Aumentar no futuro se precisar de mais.
pub const MAX_MANAGED_FRAMES: usize = 131_072;

const BITMAP_WORDS: usize = MAX_MANAGED_FRAMES / 64;

/// Primeiro 1 MiB (256 frames de 4 KiB) reservado incondicionalmente.
///
/// - Frame 0 NUNCA pode ser alocavel: entregar enderecos 0x0..0x1000 como
///   memoria valida destroi a deteccao de null-pointer deref por #PF, que
///   e uma linha de defesa de TCB zero-custo.
/// - A faixa <1 MiB contem estruturas legadas (IVT, BDA, EBDA, regioes
///   que firmware/SMM podem referenciar). Reservar tudo e YAGNI-correto:
///   0.4% de 256 MiB em troca de zero chance de aliasing com firmware.
const LOW_MEMORY_RESERVED_FRAMES: usize = 256;

// UEFI 2.9, secao 7.2.1, Table 26.
const EFI_CONVENTIONAL_MEMORY: u32 = 7;
/// Tamanho base do `EFI_MEMORY_DESCRIPTOR`. Firmwares podem ter campos extras
/// no final (`desc_size` maior), mas os 40 primeiros bytes seguem o layout.
const EFI_DESCRIPTOR_MIN_SIZE: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// `desc_size` < 40 ou zero, ou `len % desc_size != 0`.
    InvalidDescriptorSize,
    /// Buffer vazio ou ponteiro nulo.
    InvalidMemoryMap,
}

/// Endereco fisico alinhado a 4 KiB.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PhysFrame(u64);

impl PhysFrame {
    pub const SIZE: u64 = FRAME_SIZE;

    /// Trunca o endereco para baixo no limite de frame.
    pub const fn containing_address(addr: u64) -> Self {
        Self(addr & !(FRAME_SIZE - 1))
    }

    pub const fn from_index(idx: usize) -> Self {
        Self((idx as u64) * FRAME_SIZE)
    }

    pub const fn addr(self) -> u64 {
        self.0
    }

    pub const fn index(self) -> usize {
        (self.0 / FRAME_SIZE) as usize
    }
}

/// Alocador de frames baseado em bitmap. Construir com `empty()` e popular
/// via `init()`. Nao e seguro para multi-threads; o holder em `mm::mod.rs`
/// garante acesso sequencial ate termos SMP.
pub struct FrameAllocator {
    /// 1 = livre, 0 = ocupado/reservado.
    bitmap: [u64; BITMAP_WORDS],
    /// Maior indice de frame tocado por `init` (exclusive). Operacoes ignoram
    /// frames >= total_frames.
    total_frames: usize,
    /// Contador de bits=1. Invariante: sempre igual a `popcount(bitmap[..total])`.
    free_count: usize,
    /// Hint de busca first-fit; retomada circular.
    next_hint: usize,
}

impl FrameAllocator {
    pub const fn empty() -> Self {
        Self {
            bitmap: [0u64; BITMAP_WORDS],
            total_frames: 0,
            free_count: 0,
            next_hint: 0,
        }
    }

    /// Inicializa o bitmap a partir dos bytes crus da UEFI MemoryMap.
    ///
    /// - `map_bytes`: buffer com os descritores contiguos.
    /// - `desc_size`: stride entre descritores (>= 40).
    /// - `reserved`: faixas adicionais a marcar como ocupadas mesmo que
    ///   apareçam como ConventionalMemory (defesa em profundidade para
    ///   kernel_phys_range e bootinfo).
    pub fn init(
        &mut self,
        map_bytes: &[u8],
        desc_size: usize,
        reserved: &[PhysRange],
    ) -> Result<(), FrameError> {
        if desc_size < EFI_DESCRIPTOR_MIN_SIZE {
            return Err(FrameError::InvalidDescriptorSize);
        }
        if map_bytes.is_empty() || map_bytes.len() % desc_size != 0 {
            return Err(FrameError::InvalidMemoryMap);
        }

        // Reset; chamado uma unica vez mas deixa idempotente por robustez.
        self.bitmap = [0u64; BITMAP_WORDS];
        self.total_frames = 0;
        self.free_count = 0;
        self.next_hint = 0;

        let num_descriptors = map_bytes.len() / desc_size;
        for i in 0..num_descriptors {
            let base = i * desc_size;
            let desc = &map_bytes[base..base + EFI_DESCRIPTOR_MIN_SIZE];
            let typ = read_u32(desc, 0);
            let phys_start = read_u64(desc, 8);
            let num_pages = read_u64(desc, 24);

            if typ != EFI_CONVENTIONAL_MEMORY {
                continue;
            }
            // Faixa [phys_start, phys_start + num_pages * FRAME_SIZE).
            let start_idx = (phys_start / FRAME_SIZE) as usize;
            let end_idx = start_idx.saturating_add(num_pages as usize);
            self.mark_range_free(start_idx, end_idx);
        }

        // Invariante x86_64: low memory < 1 MiB fora do pool. Aplicado APOS
        // parsear conventional (sobrepoe qualquer regiao que a UEFI tenha
        // reportado como livre ali) e ANTES das reservas do chamador.
        self.mark_range_used(0, LOW_MEMORY_RESERVED_FRAMES);

        // Reservas adicionais sobrepoem conventional se houver conflito.
        for r in reserved {
            let start_idx = (r.start / FRAME_SIZE) as usize;
            // Arredonda endereco final para cima para cobrir frame parcial.
            let end_addr = r.end;
            let end_idx = ((end_addr + FRAME_SIZE - 1) / FRAME_SIZE) as usize;
            self.mark_range_used(start_idx, end_idx);
        }

        Ok(())
    }

    /// Aloca um frame livre. First-fit com retomada circular.
    pub fn alloc(&mut self) -> Option<PhysFrame> {
        if self.free_count == 0 {
            return None;
        }
        let start = self.next_hint;
        // Duas passagens: [start..total] depois [0..start].
        if let Some(idx) = self.scan_free(start, self.total_frames) {
            self.claim(idx);
            return Some(PhysFrame::from_index(idx));
        }
        if let Some(idx) = self.scan_free(0, start) {
            self.claim(idx);
            return Some(PhysFrame::from_index(idx));
        }
        None
    }

    /// Devolve um frame. Marcar livre um frame ja livre e no-op silencioso
    /// (nao aumenta free_count nem corrompe o bitmap). Atualiza `next_hint`
    /// para baixo para que a proxima `alloc` reutilize frames recem-liberados
    /// (localidade de cache + comportamento determinista em testes).
    pub fn free(&mut self, frame: PhysFrame) {
        let idx = frame.index();
        if idx >= self.total_frames {
            return;
        }
        let word = idx / 64;
        let bit = idx % 64;
        let mask = 1u64 << bit;
        if self.bitmap[word] & mask == 0 {
            self.bitmap[word] |= mask;
            self.free_count += 1;
            if idx < self.next_hint {
                self.next_hint = idx;
            }
        }
    }

    pub fn free_count(&self) -> usize {
        self.free_count
    }

    pub fn total_frames(&self) -> usize {
        self.total_frames
    }

    // --- Helpers internos ---

    fn mark_range_free(&mut self, start_idx: usize, end_idx: usize) {
        let end = core::cmp::min(end_idx, MAX_MANAGED_FRAMES);
        for idx in start_idx..end {
            let word = idx / 64;
            let bit = idx % 64;
            let mask = 1u64 << bit;
            if self.bitmap[word] & mask == 0 {
                self.bitmap[word] |= mask;
                self.free_count += 1;
            }
            if idx + 1 > self.total_frames {
                self.total_frames = idx + 1;
            }
        }
    }

    fn mark_range_used(&mut self, start_idx: usize, end_idx: usize) {
        let end = core::cmp::min(end_idx, MAX_MANAGED_FRAMES);
        for idx in start_idx..end {
            let word = idx / 64;
            let bit = idx % 64;
            let mask = 1u64 << bit;
            if self.bitmap[word] & mask != 0 {
                self.bitmap[word] &= !mask;
                self.free_count -= 1;
            }
        }
    }

    fn scan_free(&self, from: usize, to: usize) -> Option<usize> {
        let end = core::cmp::min(to, self.total_frames);
        let mut idx = from;
        while idx < end {
            let word = idx / 64;
            let bit = idx % 64;
            let w = self.bitmap[word] >> bit;
            if w == 0 {
                // Pula para o proximo word.
                idx = (word + 1) * 64;
                continue;
            }
            let off = w.trailing_zeros() as usize;
            let candidate = idx + off;
            if candidate < end {
                return Some(candidate);
            }
            return None;
        }
        None
    }

    fn claim(&mut self, idx: usize) {
        let word = idx / 64;
        let bit = idx % 64;
        let mask = 1u64 << bit;
        self.bitmap[word] &= !mask;
        self.free_count -= 1;
        self.next_hint = idx + 1;
        if self.next_hint >= self.total_frames {
            self.next_hint = 0;
        }
    }
}

// --- Leitura segura de campos little-endian do UEFI descriptor. ---
// UEFI garante little-endian em todas as plataformas onde roda.

fn read_u32(buf: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&buf[off..off + 4]);
    u32::from_le_bytes(b)
}

fn read_u64(buf: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(b)
}

// =====================================================================
// Testes de host
// =====================================================================

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// Monta um buffer de UEFI memory descriptors em formato little-endian
    /// para alimentar `FrameAllocator::init`.
    fn build_map(entries: &[(u32, u64, u64)]) -> (Vec<u8>, usize) {
        let desc_size = EFI_DESCRIPTOR_MIN_SIZE;
        let mut buf = vec![0u8; entries.len() * desc_size];
        for (i, &(typ, phys, pages)) in entries.iter().enumerate() {
            let off = i * desc_size;
            buf[off..off + 4].copy_from_slice(&typ.to_le_bytes());
            // pad [4..8]
            buf[off + 8..off + 16].copy_from_slice(&phys.to_le_bytes());
            // virtual_start [16..24] zero
            buf[off + 24..off + 32].copy_from_slice(&pages.to_le_bytes());
            // attribute [32..40] zero
        }
        (buf, desc_size)
    }

    #[test]
    fn init_rejeita_desc_size_pequeno() {
        let mut a = FrameAllocator::empty();
        let buf = vec![0u8; 32];
        assert_eq!(a.init(&buf, 32, &[]), Err(FrameError::InvalidDescriptorSize));
    }

    #[test]
    fn init_rejeita_len_desalinhado() {
        let mut a = FrameAllocator::empty();
        let buf = vec![0u8; 41]; // nao multiplo de 40
        assert_eq!(a.init(&buf, 40, &[]), Err(FrameError::InvalidMemoryMap));
    }

    #[test]
    fn init_marca_conventional_livre() {
        // 1 regiao conventional em 0x100000 (1 MiB) com 4 paginas.
        let (buf, ds) = build_map(&[(EFI_CONVENTIONAL_MEMORY, 0x100000, 4)]);
        let mut a = FrameAllocator::empty();
        a.init(&buf, ds, &[]).unwrap();
        assert_eq!(a.free_count(), 4);
    }

    #[test]
    fn init_reserva_low_memory_incondicionalmente() {
        // Firmware reporta toda a faixa baixa como ConventionalMemory.
        // Invariante: frames 0..256 (primeiro 1 MiB) jamais alocaveis.
        let (buf, ds) = build_map(&[(EFI_CONVENTIONAL_MEMORY, 0, 512)]);
        let mut a = FrameAllocator::empty();
        a.init(&buf, ds, &[]).unwrap();
        // Apenas os 256 frames acima de 1 MiB devem ser livres.
        assert_eq!(a.free_count(), 256);
        // E nenhuma alocacao pode devolver endereco < 1 MiB.
        let f = a.alloc().unwrap();
        assert!(f.addr() >= 0x100000, "alocou frame em low memory: {:#x}", f.addr());
    }

    #[test]
    fn init_ignora_nao_conventional() {
        let (buf, ds) = build_map(&[
            (3 /* LoaderCode */, 0x200000, 10),
            (EFI_CONVENTIONAL_MEMORY, 0x400000, 2),
        ]);
        let mut a = FrameAllocator::empty();
        a.init(&buf, ds, &[]).unwrap();
        assert_eq!(a.free_count(), 2);
    }

    #[test]
    fn init_reserved_sobrepoe_conventional() {
        // 8 paginas em 0x10000; reservamos 2 delas.
        let (buf, ds) = build_map(&[(EFI_CONVENTIONAL_MEMORY, 0x100000, 8)]);
        let mut a = FrameAllocator::empty();
        let reserved = [PhysRange { start: 0x100000, end: 0x102000 }];
        a.init(&buf, ds, &reserved).unwrap();
        assert_eq!(a.free_count(), 6);
    }

    #[test]
    fn alloc_retorna_frame_e_decrementa_free() {
        let (buf, ds) = build_map(&[(EFI_CONVENTIONAL_MEMORY, 0x100000, 3)]);
        let mut a = FrameAllocator::empty();
        a.init(&buf, ds, &[]).unwrap();
        let f1 = a.alloc().unwrap();
        let f2 = a.alloc().unwrap();
        let f3 = a.alloc().unwrap();
        assert_eq!(a.alloc(), None);
        assert_eq!(a.free_count(), 0);
        // Todos em endereco valido e distintos.
        assert_ne!(f1, f2);
        assert_ne!(f2, f3);
        assert_eq!(f1.addr() & (FRAME_SIZE - 1), 0);
    }

    #[test]
    fn free_restaura_frame() {
        let (buf, ds) = build_map(&[(EFI_CONVENTIONAL_MEMORY, 0x100000, 2)]);
        let mut a = FrameAllocator::empty();
        a.init(&buf, ds, &[]).unwrap();
        let f = a.alloc().unwrap();
        assert_eq!(a.free_count(), 1);
        a.free(f);
        assert_eq!(a.free_count(), 2);
        // Pode realocar.
        let f2 = a.alloc().unwrap();
        assert_eq!(f2, f);
    }

    #[test]
    fn free_de_frame_ja_livre_e_noop() {
        let (buf, ds) = build_map(&[(EFI_CONVENTIONAL_MEMORY, 0x100000, 2)]);
        let mut a = FrameAllocator::empty();
        a.init(&buf, ds, &[]).unwrap();
        let before = a.free_count();
        a.free(PhysFrame::containing_address(0x100000));
        assert_eq!(a.free_count(), before);
    }

    #[test]
    fn clampa_acima_de_max_managed_frames() {
        // Regiao 1 frame alem do limite: MAX_MANAGED_FRAMES frames.
        let base = MAX_MANAGED_FRAMES as u64 * FRAME_SIZE;
        let (buf, ds) = build_map(&[(EFI_CONVENTIONAL_MEMORY, base - FRAME_SIZE, 2)]);
        let mut a = FrameAllocator::empty();
        a.init(&buf, ds, &[]).unwrap();
        // Apenas o frame dentro do limite deve contar.
        assert_eq!(a.free_count(), 1);
    }

    #[test]
    fn phys_frame_containing_address_trunca() {
        let f = PhysFrame::containing_address(0x12345);
        assert_eq!(f.addr(), 0x12000);
        assert_eq!(f.index(), 0x12);
    }
}
