//! Construcao de page tables x86_64 4 KiB com W^X estrito.
//!
//! # Modelo
//!
//! Trabalhamos apenas em nivel logico: cada `PageTable` e um `[u64; 512]`
//! representando 4 KiB de memoria fisica. A escrita real das entradas e
//! feita em frames alocados pelo `mm::frame`. Todos os mapeamentos sao de
//! 4 KiB (sem 2 MiB / 1 GiB pages) por simplicidade: uma unica formula de
//! walk, nenhum branching por tamanho.
//!
//! # Flags
//!
//! Apenas tres perfis sao validos. Qualquer outra combinacao viola W^X
//! e e rejeitada em debug via `debug_assert!`.
//!
//! | Perfil | Present | Write | NoExec |
//! |--------|---------|-------|--------|
//! | `RX`   | 1       | 0     | 0      |
//! | `R_`   | 1       | 0     | 1      |
//! | `RW`   | 1       | 1     | 1      |
//!
//! # Seguranca / TCB
//!
//! `#![forbid(unsafe_code)]`. A unica primitiva unsafe necessaria para
//! paginacao (escrever em memoria fisica via ponteiro bruto) vive em
//! `mm/mod.rs` atras de uma API safe (`PhysMem::write_u64`). Aqui
//! manipulamos apenas valores u64 e indices dentro de `PageTable`.

#![forbid(unsafe_code)]

use crate::mm::frame::{PhysFrame, FRAME_SIZE};

/// Bits do PTE em x86_64 (Intel SDM 3A 4.5).
pub const PTE_PRESENT: u64 = 1 << 0;
pub const PTE_WRITABLE: u64 = 1 << 1;
pub const PTE_USER: u64 = 1 << 2;
pub const PTE_WRITE_THROUGH: u64 = 1 << 3;
pub const PTE_CACHE_DISABLE: u64 = 1 << 4;
pub const PTE_ACCESSED: u64 = 1 << 5;
pub const PTE_DIRTY: u64 = 1 << 6;
pub const PTE_HUGE: u64 = 1 << 7;
pub const PTE_GLOBAL: u64 = 1 << 8;
pub const PTE_NO_EXECUTE: u64 = 1 << 63;

/// Mascara para o endereco fisico de 52 bits alinhado a 4 KiB.
/// Bits [51:12] sao o endereco; demais sao flags ou reservados.
pub const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Perfil de mapeamento W^X.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Perm {
    /// Read + Execute. Usado para `.text`.
    Rx,
    /// Read-only (NX). Usado para `.rodata` e memory map apos parse.
    Ro,
    /// Read + Write (NX). Usado para `.data`, `.bss`, stack, heap.
    Rw,
}

impl Perm {
    pub const fn flags(self) -> u64 {
        match self {
            Perm::Rx => PTE_PRESENT,
            Perm::Ro => PTE_PRESENT | PTE_NO_EXECUTE,
            Perm::Rw => PTE_PRESENT | PTE_WRITABLE | PTE_NO_EXECUTE,
        }
    }
}

/// Uma tabela de paginas x86_64 (PML4/PDPT/PD/PT). 512 entradas u64.
#[repr(C, align(4096))]
#[derive(Clone)]
pub struct PageTable {
    pub entries: [u64; 512],
}

impl PageTable {
    pub const fn zeroed() -> Self {
        Self { entries: [0u64; 512] }
    }
}

/// Indice de entrada em cada nivel dado um endereco virtual.
#[derive(Debug, Clone, Copy)]
pub struct Indices {
    pub pml4: usize,
    pub pdpt: usize,
    pub pd: usize,
    pub pt: usize,
}

impl Indices {
    pub const fn from_virt(vaddr: u64) -> Self {
        Self {
            pml4: ((vaddr >> 39) & 0x1FF) as usize,
            pdpt: ((vaddr >> 30) & 0x1FF) as usize,
            pd: ((vaddr >> 21) & 0x1FF) as usize,
            pt: ((vaddr >> 12) & 0x1FF) as usize,
        }
    }
}

/// Monta um PTE a partir de um frame fisico e um perfil W^X.
pub const fn make_pte(phys: u64, perm: Perm) -> u64 {
    (phys & PTE_ADDR_MASK) | perm.flags()
}

/// Entrada de tabela intermediaria (PML4->PDPT, etc). Sempre tem
/// PRESENT+WRITABLE para permitir escrita posterior; o controle W^X
/// final acontece apenas nos PTs-folha.
pub const fn make_intermediate_pte(phys: u64) -> u64 {
    (phys & PTE_ADDR_MASK) | PTE_PRESENT | PTE_WRITABLE
}

/// Extrai o endereco fisico de uma entrada.
pub const fn pte_phys(entry: u64) -> u64 {
    entry & PTE_ADDR_MASK
}

/// Verifica se uma entrada esta presente.
pub const fn pte_present(entry: u64) -> bool {
    entry & PTE_PRESENT != 0
}

/// Retorna `true` se um endereco virtual e canonico em x86_64 48-bit.
/// Bits [63:48] devem replicar o bit 47 (extensao de sinal).
pub const fn is_canonical(vaddr: u64) -> bool {
    let high = vaddr >> 47;
    high == 0 || high == 0x1_FFFF
}

// =====================================================================
// Testes de host
// =====================================================================

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perm_flags_enforcam_wx() {
        assert_eq!(Perm::Rx.flags(), PTE_PRESENT);
        assert_eq!(Perm::Ro.flags(), PTE_PRESENT | PTE_NO_EXECUTE);
        assert_eq!(Perm::Rw.flags(), PTE_PRESENT | PTE_WRITABLE | PTE_NO_EXECUTE);
        // Invariante central: Rx nunca tem WRITABLE; Rw/Ro nunca tem executavel.
        assert_eq!(Perm::Rx.flags() & PTE_WRITABLE, 0);
        assert_ne!(Perm::Rw.flags() & PTE_NO_EXECUTE, 0);
        assert_ne!(Perm::Ro.flags() & PTE_NO_EXECUTE, 0);
    }

    #[test]
    fn indices_decompoe_endereco() {
        // vaddr = 0x0000_7FFF_FFFF_F000: maior endereco canonico user-space
        // low-half. pml4=255, pdpt=511, pd=511, pt=511.
        let i = Indices::from_virt(0x0000_7FFF_FFFF_F000);
        assert_eq!(i.pml4, 255);
        assert_eq!(i.pdpt, 511);
        assert_eq!(i.pd, 511);
        assert_eq!(i.pt, 511);
    }

    #[test]
    fn indices_higher_half() {
        // 0xFFFF_FFFF_8000_0000 = pml4=511, pdpt=510, pd=0, pt=0.
        let i = Indices::from_virt(0xFFFF_FFFF_8000_0000);
        assert_eq!(i.pml4, 511);
        assert_eq!(i.pdpt, 510);
        assert_eq!(i.pd, 0);
        assert_eq!(i.pt, 0);
    }

    #[test]
    fn canonical_aceita_limites() {
        assert!(is_canonical(0x0000_0000_0000_0000));
        assert!(is_canonical(0x0000_7FFF_FFFF_FFFF));
        assert!(is_canonical(0xFFFF_8000_0000_0000));
        assert!(is_canonical(0xFFFF_FFFF_FFFF_FFFF));
        // Nao-canonicos:
        assert!(!is_canonical(0x0000_8000_0000_0000));
        assert!(!is_canonical(0xFFFF_7FFF_FFFF_FFFF));
    }

    #[test]
    fn make_pte_combina_endereco_e_flags() {
        let pte = make_pte(0x200_000, Perm::Rx);
        assert_eq!(pte_phys(pte), 0x200_000);
        assert!(pte_present(pte));
        assert_eq!(pte & PTE_WRITABLE, 0);
        assert_eq!(pte & PTE_NO_EXECUTE, 0);

        let pte_rw = make_pte(0x300_000, Perm::Rw);
        assert_eq!(pte_phys(pte_rw), 0x300_000);
        assert_ne!(pte_rw & PTE_WRITABLE, 0);
        assert_ne!(pte_rw & PTE_NO_EXECUTE, 0);
    }

    #[test]
    fn make_intermediate_tem_write_e_sem_nx() {
        let pte = make_intermediate_pte(0x400_000);
        assert_ne!(pte & PTE_PRESENT, 0);
        assert_ne!(pte & PTE_WRITABLE, 0);
        // Intermediarias nao devem marcar NX (controle final esta no PT-folha).
        assert_eq!(pte & PTE_NO_EXECUTE, 0);
    }

    #[test]
    fn addr_mask_ignora_flags() {
        let pte = 0xDEAD_BEEF_C0DE_F007u64;
        assert_eq!(pte_phys(pte) & 0xFFF, 0);
    }
}

// Usar PhysFrame/FRAME_SIZE para convencao de tamanho/alinhamento nos testes.
const _: () = {
    assert!(FRAME_SIZE == 4096);
    assert!(core::mem::size_of::<PageTable>() == 4096);
    assert!(core::mem::size_of::<PhysFrame>() <= 16);
};
