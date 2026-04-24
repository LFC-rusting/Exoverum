//! Heap do kernel: bump allocator simples sobre um range virtual de 1 MiB.
//!
//! # Design
//!
//! - `BumpHeap` e uma estrutura fechada com cursor atomico; unica instancia
//!   global vive aqui (`KERNEL_HEAP`) e e populada por `mm::init_paging`.
//! - Range virtual = `[HEAP_VIRT_START, HEAP_VIRT_START + HEAP_SIZE)`.
//!   As paginas sao mapeadas RW+NX por `mm::init_paging`.
//! - Alocacao bump: avanca cursor; nao libera. Politica de free sera
//!   substituida por free-list real em fase posterior.
//!
//! # YAGNI
//!
//! Bump tem 20 LOC uteis. Suficiente para bootstrap. Quando aparecer um
//! caller que precise de free real (ex.: pool de Tasks), trocamos.
//!
//! # Seguranca
//!
//! `#![forbid(unsafe_code)]`. O heap nao toca memoria bruta; so devolve
//! enderecos. O caller e quem transforma em `*mut T`; esse unsafe pertence
//! a ele.

#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicUsize, Ordering};

/// Tamanho total do heap em bytes. 1 MiB. Fixo em Fase 3b.
pub const HEAP_SIZE: usize = 1024 * 1024;

/// Erros possiveis de alocacao.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapError {
    /// Heap ainda nao teve `init` chamado.
    NotInitialized,
    /// Sem espaco para satisfazer a requisicao.
    OutOfMemory,
    /// Alinhamento invalido (0 ou nao-potencia-de-2).
    BadAlignment,
}

/// Bump allocator. State machine com tres campos atomicos.
pub struct BumpHeap {
    /// Base virtual do heap; 0 enquanto nao inicializado.
    base: AtomicUsize,
    /// Offset ja consumido a partir de `base`. Nunca decresce.
    cursor: AtomicUsize,
    /// `1` apos init bem sucedido; usado para gate em `alloc_bytes`.
    ready: AtomicUsize,
}

impl BumpHeap {
    pub const fn new() -> Self {
        Self {
            base: AtomicUsize::new(0),
            cursor: AtomicUsize::new(0),
            ready: AtomicUsize::new(0),
        }
    }

    /// Marca o heap como ativo em `base..base+HEAP_SIZE`. Idempotente:
    /// chamadas subsequentes sao no-op.
    pub fn init(&self, base: usize) {
        if self.ready.swap(1, Ordering::AcqRel) == 1 {
            return;
        }
        self.base.store(base, Ordering::Relaxed);
        self.cursor.store(0, Ordering::Relaxed);
    }

    /// Aloca `size` bytes alinhados a `align`. Retorna endereco virtual.
    pub fn alloc_bytes(&self, size: usize, align: usize) -> Result<usize, HeapError> {
        if self.ready.load(Ordering::Acquire) == 0 {
            return Err(HeapError::NotInitialized);
        }
        if align == 0 || !align.is_power_of_two() {
            return Err(HeapError::BadAlignment);
        }
        let base = self.base.load(Ordering::Relaxed);
        loop {
            let cursor = self.cursor.load(Ordering::Relaxed);
            let start = (base + cursor + (align - 1)) & !(align - 1);
            let start_off = start - base;
            let end_off = start_off.checked_add(size).ok_or(HeapError::OutOfMemory)?;
            if end_off > HEAP_SIZE {
                return Err(HeapError::OutOfMemory);
            }
            if self
                .cursor
                .compare_exchange(cursor, end_off, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(start);
            }
            // Outro chamador bumpou antes; tenta de novo.
        }
    }

    pub fn used_bytes(&self) -> usize {
        self.cursor.load(Ordering::Relaxed)
    }

    pub fn free_bytes(&self) -> usize {
        HEAP_SIZE.saturating_sub(self.used_bytes())
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire) == 1
    }
}

/// Heap global do kernel. Populado por `mm::init_paging`.
pub static KERNEL_HEAP: BumpHeap = BumpHeap::new();

// =====================================================================
// Testes de host
// =====================================================================

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_antes_de_init_falha() {
        let h = BumpHeap::new();
        assert_eq!(h.alloc_bytes(16, 8), Err(HeapError::NotInitialized));
    }

    #[test]
    fn alinhamento_invalido_recusado() {
        let h = BumpHeap::new();
        h.init(0x1000);
        assert_eq!(h.alloc_bytes(16, 0), Err(HeapError::BadAlignment));
        assert_eq!(h.alloc_bytes(16, 3), Err(HeapError::BadAlignment));
    }

    #[test]
    fn alloc_respeita_alinhamento() {
        let h = BumpHeap::new();
        h.init(0x1000);
        let a = h.alloc_bytes(1, 16).unwrap();
        assert_eq!(a % 16, 0);
        let b = h.alloc_bytes(1, 64).unwrap();
        assert_eq!(b % 64, 0);
        assert!(b >= a + 1);
    }

    #[test]
    fn alloc_estoura_retorna_oom() {
        let h = BumpHeap::new();
        h.init(0x1000);
        assert!(h.alloc_bytes(HEAP_SIZE, 1).is_ok());
        assert_eq!(h.alloc_bytes(1, 1), Err(HeapError::OutOfMemory));
    }

    #[test]
    fn used_e_free_consistentes() {
        let h = BumpHeap::new();
        h.init(0x1000);
        assert_eq!(h.used_bytes(), 0);
        assert_eq!(h.free_bytes(), HEAP_SIZE);
        let _ = h.alloc_bytes(1024, 16).unwrap();
        assert!(h.used_bytes() >= 1024);
        assert_eq!(h.used_bytes() + h.free_bytes(), HEAP_SIZE);
    }

    #[test]
    fn init_e_idempotente() {
        let h = BumpHeap::new();
        h.init(0x1000);
        let a = h.alloc_bytes(16, 1).unwrap();
        // Segunda chamada nao deve resetar cursor.
        h.init(0x2000);
        assert_eq!(h.base.load(Ordering::Relaxed), 0x1000);
        let b = h.alloc_bytes(16, 1).unwrap();
        assert!(b > a);
    }
}
