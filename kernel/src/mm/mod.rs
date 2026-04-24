//! Subsistema de gerenciamento de memoria.
//!
//! # Estrutura
//!
//! - `frame`: logica pura (bitmap allocator). `#![forbid(unsafe_code)]`.
//! - Este arquivo: fronteira `unsafe` minima. Contem a unica `static mut`
//!   (o alocador global) e a unica leitura de memoria fisica bruta
//!   (UEFI MemoryMap passada por ponteiro pelo bootloader).
//!
//! # Concorrencia
//!
//! O kernel e single-core sem preempcao ate fases posteriores. Por isso
//! usamos `UnsafeCell` sem mutex. Quando formos para SMP/interrupts
//! aninhadas, substituir por `spin::Mutex` equivalente minimo.

use core::cell::UnsafeCell;

use bootinfo::BootInfo;

pub mod frame;
pub mod heap;
pub mod paging;

pub use frame::{FrameAllocator, FrameError, PhysFrame};
pub use heap::{HeapError, KERNEL_HEAP};
pub use paging::Perm;

/// Wrapper `Sync` em torno do alocador para permitir `static`. Ver comentario
/// de concorrencia acima para justificativa.
struct GlobalAlloc(UnsafeCell<FrameAllocator>);

// SAFETY: acesso mediado exclusivamente pelas funcoes `init`, `alloc_frame`,
// `free_frame`, `free_count`, `total_frames`. Kernel single-core sem
// preempcao garante ausencia de races. Substituir por Mutex ao introduzir SMP.
unsafe impl Sync for GlobalAlloc {}

static FRAME_ALLOC: GlobalAlloc = GlobalAlloc(UnsafeCell::new(FrameAllocator::empty()));

/// Inicializa o alocador global a partir do `BootInfo`. Deve ser chamada
/// uma unica vez, durante `kmain::start`, antes que qualquer modulo tente
/// alocar memoria.
pub fn init(bootinfo: &BootInfo) -> Result<(), FrameError> {
    let ptr = bootinfo.memory_map.ptr as *const u8;
    let len = bootinfo.memory_map.len as usize;
    let desc_size = bootinfo.memory_map.desc_size as usize;

    if ptr.is_null() || len == 0 {
        return Err(FrameError::InvalidMemoryMap);
    }

    // SAFETY: o bootloader documenta (em `bootinfo::MemoryMap`) que `ptr`
    // aponta para `len` bytes alocados via AllocatePool com tipo LoaderData,
    // sobreviventes a ExitBootServices. O kernel roda em identity map UEFI
    // que cobre essa regiao (antes de trocar CR3). Leitura-apenas, sem
    // aliasing mutavel.
    let map_bytes: &[u8] = unsafe { core::slice::from_raw_parts(ptr, len) };

    let reserved = [bootinfo.kernel_phys_range];

    // SAFETY: chamada unica durante boot; kernel single-core sem preempcao,
    // entao `&mut` exclusivo pelo escopo desta funcao e valido.
    let alloc = unsafe { &mut *FRAME_ALLOC.0.get() };
    alloc.init(map_bytes, desc_size, &reserved)
}

/// Aloca um frame fisico de 4 KiB. Retorna `None` se sem memoria livre.
pub fn alloc_frame() -> Option<PhysFrame> {
    // SAFETY: ver comentario de concorrencia no topo; acesso sequencial.
    let alloc = unsafe { &mut *FRAME_ALLOC.0.get() };
    alloc.alloc()
}

/// Devolve um frame fisico ao pool. Devolver um frame nao alocado ou fora
/// da area gerenciada e no-op silencioso (nao corrompe estado).
pub fn free_frame(frame: PhysFrame) {
    // SAFETY: idem.
    let alloc = unsafe { &mut *FRAME_ALLOC.0.get() };
    alloc.free(frame);
}

/// Quantidade de frames atualmente livres.
pub fn free_count() -> usize {
    // SAFETY: leitura imutavel; kernel single-core.
    let alloc = unsafe { &*FRAME_ALLOC.0.get() };
    alloc.free_count()
}

/// Quantidade total de frames gerenciados (indice mais alto tocado por init).
pub fn total_frames() -> usize {
    // SAFETY: leitura imutavel.
    let alloc = unsafe { &*FRAME_ALLOC.0.get() };
    alloc.total_frames()
}

// =====================================================================
// Paging init
// =====================================================================
//
// Simbolos exportados pelo linker para delimitar cada secao do kernel.
// Definidos em `kernel/linker.ld`. Leitura via `addr_of!` evita formar
// referencias a simbolos externos sem tipo concreto.

#[cfg(target_os = "none")]
extern "C" {
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __bss_end: u8;
}

/// Offset higher-half: `virt = phys + KERNEL_VMA_OFFSET`. Tem que bater
/// com `kernel/linker.ld` (KERNEL_VMA - KERNEL_LMA) e com o bootloader
/// (`bootloader/src/platform/uefi.rs::KERNEL_VMA_OFFSET`).
pub const KERNEL_VMA_OFFSET: u64 = 0xFFFF_FFFF_8000_0000;

/// Erro de inicializacao da paginacao.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagingError {
    /// Sem frame livre para alocar tabela intermediaria.
    OutOfFrames,
    /// Colisao interna ao montar o mapa (bug logico; nao deveria acontecer).
    InternalConflict,
}

/// Constroi um novo PML4 higher-half puro: kernel em 0xFFFFFFFF80200000+,
/// heap logo apos `__bss_end`, aplica W^X por secao, habilita NX no EFER e
/// troca CR3 (drop do identity UEFI).
///
/// # Safety
///
/// - Deve ser chamado uma unica vez apos `mm::init`.
/// - Kernel roda sob PML4 do bootloader (UEFI identity + higher-half).
///   A troca de CR3 para o novo PML4 so e segura porque ele cobre todas
///   as paginas que o kernel continuara a tocar (text, rodata, .bss incl.
///   stack, heap recem-mapeado) em higher-half.
/// - **Contrato forte**: qualquer referencia `&BootInfo` do caller torna-se
///   invalida apos esta chamada (o buffer UEFI de BootInfo/MemoryMap esta
///   em baixo-half, que deixa de ser mapeado). Por isso NAO recebemos
///   `&BootInfo` como parametro: o caller nao pode passar uma referencia
///   que ele mesmo nao deve mais usar. Todos os dados necessarios ja
///   foram copiados em `mm::init`.
#[cfg(target_os = "none")]
pub unsafe fn init_paging() -> Result<u64, PagingError> {
    use crate::arch::x86_64::cpu;
    use core::ptr::addr_of;

    // Habilita NX antes de popular qualquer PTE com bit 63 setado. Sem NXE,
    // bit 63 e reservado-must-be-zero e qualquer escrita causa #GP ao
    // tentarmos carregar esse PTE.
    cpu::enable_nxe();

    let text_start = addr_of!(__text_start) as u64;
    let text_end = addr_of!(__text_end) as u64;
    let rodata_start = addr_of!(__rodata_start) as u64;
    let rodata_end = addr_of!(__rodata_end) as u64;
    let data_start = addr_of!(__data_start) as u64;
    let bss_end = addr_of!(__bss_end) as u64;

    let pml4_phys = alloc_zeroed_table().ok_or(PagingError::OutOfFrames)?;

    // Mapeia cada secao do kernel com seu perfil W^X. `virt` = simbolo do
    // linker (higher-half); `phys` = virt - KERNEL_VMA_OFFSET.
    map_range(pml4_phys, text_start, text_end, text_start - KERNEL_VMA_OFFSET, Perm::Rx)?;
    map_range(pml4_phys, rodata_start, rodata_end, rodata_start - KERNEL_VMA_OFFSET, Perm::Ro)?;
    map_range(pml4_phys, data_start, bss_end, data_start - KERNEL_VMA_OFFSET, Perm::Rw)?;

    // Heap: 256 frames RW+NX em faixa virtual contigua logo apos `__bss_end`.
    // Cada pagina virtual recebe um frame fisico independente (nao-contiguo).
    // heap::KERNEL_HEAP e inicializado com a base virtual apos mapear tudo.
    let heap_base = bss_end;
    let heap_pages = (heap::HEAP_SIZE as u64) / frame::FRAME_SIZE;
    for i in 0..heap_pages {
        let virt = heap_base + i * frame::FRAME_SIZE;
        let f = alloc_frame().ok_or(PagingError::OutOfFrames)?;
        map_4k(pml4_phys, virt, f.addr(), Perm::Rw)?;
    }

    // SAFETY: pml4_phys foi construido acima. Todas as paginas que o
    // kernel continuara a executar ate `halt_forever` (text, stack em
    // .bss, heap) estao mapeadas em higher-half. A MM buffer fica orfa,
    // mas nao e mais lida (mm::init ja copiou tudo que precisavamos).
    unsafe { cpu::load_cr3(pml4_phys); }

    heap::KERNEL_HEAP.init(heap_base as usize);

    Ok(pml4_phys)
}

/// Aloca um frame e zera o conteudo (para ser usado como tabela).
///
/// Roda apenas sob identity map UEFI: interpreta o endereco fisico como
/// ponteiro virtual para zerar as 4 KiB.
#[cfg(target_os = "none")]
fn alloc_zeroed_table() -> Option<u64> {
    let frame = alloc_frame()?;
    let phys = frame.addr();
    // SAFETY: frame recem-alocado pertence a nos exclusivamente; identity
    // map UEFI garante que `phys` e um ponteiro valido para 4 KiB. Zerar
    // e pre-requisito para usa-lo como page table.
    unsafe {
        core::ptr::write_bytes(phys as *mut u8, 0, frame::FRAME_SIZE as usize);
    }
    Some(phys)
}

/// Mapeia um intervalo virtual `[vstart, vend)` para `[phys_start, ...)`
/// em paginas de 4 KiB com o perfil W^X indicado. Todos os enderecos
/// devem estar alinhados a 4 KiB.
#[cfg(target_os = "none")]
fn map_range(
    pml4_phys: u64,
    vstart: u64,
    vend: u64,
    phys_start: u64,
    perm: Perm,
) -> Result<(), PagingError> {
    debug_assert!(vstart & (frame::FRAME_SIZE - 1) == 0);
    debug_assert!(vend & (frame::FRAME_SIZE - 1) == 0);
    debug_assert!(phys_start & (frame::FRAME_SIZE - 1) == 0);
    let mut v = vstart;
    let mut p = phys_start;
    while v < vend {
        map_4k(pml4_phys, v, p, perm)?;
        v += frame::FRAME_SIZE;
        p += frame::FRAME_SIZE;
    }
    Ok(())
}

/// Mapeia uma unica pagina de 4 KiB em `pml4_phys`. Aloca tabelas
/// intermediarias conforme necessario.
#[cfg(target_os = "none")]
fn map_4k(pml4_phys: u64, virt: u64, phys: u64, perm: Perm) -> Result<(), PagingError> {
    use paging::{make_pte, pte_phys, pte_present, Indices};

    let idx = Indices::from_virt(virt);
    // Caminha PML4 -> PDPT -> PD -> PT, criando niveis vazios se preciso.
    let pdpt_phys = ensure_next_level(pml4_phys, idx.pml4)?;
    let pd_phys = ensure_next_level(pdpt_phys, idx.pdpt)?;
    let pt_phys = ensure_next_level(pd_phys, idx.pd)?;

    // Escreve PTE folha com o perfil W^X final.
    // SAFETY: pt_phys foi obtido via ensure_next_level, que so retorna
    // frames que alocamos nos ou ja presentes em intermediarias. Identity
    // map UEFI garante acesso.
    let pt = pt_phys as *mut u64;
    let pte_addr = unsafe { pt.add(idx.pt) };
    let existing = unsafe { pte_addr.read() };
    // Conflito se (a) endereco fisico divergir, ou (b) flags (W/NX) divergirem.
    // Sem (b) seria possivel escalar permissoes re-mapeando o mesmo frame.
    let new_pte = make_pte(phys, perm);
    if pte_present(existing) && existing != new_pte {
        return Err(PagingError::InternalConflict);
    }
    unsafe { pte_addr.write(new_pte); }
    Ok(())
}

/// Retorna o endereco fisico da tabela-filha referenciada em `parent[idx]`;
/// aloca uma nova se ainda nao existir.
#[cfg(target_os = "none")]
fn ensure_next_level(parent_phys: u64, idx: usize) -> Result<u64, PagingError> {
    use paging::{make_intermediate_pte, pte_phys, pte_present};
    // SAFETY: parent_phys ja foi alocado por nos (ou e o PML4 inicial).
    // Identity map UEFI cobre.
    let parent = parent_phys as *mut u64;
    let entry_ptr = unsafe { parent.add(idx) };
    let entry = unsafe { entry_ptr.read() };
    if pte_present(entry) {
        return Ok(pte_phys(entry));
    }
    let new_phys = alloc_zeroed_table().ok_or(PagingError::OutOfFrames)?;
    unsafe { entry_ptr.write(make_intermediate_pte(new_phys)); }
    Ok(new_phys)
}
