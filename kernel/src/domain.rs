//! Phase 7a.4 + 7a.5 + 7a.6: dominios ring 3.
//!
//! Um `Domain` agrega:
//!   - **CR3** (PML4 proprio com higher-half kernel clonado);
//!   - **CSpace propria** — `CapTable` independente da do kernel.
//!     Multi-CSpace (Phase 7a.5) sai naturalmente ja que `CapTable` e
//!     uma struct instanciavel sem estado global.
//!   - **handle estavel** que pode ser referenciado por
//!     `CapObject::Domain { handle }`.
//!
//! O kernel **nao** mantem scheduler ou run queue de dominios; quem
//! decide qual entra em ring 3 e quando e o codigo de boot ou, futuramente
//! (Phase 7b), o protocolo de PCT entre dominios.
//!
//! # Auditoria de paging (Phase 7a.6)
//!
//! `domain::map` e a unica API que escreve PTEs ring-3. Cada chamada:
//!   1. Verifica que o `frame_slot` aponta para um `CapObject::Frame`
//!      *na CSpace do proprio dominio*.
//!   2. Verifica que `CapRights` cobrem o `Perm` solicitado:
//!      - `UserRx` exige READ;
//!      - `UserRw` exige READ+WRITE.
//!   3. Delega a `mm::map_user_page`, que reasserta `is_user` e
//!      alinhamento (defesa em profundidade).
//! Sem isso, ring 3 poderia escalar privilegios escolhendo `Perm` rico
//! para uma cap atenuada.
//!
//! # Plano para Phase 7a.7+ (cap_grant, ainda fora de escopo)
//!
//! Transferir capabilities entre CSpaces preservando a CDT exige id
//! global de capability (cross-CSpace), o que e uma refatoracao em
//! `cap.rs`. Decisao: implementado junto com revogacao visivel/PCT
//! em Phase 7b, onde a mesma maquinaria de CDT global resolve revogacao
//! cross-domain. Aqui, dominios ja existem e validam mapeamentos; a
//! transferencia de cap esta documentada como pendente no README.

#![cfg(target_os = "none")]

use core::cell::UnsafeCell;

use crate::cap::{CapError, CapObject, CapRights, CapSlot, CapTable};
use crate::mm::{self, Perm};

/// Numero maximo de dominios simultaneos. KISS.
pub const MAX_DOMAINS: usize = 4;

/// Handle opaco para um dominio. So `domain::create` distribui.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct DomainHandle(u8);

impl DomainHandle {
    pub const fn raw(self) -> u8 {
        self.0
    }
    /// Reconstroi um handle a partir de seu valor cru.
    ///
    /// # Safety
    ///
    /// Caller garante que `raw` foi devolvido por `create` e o dominio
    /// ainda existe. Operacoes validam o slot, entao uso indevido
    /// produz `BadHandle` em vez de UB.
    pub const unsafe fn from_raw(raw: u8) -> Self {
        Self(raw)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DomainError {
    /// `DOMAINS` cheio.
    TableFull,
    /// `mm::clone_kernel_higher_half` falhou (sem frames).
    OutOfMemory,
    /// `mm::map_user_page` falhou (colisao ou sem frames).
    MappingFailed,
    /// Handle invalido (slot livre ou fora do range).
    BadHandle,
    /// Erro propagado da CSpace (lookup vazio, fora de range, etc.).
    Cap(CapError),
    /// `frame_slot` nao aponta para `CapObject::Frame`.
    WrongType,
    /// `CapRights` nao cobrem o `Perm` solicitado.
    InsufficientRights,
    /// `perm` nao e user (`is_user() == false`).
    NotUserPerm,
}

impl From<CapError> for DomainError {
    fn from(e: CapError) -> Self {
        DomainError::Cap(e)
    }
}

/// Slot na tabela de dominios. `in_use` separa estados livre/ocupado
/// sem precisar de `Option<Domain>` (CapTable e grande, evita move).
struct DomainSlot {
    in_use: bool,
    cr3: u64,
    cspace: CapTable,
}

impl DomainSlot {
    const fn empty() -> Self {
        Self {
            in_use: false,
            cr3: 0,
            cspace: CapTable::new(),
        }
    }
}

struct DomainTable(UnsafeCell<[DomainSlot; MAX_DOMAINS]>);
// SAFETY: kernel single-core sem preempcao; toda a API deste modulo
// roda em ring 0 com IF=0 ou via codigo sequencial em kmain. Substituir
// por mutex/atomics ao introduzir SMP.
unsafe impl Sync for DomainTable {}

static DOMAINS: DomainTable = DomainTable(UnsafeCell::new(
    [const { DomainSlot::empty() }; MAX_DOMAINS],
));

/// Cria um dominio: aloca PML4 com higher-half kernel clonado, marca
/// slot ocupado, devolve handle. CSpace comeca vazia; o caller povoa
/// via `insert_root`.
///
/// # Safety
///
/// - Pos-`mm::init_paging` (precisa do physmap).
/// - Single-core.
pub unsafe fn create() -> Result<DomainHandle, DomainError> {
    // SAFETY: tabela acessada so por este modulo, single-core.
    let table = unsafe { &mut *DOMAINS.0.get() };
    let slot = (0..MAX_DOMAINS)
        .find(|&i| !table[i].in_use)
        .ok_or(DomainError::TableFull)?;
    // SAFETY: `clone_kernel_higher_half` documenta os requisitos; ja
    // estamos pos-init_paging por contrato deste fn.
    let cr3 = unsafe {
        mm::clone_kernel_higher_half().map_err(|_| DomainError::OutOfMemory)?
    };
    table[slot].in_use = true;
    table[slot].cr3 = cr3;
    table[slot].cspace = CapTable::new();
    Ok(DomainHandle(slot as u8))
}

/// Insere uma capability raiz na CSpace do dominio. Usado pelo kernel
/// (boot ou criador do dominio) para popular o CSpace inicial. Apos
/// Phase 7a.7+, a forma "normal" sera `cap_grant` vindo de outro dominio.
pub fn insert_root(
    h: DomainHandle,
    slot: CapSlot,
    object: CapObject,
    rights: CapRights,
) -> Result<(), DomainError> {
    let idx = h.0 as usize;
    if idx >= MAX_DOMAINS {
        return Err(DomainError::BadHandle);
    }
    // SAFETY: idem create.
    let table = unsafe { &mut *DOMAINS.0.get() };
    if !table[idx].in_use {
        return Err(DomainError::BadHandle);
    }
    Ok(table[idx].cspace.insert_root(slot, object, rights)?)
}

/// Mapeia uma pagina ring-3 no dominio com auditoria de capability.
///
/// # Safety
///
/// - Pos-`mm::init_paging`.
/// - `va` em lower-half user.
/// - `perm.is_user()` (auditado tambem em `mm::map_user_page`).
pub unsafe fn map(
    h: DomainHandle,
    va: u64,
    frame_slot: CapSlot,
    perm: Perm,
) -> Result<(), DomainError> {
    if !perm.is_user() {
        return Err(DomainError::NotUserPerm);
    }
    let idx = h.0 as usize;
    if idx >= MAX_DOMAINS {
        return Err(DomainError::BadHandle);
    }
    // SAFETY: idem create.
    let table = unsafe { &mut *DOMAINS.0.get() };
    if !table[idx].in_use {
        return Err(DomainError::BadHandle);
    }
    let (object, rights) = table[idx].cspace.lookup(frame_slot)?;
    let phys = match object {
        CapObject::Frame { phys } => phys,
        _ => return Err(DomainError::WrongType),
    };
    // Auditoria de direitos vs perm. UserRx exige READ; UserRw exige
    // READ+WRITE (defesa em profundidade: mesmo que paging.rs ja
    // garanta W^X de bit, ainda checamos rights da cap).
    let needed = match perm {
        Perm::UserRx => CapRights::READ,
        Perm::UserRw => CapRights(CapRights::READ.0 | CapRights::WRITE.0),
        _ => return Err(DomainError::NotUserPerm),
    };
    if !rights.contains(needed) {
        return Err(DomainError::InsufficientRights);
    }
    let cr3 = table[idx].cr3;
    // SAFETY: cr3 foi gerado por `clone_kernel_higher_half` (cobre kernel),
    // va em lower-half (asserted la), phys e perm validados acima.
    unsafe {
        mm::map_user_page(cr3, va, phys, perm)
            .map_err(|_| DomainError::MappingFailed)
    }
}

/// Carrega o CR3 do dominio e salta para `entry_rip` em ring 3 com
/// `user_rsp`. Divergente: a unica forma de retorno e via INT 0x80.
///
/// # Safety
///
/// - O dominio deve ter `entry_rip` mapeado UserRx e `user_rsp - 0x1000`
///   mapeado UserRw via `domain::map`.
/// - `userland::install` ja chamado (TSS.RSP0 setado).
/// - Single-core.
pub unsafe fn enter(
    h: DomainHandle,
    entry_rip: u64,
    user_rsp: u64,
) -> Result<core::convert::Infallible, DomainError> {
    let idx = h.0 as usize;
    if idx >= MAX_DOMAINS {
        return Err(DomainError::BadHandle);
    }
    // SAFETY: idem create.
    let cr3 = unsafe {
        let table = &*DOMAINS.0.get();
        if !table[idx].in_use {
            return Err(DomainError::BadHandle);
        }
        table[idx].cr3
    };
    // SAFETY: cr3 e PML4 valido com higher-half kernel; depois deste
    // load, kernel ainda enxerga seu .text/.rodata/.data + physmap. Em
    // seguida `enter_ring3` faz `iretq` com selectors user.
    unsafe {
        crate::arch::x86_64::cpu::load_cr3(cr3);
        crate::arch::x86_64::userland::enter_ring3(entry_rip, user_rsp);
    }
}
