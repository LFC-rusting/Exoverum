//! Phases 7a/7b/8: dominios ring 3 com PCT, upcalls, cap_grant,
//! visible cross-CSpace revocation e abort protocol.
//!
//! # Modelo
//!
//! Um `Domain` agrega:
//!   - **CR3** proprio (PML4 com higher-half kernel clonado);
//!   - **CSpace** propria (`CapTable` independente da do kernel);
//!   - **Pontos de entrada** (`entry_rip`/`entry_rsp`) usados quando
//!     outro dominio invoca este via PCT pela primeira vez;
//!   - **Upcall handler** (`upcall_entry`/`upcall_stack`) usado quando
//!     o kernel entrega evento (timer, fault, repossession) ao dominio;
//!   - **Estado de PCT**: `caller`, `saved_ctx`, `pre_upcall_ctx`;
//!   - **Flags de estado** (Phase 8): `pending_upcall` (upcall a
//!     entregar na proxima entrada), `aborted` (dominio faulted; nao
//!     pode mais ser escalonado).
//!
//! # Visible cross-CSpace revocation (Phase 8)
//!
//! Uma tabela paralela (`GRANTS`) registra cada `cap_grant` (origem:
//! `(src_dh, src_slot)`; destino: `(dst_dh, dst_slot)`).
//! `revoke_granted(src_dh, src_slot)` varre, remove o destino da
//! CSpace e marca cada dominio afetado com `pending_upcall =
//! Repossession`. Na proxima entrada (PCT ou timer), o kernel
//! preempta a execucao normal com um upcall de repossession.
//!
//! # Abort protocol (Phase 8)
//!
//! Qualquer exception em CPL=3 (`#PF`, `#GP`, `#UD`, `#DE`) invoca
//! `abort_current(kind)`: loga + marca `aborted = true` e retorna
//! controle ao kernel (halt ou proxima LibOS, conforme politica).
//! Seguranca > liveness: domain faulty nunca retoma execucao.
//!
//! # Single-thread invariant
//!
//! Single-core, sem preempcao em ring 0. `CURRENT` indica qual dominio
//! possui a CPU agora (None = ring 0 puro).

#![cfg(target_os = "none")]

use core::cell::UnsafeCell;

use crate::arch::x86_64::userland::UserContext;
use crate::cap::{CapError, CapObject, CapRights, CapSlot, CapTable, CAP_SLOTS};
use crate::mm::{self, Perm};

/// Numero maximo de dominios simultaneos. KISS.
pub const MAX_DOMAINS: usize = 4;

/// Razao do upcall, passada em RDI ao handler ring 3.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u64)]
pub enum UpcallReason {
    Timer = 0,
    Fault = 1,
    Repossession = 2,
}

/// Handle opaco para um dominio.
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
    /// `cap_grant` chamado com src_dh == dst_dh (use `cap.copy` local).
    SameDomain,
    /// `pct_call` em dominio sem entry_rip programado.
    NoEntry,
    /// `pct_call` em dominio que ja tem caller pendente.
    Busy,
    /// `pct_reply` sem caller registrado.
    NoCaller,
    /// `upcall_return` sem ctx pre-upcall salvo.
    NoSavedUpcall,
    /// PCT/upcall com `CURRENT_DOMAIN` nulo.
    NoCurrentDomain,
    /// (Phase 8) Dominio alvo marcado como abortado.
    Aborted,
    /// (Phase 8) `revoke_granted` em slot que nunca foi origem de grant.
    NoGrant,
    /// (Phase 8) `GRANTS` cheio.
    GrantTableFull,
}

impl From<CapError> for DomainError {
    fn from(e: CapError) -> Self {
        DomainError::Cap(e)
    }
}

/// Slot na tabela de dominios.
struct DomainSlot {
    in_use: bool,
    cr3: u64,
    cspace: CapTable,
    /// Endereco onde o dominio comeca a executar quando outro o invoca
    /// via `pct_call` *pela primeira vez*. Zero = nao programado.
    entry_rip: u64,
    /// RSP user inicial, idem.
    entry_rsp: u64,
    /// Endereco do handler de upcall (timer, fault, etc.). Zero = sem
    /// upcall handler; nesse caso, timer interrompendo ring 3 nao faz
    /// nada alem de EOI+rearm.
    upcall_entry: u64,
    /// RSP user para o handler de upcall.
    upcall_stack: u64,
    /// Quem chamou este dominio via `pct_call`. `None` = livre para receber.
    caller: Option<DomainHandle>,
    /// `UserContext` salvo quando este dominio foi *suspenso* por
    /// chamar outro (`pct_call`). Restaurado por `pct_reply` no callee.
    saved_ctx: UserContext,
    /// `UserContext` salvo no momento em que um upcall interrompeu este
    /// dominio. Restaurado por `syscall=4 upcall_return`. Bit `valid`
    /// distingue "Some" sem precisar de Option (alinhamento simples).
    pre_upcall_ctx: UserContext,
    pre_upcall_valid: bool,
    /// (Phase 8) Upcall pendente para o dominio (ex.: repossession
    /// disparada por `revoke_granted`). `None` = sem nada pendente.
    pending_upcall: Option<UpcallReason>,
    /// (Phase 8) Dominio marcado como abortado — faulted ou teve
    /// capabilities criticas repossessed. Nunca mais recebe CPU;
    /// `pct_call` para este dominio falha com `Aborted`.
    aborted: bool,
}

impl DomainSlot {
    const fn empty() -> Self {
        Self {
            in_use: false,
            cr3: 0,
            cspace: CapTable::new(),
            entry_rip: 0,
            entry_rsp: 0,
            upcall_entry: 0,
            upcall_stack: 0,
            caller: None,
            saved_ctx: UserContext::fresh(0, 0),
            pre_upcall_ctx: UserContext::fresh(0, 0),
            pre_upcall_valid: false,
            pending_upcall: None,
            aborted: false,
        }
    }
}

struct DomainTable(UnsafeCell<[DomainSlot; MAX_DOMAINS]>);
// SAFETY: kernel single-core sem preempcao em ring 0.
unsafe impl Sync for DomainTable {}

static DOMAINS: DomainTable = DomainTable(UnsafeCell::new(
    [const { DomainSlot::empty() }; MAX_DOMAINS],
));

/// Dominio que detem a CPU agora. `None` = ring 0 puro (boot ou apos
/// um dominio haltar).
struct CurrentDomain(UnsafeCell<Option<DomainHandle>>);
// SAFETY: idem `DomainTable`.
unsafe impl Sync for CurrentDomain {}

static CURRENT: CurrentDomain = CurrentDomain(UnsafeCell::new(None));

/// Le `CURRENT_DOMAIN` (apenas para diagnosticos / `pct_*`).
fn current() -> Option<DomainHandle> {
    // SAFETY: single-core; sem corrida.
    unsafe { *CURRENT.0.get() }
}

/// Define `CURRENT_DOMAIN`. Chamado por `enter`, `pct_call`, `pct_reply`.
fn set_current(h: Option<DomainHandle>) {
    // SAFETY: idem.
    unsafe { *CURRENT.0.get() = h };
}

// =================================================================
// API publica
// =================================================================

/// Cria um dominio: aloca PML4 com higher-half kernel clonado, marca
/// slot ocupado, devolve handle. CSpace comeca vazia; o caller povoa
/// via `insert_root` ou recebe caps via `cap_grant`.
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
    // SAFETY: pos-init_paging por contrato.
    let cr3 = unsafe {
        mm::clone_kernel_higher_half().map_err(|_| DomainError::OutOfMemory)?
    };
    table[slot] = DomainSlot::empty();
    table[slot].in_use = true;
    table[slot].cr3 = cr3;
    Ok(DomainHandle(slot as u8))
}

/// Programa `(entry_rip, entry_rsp)`, ponto de entrada quando o dominio
/// e invocado via `pct_call` pela primeira vez. Pode ser sobrescrito.
pub fn set_entry(h: DomainHandle, rip: u64, rsp: u64) -> Result<(), DomainError> {
    let idx = h.0 as usize;
    if idx >= MAX_DOMAINS {
        return Err(DomainError::BadHandle);
    }
    // SAFETY: idem create.
    let table = unsafe { &mut *DOMAINS.0.get() };
    if !table[idx].in_use {
        return Err(DomainError::BadHandle);
    }
    table[idx].entry_rip = rip;
    table[idx].entry_rsp = rsp;
    Ok(())
}

/// Programa `(upcall_entry, upcall_stack)`. Quando timer/fault interrompe
/// o dominio em ring 3, o kernel salva o ctx atual, sobrescreve o iret
/// frame para apontar aqui e retoma; o handler chama `syscall 4`
/// (`upcall_return`) para voltar ao ponto interrompido.
#[allow(dead_code)]
pub fn set_upcall(h: DomainHandle, entry: u64, stack: u64) -> Result<(), DomainError> {
    let idx = h.0 as usize;
    if idx >= MAX_DOMAINS {
        return Err(DomainError::BadHandle);
    }
    // SAFETY: idem.
    let table = unsafe { &mut *DOMAINS.0.get() };
    if !table[idx].in_use {
        return Err(DomainError::BadHandle);
    }
    table[idx].upcall_entry = entry;
    table[idx].upcall_stack = stack;
    Ok(())
}

/// Insere uma capability raiz na CSpace do dominio.
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
    // SAFETY: idem.
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
    // SAFETY: idem.
    let table = unsafe { &mut *DOMAINS.0.get() };
    if !table[idx].in_use {
        return Err(DomainError::BadHandle);
    }
    let (object, rights) = table[idx].cspace.lookup(frame_slot)?;
    let phys = match object {
        CapObject::Frame { phys } => phys,
        _ => return Err(DomainError::WrongType),
    };
    let needed = match perm {
        Perm::UserRx => CapRights::READ,
        Perm::UserRw => CapRights(CapRights::READ.0 | CapRights::WRITE.0),
        _ => return Err(DomainError::NotUserPerm),
    };
    if !rights.contains(needed) {
        return Err(DomainError::InsufficientRights);
    }
    let cr3 = table[idx].cr3;
    // SAFETY: cr3 valido (clone_kernel_higher_half), va lower-half, phys
    // e perm validados acima.
    unsafe {
        mm::map_user_page(cr3, va, phys, perm)
            .map_err(|_| DomainError::MappingFailed)
    }
}

/// Carrega CR3 do dominio, marca-o como `CURRENT_DOMAIN`, e salta para
/// `entry_rip` em ring 3 com `user_rsp`. Divergente.
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
    let cr3 = {
        // SAFETY: idem.
        let table = unsafe { &*DOMAINS.0.get() };
        if !table[idx].in_use {
            return Err(DomainError::BadHandle);
        }
        table[idx].cr3
    };
    set_current(Some(h));
    // SAFETY: cr3 e PML4 valido com higher-half kernel; depois deste
    // load, kernel ainda enxerga seu .text/.rodata/.data + physmap. Em
    // seguida `enter_ring3` faz `iretq` com selectors user.
    unsafe {
        crate::arch::x86_64::cpu::load_cr3(cr3);
        crate::arch::x86_64::userland::enter_ring3(entry_rip, user_rsp);
    }
}

/// `cap_grant`: transfere capability entre CSpaces de dominios distintos.
///
/// Le `(object, rights_src)` em `(src_dh, src_slot)`, valida `rights ⊆
/// rights_src`, insere copia em `(dst_dh, dst_slot)` como root local
/// da CSpace destino, e registra `(src_dh, src_slot) → (dst_dh,
/// dst_slot)` em `GRANTS` para rastrear a transferencia.
///
/// `revoke_granted(src_dh, src_slot)` (Phase 8) varre `GRANTS` e
/// remove todos os destinos derivados, entregando upcall de
/// repossession aos dominios afetados.
pub fn cap_grant(
    src_dh: DomainHandle,
    src_slot: CapSlot,
    dst_dh: DomainHandle,
    dst_slot: CapSlot,
    rights: CapRights,
) -> Result<(), DomainError> {
    if src_dh == dst_dh {
        return Err(DomainError::SameDomain);
    }
    let src_idx = src_dh.0 as usize;
    let dst_idx = dst_dh.0 as usize;
    if src_idx >= MAX_DOMAINS || dst_idx >= MAX_DOMAINS {
        return Err(DomainError::BadHandle);
    }
    // SAFETY: idem.
    let table = unsafe { &mut *DOMAINS.0.get() };
    if !table[src_idx].in_use || !table[dst_idx].in_use {
        return Err(DomainError::BadHandle);
    }
    let (object, src_rights) = table[src_idx].cspace.lookup(src_slot)?;
    if !src_rights.contains(rights) {
        return Err(DomainError::InsufficientRights);
    }
    table[dst_idx].cspace.insert_root(dst_slot, object, rights)?;
    // (Phase 8) Registra grant em tabela paralela para revogacao
    // visivel cross-CSpace.
    register_grant(src_dh, src_slot, dst_dh, dst_slot)?;
    Ok(())
}

// =================================================================
// Visible cross-CSpace revocation (Phase 8)
// =================================================================

/// Capacidade da tabela de grants. Pequena de proposito: cada
/// registro consome 4 bytes; capability transfer e raro fora de
/// boot. Se atingir o limite, `cap_grant` falha com
/// `DomainError::GrantTableFull` em vez de UB.
const MAX_GRANTS: usize = 32;

/// Registro de uma transferencia ativa: `(src_dh, src_slot)` foi
/// usado para criar `(dst_dh, dst_slot)` via `cap_grant`. Slot livre
/// quando `in_use == false`.
#[derive(Copy, Clone)]
struct GrantEntry {
    in_use: bool,
    src_dh: u8,
    src_slot: CapSlot,
    dst_dh: u8,
    dst_slot: CapSlot,
}

impl GrantEntry {
    const fn empty() -> Self {
        Self {
            in_use: false,
            src_dh: 0,
            src_slot: 0,
            dst_dh: 0,
            dst_slot: 0,
        }
    }
}

struct GrantTable(UnsafeCell<[GrantEntry; MAX_GRANTS]>);
// SAFETY: idem `DomainTable` — single-core.
unsafe impl Sync for GrantTable {}

static GRANTS: GrantTable = GrantTable(UnsafeCell::new(
    [const { GrantEntry::empty() }; MAX_GRANTS],
));

fn register_grant(
    src_dh: DomainHandle,
    src_slot: CapSlot,
    dst_dh: DomainHandle,
    dst_slot: CapSlot,
) -> Result<(), DomainError> {
    // SAFETY: idem.
    let grants = unsafe { &mut *GRANTS.0.get() };
    let slot = grants
        .iter()
        .position(|g| !g.in_use)
        .ok_or(DomainError::GrantTableFull)?;
    grants[slot] = GrantEntry {
        in_use: true,
        src_dh: src_dh.0,
        src_slot,
        dst_dh: dst_dh.0,
        dst_slot,
    };
    Ok(())
}

/// Revoga visivelmente todas as caps que foram derivadas de
/// `(src_dh, src_slot)` via `cap_grant`. Para cada destino afetado:
///
/// 1. Remove a entry da CSpace destino (`delete`); se ja foi
///    deletada, ignora.
/// 2. Marca `pending_upcall = Some(Repossession)` no dominio destino.
///    O proximo `pct_call` ou timer-upcall entrega o aviso antes de
///    retomar execucao normal — o dominio sabe que perdeu cap.
///
/// Retorna numero de destinos revogados (>= 0).
pub fn revoke_granted(
    src_dh: DomainHandle,
    src_slot: CapSlot,
) -> Result<usize, DomainError> {
    // SAFETY: idem.
    let grants = unsafe { &mut *GRANTS.0.get() };
    let table = unsafe { &mut *DOMAINS.0.get() };
    let mut count = 0usize;
    for g in grants.iter_mut() {
        if !g.in_use {
            continue;
        }
        if g.src_dh != src_dh.0 || g.src_slot != src_slot {
            continue;
        }
        let dst_idx = g.dst_dh as usize;
        if dst_idx < MAX_DOMAINS && table[dst_idx].in_use {
            // Tenta deletar; se ja sumiu (dominio fez delete por
            // conta propria), ignora.
            let _ = table[dst_idx].cspace.delete(g.dst_slot);
            // Marca repossession; nao sobrescreve outro pending
            // pre-existente (preserva FIFO degenerado).
            if table[dst_idx].pending_upcall.is_none() {
                table[dst_idx].pending_upcall =
                    Some(UpcallReason::Repossession);
            }
        }
        g.in_use = false;
        count += 1;
    }
    if count == 0 {
        return Err(DomainError::NoGrant);
    }
    Ok(count)
}

// =================================================================
// Abort protocol (Phase 8)
// =================================================================

/// Marca o dominio em execucao como abortado e devolve controle ao
/// kernel. Chamado pelos handlers de exception ring 3 em `idt.rs`.
/// Apos esta chamada o dominio nunca mais e escalonado; `pct_call`
/// apontando para ele falha com `Aborted`.
pub fn abort_current(reason: UpcallReason) {
    let cur_h = match current() {
        Some(h) => h,
        None => return,
    };
    let idx = cur_h.0 as usize;
    // SAFETY: idem.
    let table = unsafe { &mut *DOMAINS.0.get() };
    if idx < MAX_DOMAINS && table[idx].in_use {
        table[idx].aborted = true;
        table[idx].pending_upcall = None;
        table[idx].caller = None;
    }
    set_current(None);
    crate::log::write_str("[kernel] domain abort, reason=");
    crate::log::write_str(match reason {
        UpcallReason::Fault => "fault\n",
        UpcallReason::Repossession => "repossession\n",
        UpcallReason::Timer => "timer\n",
    });
}

// =================================================================
// PCT (Protected Control Transfer)
// =================================================================

/// Verifica se `caller` tem na sua CSpace alguma cap `Domain { handle: target }`.
/// Esse e o bilhete de autorizacao para `pct_call`. Tipicamente o
/// kernel boot popula isto via `insert_root`; em LibOSes futuras, via
/// `cap_grant` mediada.
fn caller_has_domain_cap(caller_idx: usize, target: DomainHandle) -> bool {
    // SAFETY: idem.
    let table = unsafe { &*DOMAINS.0.get() };
    let cspace = &table[caller_idx].cspace;
    let mut slot: u16 = 0;
    while (slot as usize) < CAP_SLOTS {
        if let Ok((CapObject::Domain { handle }, _)) = cspace.lookup(slot) {
            if handle == target.0 {
                return true;
            }
        }
        slot += 1;
    }
    false
}

/// `domain_call(target)`: salva ctx do caller, ativa target.
///
/// O `*ctx` aponta para `UserContext` na syscall stack: o kernel
/// **sobrescreve** com o ctx fresh do target, e o `iretq` final no
/// trampolim carrega o target em ring 3.
///
/// # Safety
///
/// `ctx` deve apontar para `UserContext` valido na syscall stack
/// (construido por `syscall_entry`).
pub unsafe fn pct_call(
    ctx: *mut UserContext,
    target_raw: u8,
) -> Result<(), DomainError> {
    let cur_h = current().ok_or(DomainError::NoCurrentDomain)?;
    let target_h = DomainHandle(target_raw);
    if cur_h == target_h {
        return Err(DomainError::SameDomain);
    }
    let cur_idx = cur_h.0 as usize;
    let tgt_idx = target_raw as usize;
    if tgt_idx >= MAX_DOMAINS {
        return Err(DomainError::BadHandle);
    }
    // Validacao em duas fases para evitar segurar &mut atravessando o load_cr3.
    {
        // SAFETY: idem.
        let table = unsafe { &*DOMAINS.0.get() };
        if !table[tgt_idx].in_use {
            return Err(DomainError::BadHandle);
        }
        if table[tgt_idx].caller.is_some() {
            return Err(DomainError::Busy);
        }
        if table[tgt_idx].entry_rip == 0 || table[tgt_idx].entry_rsp == 0 {
            return Err(DomainError::NoEntry);
        }
    }
    if !caller_has_domain_cap(cur_idx, target_h) {
        return Err(DomainError::InsufficientRights);
    }
    // SAFETY: idem.
    let table = unsafe { &mut *DOMAINS.0.get() };
    if table[tgt_idx].aborted {
        return Err(DomainError::Aborted);
    }
    // Salva ctx do caller. SAFETY: ctx valido por contrato.
    table[cur_idx].saved_ctx = unsafe { *ctx };
    table[tgt_idx].caller = Some(cur_h);
    let entry = table[tgt_idx].entry_rip;
    let rsp = table[tgt_idx].entry_rsp;
    let cr3 = table[tgt_idx].cr3;
    let pending = table[tgt_idx].pending_upcall.take();
    let upcall_entry = table[tgt_idx].upcall_entry;
    let upcall_stack = table[tgt_idx].upcall_stack;
    // (Phase 8) Se ha upcall pendente para o target e ele tem handler,
    // entrega ANTES de tocar o entry normal: caller fica suspenso
    // como sempre, mas o target acorda no upcall_entry com a razao
    // em RDI.
    let mut delivered_upcall = false;
    let new_ctx = match pending {
        Some(reason) if upcall_entry != 0 && upcall_stack != 0 => {
            let mut c = UserContext::fresh(upcall_entry, upcall_stack);
            c.rdi = reason as u64;
            c.rflags = 0x002; // IF=0 enquanto handler roda
            // pre_upcall_ctx aponta para a entrada normal: handler
            // chama upcall_return e cai no servico de PCT.
            table[tgt_idx].pre_upcall_ctx = UserContext::fresh(entry, rsp);
            table[tgt_idx].pre_upcall_valid = true;
            delivered_upcall = true;
            c
        }
        _ => UserContext::fresh(entry, rsp),
    };
    // SAFETY: idem.
    unsafe { *ctx = new_ctx };
    set_current(Some(target_h));
    // SAFETY: cr3 valido (clone_kernel_higher_half do target).
    unsafe { crate::arch::x86_64::cpu::load_cr3(cr3) };
    if delivered_upcall {
        crate::log::write_str("[kernel] pct_call -> upcall (repossession)\n");
    } else {
        crate::log::write_str("[kernel] pct_call ok\n");
    }
    Ok(())
}

/// `domain_reply(value)`: callee retorna controle ao caller.
///
/// Restaura `caller.saved_ctx`, sobrescreve `rax = value` e troca CR3.
/// O caller continua exatamente apos seu `INT 0x80` ver o valor em RAX.
///
/// # Safety
///
/// Idem `pct_call`.
pub unsafe fn pct_reply(
    ctx: *mut UserContext,
    value: u64,
) -> Result<(), DomainError> {
    let cur_h = current().ok_or(DomainError::NoCurrentDomain)?;
    let cur_idx = cur_h.0 as usize;
    // SAFETY: idem.
    let table = unsafe { &mut *DOMAINS.0.get() };
    let caller = table[cur_idx].caller.take().ok_or(DomainError::NoCaller)?;
    let caller_idx = caller.0 as usize;
    let mut saved = table[caller_idx].saved_ctx;
    saved.rax = value;
    // SAFETY: ctx valido.
    unsafe { *ctx = saved };
    let cr3 = table[caller_idx].cr3;
    set_current(Some(caller));
    // SAFETY: cr3 do caller, clone_kernel_higher_half.
    unsafe { crate::arch::x86_64::cpu::load_cr3(cr3) };
    crate::log::write_str("[kernel] pct_reply ok\n");
    Ok(())
}

// =================================================================
// Upcalls (timer, fault, repossession)
// =================================================================

/// Tentativa de entrega de upcall por timer ao dominio em execucao.
/// Se o dominio nao registrou upcall handler (`upcall_entry == 0`), o
/// kernel apenas retorna sem mexer no ctx — ring 3 retoma onde estava.
///
/// Se ja ha um upcall em curso (`pre_upcall_valid == true`), evitamos
/// nesting: simplesmente retornamos. Phase 8 hardening pode promover
/// para upcall fila.
///
/// # Safety
///
/// `ctx` aponta para `UserContext` na stack; CPL=3 ja foi confirmado
/// pelo caller (`timer_handler_rust`).
pub unsafe fn timer_upcall(ctx: *mut UserContext) {
    let cur_h = match current() {
        Some(h) => h,
        None => return,
    };
    let idx = cur_h.0 as usize;
    // SAFETY: idem.
    let table = unsafe { &mut *DOMAINS.0.get() };
    if !table[idx].in_use || table[idx].aborted {
        return;
    }
    if table[idx].upcall_entry == 0 || table[idx].upcall_stack == 0 {
        return;
    }
    if table[idx].pre_upcall_valid {
        // Upcall ja em curso; ignora (sem nesting).
        return;
    }
    // (Phase 8) Repossession pendente tem prioridade sobre timer:
    // entrega-a; senao, entrega timer.
    let reason = table[idx]
        .pending_upcall
        .take()
        .unwrap_or(UpcallReason::Timer);
    // SAFETY: ctx valido.
    let saved = unsafe { *ctx };
    table[idx].pre_upcall_ctx = saved;
    table[idx].pre_upcall_valid = true;
    let entry = table[idx].upcall_entry;
    let stack = table[idx].upcall_stack;
    let mut new_ctx = UserContext::fresh(entry, stack);
    new_ctx.rdi = reason as u64;
    // IF=0 enquanto o dominio processa o upcall (evita nesting natural).
    new_ctx.rflags = 0x002;
    // SAFETY: ctx valido.
    unsafe { *ctx = new_ctx };
}

/// `syscall=4 upcall_return`: restaura `pre_upcall_ctx`. O dominio
/// retoma exatamente apos o ponto interrompido.
///
/// # Safety
///
/// Idem `pct_*`.
pub unsafe fn upcall_return(ctx: *mut UserContext) -> Result<(), DomainError> {
    let cur_h = current().ok_or(DomainError::NoCurrentDomain)?;
    let idx = cur_h.0 as usize;
    // SAFETY: idem.
    let table = unsafe { &mut *DOMAINS.0.get() };
    if !table[idx].pre_upcall_valid {
        return Err(DomainError::NoSavedUpcall);
    }
    table[idx].pre_upcall_valid = false;
    let saved = table[idx].pre_upcall_ctx;
    // SAFETY: ctx valido.
    unsafe { *ctx = saved };
    Ok(())
}
