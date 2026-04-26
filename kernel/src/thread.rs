//! Thread Control Blocks + cooperative `yield_to`.
//!
//! "Thread" aqui = unidade de execucao no kernel (Thread Control Block).
//! Nao confundir com TCB = Trusted Computing Base.
//!
//! # Filosofia (Engler95 §3, *protection vs management*)
//!
//! Este modulo expoe **mecanismo puro**: criar uma thread (`spawn`),
//! trocar contexto (`yield_to`). **Nao** ha run queue, prioridade,
//! fairness, fila de prontos, scheduler — tudo isso vive na LibOS.
//! O kernel sabe somente:
//!   - quais threads existem (tabela estatica `THREADS`);
//!   - qual esta rodando agora (`CURRENT`).
//!
//! Politica de "qual roda em seguida" e responsabilidade do chamador
//! de `yield_to`: hoje, codigo do proprio kernel; na fase 7+, LibOS.
//!
//! # Concorrencia
//!
//! Single-core sem preempcao. Acessos a `THREADS`/`CURRENT` sao
//! sequenciais por construcao. Quando entrar SMP/preempcao, trocar
//! por mutex/atomics com Acquire/Release adequados.
//!
//! # unsafe
//!
//! Concentrado em `spawn` (escrita de RIP no topo de stack bruta) e
//! `yield_to` (chamada a `switch_context` naked). Ambos com SAFETY
//! detalhado. O resto do modulo e logica safe sobre `THREADS`.

#[cfg(target_os = "none")]
use core::cell::UnsafeCell;
#[cfg(target_os = "none")]
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "none")]
use crate::arch::x86_64::context::switch_context;
#[cfg(target_os = "none")]
use crate::mm::{self, frame, Perm};

/// Numero maximo de threads simultaneas. Dimensionado em compile-time
/// (sem heap, conforme regra exokernel). Aumentar conforme necessidade
/// das fases seguintes.
pub const MAX_THREADS: usize = 8;

/// Paginas por stack de thread (4 paginas = 16 KiB). Mais 1 pagina de
/// guarda nao-mapeada por baixo da stack (overflow vira #PF).
pub const STACK_PAGES: u64 = 4;

/// Base de VA usada para stacks de thread. Cada thread reserva
/// `(STACK_PAGES + 1) * 4 KiB` consecutivos a partir do bump.
/// Layout (PML4=511, PDPT=511, PD=128+):
///   `0xFFFF_FFFF_D000_0000` ..
#[cfg(target_os = "none")]
const STACK_VA_BASE: u64 = 0xFFFF_FFFF_D000_0000;

/// Bump atomico de VA. Cada `spawn` avanca em `(STACK_PAGES + 1) * FRAME_SIZE`.
#[cfg(target_os = "none")]
static STACK_VA_NEXT: AtomicU64 = AtomicU64::new(STACK_VA_BASE);

/// Estado de uma slot da `THREADS`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ThreadState {
    Empty,
    Ready,
    Running,
}

/// Contexto salvo de uma thread. **CRITICO**: o layout precisa bater com
/// os offsets em `arch::x86_64::context::switch_context`. Mudar a ordem
/// dos campos sem atualizar o asm = stack corruption.
///
/// Apenas registradores nao-volateis SysV64 (rbx, rbp, r12-r15) + rsp.
/// Os volateis sao salvos pelo caller na sua propria stack via convencao
/// de chamada.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct ThreadContext {
    pub rsp: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

/// Slot de uma thread na tabela global.
#[derive(Copy, Clone)]
pub struct Thread {
    pub ctx: ThreadContext,
    pub state: ThreadState,
    /// Topo da stack alocada para esta thread (endereco virtual).
    pub stack_top: u64,
}

impl Thread {
    #[cfg(target_os = "none")]
    const fn empty() -> Self {
        Self {
            ctx: ThreadContext {
                rsp: 0,
                rbx: 0,
                rbp: 0,
                r12: 0,
                r13: 0,
                r14: 0,
                r15: 0,
            },
            state: ThreadState::Empty,
            stack_top: 0,
        }
    }
}

/// Handle opaco. So o `thread` distribui; nunca construir a partir de u8 cru.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ThreadHandle(u8);

impl ThreadHandle {
    pub fn index(self) -> usize {
        self.0 as usize
    }

    /// Valor cru do handle (indice na tabela). Util para serializar em
    /// `AtomicU8` ou em capabilities (`CapObject::Thread { handle }`).
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Reconstroi um handle a partir de seu valor cru.
    ///
    /// # Safety
    ///
    /// Caller deve garantir que `raw` foi devolvido por `spawn` e que a
    /// thread ainda nao foi destruida. `yield_to` valida o slot, entao
    /// uso indevido produz `BadHandle`, nao UB; mesmo assim, a API e
    /// `unsafe` para sinalizar o contrato.
    pub const unsafe fn from_raw(raw: u8) -> Self {
        Self(raw)
    }
}

/// Erros de criacao/troca de threads.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ThreadError {
    /// `THREADS` cheio.
    TableFull,
    /// `STACK_VA_NEXT` ou frame allocator esgotado.
    OutOfMemory,
    /// `map_kernel_page` falhou ao mapear stack.
    MappingFailed,
    /// Handle invalido (slot vazio ou fora do range).
    BadHandle,
}

// =====================================================================
// Estado global
// =====================================================================

/// Tabela de threads. UnsafeCell + acesso single-threaded mediado pelas
/// APIs deste modulo.
#[cfg(target_os = "none")]
struct ThreadTable(UnsafeCell<[Thread; MAX_THREADS]>);
// SAFETY: kernel single-core sem preempcao; acesso sequencial garantido
// por construcao. Substituir por mutex ao introduzir SMP.
#[cfg(target_os = "none")]
unsafe impl Sync for ThreadTable {}

#[cfg(target_os = "none")]
static THREADS: ThreadTable =
    ThreadTable(UnsafeCell::new([Thread::empty(); MAX_THREADS]));

/// Indice da thread em execucao. `u8::MAX` = nenhuma (so o "boot context"
/// nao registrado, que tambem pode aparecer como caller de `yield_to`).
#[cfg(target_os = "none")]
static CURRENT: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(u8::MAX);

/// Contexto do "boot thread" implicito (nao-registrado). Quando o codigo
/// do kmain chama `yield_to(t)` pela primeira vez, salvamos seu contexto
/// aqui para poder ser restaurado mais tarde. Single-core: uma instancia.
#[cfg(target_os = "none")]
struct BootCtx(UnsafeCell<ThreadContext>);
// SAFETY: idem THREADS — single-core, acesso sequencial via APIs deste modulo.
#[cfg(target_os = "none")]
unsafe impl Sync for BootCtx {}
#[cfg(target_os = "none")]
static BOOT_CTX: BootCtx = BootCtx(UnsafeCell::new(ThreadContext {
    rsp: 0, rbx: 0, rbp: 0, r12: 0, r13: 0, r14: 0, r15: 0,
}));

// =====================================================================
// API publica
// =====================================================================

/// Cria uma thread que executa `entry` em uma stack recem-mapeada.
///
/// `entry` precisa ser `extern "sysv64" fn() -> !`: nunca retorna (se
/// retornar, o `ret` final cai em RIP=0, levando a #PF — fail-safe).
///
/// # Safety
///
/// - Deve ser chamado APOS `mm::init_paging` (precisa de `map_kernel_page`
///   ativo).
/// - Single-thread: nao chamar concorrentemente em outra CPU/IRQ.
#[cfg(target_os = "none")]
pub unsafe fn spawn(entry: extern "sysv64" fn() -> !) -> Result<ThreadHandle, ThreadError> {
    // 1. Encontra slot livre.
    let slot = unsafe { find_empty_slot() }.ok_or(ThreadError::TableFull)?;

    // 2. Reserva VA para `STACK_PAGES` + 1 guard (nao mapeada).
    let total_pages = STACK_PAGES + 1;
    let stack_base_va = STACK_VA_NEXT.fetch_add(
        total_pages * frame::FRAME_SIZE,
        Ordering::Relaxed,
    );

    // 3. Mapeia STACK_PAGES paginas RW+NX (a guard fica fora, nao mapeada).
    //    Layout: [guard | stack0 | stack1 | ... | stackN-1]
    //    stack cresce para baixo a partir de stack_top = base + total*4K.
    for i in 0..STACK_PAGES {
        let va = stack_base_va + (i + 1) * frame::FRAME_SIZE; // pula a guard
        let f = mm::alloc_frame().ok_or(ThreadError::OutOfMemory)?;
        // SAFETY: pos-init_paging; va e phys alinhados; va inedito (bump).
        unsafe {
            mm::map_kernel_page(va, f.addr(), Perm::Rw)
                .map_err(|_| ThreadError::MappingFailed)?;
        }
    }

    let stack_top = stack_base_va + total_pages * frame::FRAME_SIZE;

    // 4. Pre-empilha `entry` no topo (RIP que `ret` vai consumir).
    //    SAFETY: stack_top - 8 cai dentro da ultima pagina mapeada RW+NX
    //    desta thread, que acabamos de criar exclusivamente.
    let entry_addr = entry as u64;
    unsafe {
        let sp = (stack_top - 8) as *mut u64;
        sp.write(entry_addr);
    }

    // 5. Inicializa Thread no slot.
    // SAFETY: slot pertence a nos (find_empty_slot retornou Empty); nao ha
    // outro acessor concorrente (single-core, sem preempcao).
    unsafe {
        let table = &mut *THREADS.0.get();
        table[slot] = Thread {
            ctx: ThreadContext {
                rsp: stack_top - 8,
                ..ThreadContext::default()
            },
            state: ThreadState::Ready,
            stack_top,
        };
    }
    Ok(ThreadHandle(slot as u8))
}

/// Cooperativo: salva o contexto do chamador, restaura o de `to`. So
/// retorna quando outra thread fizer `yield_to(<handle desta thread>)`.
///
/// # Safety
///
/// - `to` deve ter sido devolvido por `spawn` e nao ter sido destruido.
/// - Pos-`init_paging` (precisa de stacks mapeadas).
/// - Single-core.
#[cfg(target_os = "none")]
pub unsafe fn yield_to(to: ThreadHandle) -> Result<(), ThreadError> {
    let to_idx = to.0 as usize;
    if to_idx >= MAX_THREADS {
        return Err(ThreadError::BadHandle);
    }
    // SAFETY: leitura validada por bound; tabela single-thread.
    let (to_state, to_ctx_ptr) = unsafe {
        let table = &mut *THREADS.0.get();
        let t = &mut table[to_idx];
        if t.state == ThreadState::Empty {
            return Err(ThreadError::BadHandle);
        }
        let ptr = &mut t.ctx as *mut ThreadContext as *mut u64;
        (t.state, ptr)
    };
    // Identifica o contexto "from": ou uma thread registrada, ou o boot.
    let from_ctx_ptr: *mut u64 = match current() {
        Some(h) => {
            // SAFETY: h.0 < MAX_THREADS porque vem de spawn.
            unsafe {
                let table = &mut *THREADS.0.get();
                &mut table[h.index()].ctx as *mut ThreadContext as *mut u64
            }
        }
        None => BOOT_CTX.0.get() as *mut u64,
    };

    // Atualiza estados ANTES da troca: o novo CURRENT precisa estar
    // visivel quando a thread de destino observar `current()`.
    if let Some(prev) = current() {
        // SAFETY: idem.
        unsafe {
            let table = &mut *THREADS.0.get();
            if table[prev.index()].state == ThreadState::Running {
                table[prev.index()].state = ThreadState::Ready;
            }
        }
    }
    // SAFETY: idem.
    unsafe {
        let table = &mut *THREADS.0.get();
        table[to_idx].state = ThreadState::Running;
    }
    let _ = to_state; // diagnostico futuro
    CURRENT.store(to.0, Ordering::Relaxed);

    // Troca de contexto. Quando voltarmos aqui, e porque alguem
    // re-cedeu para `from_ctx_ptr` — CURRENT ja foi atualizado por ele.
    // SAFETY: ambos os ponteiros vivem em memoria estatica (THREADS) ou
    // BOOT_CTX, ambos validos pelo lifetime do kernel.
    unsafe {
        switch_context(from_ctx_ptr, to_ctx_ptr as *const u64);
    }
    Ok(())
}

/// Devolve o handle da thread em execucao, ou `None` se ainda estamos
/// no boot context (nenhum `yield_to` chamado ainda).
#[cfg(target_os = "none")]
pub fn current() -> Option<ThreadHandle> {
    let v = CURRENT.load(Ordering::Relaxed);
    if v == u8::MAX { None } else { Some(ThreadHandle(v)) }
}

// =====================================================================
// Internos
// =====================================================================

/// Procura primeira slot Empty na tabela.
///
/// # Safety
///
/// Leitura nao-sincronizada de THREADS; valida apenas em single-core.
#[cfg(target_os = "none")]
unsafe fn find_empty_slot() -> Option<usize> {
    // SAFETY: single-core; sem outros acessadores enquanto find roda.
    let table = unsafe { &*THREADS.0.get() };
    table.iter().position(|t| t.state == ThreadState::Empty)
}

// =====================================================================
// Testes de host (logica pura, sem asm/hardware)
// =====================================================================

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use super::*;

    #[test]
    fn thread_context_layout_bate_com_asm() {
        // Offsets devem casar com arch::x86_64::context::switch_context.
        use core::mem::offset_of;
        assert_eq!(offset_of!(ThreadContext, rsp), 0x00);
        assert_eq!(offset_of!(ThreadContext, rbx), 0x08);
        assert_eq!(offset_of!(ThreadContext, rbp), 0x10);
        assert_eq!(offset_of!(ThreadContext, r12), 0x18);
        assert_eq!(offset_of!(ThreadContext, r13), 0x20);
        assert_eq!(offset_of!(ThreadContext, r14), 0x28);
        assert_eq!(offset_of!(ThreadContext, r15), 0x30);
        assert_eq!(core::mem::size_of::<ThreadContext>(), 0x38);
    }

    #[test]
    fn handle_index_round_trip() {
        let h = ThreadHandle(3);
        assert_eq!(h.index(), 3);
    }
}
