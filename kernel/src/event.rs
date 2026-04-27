//! Eventos: sinais assincronos single-bit idempotentes.
//!
//! Fase 6a da arquitetura. **Mecanismo puro, zero politica.**
//!
//! # Modelo
//!
//! Um `Event` e uma celula de 1 bit com estado `Clear` ou `Signaled`
//! (fora "Empty" = slot livre). Duas operacoes:
//!
//!   - `signal(evt)`     : bit <- 1. Idempotente (N signals = 1 signal).
//!                         Se ha waiter parkeado, consome o bit e acorda-o.
//!   - `wait(evt, to)`   : se bit = 1, clear e retorna. Senao parkeia a
//!                         thread atual, muda para `ThreadState::Waiting`
//!                         e cede a CPU para `to` via `thread::yield_to`.
//!                         Retorna quando signal consumir o bit.
//!
//! # Single-waiter
//!
//! No maximo uma thread parkeada por evento. Se uma segunda thread chama
//! `wait` sobre o mesmo evento, recebe `EventError::AlreadyWaited`.
//! Multi-waiter viria com SMP; hoje e unnecessary complexity (regra
//! essenciais §5: "Isso e muito? Nao faca.").
//!
//! # Por que `wait` recebe `fallback`
//!
//! O kernel **nao** escolhe quem roda apos parkear uma thread. A
//! selecao de proxima thread e politica de scheduling, que vive em
//! userland (filosofia exokernel Engler95 §3). `wait` apenas cumpre
//! o mecanismo: troca contexto para o `ThreadHandle` indicado pelo
//! caller, que pode ser qualquer thread `Ready` conhecida por ele.
//!
//! # Host-testavel
//!
//! A logica de estado (`tick_signal`, `tick_wait`) e pura e esta em
//! um submodulo `fsm` testado no host, sem tocar em tabela global
//! nem em thread.

#[cfg(target_os = "none")]
use core::cell::UnsafeCell;

#[cfg(target_os = "none")]
use crate::thread::{self, ThreadHandle, ThreadState};

/// Teto estatico. Dimensiona `.bss` sem heap. Aumentar conforme demanda
/// das fases seguintes (LibOS costuma criar eventos em lote).
pub const MAX_EVENTS: usize = 16;

/// Estado de um slot de evento.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum EventState {
    /// Slot livre.
    Empty,
    /// Alocado, sem sinal pendente.
    Clear,
    /// Alocado, sinal pendente (sticky ate o proximo `wait`).
    Signaled,
}

/// Celula de evento. Quando ha waiter parkeado, `waiter = Some(h)` e
/// `state` e obrigatoriamente `Clear` (signal consumido na troca
/// Signaled->Clear feita por `tick_signal`).
#[derive(Copy, Clone, Debug)]
pub struct Event {
    pub state: EventState,
    pub waiter: Option<u8>, // indice de thread, u8::MAX = nenhum (codificado via Option)
}

impl Event {
    pub const fn empty() -> Self {
        Self { state: EventState::Empty, waiter: None }
    }
}

/// Handle opaco distribuido por `create`. Nao construir a partir de u8
/// cru fora do `from_raw` (marcado `unsafe`).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct EventHandle(u8);

impl EventHandle {
    pub fn index(self) -> usize {
        self.0 as usize
    }

    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Reconstroi um handle a partir de seu valor cru.
    ///
    /// # Safety
    ///
    /// Caller deve garantir que `raw` foi devolvido por `create`
    /// anteriormente e que o slot nao foi destruido. Uso indevido e
    /// detectado (`signal`/`wait` validam estado), portanto produz
    /// `BadHandle` e nao UB; mesmo assim, a API e `unsafe` para
    /// sinalizar o contrato.
    pub const unsafe fn from_raw(raw: u8) -> Self {
        Self(raw)
    }
}

/// Erros do subsistema de eventos.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum EventError {
    /// Tabela `EVENTS` cheia.
    TableFull,
    /// Handle fora do range ou apontando para slot `Empty`.
    BadHandle,
    /// Outra thread ja esta em `wait` neste evento.
    AlreadyWaited,
    /// `wait` chamado fora de um contexto de thread registrada (ex:
    /// boot context). Fail-stop seguro: melhor erro explicito do que
    /// parkear uma thread fantasma.
    NoCurrentThread,
    /// `wait` recebeu `fallback` que coincide com a thread atual.
    /// Permitir isso daria deadlock silencioso (ceder para si mesma
    /// sem sinal pendente).
    FallbackIsSelf,
}

// =====================================================================
// FSM pura (host-testavel)
// =====================================================================

pub mod fsm {
    //! Maquina de estados pura do evento. Isolada do acesso a tabela
    //! global e de `thread::*` para que os invariantes de transicao
    //! sejam testados no host sem mocks.
    //!
    //! Retorno de `tick_signal`: `Some(tid)` quer dizer "acordar a
    //! thread `tid`"; `None` quer dizer "sinal ficou sticky, nao ha
    //! ninguem para acordar".
    //!
    //! Retorno de `tick_wait`: `Consumed` = retorne imediato; `Park` =
    //! marque a thread atual como waiter e ceda CPU.

    use super::{Event, EventError, EventState};

    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub enum WaitOutcome {
        /// Signal estava pendente; consumimos e retornamos sem parkear.
        Consumed,
        /// Signal nao estava pendente; parkeamos a thread (caller).
        Park,
    }

    /// Avanca o estado apos `signal`. Retorna `Some(tid)` da thread a
    /// ser acordada, se houver.
    pub fn tick_signal(ev: &mut Event) -> Result<Option<u8>, EventError> {
        match ev.state {
            EventState::Empty => Err(EventError::BadHandle),
            EventState::Signaled | EventState::Clear => {
                if let Some(tid) = ev.waiter.take() {
                    // Waiter presente: consome o bit direto e acorda.
                    ev.state = EventState::Clear;
                    Ok(Some(tid))
                } else {
                    // Sem waiter: fica sticky ate proximo wait.
                    ev.state = EventState::Signaled;
                    Ok(None)
                }
            }
        }
    }

    /// Decide o desfecho de `wait` (sem parkear; o caller faz isso).
    /// Em caso de `Park`, escreve `me` em `ev.waiter`.
    pub fn tick_wait(ev: &mut Event, me: u8) -> Result<WaitOutcome, EventError> {
        match ev.state {
            EventState::Empty => Err(EventError::BadHandle),
            EventState::Signaled => {
                ev.state = EventState::Clear;
                Ok(WaitOutcome::Consumed)
            }
            EventState::Clear => {
                if ev.waiter.is_some() {
                    return Err(EventError::AlreadyWaited);
                }
                ev.waiter = Some(me);
                Ok(WaitOutcome::Park)
            }
        }
    }
}

// =====================================================================
// Tabela global + API bare-metal
// =====================================================================

/// Wrapper `Sync` em torno da tabela; mesmo padrao de `thread::THREADS`.
/// Kernel single-core sem preempcao -> acesso sequencial por construcao.
#[cfg(target_os = "none")]
struct EventTable(UnsafeCell<[Event; MAX_EVENTS]>);

// SAFETY: kernel single-core sem preempcao; acessos sao sequenciais pelas
// APIs publicas deste modulo. Substituir por mutex ao introduzir SMP.
#[cfg(target_os = "none")]
unsafe impl Sync for EventTable {}

#[cfg(target_os = "none")]
static EVENTS: EventTable = EventTable(UnsafeCell::new([Event::empty(); MAX_EVENTS]));

/// Aloca um evento em estado `Clear`.
///
/// # Safety
///
/// Acessa tabela global via `UnsafeCell`. Seguro sob kernel single-core
/// sem preempcao (invariante global; ver comentario do topo do modulo).
#[cfg(target_os = "none")]
pub unsafe fn create() -> Result<EventHandle, EventError> {
    // SAFETY: invariante single-core; nenhum outro acessor vivo.
    let slot = unsafe { find_empty_slot() }.ok_or(EventError::TableFull)?;
    // SAFETY: idem; acabamos de localizar slot empty.
    unsafe {
        let table = &mut *EVENTS.0.get();
        table[slot] = Event { state: EventState::Clear, waiter: None };
    }
    Ok(EventHandle(slot as u8))
}

/// Sinaliza o evento. Idempotente. Se ha waiter parkeado, acorda-o
/// (muda seu estado para `Ready`) e consome o bit.
///
/// # Safety
///
/// Idem `create` + requer que `thread::set_state` possa ser chamado
/// (pos-init de `thread`).
#[cfg(target_os = "none")]
pub unsafe fn signal(h: EventHandle) -> Result<(), EventError> {
    let idx = h.index();
    if idx >= MAX_EVENTS {
        return Err(EventError::BadHandle);
    }
    // SAFETY: single-core; tabela acessada so aqui.
    let awaken = unsafe {
        let table = &mut *EVENTS.0.get();
        fsm::tick_signal(&mut table[idx])?
    };
    if let Some(tid) = awaken {
        // SAFETY: `tid` foi previamente escrito por `tick_wait` e
        // corresponde a uma thread que estava `Waiting` neste evento.
        unsafe {
            thread::set_state_by_raw(tid, ThreadState::Ready);
        }
    }
    Ok(())
}

/// Espera o evento. Se ja signaled, consome e retorna. Senao parkeia
/// a thread atual e cede CPU para `fallback` via `thread::yield_to`.
///
/// # Safety
///
/// - Idem `create`.
/// - `fallback` deve ter sido devolvido por `thread::spawn` e estar em
///   estado `Ready` (validado por `yield_to`).
/// - Chamado do contexto de uma thread registrada (nao do boot context);
///   senao retorna `NoCurrentThread` sem parkear (fail-safe).
#[cfg(target_os = "none")]
pub unsafe fn wait(h: EventHandle, fallback: ThreadHandle) -> Result<(), EventError> {
    let idx = h.index();
    if idx >= MAX_EVENTS {
        return Err(EventError::BadHandle);
    }
    let me = thread::current().ok_or(EventError::NoCurrentThread)?;
    if me == fallback {
        return Err(EventError::FallbackIsSelf);
    }
    // SAFETY: single-core; tabela acessada so aqui.
    let outcome = unsafe {
        let table = &mut *EVENTS.0.get();
        fsm::tick_wait(&mut table[idx], me.raw())?
    };
    match outcome {
        fsm::WaitOutcome::Consumed => Ok(()),
        fsm::WaitOutcome::Park => {
            // Marca thread atual como Waiting ANTES de ceder: signal
            // vindo de outra thread no meio da cessao vai achar o
            // estado consistente.
            // SAFETY: `me` foi devolvido por `thread::current()`,
            // logo aponta para slot valido.
            unsafe {
                thread::set_state_by_raw(me.raw(), ThreadState::Waiting);
            }
            // SAFETY: `fallback` validado pelo caller.
            match unsafe { thread::yield_to(fallback) } {
                Ok(()) => Ok(()),
                Err(_) => {
                    // `yield_to` falhou (handle ruim). Desfaz park para
                    // nao deixar thread presa; devolve erro via BadHandle.
                    // SAFETY: mesma invariante.
                    unsafe {
                        thread::set_state_by_raw(me.raw(), ThreadState::Ready);
                        let table = &mut *EVENTS.0.get();
                        table[idx].waiter = None;
                    }
                    Err(EventError::BadHandle)
                }
            }
        }
    }
}

/// Leitura diagnostica do estado de um evento. Nao consome nada.
/// Util em demos e testes-smoke.
#[cfg(target_os = "none")]
pub fn state(h: EventHandle) -> EventState {
    let idx = h.index();
    if idx >= MAX_EVENTS {
        return EventState::Empty;
    }
    // SAFETY: leitura imutavel; single-core.
    let table = unsafe { &*EVENTS.0.get() };
    table[idx].state
}

#[cfg(target_os = "none")]
unsafe fn find_empty_slot() -> Option<usize> {
    // SAFETY: single-core; sem outros acessadores enquanto find roda.
    let table = unsafe { &*EVENTS.0.get() };
    table.iter().position(|e| matches!(e.state, EventState::Empty))
}

// =====================================================================
// Testes de host (FSM pura)
// =====================================================================

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use super::fsm::{tick_signal, tick_wait, WaitOutcome};
    use super::*;

    fn clear() -> Event {
        Event { state: EventState::Clear, waiter: None }
    }

    #[test]
    fn signal_primeiro_fica_sticky() {
        let mut e = clear();
        assert_eq!(tick_signal(&mut e).unwrap(), None);
        assert_eq!(e.state, EventState::Signaled);
    }

    #[test]
    fn signal_idempotente() {
        let mut e = clear();
        let _ = tick_signal(&mut e).unwrap();
        let _ = tick_signal(&mut e).unwrap();
        let _ = tick_signal(&mut e).unwrap();
        // N signals = 1 signal; bit permanece setado uma unica vez.
        assert_eq!(e.state, EventState::Signaled);
        assert!(e.waiter.is_none());
    }

    #[test]
    fn wait_apos_signal_consome_imediato() {
        let mut e = clear();
        let _ = tick_signal(&mut e).unwrap();
        match tick_wait(&mut e, 7).unwrap() {
            WaitOutcome::Consumed => {}
            WaitOutcome::Park => panic!("deveria consumir sem parkear"),
        }
        assert_eq!(e.state, EventState::Clear);
        assert!(e.waiter.is_none());
    }

    #[test]
    fn wait_sem_signal_parkeia() {
        let mut e = clear();
        match tick_wait(&mut e, 7).unwrap() {
            WaitOutcome::Park => {}
            WaitOutcome::Consumed => panic!("deveria parkear"),
        }
        assert_eq!(e.state, EventState::Clear);
        assert_eq!(e.waiter, Some(7));
    }

    #[test]
    fn signal_com_waiter_acorda_e_limpa() {
        let mut e = clear();
        let _ = tick_wait(&mut e, 7).unwrap();
        assert_eq!(e.waiter, Some(7));
        let tid = tick_signal(&mut e).unwrap();
        assert_eq!(tid, Some(7));
        assert_eq!(e.state, EventState::Clear);
        assert!(e.waiter.is_none(), "bit consumido pelo despertar");
    }

    #[test]
    fn segunda_wait_no_mesmo_evento_falha() {
        let mut e = clear();
        let _ = tick_wait(&mut e, 7).unwrap();
        let err = tick_wait(&mut e, 3).unwrap_err();
        assert_eq!(err, EventError::AlreadyWaited);
    }

    #[test]
    fn signal_em_slot_empty_falha() {
        let mut e = Event::empty();
        assert_eq!(tick_signal(&mut e), Err(EventError::BadHandle));
    }

    #[test]
    fn wait_em_slot_empty_falha() {
        let mut e = Event::empty();
        assert_eq!(tick_wait(&mut e, 0).unwrap_err(), EventError::BadHandle);
    }

    #[test]
    fn handle_round_trip() {
        // from_raw reconstroi o mesmo handle; propriedade esperada por
        // `CapObject::Event { handle }` em fases seguintes.
        let h = EventHandle(5);
        let raw = h.raw();
        let recomposed = unsafe { EventHandle::from_raw(raw) };
        assert_eq!(h, recomposed);
        assert_eq!(h.index(), 5);
    }
}
