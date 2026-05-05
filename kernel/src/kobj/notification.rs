//! Notification objects (minimalist seL4-style async signalling primitive).
//!
//! # Modelo
//!
//! Um `Notification` e um objeto kernel com um `u64` signalword atomico.
//! Duas operacoes, ambas nao-bloqueantes (exokernel puro):
//!
//!   - `signal(h, bits)` -> `signalword |= bits` (`fetch_or`).
//!   - `poll(h)` -> le e zera `signalword` (`swap(0)`).
//!
//! *Mechanism only, not policy* (Engler-1995 §3.1): o kernel entrega
//! o bit, LibOS decide politica (poll vs IPC wrapper vs spin etc.). Sem
//! scheduler, sem bloqueio em kernel: se o LibOS quer esperar, ela
//! mesma implementa o loop de poll.
//!
//! # Cross-domain
//!
//! `signal` e `poll` sao validados por capability: dominio so invoca
//! se tem `CapObject::Notification { handle }` em sua CSpace com
//! direito WRITE (signal) ou READ (poll). Pode-se entregar cap
//! atenuada (so READ) via `cap_grant` a outro dominio — consumer pode
//! ler mas nao signalizar.
//!
//! # Bit allocation
//!
//! O `u64` e dividido pelo LibOS: cada bit = um evento. Kernel nao
//! atribui semantica a bits. `bits=0` em signal e no-op.
//!
//! # TCB
//!
//! Modulo e `#![forbid(unsafe_code)]`. Toda concorrencia via
//! `AtomicU64`/`AtomicBool`; zero UB possivel. Host-testavel sem
//! dependencias bare-metal.

#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Capacidade da pool. Pequena intencional (cada slot = 16 bytes).
/// LibOS que queira mais multiplexa bits em menos objetos.
pub const MAX_NOTIFICATIONS: usize = 16;

/// Handle opaco para um Notification object.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct NotifyHandle(u8);

impl NotifyHandle {
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Reconstroi a partir do valor cru. Validado em uso via pool.
    pub const fn from_raw(raw: u8) -> Self {
        Self(raw)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NotifyError {
    /// Pool cheia.
    TableFull,
    /// Handle fora do range ou slot livre.
    BadHandle,
}

struct Slot {
    in_use: AtomicBool,
    signalword: AtomicU64,
}

static SLOTS: [Slot; MAX_NOTIFICATIONS] = [const {
    Slot {
        in_use: AtomicBool::new(false),
        signalword: AtomicU64::new(0),
    }
}; MAX_NOTIFICATIONS];

/// Aloca um Notification object. CAS no `in_use` garante atomicidade
/// mesmo que algum dia rodemos SMP. Signalword zerado no ato.
pub fn create() -> Result<NotifyHandle, NotifyError> {
    for i in 0..MAX_NOTIFICATIONS {
        if SLOTS[i]
            .in_use
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            SLOTS[i].signalword.store(0, Ordering::Release);
            return Ok(NotifyHandle(i as u8));
        }
    }
    Err(NotifyError::TableFull)
}

/// Libera o slot. `signal` e `poll` subsequentes retornam `BadHandle`.
/// Signalword zerado para reutilizacao limpa.
pub fn destroy(h: NotifyHandle) -> Result<(), NotifyError> {
    let idx = h.0 as usize;
    if idx >= MAX_NOTIFICATIONS || !SLOTS[idx].in_use.load(Ordering::Acquire) {
        return Err(NotifyError::BadHandle);
    }
    SLOTS[idx].signalword.store(0, Ordering::Release);
    SLOTS[idx].in_use.store(false, Ordering::Release);
    Ok(())
}

/// OR `bits` no signalword. `bits=0` e no-op explicito. Nao bloqueia.
/// Idempotente: sinalizar o mesmo bit duas vezes resulta no mesmo estado.
pub fn signal(h: NotifyHandle, bits: u64) -> Result<(), NotifyError> {
    let idx = h.0 as usize;
    if idx >= MAX_NOTIFICATIONS || !SLOTS[idx].in_use.load(Ordering::Acquire) {
        return Err(NotifyError::BadHandle);
    }
    SLOTS[idx].signalword.fetch_or(bits, Ordering::Release);
    Ok(())
}

/// Le e zera o signalword atomicamente. Retorna os bits que estavam
/// setados no momento do swap (reset-on-read, padrao seL4 Notification).
pub fn poll(h: NotifyHandle) -> Result<u64, NotifyError> {
    let idx = h.0 as usize;
    if idx >= MAX_NOTIFICATIONS || !SLOTS[idx].in_use.load(Ordering::Acquire) {
        return Err(NotifyError::BadHandle);
    }
    Ok(SLOTS[idx].signalword.swap(0, Ordering::AcqRel))
}

// =====================================================================
// Testes host
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Testes compartilham a pool estatica. Fazemos cleanup via `destroy`
    // no final de cada teste para nao vazar slots entre execucoes.
    // `cargo test` roda testes em paralelo, entao adquirimos slots
    // disjuntos: create() retorna handles distintos sob CAS.

    #[test]
    fn create_returns_distinct_handles() {
        let a = create().unwrap();
        let b = create().unwrap();
        assert_ne!(a, b);
        destroy(a).unwrap();
        destroy(b).unwrap();
    }

    #[test]
    fn signal_ors_bits_into_signalword() {
        let h = create().unwrap();
        signal(h, 0b0101).unwrap();
        signal(h, 0b1010).unwrap();
        let v = poll(h).unwrap();
        assert_eq!(v, 0b1111);
        destroy(h).unwrap();
    }

    #[test]
    fn poll_resets_signalword() {
        let h = create().unwrap();
        signal(h, 0xDEAD).unwrap();
        assert_eq!(poll(h).unwrap(), 0xDEAD);
        assert_eq!(poll(h).unwrap(), 0, "second poll sees cleared word");
        destroy(h).unwrap();
    }

    #[test]
    fn signal_zero_is_noop() {
        let h = create().unwrap();
        signal(h, 0x42).unwrap();
        signal(h, 0).unwrap();
        assert_eq!(poll(h).unwrap(), 0x42);
        destroy(h).unwrap();
    }

    #[test]
    fn bad_handle_rejected() {
        let fake = NotifyHandle::from_raw(255);
        assert_eq!(signal(fake, 1), Err(NotifyError::BadHandle));
        assert_eq!(poll(fake), Err(NotifyError::BadHandle));
    }

    #[test]
    fn destroy_releases_slot() {
        let h = create().unwrap();
        destroy(h).unwrap();
        // Depois de destroy, o handle antigo ja nao e valido.
        assert_eq!(signal(h, 1), Err(NotifyError::BadHandle));
        assert_eq!(poll(h), Err(NotifyError::BadHandle));
    }

    #[test]
    fn double_destroy_fails_second_time() {
        let h = create().unwrap();
        destroy(h).unwrap();
        assert_eq!(destroy(h), Err(NotifyError::BadHandle));
    }
}
