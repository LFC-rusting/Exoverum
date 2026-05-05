//! Timer kernel: reintroduz Phase 5b como *capability*, nao politica.
//!
//! # Decisao arquitetural
//!
//! Phase 5b original configurava LAPIC + IRQ + stub handler como
//! mecanismo kernel. Foi removido em Phase 7b por ser politica ("quando
//! preemptar?"). Retornamos agora como mecanismo **exposto via
//! capability**:
//!
//!   - Dominio com cap `CapObject::Timer` (direito WRITE) pode armar
//!     one-shot via syscall.
//!   - Ao armar, dominio fornece uma `CapObject::Notification` e uma
//!     mascara de bits: quando o LAPIC dispara, kernel sinaliza aquele
//!     bit naquela notification. LibOS descobre na proxima `poll_notify`.
//!   - Zero politica de scheduling no kernel. Se LibOS quer preempcao
//!     entre dominios, ela mesma implementa via `domain_call` em
//!     resposta ao bit setado.
//!
//! Isso entrega o **mecanismo** exigido por Engler-1995 §3.3 (expose
//! events) sem trazer politica.
//!
//! # Estado armado
//!
//! Um unico callback global: single-core, LAPIC e per-core, e so um
//! oneshot pendente por vez. Se LibOS quer multiplos timers, multiplexa
//! em user-space.
//!
//! # Safety
//!
//! Modulo target-agnostico para ter host-tests da logica de callback.
//! MMIO real fica em `arch::x86_64::lapic`. `#![forbid(unsafe_code)]`
//! possivel porque toda concorrencia e atomica.

#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use super::notification::{self, NotifyHandle};

/// Estado do callback armado. `armed = true` indica que o IRQ do LAPIC
/// deve sinalizar `notify_handle` com `bits`.
static ARMED: AtomicBool = AtomicBool::new(false);
static NOTIFY_HANDLE: AtomicU8 = AtomicU8::new(0);
static NOTIFY_BITS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TimerError {
    /// Ticks invalidos (0 = disarm, tratar como Ok).
    BadTicks,
    /// NotifyHandle fora de range.
    BadNotify,
}

/// Arma timer one-shot. Quando o IRQ chegar, kernel sinaliza
/// `(notify, bits)`. `ticks=0` cancela arming existente.
///
/// Retorna ok mesmo se outro arm anterior estava pendente; o novo
/// sobrescreve (single LAPIC timer, single callback).
pub fn arm(notify: NotifyHandle, bits: u64, ticks: u32) -> Result<(), TimerError> {
    if ticks == 0 {
        disarm();
        return Ok(());
    }
    NOTIFY_HANDLE.store(notify.raw(), Ordering::Relaxed);
    NOTIFY_BITS.store(bits, Ordering::Relaxed);
    ARMED.store(true, Ordering::Release);
    arm_hw(ticks);
    Ok(())
}

/// Cancela arming. Idempotente.
pub fn disarm() {
    ARMED.store(false, Ordering::Release);
    disarm_hw();
}

/// Chamado pelo IRQ handler quando o LAPIC timer dispara. Sinaliza a
/// notification armada (se houver), desmarca e envia EOI.
///
/// `fire()` e safe e target-agnostico; EOI e feito em
/// `fire_with_eoi()` que vive no modulo arch.
pub fn fire() {
    if !ARMED.swap(false, Ordering::AcqRel) {
        return;
    }
    let handle = NotifyHandle::from_raw(NOTIFY_HANDLE.load(Ordering::Relaxed));
    let bits = NOTIFY_BITS.load(Ordering::Relaxed);
    let _ = notification::signal(handle, bits);
}

// -------------------------------------------------------------------
// Hook arch: host-test stub via feature, bare-metal delega ao LAPIC.
// -------------------------------------------------------------------

#[cfg(target_os = "none")]
fn arm_hw(ticks: u32) {
    crate::arch::x86_64::lapic::arm_oneshot(ticks);
}

#[cfg(target_os = "none")]
fn disarm_hw() {
    crate::arch::x86_64::lapic::disarm();
}

// Em host tests nao temos LAPIC; no-ops preservam a logica de fire()
// testavel manualmente via fire() direto.
#[cfg(not(target_os = "none"))]
fn arm_hw(_ticks: u32) {}

#[cfg(not(target_os = "none"))]
fn disarm_hw() {}

// =====================================================================
// Testes host
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm_with_zero_ticks_disarms() {
        let n = notification::create().unwrap();
        arm(n, 0b1, 0).unwrap();
        assert!(!ARMED.load(Ordering::Acquire));
        notification::destroy(n).unwrap();
    }

    #[test]
    fn fire_signals_armed_notification() {
        let n = notification::create().unwrap();
        arm(n, 0b1000, 100).unwrap();
        fire();
        let v = notification::poll(n).unwrap();
        assert_eq!(v, 0b1000);
        notification::destroy(n).unwrap();
    }

    #[test]
    fn fire_is_noop_when_not_armed() {
        disarm();
        let n = notification::create().unwrap();
        fire();
        assert_eq!(notification::poll(n).unwrap(), 0);
        notification::destroy(n).unwrap();
    }

    #[test]
    fn double_fire_signals_once() {
        let n = notification::create().unwrap();
        arm(n, 0b10, 100).unwrap();
        fire();
        fire(); // segundo fire nao acha armado, no-op
        let v = notification::poll(n).unwrap();
        assert_eq!(v, 0b10);
        notification::destroy(n).unwrap();
    }

    #[test]
    fn rearm_overwrites_callback() {
        let n1 = notification::create().unwrap();
        let n2 = notification::create().unwrap();
        arm(n1, 0b1, 100).unwrap();
        arm(n2, 0b10, 100).unwrap();
        fire();
        assert_eq!(notification::poll(n1).unwrap(), 0, "n1 nao sinalizado");
        assert_eq!(notification::poll(n2).unwrap(), 0b10, "n2 sinalizado");
        notification::destroy(n1).unwrap();
        notification::destroy(n2).unwrap();
    }
}
