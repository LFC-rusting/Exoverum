//! Objetos de kernel (capabilities + dominio + primitivas de evento).
//!
//! Agrupa os tipos cujo papel e *dados de kernel expostos via capability*:
//!
//!   - `cap`          — tabela flat de capabilities + CDT + global revoke.
//!   - `domain`       — dominios ring-3 com CSpace/CR3 proprios, PCT,
//!     cap_grant. Bare-metal-only (precisa de mm + arch).
//!   - `notification` — objetos de sinalizacao assincrona (seL4-style).
//!   - `timer`        — callback do LAPIC timer como capability (Phase 5b).
//!
//! `cap`, `notification` e `timer` sao target-agnostic (host-testaveis).
//!
//! Modulo roteador. `forbid(unsafe_code)` nao pode ser aplicado aqui porque
//! `forbid` propaga para submodulos (regra do compilador) e `domain`
//! precisa de `unsafe` legitimo (asm + UnsafeCell single-core). Cada
//! submodulo declara seu proprio policy.

pub mod cap;
pub mod notification;
pub mod timer;

#[cfg(target_os = "none")]
pub mod domain;
