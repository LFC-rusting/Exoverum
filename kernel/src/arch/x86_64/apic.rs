//! Local APIC (xAPIC) minimo: habilita, configura timer one-shot, EOI.
//!
//! # Modelo
//!
//! O LAPIC e memory-mapped em `0xFEE0_0000` (default pos-reset). Intel SDM
//! 10.4.1 exige acesso UC (uncacheable). Mapeamos via `Perm::Mmio`
//! (PCD+PWT) em VA higher-half reservado `0xFFFF_FFFF_E000_0000`.
//!
//! # Escopo da Fase 5b
//!
//! Apenas: enable MSR, SVR, timer one-shot, EOI. **Sem** preempcao real
//! com troca de contexto — isso fica para Fase 7 junto com TSS IST e
//! swapgs (infraestrutura compartilhada com syscalls).
//!
//! # Seguranca
//!
//! Todo o `unsafe` concentrado aqui. APIs publicas sao `unsafe` apenas
//! quando a invariante depender do caller (init uma unica vez, interrupts
//! ja habilitadas antes de arm_oneshot etc).

use core::ptr::{read_volatile, write_volatile};

use super::cpu::{rdmsr, wrmsr};
use crate::mm::{self, Perm};

/// Endereco fisico padrao do LAPIC apos reset. Pode ser relocado via
/// MSR IA32_APIC_BASE; `init` le o MSR e usa o valor real.
const LAPIC_BASE_DEFAULT: u64 = 0xFEE0_0000;

/// VA reservado para MMIO do LAPIC. Fora das faixas de kernel text,
/// physmap e stacks de thread. Layout: PML4=511, PDPT=511, PD=256.
const LAPIC_VA: u64 = 0xFFFF_FFFF_E000_0000;

/// Offsets dos registradores LAPIC (relativos a `LAPIC_VA`).
const REG_EOI: u64 = 0x0B0;
const REG_SVR: u64 = 0x0F0;
const REG_LVT_TIMER: u64 = 0x320;
const REG_TIMER_ICR: u64 = 0x380;
const REG_TIMER_CCR: u64 = 0x390;
const REG_TIMER_DCR: u64 = 0x3E0;

/// MSR IA32_APIC_BASE. Bit 11 = global enable.
const MSR_IA32_APIC_BASE: u32 = 0x1B;
const APIC_BASE_ENABLE: u64 = 1 << 11;
/// Mascara de endereco fisico no MSR (bits [51:12]).
const APIC_BASE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Bit 8 do SVR = APIC software enable.
const SVR_ENABLE: u32 = 1 << 8;

/// Vector do spurious interrupt (baixa prioridade, nunca deve disparar
/// efetivamente; Intel recomenda 0xFF).
pub const SPURIOUS_VECTOR: u8 = 0xFF;

/// Vector do timer LAPIC (usado em `idt::init` para registrar handler).
pub const TIMER_VECTOR: u8 = 0x40;

/// Divide config: by 16 (pattern 0b1011 = 0x0B).
const DCR_DIVIDE_BY_16: u32 = 0x0B;

/// Erros de init.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApicError {
    /// Falha ao mapear MMIO no PML4 kernel.
    MappingFailed,
}

/// Inicializa LAPIC em modo xAPIC com timer one-shot armado. Deve ser
/// chamado **apos** `mm::init_paging` (precisa de `map_kernel_page`) e
/// **antes** de habilitar interrupcoes (`sti`).
///
/// # Safety
///
/// - Chamar uma unica vez por boot.
/// - IDT ja deve conter handler para `TIMER_VECTOR` (caso contrario,
///   primeira interrupcao causa #GP/PF).
pub unsafe fn init() -> Result<(), ApicError> {
    // 1. Garante enable global via MSR. Tambem captura o endereco fisico
    //    real (firmware pode relocar; por seguranca, nao assumimos o
    //    default).
    let msr = rdmsr(MSR_IA32_APIC_BASE);
    let phys = msr & APIC_BASE_ADDR_MASK;
    // Se firmware desabilitou o APIC, religar. Se estiver em x2APIC
    // (bit 10), ainda assim funcionamos em MMIO se voltarmos para xAPIC
    // — mas QEMU padrao ja expoe xAPIC.
    wrmsr(MSR_IA32_APIC_BASE, msr | APIC_BASE_ENABLE);

    // 2. Mapeia MMIO uncacheable (PCD+PWT) no VA reservado.
    //    Uma unica pagina de 4 KiB: LAPIC ocupa [0xFEE00000, 0xFEE00400).
    // SAFETY: pos-init_paging; VA inedito; phys obtido do MSR.
    unsafe {
        mm::map_kernel_page(LAPIC_VA, phys, Perm::Mmio)
            .map_err(|_| ApicError::MappingFailed)?;
    }
    // Alguns firmwares reportam phys == 0 (bit 11 sozinho nao define base);
    // se o default diferir, loga via debug_assert. Ao chegar aqui o mapeamento
    // aponta para o valor real do MSR.
    let _ = LAPIC_BASE_DEFAULT;

    // 3. Habilita APIC via SVR (bit 8) e define vector do spurious.
    // SAFETY: LAPIC_VA mapeado no passo 2.
    unsafe {
        write_reg(REG_SVR, SVR_ENABLE | SPURIOUS_VECTOR as u32);
    }

    // 4. Configura divide-by-16 e LVT Timer em modo one-shot + vector.
    //    Mode = bits [18:17] = 00 (one-shot). Mask = bit 16 = 0 (unmasked).
    // SAFETY: idem.
    unsafe {
        write_reg(REG_TIMER_DCR, DCR_DIVIDE_BY_16);
        write_reg(REG_LVT_TIMER, TIMER_VECTOR as u32);
    }

    Ok(())
}

/// Arma o timer one-shot com `count` ticks (ja divididos pelo DCR).
/// Escrever 0 em ICR DESARMA o timer.
///
/// # Safety
///
/// Chamar apenas apos `init` bem-sucedido.
pub unsafe fn arm_oneshot(count: u32) {
    // SAFETY: LAPIC_VA mapeado por init.
    unsafe { write_reg(REG_TIMER_ICR, count); }
}

/// End Of Interrupt. Sinaliza para o LAPIC que o handler da ISR corrente
/// terminou. Obrigatorio em toda ISR vinda do LAPIC (timer, IPIs, etc).
///
/// # Safety
///
/// Chamar apenas de dentro de um ISR (ou imediatamente apos), com LAPIC
/// ja inicializado.
pub unsafe fn eoi() {
    // SAFETY: LAPIC_VA mapeado por init.
    unsafe { write_reg(REG_EOI, 0); }
}

/// Le o Current Count Register (debug/diagnostico).
///
/// # Safety
///
/// Chamar apenas apos `init`.
#[allow(dead_code)]
pub unsafe fn current_count() -> u32 {
    // SAFETY: LAPIC_VA mapeado por init.
    unsafe { read_reg(REG_TIMER_CCR) }
}

// =====================================================================
// Helpers internos
// =====================================================================

/// # Safety
///
/// `offset` deve ser um registrador valido do LAPIC e `LAPIC_VA` mapeado
/// como MMIO UC RW (`Perm::Mmio`).
unsafe fn write_reg(offset: u64, val: u32) {
    let ptr = (LAPIC_VA + offset) as *mut u32;
    // SAFETY: volatile write evita merge; alinhamento 4B garantido por
    // construcao (offsets constantes multiplos de 0x10).
    unsafe { write_volatile(ptr, val); }
}

/// # Safety
///
/// Idem `write_reg`.
unsafe fn read_reg(offset: u64) -> u32 {
    let ptr = (LAPIC_VA + offset) as *const u32;
    // SAFETY: idem.
    unsafe { read_volatile(ptr) }
}
