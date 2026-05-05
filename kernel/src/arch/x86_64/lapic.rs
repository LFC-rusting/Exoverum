//! Local APIC (xAPIC mode): primitivas de baixo nivel.
//!
//! # Escopo
//!
//! Mecanismo puro de timer one-shot + EOI. Politica (quando disparar,
//! o que fazer no IRQ) fica em `crate::timer` e nos handlers que ele
//! invoca. Este modulo concentra todo o `unsafe` do hardware LAPIC.
//!
//! # Registros usados (xAPIC offsets)
//!
//! | Offset | Nome                       | Papel                   |
//! |--------|----------------------------|-------------------------|
//! | 0x020  | Local APIC ID              | leitura inicial         |
//! | 0x080  | Task Priority Register     | zerado em `init`        |
//! | 0x0B0  | End Of Interrupt           | escrita=0 finaliza IRQ  |
//! | 0x0F0  | Spurious Interrupt Vector  | enable bit + vec=0xFF   |
//! | 0x320  | LVT Timer                  | vector + mode one-shot  |
//! | 0x380  | Initial Count              | ticks ate disparar      |
//! | 0x390  | Current Count              | decrementa; 0 = fired   |
//! | 0x3E0  | Divide Configuration       | divide by 16 (0x3)      |
//!
//! Intel SDM Vol.3 10.4 (xAPIC) / 10.5.4 (timer).
//!
//! # Safety
//!
//! `#[forbid(unsafe_code)]` nao pode ser aplicado (escrita MMIO exige
//! ponteiro bruto). `unsafe` minimo, isolado, cada bloco com `SAFETY:`.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::arch::x86_64::cpu::{rdmsr, wrmsr};

/// MSR IA32_APIC_BASE. Bit 11 = xAPIC global enable. Bits [51:12] = base fisica.
const MSR_APIC_BASE: u32 = 0x1B;
const APIC_BASE_ENABLE: u64 = 1 << 11;
const APIC_BASE_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// Offsets xAPIC (em bytes a partir da base MMIO, 16-byte aligned).
const REG_ID: usize = 0x020;
const REG_TPR: usize = 0x080;
const REG_EOI: usize = 0x0B0;
const REG_SVR: usize = 0x0F0;
const REG_LVT_TIMER: usize = 0x320;
const REG_INITIAL_COUNT: usize = 0x380;
const REG_DIVIDE_CONFIG: usize = 0x3E0;

/// Enable bit em SVR. Vector ocupa bits [7:0]; usamos 0xFF como
/// spurious (padrao). Bit 8 = APIC software enable.
const SVR_ENABLE: u32 = 1 << 8;
const SVR_SPURIOUS_VECTOR: u32 = 0xFF;

/// LVT Timer: bits [7:0]=vector, bit 16=mask, bits [18:17]=mode
/// (00=one-shot, 01=periodic, 10=tsc-deadline).
const LVT_MASKED: u32 = 1 << 16;

/// Divide Configuration Register: 0b1011 = divide by 1 (pass-through).
/// 0b0011 = divide by 16. Usamos 16 para reduzir frequencia e ter
/// range maior antes de overflow de u32 em ticks.
const DIVIDE_BY_16: u32 = 0b0011;

/// VA kernel reservada para mapear a pagina MMIO do LAPIC. Escolhida
/// fora do physmap (PML4[256]..PML4[257]) e fora do kernel higher-half
/// (PDPT=510). PML4=511, PDPT=508. Nao colide com framebuffer (PDPT=504).
const LAPIC_VA: u64 = 0xFFFF_FFFF_D000_0000;

/// Vetor de IRQ para timer oneshot. Acima da faixa de exceptions
/// (0..31) e do PIC legado (32..47). Escolhido 0x40.
pub const TIMER_VECTOR: u8 = 0x40;

/// Ponteiro para base MMIO do LAPIC, setado em `init`. `AtomicPtr`
/// porque future-SMP: cada core le o mesmo global (LAPIC e per-core,
/// mas MMIO aliases de cada core pra sua propria instancia — Intel SDM).
static LAPIC_BASE: AtomicPtr<u32> = AtomicPtr::new(core::ptr::null_mut());

/// Le registro 32-bit do LAPIC via MMIO. Retorna 0 se nao inicializado.
fn read_reg(off: usize) -> u32 {
    let base = LAPIC_BASE.load(Ordering::Relaxed);
    if base.is_null() {
        return 0;
    }
    // SAFETY: `base` foi mapeado como Mmio (UC+NX+RW) em `init`; off esta
    // no intervalo valido de registros xAPIC (< 4 KiB); leitura volatile
    // de 32 bits alinhada (offsets sao multiplos de 16).
    unsafe { read_volatile(base.cast::<u8>().add(off).cast::<u32>()) }
}

/// Escreve registro 32-bit do LAPIC via MMIO. No-op se nao inicializado.
fn write_reg(off: usize, val: u32) {
    let base = LAPIC_BASE.load(Ordering::Relaxed);
    if base.is_null() {
        return;
    }
    // SAFETY: idem `read_reg`; escrita volatile.
    unsafe {
        write_volatile(base.cast::<u8>().add(off).cast::<u32>(), val);
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LapicError {
    /// MSR reporta LAPIC desabilitado (bit 11 do IA32_APIC_BASE).
    Disabled,
    /// `mm::map_kernel_page` falhou mapeando a pagina MMIO.
    MapFailed,
}

/// Inicializa o LAPIC: mapeia MMIO, habilita via SVR, mascara o timer.
/// Idempotente: reexecucao remapeia e reenables (seguro em ring 0).
///
/// # Safety
///
/// - Deve ser chamada apos `mm::init_paging` (precisa de physmap).
/// - Invocada uma unica vez por boot/per-core.
pub unsafe fn init() -> Result<(), LapicError> {
    // Le MSR e verifica enable global.
    let base_msr = rdmsr(MSR_APIC_BASE);
    if base_msr & APIC_BASE_ENABLE == 0 {
        // Enable global (bit 11) caso firmware tenha deixado off.
        wrmsr(MSR_APIC_BASE, base_msr | APIC_BASE_ENABLE);
    }
    let phys = (base_msr & APIC_BASE_MASK) | 0; // 4KiB-aligned por construcao do MSR.

    // Mapeia 1 pagina MMIO em VA kernel fixa.
    // SAFETY: pos-init_paging por contrato da funcao. LAPIC_VA 4KiB-aligned;
    // phys idem (MSR garante). Mmio = UC+NX+RW (forbidden em user).
    unsafe {
        crate::mm::map_kernel_page(LAPIC_VA, phys, crate::mm::Perm::Mmio)
            .map_err(|_| LapicError::MapFailed)?;
    }
    LAPIC_BASE.store(LAPIC_VA as *mut u32, Ordering::Release);

    // TPR = 0: aceita qualquer vetor >= 0x10.
    write_reg(REG_TPR, 0);

    // LVT Timer mascarado inicialmente (so desmascara quando armado).
    write_reg(REG_LVT_TIMER, LVT_MASKED);

    // Divide by 16 (reduz frequencia do clock do timer).
    write_reg(REG_DIVIDE_CONFIG, DIVIDE_BY_16);

    // Spurious Vector: enable + vector=0xFF. Tem que vir DEPOIS de TPR/LVT
    // para nao gerar interrupcao durante o init.
    write_reg(REG_SVR, SVR_ENABLE | SVR_SPURIOUS_VECTOR);

    Ok(())
}

/// Arma o timer em modo one-shot com `ticks` unidades (pos-divide).
/// Desmascara LVT e usa `TIMER_VECTOR`. Escrever 0 em Initial Count
/// efetivamente cancela.
pub fn arm_oneshot(ticks: u32) {
    // LVT Timer: vector=TIMER_VECTOR, mode=one-shot (bits 17-18 = 00),
    // nao mascarado.
    write_reg(REG_LVT_TIMER, TIMER_VECTOR as u32);
    // Programa o contador; decrementa automaticamente.
    write_reg(REG_INITIAL_COUNT, ticks);
}

/// Cancela o timer armado. Idempotente.
pub fn disarm() {
    write_reg(REG_INITIAL_COUNT, 0);
    write_reg(REG_LVT_TIMER, LVT_MASKED);
}

/// Sinaliza End-Of-Interrupt ao LAPIC. Chamado no final do handler
/// de qualquer IRQ entregue pelo LAPIC (timer, IPI, etc).
pub fn eoi() {
    write_reg(REG_EOI, 0);
}

/// Retorna o APIC ID do core atual (para diagnostico).
#[allow(dead_code)]
pub fn local_id() -> u32 {
    read_reg(REG_ID) >> 24
}
