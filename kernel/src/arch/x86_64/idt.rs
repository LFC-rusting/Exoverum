//! IDT minima da Fase 1.
//!
//! Objetivo: qualquer excecao do CPU causa um log pela serial e halt. Ainda
//! nao diferencio vetor nem leio error code do stack; isso chega nas fases
//! seguintes junto com o fluxo real de interrupcoes (LAPIC timer, syscall).
//!
//! Os 256 vetores apontam para o mesmo handler `exception_entry`. O vetor 8
//! (#DF) usa IST=1, pulando para a stack dedicada em `gdt::DF_STACK` mesmo
//! que a stack corrente esteja corrompida.

use core::arch::asm;
use core::mem::size_of;

use super::gdt::KERNEL_CS;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_lo: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_hi: u32,
    reserved: u32,
}

impl IdtEntry {
    const fn zero() -> Self {
        IdtEntry {
            offset_lo: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_hi: 0,
            reserved: 0,
        }
    }

    fn set(&mut self, handler: u64, selector: u16, ist: u8, type_attr: u8) {
        self.offset_lo = handler as u16;
        self.selector = selector;
        self.ist = ist & 0x7;
        self.type_attr = type_attr;
        self.offset_mid = (handler >> 16) as u16;
        self.offset_hi = (handler >> 32) as u32;
        self.reserved = 0;
    }
}

const IDT_LEN: usize = 256;
static mut IDT: [IdtEntry; IDT_LEN] = [IdtEntry::zero(); IDT_LEN];

#[repr(C, packed)]
struct IdtPtr {
    limit: u16,
    base: u64,
}

/// Handler unico de excecao desta fase. Nao retorna: loga e halta.
///
/// `extern "C"` aceitavel porque a funcao e `-> !` (nao retornara, nao
/// precisa de prologo/epilogo compativel com IRET). Nao confio no estado
/// de registradores nem no alinhamento de RSP; por isso evito chamadas que
/// exijam SSE — ja desabilitado via rustflags (`-sse,+soft-float`).
#[no_mangle]
extern "C" fn exception_entry() -> ! {
    crate::log::write_str("[kernel] EXCEPTION - halt\n");
    super::cpu::halt_forever();
}

/// Inicializa IDT e carrega no core.
pub fn init() {
    // Cast via *const () para satisfazer lint `function_casts_as_integer`
    // (Rust 2024). Conversao bit-exata para endereco do handler.
    let handler = exception_entry as *const () as usize as u64;

    // type_attr = 0x8E: P=1, DPL=0, Type=0xE (64-bit interrupt gate).
    const INTERRUPT_GATE: u8 = 0x8E;

    // SAFETY: init roda antes de qualquer interrupcao; unica escrita na
    // IDT. Acesso via ponteiro bruto evita criar referencia mutavel a
    // static (lint static_mut_refs).
    unsafe {
        let idt = core::ptr::addr_of_mut!(IDT) as *mut IdtEntry;
        let mut i = 0usize;
        while i < IDT_LEN {
            (*idt.add(i)).set(handler, KERNEL_CS, 0, INTERRUPT_GATE);
            i += 1;
        }
        // Double fault (#DF) usa IST1 para garantir stack valida mesmo se
        // a stack do kernel estiver corrompida (recomendacao Intel SDM).
        (*idt.add(8)).set(handler, KERNEL_CS, 1, INTERRUPT_GATE);
    }

    let base = core::ptr::addr_of!(IDT) as u64;
    let ptr = IdtPtr {
        limit: (size_of::<[IdtEntry; IDT_LEN]>() - 1) as u16,
        base,
    };

    // SAFETY: `lidt` carrega IDTR com base/limit validos; instrucao
    // privilegiada mas segura em ring0. Apos esta instrucao, excecoes
    // passam pelo handler acima.
    unsafe {
        asm!(
            "lidt [{0}]",
            in(reg) &ptr,
            options(nostack, preserves_flags),
        );
    }
}
