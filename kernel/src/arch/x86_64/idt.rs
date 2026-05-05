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

/// Dispatcher comum de exception. Recebe ctx canonico (`UserContext`) —
/// para vetores com error code, o trampolim ja descartou o errcode com
/// `add rsp, 8`. Decide por CPL:
///   - **CPL=0**: kernel faltou; loga e halta (security > liveness).
///   - **CPL=3**: dominio user faltou; chama `domain::abort_current`
///     que marca aborted e zera CURRENT, depois halta.
#[no_mangle]
extern "sysv64" fn fault_dispatch(ctx: *mut super::userland::UserContext) -> ! {
    // SAFETY: ctx aponta para UserContext valido na stack do handler.
    let ctx_ref = unsafe { &*ctx };
    let cpl = ctx_ref.cs & 3;
    if cpl == 3 {
        crate::kobj::domain::abort_current();
        super::serial::write_str("[kernel] ring-3 fault; halting\n");
    } else {
        super::serial::write_str("[kernel] EXCEPTION ring-0 - halt\n");
    }
    super::cpu::halt_forever();
}

/// Trampolim para vetores SEM error code. Salva 15 GPRs e chama
/// `fault_dispatch` com `*UserContext`.
#[unsafe(naked)]
unsafe extern "sysv64" fn fault_no_err_entry() {
    core::arch::naked_asm!(
        "push r15", "push r14", "push r13", "push r12",
        "push r11", "push r10", "push r9",  "push r8",
        "push rbp", "push rdi", "push rsi", "push rdx",
        "push rcx", "push rbx", "push rax",
        "mov rdi, rsp",
        "call {dispatch}",
        "ud2",
        dispatch = sym fault_dispatch,
    );
}

/// Dispatcher Rust do IRQ de timer LAPIC. Apenas delega ao modulo
/// `timer`, que sinaliza a notification armada, e manda EOI ao LAPIC.
/// Nao modifica o `UserContext` do interrompido: ring 3 retoma com
/// estado identico, e so descobre o evento via `poll_notify`.
#[no_mangle]
extern "sysv64" fn timer_irq_dispatch() {
    crate::kobj::timer::fire();
    super::lapic::eoi();
}

/// Trampolim para IRQ de timer (vetor 0x40). Salva volatiles + call +
/// restaura + iretq. Nao usa UserContext (IRQ nao precisa modificar
/// registros user). Alinhamento SysV: CPU empilha 5 u64 (40B); ate o
/// call, empilhamos pares de push para manter RSP%16==0 pre-call.
#[unsafe(naked)]
unsafe extern "sysv64" fn timer_irq_entry() {
    core::arch::naked_asm!(
        // Salva volatiles (caller-saved do SysV que podemos mexer):
        // rax, rcx, rdx, rsi, rdi, r8-r11. 9 regs = 72 bytes. Com 40B
        // do iret frame = 112 bytes (nao %16). Adiciono 8 de padding.
        "push rax", "push rcx", "push rdx", "push rsi",
        "push rdi", "push r8",  "push r9",  "push r10",
        "push r11",
        "sub rsp, 8",
        "call {dispatch}",
        "add rsp, 8",
        "pop r11", "pop r10", "pop r9",  "pop r8",
        "pop rdi", "pop rsi", "pop rdx", "pop rcx",
        "pop rax",
        "iretq",
        dispatch = sym timer_irq_dispatch,
    );
}

/// Trampolim para vetores COM error code (#DF, #TS, #NP, #SS, #GP,
/// #PF, #AC, #CP). Descarta o errcode com `add rsp, 8` antes de
/// salvar GPRs — assim o ctx fica canonico.
#[unsafe(naked)]
unsafe extern "sysv64" fn fault_with_err_entry() {
    core::arch::naked_asm!(
        "add rsp, 8",
        "push r15", "push r14", "push r13", "push r12",
        "push r11", "push r10", "push r9",  "push r8",
        "push rbp", "push rdi", "push rsi", "push rdx",
        "push rcx", "push rbx", "push rax",
        "mov rdi, rsp",
        "call {dispatch}",
        "ud2",
        dispatch = sym fault_dispatch,
    );
}

/// Inicializa IDT e carrega no core.
pub fn init() {
    // Cast via *const () para satisfazer lint `function_casts_as_integer`
    // (Rust 2024). Conversao bit-exata para endereco do handler.
    let h_no_err = fault_no_err_entry as *const () as usize as u64;
    let h_with_err = fault_with_err_entry as *const () as usize as u64;

    // type_attr = 0x8E: P=1, DPL=0, Type=0xE (64-bit interrupt gate).
    const INTERRUPT_GATE: u8 = 0x8E;

    // Vetores que empilham error code (Intel SDM Vol.3 6.13).
    const HAS_ERR_CODE: &[usize] = &[8, 10, 11, 12, 13, 14, 17, 21];

    // SAFETY: init roda antes de qualquer interrupcao; unica escrita na
    // IDT. Acesso via ponteiro bruto evita criar referencia mutavel a
    // static (lint static_mut_refs).
    unsafe {
        let idt = core::ptr::addr_of_mut!(IDT) as *mut IdtEntry;
        let mut i = 0usize;
        while i < IDT_LEN {
            (*idt.add(i)).set(h_no_err, KERNEL_CS, 0, INTERRUPT_GATE);
            i += 1;
        }
        // Vetores com error code usam o trampolim que descarta errcode.
        for &v in HAS_ERR_CODE {
            (*idt.add(v)).set(h_with_err, KERNEL_CS, 0, INTERRUPT_GATE);
        }
        // Double fault (#DF) usa IST1 para garantir stack valida mesmo se
        // a stack do kernel estiver corrompida (recomendacao Intel SDM).
        (*idt.add(8)).set(h_with_err, KERNEL_CS, 1, INTERRUPT_GATE);

        // Vetor 0x80 = porta de syscall vinda de ring 3.
        // type_attr 0xEE: P=1, DPL=3 (acessivel a user), Type=0xE (int gate).
        const USER_INTERRUPT_GATE: u8 = 0xEE;
        let syscall = super::userland::syscall_handler_addr();
        (*idt.add(0x80)).set(syscall, KERNEL_CS, 0, USER_INTERRUPT_GATE);

        // Vetor 0x40 = LAPIC timer. DPL=0 (hardware IRQ). Substitui o
        // handler generico `h_no_err` que so halta: timer precisa
        // sinalizar notification + EOI + retornar.
        let timer_h = timer_irq_entry as *const () as usize as u64;
        (*idt.add(super::lapic::TIMER_VECTOR as usize))
            .set(timer_h, KERNEL_CS, 0, INTERRUPT_GATE);
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
