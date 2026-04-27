//! Phase 7a.2 + 7a.3: entrada e saida de ring 3.
//!
//! Trafego: kernel -> ring 3 via `enter_ring3` (iretq sintetico);
//! ring 3 -> kernel via `INT 0x80` (gate DPL=3). SYSCALL/SYSRET fica
//! como otimizacao futura: e fast-path, nao primitiva exokernel.
//!
//! # Mecanismo, nao politica
//!
//! O numero de syscall vai em RAX e o `dispatch` do exokernel e
//! propositalmente *minimo*. Para o smoke test de 7a.3 expomos:
//!   - 0 = `nop_test`: prova bidirecional ring3 <-> ring0.
//!   - 1 = `exit`: ring 3 desiste, kernel halta o demo.
//! Qualquer LibOS futura vai colocar suas proprias syscalls aqui ou,
//! preferivelmente, via PCT/upcalls (Phase 7b) substituindo este vetor.
//!
//! # Stack para syscalls vindas de ring 3
//!
//! Quando a CPU recebe uma INT vinda de DPL=3, ela carrega
//! SS:RSP = TSS.SS0:RSP0 *antes* de empilhar o frame da excecao.
//! Sem RSP0 setado isso e #DF imediato. Por isso reservamos
//! `SYSCALL_STACK` dedicada (16 KiB).
//!
//! # Payload de teste
//!
//! Position-independent, definido em `global_asm!`. O kernel copia os
//! bytes para um frame mapeado UserRx no dominio (Phase 7a.6 garante a
//! auditoria via capability).

#![cfg(target_os = "none")]

use core::arch::global_asm;

use crate::arch::x86_64::cpu;
use crate::arch::x86_64::gdt::{USER_CS, USER_DS};
use crate::log;

// Payload smoke test de ring 3. Nao referencia simbolos externos
// (position-independent): encodings de `mov rax, imm32` + `int 0x80`
// + `ud2`. Encerra em `ud2` para fail-fast caso o kernel ignore exit.
global_asm!(
    r#"
    .section .rodata.userland_payload, "a"
    .globl __userland_payload_start
    .globl __userland_payload_end
    .balign 16
__userland_payload_start:
    mov rax, 0
    int 0x80
    mov rax, 1
    int 0x80
    ud2
__userland_payload_end:
    "#
);

extern "C" {
    static __userland_payload_start: u8;
    static __userland_payload_end: u8;
}

/// Bytes do payload smoke test (`.rodata.userland_payload`). Copiar
/// para um frame mapeado em ring 3 com `Perm::UserRx`.
pub fn payload_bytes() -> &'static [u8] {
    let start = core::ptr::addr_of!(__userland_payload_start);
    let end = core::ptr::addr_of!(__userland_payload_end);
    // SAFETY: simbolos de linker; intervalo bem-formado e em higher-half
    // do kernel (mapeado RX no boot). Bytes constantes.
    unsafe {
        let len = (end as usize) - (start as usize);
        core::slice::from_raw_parts(start, len)
    }
}

// Stack kernel dedicada a INTs vindas de ring 3 (CPU usa TSS.RSP0).
const SYSCALL_STACK_SIZE: usize = 16 * 1024;
static mut SYSCALL_STACK: [u8; SYSCALL_STACK_SIZE] = [0; SYSCALL_STACK_SIZE];

/// Topo da `SYSCALL_STACK` (RSP cresce para baixo). Setado em TSS.RSP0
/// via `userland::install`.
fn syscall_stack_top() -> u64 {
    let base = core::ptr::addr_of!(SYSCALL_STACK) as u64;
    base + SYSCALL_STACK_SIZE as u64
}

/// Dispatcher Rust chamado pelo trampolim `syscall_entry` (naked).
/// `num` vem do RAX do user; retorno tambem em RAX (no caller convenciona).
extern "sysv64" fn syscall_dispatch(num: u64) -> u64 {
    match num {
        0 => {
            log::write_str("[kernel] ring 3 -> kernel via INT 0x80 (nop_test)\n");
            0
        }
        1 => {
            log::write_str("[kernel] ring 3 exit; halting\n");
            cpu::halt_forever();
        }
        _ => {
            log::write_str("[kernel] syscall desconhecida; halt\n");
            cpu::halt_forever();
        }
    }
}

/// Trampolim INT 0x80. CPU ja empilhou SS/RSP/RFLAGS/CS/RIP do user
/// e trocou para RSP0. Salvo volateis SysV, chamo dispatcher, restauro,
/// `iretq` retorna a ring 3 (caso syscall 0). Para syscall 1 (exit)
/// o dispatcher nao retorna (`halt_forever`), o `iretq` final nunca
/// e atingido nesse caminho.
///
/// # Safety
///
/// Instalado em IDT[0x80] com gate DPL=3. CPU invoca apenas via
/// `INT 0x80`. Naked: prologo/epilogo manuais.
#[unsafe(naked)]
unsafe extern "sysv64" fn syscall_entry() {
    core::arch::naked_asm!(
        // ABI: num em RAX. Salvar volateis sysV antes de chamar Rust.
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "mov rdi, rax",
        "call {dispatch}",
        // resultado em RAX (preservado pelo callee SysV; volateis nao
        // sao salvos pelo callee, ja restauramos abaixo).
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "iretq",
        dispatch = sym syscall_dispatch,
    );
}

/// Endereco do trampolim `syscall_entry`, consumido por `idt::init`
/// para registrar a entrada com DPL=3.
pub fn syscall_handler_addr() -> u64 {
    syscall_entry as *const () as usize as u64
}

/// Configura o estado da CPU para aceitar INT 0x80 vindo de ring 3:
///   - TSS.RSP0 = topo de `SYSCALL_STACK`;
///   - IDT[0x80] e instalado por `idt::init` com DPL=3 (ja feito).
///
/// Idempotente. Deve ser chamado antes do primeiro `enter_ring3`.
pub fn install() {
    crate::arch::x86_64::gdt::set_rsp0(syscall_stack_top());
}

/// Salta para `entry_rip` em ring 3 com stack `user_rsp`. Nao retorna:
/// o caminho de volta e via INT 0x80 (que retorna ao instruction
/// seguinte ao `int` no user).
///
/// IF=0 ao entrar em ring 3 (RFLAGS = bit 1 reservado = 0x002): este
/// demo e single-thread e nao quer ser interrompido por LAPIC.
/// Phase 7b setara IF=1 quando upcalls de timer estiverem prontos.
///
/// # Safety
///
/// - CR3 atualmente carregado deve cobrir `entry_rip` (UserRx) e
///   `user_rsp - 0x1000` (UserRw) em lower-half.
/// - GDT carregada com USER_CS/USER_DS validos (ja feito por `gdt::init`).
/// - TSS.RSP0 setado (`install`).
/// - Funcao divergente: a unica forma de "voltar" e via syscall vindo
///   de ring 3.
#[unsafe(naked)]
pub unsafe extern "sysv64" fn enter_ring3(entry_rip: u64, user_rsp: u64) -> ! {
    core::arch::naked_asm!(
        // Zerar segmentos data para nao vazar selectors do kernel.
        // ds/es/fs/gs nao sao usados em long mode para enderecamento,
        // mas e higiene.
        "xor rax, rax",
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "mov gs, ax",
        // Empilhar frame de iretq (ordem: SS, RSP, RFLAGS, CS, RIP).
        "push {user_ds}",
        "push rsi",       // user_rsp
        "push 0x002",     // RFLAGS: IF=0, bit1=1 reservado
        "push {user_cs}",
        "push rdi",       // entry_rip
        "iretq",
        user_ds = const USER_DS as u64,
        user_cs = const USER_CS as u64,
    );
}
