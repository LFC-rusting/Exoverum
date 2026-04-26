//! Context switch entre threads do kernel.
//!
//! Salva os registradores **nao-volateis** SysV64 (rbx, rbp, r12-r15) +
//! rsp em `from`, restaura os mesmos de `to`, e executa `ret`. O `ret`
//! pega o RIP da nova stack:
//!   - threads novas: spawn pre-empilhou `entry` no topo;
//!   - threads que ja rodaram: o RIP foi pushed pelo `call` que originou
//!     o yield_to anterior.
//!
//! Voláteis (rax, rcx, rdx, rsi, rdi, r8-r11) sao caller-saved pelo
//! ABI sysv64; quem chamou `switch_context` ja salvou se precisava.
//!
//! # Layout obrigatorio de `ThreadContext` (bate com offsets abaixo)
//!
//! ```text
//! offset  campo
//!   0x00  rsp
//!   0x08  rbx
//!   0x10  rbp
//!   0x18  r12
//!   0x20  r13
//!   0x28  r14
//!   0x30  r15
//! ```
//!
//! Mudar a struct sem atualizar este asm = corrupcao silenciosa de stack.

use core::arch::naked_asm;

/// Salva o contexto atual em `from` e restaura `to`. Apos retornar, a
/// stack ativa e a de `to` e a execucao continua no RIP que estava no
/// topo dela.
///
/// # Safety
///
/// - `from` e `to` devem apontar para `ThreadContext` validos e mutaveis
///   (kernel-only, single-core).
/// - `to` deve ter um RSP que aponta para uma stack mapeada RW+NX no
///   PML4 ativo, com um RIP valido no topo.
/// - Apos a chamada, o caller "perde" sua continuacao para o thread `to`;
///   so volta a executar quando alguem chamar `switch_context(_, &caller_ctx)`.
#[unsafe(naked)]
pub unsafe extern "sysv64" fn switch_context(from: *mut u64, to: *const u64) {
    naked_asm!(
        // Salva nao-volateis em [rdi + offsets].
        "mov [rdi + 0x00], rsp",
        "mov [rdi + 0x08], rbx",
        "mov [rdi + 0x10], rbp",
        "mov [rdi + 0x18], r12",
        "mov [rdi + 0x20], r13",
        "mov [rdi + 0x28], r14",
        "mov [rdi + 0x30], r15",
        // Restaura nao-volateis de [rsi + offsets].
        "mov rsp, [rsi + 0x00]",
        "mov rbx, [rsi + 0x08]",
        "mov rbp, [rsi + 0x10]",
        "mov r12, [rsi + 0x18]",
        "mov r13, [rsi + 0x20]",
        "mov r14, [rsi + 0x28]",
        "mov r15, [rsi + 0x30]",
        // ret pega o RIP do topo da nova stack.
        "ret",
    );
}
