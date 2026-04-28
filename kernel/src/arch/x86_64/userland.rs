//! Phase 7a + 7b: entrada/saida de ring 3, syscall dispatch, upcalls.
//!
//! # Trafego ring 3 <-> kernel
//!
//! - **Entrada inicial:** `enter_ring3` faz `iretq` sintetico (kernel
//!   nunca vai voltar; quem volta e o handler de INT 0x80 ou de timer).
//! - **Syscall:** `INT 0x80`, gate DPL=3, trampolim `syscall_entry`
//!   salva `UserContext` completo na stack RSP0 e chama
//!   `syscall_dispatch`. O dispatcher pode modificar o `UserContext`
//!   in-place (PCT troca de dominio), e o `iretq` final carrega o
//!   estado modificado.
//! - **Timer:** `timer_handler_entry` ja existia em `idt.rs` para o
//!   caminho ring 0. Phase 7b adiciona o caminho ring 3 — quando o
//!   timer interrompe ring 3, o handler entrega o controle ao
//!   `upcall_entry` do dominio ativo.
//!
//! # `UserContext` na stack RSP0
//!
//! Quando o trampolim termina seus pushes, `RSP` aponta para um bloco
//! contiguo de 160 bytes com a layout exata de `UserContext`. O kernel
//! pode ler/escrever esse bloco como `*mut UserContext`. Se ele
//! sobrescreve o bloco com o ctx de outro dominio (PCT), o `iretq`
//! seguinte carrega o novo ring 3.
//!
//! SYSCALL/SYSRET fica como otimizacao opcional; o INT path e mais
//! simples e ja exercita o caminho de excecao reusado pelos upcalls.

#![cfg(target_os = "none")]

use core::arch::global_asm;

use crate::arch::x86_64::cpu;
use crate::arch::x86_64::gdt::{USER_CS, USER_DS};
use crate::domain;
use crate::log;

// =================================================================
// UserContext
// =================================================================

/// Snapshot completo do estado ring 3 quando o kernel toma controle
/// (via INT 0x80 ou timer interrompendo ring 3).
///
/// Layout casa **exatamente** com a ordem em que `syscall_entry` /
/// `timer_handler_user_entry` pushed os registradores na stack RSP0.
/// Os 5 ultimos campos (`rip`..`ss`) sao escritos pela CPU automaticamente
/// no `iret frame` quando ela aceita a interrupcao DPL=3.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UserContext {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    // Iret frame escrito pelo CPU:
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl UserContext {
    /// Constroi um ctx fresh apontando para `rip` em ring 3 com
    /// `rsp` user. Usado por `domain::pct_call` ao "ativar" um
    /// dominio pela primeira vez.
    pub const fn fresh(rip: u64, rsp: u64) -> Self {
        Self {
            rax: 0, rbx: 0, rcx: 0, rdx: 0,
            rsi: 0, rdi: 0, rbp: 0,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip,
            cs: USER_CS as u64,
            // RFLAGS bit 1 reservado=1, IF=1 (bit 9): timer pode upcall.
            rflags: 0x202,
            rsp,
            ss: USER_DS as u64,
        }
    }
}

const _: () = assert!(core::mem::size_of::<UserContext>() == 20 * 8);

// =================================================================
// Payload smoke test (Phase 7a)
// =================================================================

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

/// Bytes do payload smoke test (`.rodata.userland_payload`).
pub fn payload_bytes() -> &'static [u8] {
    let start = core::ptr::addr_of!(__userland_payload_start);
    let end = core::ptr::addr_of!(__userland_payload_end);
    // SAFETY: simbolos de linker em higher-half kernel; intervalo
    // bem-formado, bytes constantes.
    unsafe {
        let len = (end as usize) - (start as usize);
        core::slice::from_raw_parts(start, len)
    }
}

// =================================================================
// Payload Phase 7b: dois clientes de PCT.
// =================================================================
//
// Layouts position-independent (sem .data, sem GOT). Cada um cabe em
// 32 bytes. A copia para frame fisico mapeado UserRx no dominio
// e identica ao smoke test 7a.
//
// payload_a:
//   mov rax, 2          ; syscall = domain_call
//   mov rdi, B_HANDLE   ; sobrescrito pelo kernel antes da copia
//   int 0x80
//   ; rax volta com o valor passado por B em domain_reply
//   mov rax, 1          ; exit
//   int 0x80
//   ud2
//
// payload_b:
//   mov rax, 3          ; syscall = domain_reply
//   mov rdi, 0x42       ; valor magico para A ver
//   int 0x80
//   ud2                 ; reply nao retorna (kernel troca contexto p/ A)
//
// O kernel **patcha** o `mov rdi, imm32` de payload_a com o handle de B
// no momento da copia para o frame. O offset do imm32 e `1 + 3` = 4
// (1 byte de prefixo REX `48`, 1 opcode, 1 ModRM/SIB? Na verdade
// `mov rdi, imm64` em x86-64 tem encoding `48 BF imm64`). Para usar
// imm32 sign-extended escrevo `48 C7 C7 imm32`. Vou usar imm32.
global_asm!(
    r#"
    .section .rodata.userland_payload_a, "a"
    .globl __userland_payload_a_start
    .globl __userland_payload_a_end
    .balign 16
__userland_payload_a_start:
    mov rax, 2
__userland_payload_a_target:
    mov edi, 0x7FFFFFFF
    int 0x80
    mov rax, 1
    int 0x80
    ud2
__userland_payload_a_end:

    .globl __userland_payload_a_target_offset
__userland_payload_a_target_offset:
    .quad __userland_payload_a_target - __userland_payload_a_start

    .section .rodata.userland_payload_b, "a"
    .globl __userland_payload_b_start
    .globl __userland_payload_b_end
    .balign 16
__userland_payload_b_start:
    mov rax, 3
    mov edi, 0x42
    int 0x80
    ud2
__userland_payload_b_end:

    // Phase 8: handler de upcall trivial. Faz syscall=4 (upcall_return),
    // que retorna ao ctx pre-upcall (entry normal do dominio).
    .section .rodata.userland_upcall_handler, "a"
    .globl __userland_upcall_handler_start
    .globl __userland_upcall_handler_end
    .balign 16
__userland_upcall_handler_start:
    mov rax, 4
    int 0x80
    ud2
__userland_upcall_handler_end:
    "#
);

extern "C" {
    static __userland_payload_a_start: u8;
    static __userland_payload_a_end: u8;
    static __userland_payload_a_target_offset: u64;
    static __userland_payload_b_start: u8;
    static __userland_payload_b_end: u8;
    static __userland_upcall_handler_start: u8;
    static __userland_upcall_handler_end: u8;
}

/// Bytes do payload do dominio A (cliente PCT). O caller deve
/// patchar `target_offset` com `0xC7 0x48 ...` movendo o `target_dh`
/// real. Em vez disso, simplificamos expondo
/// `payload_a_patch_target` que escreve o imm32 diretamente.
pub fn payload_a_bytes() -> &'static [u8] {
    let start = core::ptr::addr_of!(__userland_payload_a_start);
    let end = core::ptr::addr_of!(__userland_payload_a_end);
    // SAFETY: idem.
    unsafe {
        let len = (end as usize) - (start as usize);
        core::slice::from_raw_parts(start, len)
    }
}

/// Offset (em bytes a partir do inicio de `payload_a_bytes`) do imm32
/// na instrucao `mov edi, imm32`. Encoding: `BF imm32` (5 bytes total).
/// O byte +0 e o opcode `BF`, +1..+4 e o imm32 little-endian.
pub fn payload_a_target_imm_offset() -> usize {
    // SAFETY: `__userland_payload_a_target_offset` e linker symbol com
    // valor constante (offset em bytes do label). +1 pula opcode `BF`.
    let off_label =
        unsafe { core::ptr::addr_of!(__userland_payload_a_target_offset).read() } as usize;
    off_label + 1
}

/// Bytes do payload do dominio B (servidor PCT).
pub fn payload_b_bytes() -> &'static [u8] {
    let start = core::ptr::addr_of!(__userland_payload_b_start);
    let end = core::ptr::addr_of!(__userland_payload_b_end);
    // SAFETY: idem.
    unsafe {
        let len = (end as usize) - (start as usize);
        core::slice::from_raw_parts(start, len)
    }
}

/// (Phase 8) Bytes do handler de upcall trivial.
pub fn upcall_handler_bytes() -> &'static [u8] {
    let start = core::ptr::addr_of!(__userland_upcall_handler_start);
    let end = core::ptr::addr_of!(__userland_upcall_handler_end);
    // SAFETY: idem.
    unsafe {
        let len = (end as usize) - (start as usize);
        core::slice::from_raw_parts(start, len)
    }
}

// =================================================================
// Stack RSP0 dedicada para INT vinda de ring 3
// =================================================================

const SYSCALL_STACK_SIZE: usize = 16 * 1024;
static mut SYSCALL_STACK: [u8; SYSCALL_STACK_SIZE] = [0; SYSCALL_STACK_SIZE];

fn syscall_stack_top() -> u64 {
    let base = core::ptr::addr_of!(SYSCALL_STACK) as u64;
    base + SYSCALL_STACK_SIZE as u64
}

// =================================================================
// Syscall dispatch
// =================================================================

/// Dispatcher Rust. Recebe ponteiro para `UserContext` na stack RSP0.
/// Pode modificar o ctx in-place; o trampolim faz pop+iretq carregando
/// o estado (potencialmente novo) ring 3.
///
/// Syscalls:
///   - 0  `nop_test`       -> retorna 0
///   - 1  `exit`           -> halta (nao retorna)
///   - 2  `domain_call(t)` -> PCT sync; muda ctx para o dominio `t`
///   - 3  `domain_reply(v)`-> PCT sync; muda ctx para o caller
///   - 4  `upcall_return`  -> restaura ctx pre-upcall salvo
extern "sysv64" fn syscall_dispatch(ctx: *mut UserContext) {
    // SAFETY: `ctx` aponta para UserContext na SYSCALL_STACK,
    // construido pelo trampolim. Single-core; nao ha alias.
    let ctx_ref = unsafe { &mut *ctx };
    let num = ctx_ref.rax;
    match num {
        0 => {
            log::write_str("[kernel] ring 3 -> kernel via INT 0x80 (nop_test)\n");
            ctx_ref.rax = 0;
        }
        1 => {
            log::write_str("[kernel] ring 3 exit; halting\n");
            cpu::halt_forever();
        }
        2 => {
            // domain_call(target_dh) — target em RDI.
            let target = ctx_ref.rdi as u8;
            // SAFETY: ctx valido por contrato deste dispatcher.
            if let Err(e) = unsafe { domain::pct_call(ctx, target) } {
                log::write_str("[kernel] pct_call err\n");
                let _ = e;
                ctx_ref.rax = u64::MAX;
            }
            // Caso Ok, ctx ja foi sobrescrito para o target.
        }
        3 => {
            // domain_reply(value) — value em RDI.
            let value = ctx_ref.rdi;
            // SAFETY: idem.
            if let Err(e) = unsafe { domain::pct_reply(ctx, value) } {
                log::write_str("[kernel] pct_reply err\n");
                let _ = e;
                ctx_ref.rax = u64::MAX;
            }
        }
        4 => {
            // upcall_return: restaura ctx pre-upcall.
            // SAFETY: idem.
            if let Err(_) = unsafe { domain::upcall_return(ctx) } {
                log::write_str("[kernel] upcall_return err\n");
                ctx_ref.rax = u64::MAX;
            }
        }
        _ => {
            log::write_str("[kernel] unknown syscall; halt\n");
            cpu::halt_forever();
        }
    }
}

/// Trampolim INT 0x80. CPU empilhou SS/RSP/RFLAGS/CS/RIP. Salvo todos
/// os 15 GPRs em ordem para formar `UserContext` na stack, passo
/// `RSP` como ptr ao Rust, restauro e `iretq`.
///
/// # Stack alignment
///
/// CPU pushed 5 u64 (40B). 15 pushes = 120B. 40+120 = 160 (mod 16=0).
/// `call` empilha +8 => prologo SysV ve RSP%16 == 8 (esperado).
///
/// # Safety
///
/// IDT[0x80] gate DPL=3. CPU invoca apenas via `INT 0x80`.
#[unsafe(naked)]
unsafe extern "sysv64" fn syscall_entry() {
    core::arch::naked_asm!(
        // Push GPRs em ordem reversa de UserContext (ultimo pushed = rax = offset 0).
        "push r15", "push r14", "push r13", "push r12",
        "push r11", "push r10", "push r9",  "push r8",
        "push rbp", "push rdi", "push rsi", "push rdx",
        "push rcx", "push rbx", "push rax",
        // RDI = ptr para UserContext (RSP atual).
        "mov rdi, rsp",
        "call {dispatch}",
        // Pops (ordem inversa).
        "pop rax", "pop rbx", "pop rcx", "pop rdx",
        "pop rsi", "pop rdi", "pop rbp",
        "pop r8",  "pop r9",  "pop r10", "pop r11",
        "pop r12", "pop r13", "pop r14", "pop r15",
        "iretq",
        dispatch = sym syscall_dispatch,
    );
}

/// Endereco do trampolim `syscall_entry`, consumido por `idt::init`.
pub fn syscall_handler_addr() -> u64 {
    syscall_entry as *const () as usize as u64
}

// =================================================================
// Timer handler com upcall ring 3
// =================================================================

/// Corpo Rust do timer. Recebe ptr para UserContext (15 GPRs + iret
/// frame). Decide entre:
///   - **CPL=0** (interrompeu kernel): log + EOI + rearm; nao toca ctx.
///   - **CPL=3** (interrompeu ring 3): se o dominio ativo registrou
///     upcall, sobrescreve ctx para entrar em `upcall_entry`. Senao,
///     comportamento idem ao CPL=0 (apenas EOI+rearm; ring 3 retoma).
///
/// O bit CPL fica em `cs & 3` no iret frame.
#[no_mangle]
extern "sysv64" fn timer_handler_rust(ctx: *mut UserContext) {
    use core::sync::atomic::Ordering;
    crate::arch::x86_64::idt::TIMER_TICKS.fetch_add(1, Ordering::Relaxed);

    // SAFETY: ctx valido na syscall stack.
    let ctx_ref = unsafe { &mut *ctx };
    let cpl = ctx_ref.cs & 3;

    if cpl == 3 {
        // Interrompeu ring 3. Tenta entregar upcall.
        // SAFETY: ctx em SYSCALL_STACK; pct_timer_upcall consulta
        // CURRENT_DOMAIN e modifica *ctx in-place se houver upcall.
        unsafe { domain::timer_upcall(ctx) };
    } else {
        log::write_str("[kernel] timer tick\n");
    }

    // SAFETY: handler so executa apos apic::init; EOI valido em ISR.
    unsafe {
        crate::arch::x86_64::apic::eoi();
        crate::arch::x86_64::apic::arm_oneshot(crate::arch::x86_64::idt::timer_reload());
    }
}

/// Trampolim do IRQ 0x40 com save/restore completo. Mesmo formato
/// que `syscall_entry`: empilha UserContext na stack atual.
///
/// Quando IRQ vem de CPL=0, a CPU NAO troca para RSP0 — usa a stack
/// atual do kernel. Mesmo assim, push de 15 GPRs cria UserContext
/// valido (rip/cs/rflags/rsp/ss vem do iret frame).
///
/// Quando IRQ vem de CPL=3, CPU troca para RSP0 (TSS).
#[unsafe(naked)]
pub unsafe extern "sysv64" fn timer_handler_entry() {
    core::arch::naked_asm!(
        "push r15", "push r14", "push r13", "push r12",
        "push r11", "push r10", "push r9",  "push r8",
        "push rbp", "push rdi", "push rsi", "push rdx",
        "push rcx", "push rbx", "push rax",
        "mov rdi, rsp",
        "call {handler}",
        "pop rax", "pop rbx", "pop rcx", "pop rdx",
        "pop rsi", "pop rdi", "pop rbp",
        "pop r8",  "pop r9",  "pop r10", "pop r11",
        "pop r12", "pop r13", "pop r14", "pop r15",
        "iretq",
        handler = sym timer_handler_rust,
    );
}

// =================================================================
// Setup de TSS + boot do primeiro ring 3
// =================================================================

/// Configura TSS.RSP0 = topo da SYSCALL_STACK. Idempotente.
pub fn install() {
    crate::arch::x86_64::gdt::set_rsp0(syscall_stack_top());
}

/// Salta para `entry_rip` em ring 3 com `user_rsp`. Divergente.
///
/// # Safety
///
/// - CR3 atual cobre `entry_rip` (UserRx) e `user_rsp - 0x1000` (UserRw).
/// - GDT carregada (gdt::init).
/// - TSS.RSP0 setado (`install`).
/// - `domain::set_current(dh)` ja foi chamada para o dominio
///   correspondente, senao timer upcalls vao falhar silenciosamente.
#[unsafe(naked)]
pub unsafe extern "sysv64" fn enter_ring3(entry_rip: u64, user_rsp: u64) -> ! {
    core::arch::naked_asm!(
        "xor rax, rax",
        "mov ds, ax", "mov es, ax", "mov fs, ax", "mov gs, ax",
        "push {user_ds}",
        "push rsi",       // user_rsp
        "push 0x202",     // RFLAGS: bit1=1 reservado, IF=1 (timer pode upcall)
        "push {user_cs}",
        "push rdi",       // entry_rip
        "iretq",
        user_ds = const USER_DS as u64,
        user_cs = const USER_CS as u64,
    );
}
