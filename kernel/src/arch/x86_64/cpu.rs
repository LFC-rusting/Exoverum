//! Primitivas x86_64 de baixo nivel (I/O ports, flags, halt).
//!
//! Cada funcao expoe API safe externa e contem `unsafe` interno com SAFETY
//! inline. Auditar este arquivo e suficiente para verificar a base de portas
//! e asm inline do kernel.

use core::arch::asm;

/// Escreve um byte em uma porta de I/O.
#[inline]
pub fn outb(port: u16, val: u8) {
    // SAFETY: a instrucao `out` e privilegiada mas valida em ring0. Sem efeito
    // fora da porta indicada; nao mexe em memoria ou em stack.
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Le um byte de uma porta de I/O.
#[inline]
pub fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: a instrucao `in` e privilegiada mas valida em ring0. Leitura
    // pura; nao altera memoria nem stack.
    unsafe {
        asm!(
            "in al, dx",
            out("al") val,
            in("dx") port,
            options(nomem, nostack, preserves_flags),
        );
    }
    val
}

/// Desabilita interrupcoes no core atual.
#[inline]
pub fn cli() {
    // SAFETY: `cli` limpa IF; seguro em ring0. Deve ser usado em secoes
    // criticas curtas.
    unsafe { asm!("cli", options(nomem, nostack, preserves_flags)); }
}

/// Habilita interrupcoes no core atual.
#[inline]
pub fn sti() {
    // SAFETY: `sti` seta IF; seguro em ring0.
    unsafe { asm!("sti", options(nomem, nostack, preserves_flags)); }
}

/// Aguarda proxima interrupcao (usado em laco de halt).
#[inline]
pub fn hlt() {
    // SAFETY: `hlt` e privilegiada mas valida em ring0; aguarda IRQ/NMI.
    unsafe { asm!("hlt", options(nomem, nostack, preserves_flags)); }
}

/// Para o core permanentemente. Chamado em panic e handlers de excecao.
#[inline]
pub fn halt_forever() -> ! {
    cli();
    loop {
        hlt();
    }
}

/// MSR EFER (Extended Feature Enable Register).
const MSR_EFER: u32 = 0xC000_0080;
const EFER_NXE: u64 = 1 << 11;

/// Le um MSR.
#[inline]
fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: `rdmsr` e privilegiada mas valida em ring0. Le o MSR
    // indicado em ECX para EDX:EAX. Sem efeito em memoria/stack.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Escreve um MSR.
#[inline]
fn wrmsr(msr: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    // SAFETY: `wrmsr` e privilegiada mas valida em ring0. Escreve EDX:EAX
    // no MSR indicado em ECX. Caller responsavel por invariantes do MSR
    // especifico (aqui, so EFER.NXE).
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Habilita o bit NX (No-Execute) setando `EFER.NXE`. Idempotente.
///
/// Necessario para que bit 63 dos PTEs seja respeitado como NX. Sem isso,
/// a flag e reservada-must-be-zero e causaria #GP se setada.
pub fn enable_nxe() {
    let efer = rdmsr(MSR_EFER);
    if efer & EFER_NXE == 0 {
        wrmsr(MSR_EFER, efer | EFER_NXE);
    }
}

/// Carrega `phys` no CR3, efetivando a nova tabela de paginas. A proxima
/// instrucao ja e resolvida pelo novo mapeamento; por isso o caller deve
/// garantir que o codigo atual (RIP) e a stack (RSP) estejam mapeados.
///
/// # Safety
///
/// `phys` deve ser o endereco fisico de um PML4 valido, 4 KiB-alinhado,
/// que contenha mapeamentos cobrindo: o proprio kernel (text executavel),
/// a stack atual, e qualquer dado tocado entre esta chamada e a proxima
/// operacao segura. Violar isso causa triple-fault.
#[inline]
pub unsafe fn load_cr3(phys: u64) {
    // SAFETY: delegada ao caller (documentada acima).
    unsafe {
        asm!(
            "mov cr3, {0}",
            in(reg) phys,
            options(nostack, preserves_flags),
        );
    }
}

/// Le o valor atual de CR3 (endereco fisico do PML4 ativo).
#[inline]
pub fn read_cr3() -> u64 {
    let val: u64;
    // SAFETY: leitura de registro de controle; ring0, sem efeito colateral.
    unsafe {
        asm!(
            "mov {0}, cr3",
            out(reg) val,
            options(nomem, nostack, preserves_flags),
        );
    }
    val
}
