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
