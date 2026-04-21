//! Saída serial COM1 (write-only, sem input, sem parsing).
//!
//! Uso estrito para logs de boot/diagnóstico. Nunca escrevo dados sensíveis aqui.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

// Offsets UART 16550 relativos a COM1 e bits de status. Mantenho tudo
// nomeado para evitar números mágicos e facilitar auditoria.
const COM1: u16 = 0x3F8;
const UART_THR: u16 = 0; // Transmit Holding Register (W) / RBR (R)
const UART_IER: u16 = 1; // Interrupt Enable Register
const UART_FCR: u16 = 2; // FIFO Control Register (W)
const UART_LCR: u16 = 3; // Line Control Register
const UART_MCR: u16 = 4; // Modem Control Register
const UART_LSR: u16 = 5; // Line Status Register (R)
const UART_SCR: u16 = 7; // Scratch Register (R/W, sem efeito colateral)

const LCR_DLAB: u8 = 0x80;           // habilita acesso ao divisor
const LCR_8N1: u8 = 0x03;            // 8 bits, sem paridade, 1 stop bit
const FCR_ENABLE_CLEAR_14: u8 = 0xC7; // FIFO on, limpa RX/TX, threshold 14
const MCR_DTR_RTS: u8 = 0x03;        // DTR + RTS
const LSR_THR_EMPTY: u8 = 0x20;      // bit 5: transmitter holding register vazio
const SCR_PROBE_PATTERN: u8 = 0xAE;  // valor arbitrário para teste de presença

/// Sinaliza se o UART respondeu ao teste de presença.
/// Enquanto `false`, nenhuma função de escrita toca o hardware.
static UART_PRESENT: AtomicBool = AtomicBool::new(false);

/// Envio um byte para a porta indicada.
#[inline]
unsafe fn outb(port: u16, val: u8) {
    // SAFETY: instrução `out` é privilegiada mas válida em ring0/UEFI pré-ExitBootServices
    // e pós-ExitBootServices (ainda rodo como firmware/kernel). Escrevo apenas em portas
    // COM1 fixas, sem efeitos colaterais fora do UART.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
    }
}

/// Leio um byte de uma porta (apenas para checar status do UART, nunca para input de dados).
#[inline]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: leitura de porta de status do UART (LSR) não tem efeito colateral.
    unsafe {
        asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Verifico se o UART está presente usando o scratch register (offset 7).
/// Se a leitura não bater com o valor escrito, trato como ausente/não confiável.
fn probe_uart() -> bool {
    // SAFETY: escrita/leitura no scratch register (UART_SCR) não tem efeito colateral
    // em UART 16550 ou compatíveis; em firmware sem UART a leitura devolve 0xFF.
    unsafe {
        outb(COM1 + UART_SCR, SCR_PROBE_PATTERN);
        inb(COM1 + UART_SCR) == SCR_PROBE_PATTERN
    }
}

/// Inicializo a COM1 em 115200 bps, 8N1, sem interrupções, FIFO habilitado.
/// Se o UART não responder ao teste de presença, não habilito nenhum log serial.
pub fn init() {
    if !probe_uart() {
        // UART ausente/não confiável: deixo UART_PRESENT = false e não toco mais no hardware.
        return;
    }

    // SAFETY: sequência padrão de init de UART 16550 (Linux `8250_early`, OpenBSD `com.c`):
    // desabilito IRQs, configuro divisor via DLAB, volto ao modo 8N1, habilito FIFO
    // e sinalizo DTR/RTS. Todas as escritas atingem apenas portas fixas da COM1.
    unsafe {
        outb(COM1 + UART_IER, 0x00);
        outb(COM1 + UART_LCR, LCR_DLAB);
        outb(COM1 + UART_THR, 0x01); // divisor LSB = 1 => 115200 bps
        outb(COM1 + UART_IER, 0x00); // divisor MSB = 0
        outb(COM1 + UART_LCR, LCR_8N1);
        outb(COM1 + UART_FCR, FCR_ENABLE_CLEAR_14);
        outb(COM1 + UART_MCR, MCR_DTR_RTS);
    }

    UART_PRESENT.store(true, Ordering::Relaxed);
}

/// Espero o UART ficar pronto para transmitir. Confio no probe feito em `init`:
/// se o UART respondeu no scratch register, assumo que o THR vai esvaziar.
/// Mesmo padrão adotado por Linux early serial, GRUB e OpenBSD (`com.c`).
#[inline]
fn wait_tx_ready() {
    // SAFETY: leitura do LSR não tem efeito colateral; bit LSR_THR_EMPTY indica THR vazio.
    while unsafe { inb(COM1 + UART_LSR) } & LSR_THR_EMPTY == 0 {
        core::hint::spin_loop();
    }
}

/// Escrevo um byte na COM1.
/// Não faço nada se o UART não passou no teste de presença.
pub fn write_byte(b: u8) {
    if !UART_PRESENT.load(Ordering::Relaxed) {
        return;
    }
    wait_tx_ready();
    // SAFETY: COM1 verificado e inicializado; escrita no THR é a operação esperada.
    unsafe { outb(COM1 + UART_THR, b) };
}

/// Escrevo uma sequência de bytes na COM1.
pub fn write_bytes(bytes: &[u8]) {
    for &b in bytes {
        write_byte(b);
    }
}

/// Escrevo uma string ASCII na COM1 traduzindo `\n` para `\r\n`.
/// Não interpreto nem filtro outro conteúdo.
pub fn write_str(s: &str) {
    for &b in s.as_bytes() {
        if b == b'\n' {
            write_byte(b'\r');
        }
        write_byte(b);
    }
}
