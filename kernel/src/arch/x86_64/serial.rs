//! Saida serial COM1 para debug do kernel.
//!
//! Write-only, sem input, sem parsing. Equivalente funcional a serial do
//! bootloader; mantida separada porque cada binario (UEFI e ELF bare-metal)
//! inicializa o hardware em seu contexto.

use core::sync::atomic::{AtomicBool, Ordering};

use super::cpu::{inb, outb};

// Offsets UART 16550 relativos a COM1. Mesma convencao do bootloader.
const COM1: u16 = 0x3F8;
const UART_THR: u16 = 0;
const UART_IER: u16 = 1;
const UART_FCR: u16 = 2;
const UART_LCR: u16 = 3;
const UART_MCR: u16 = 4;
const UART_LSR: u16 = 5;
const UART_SCR: u16 = 7;

const LCR_DLAB: u8 = 0x80;
const LCR_8N1: u8 = 0x03;
const FCR_ENABLE_CLEAR_14: u8 = 0xC7;
const MCR_DTR_RTS: u8 = 0x03;
const LSR_THR_EMPTY: u8 = 0x20;
const SCR_PROBE_PATTERN: u8 = 0xBE;

static UART_PRESENT: AtomicBool = AtomicBool::new(false);

fn probe_uart() -> bool {
    outb(COM1 + UART_SCR, SCR_PROBE_PATTERN);
    inb(COM1 + UART_SCR) == SCR_PROBE_PATTERN
}

/// Inicializa COM1 em 115200 bps, 8N1. Idempotente: checa presenca via
/// scratch register. Se o UART nao responder, deixa `UART_PRESENT` falso.
pub fn init() {
    if !probe_uart() {
        return;
    }

    outb(COM1 + UART_IER, 0x00);
    outb(COM1 + UART_LCR, LCR_DLAB);
    outb(COM1 + UART_THR, 0x01); // divisor LSB = 1 => 115200
    outb(COM1 + UART_IER, 0x00); // divisor MSB = 0
    outb(COM1 + UART_LCR, LCR_8N1);
    outb(COM1 + UART_FCR, FCR_ENABLE_CLEAR_14);
    outb(COM1 + UART_MCR, MCR_DTR_RTS);

    UART_PRESENT.store(true, Ordering::Relaxed);
}

#[inline]
fn wait_tx_ready() {
    while inb(COM1 + UART_LSR) & LSR_THR_EMPTY == 0 {
        core::hint::spin_loop();
    }
}

pub fn write_byte(b: u8) {
    if !UART_PRESENT.load(Ordering::Relaxed) {
        return;
    }
    wait_tx_ready();
    outb(COM1 + UART_THR, b);
}

pub fn write_str(s: &str) {
    for &b in s.as_bytes() {
        if b == b'\n' {
            write_byte(b'\r');
        }
        write_byte(b);
    }
}
