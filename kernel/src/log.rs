//! Logger de texto do kernel.
//!
//! Por enquanto apenas um pass-through pela COM1. Evito `core::fmt` para
//! manter o binario minimo; se precisar de formatacao, adiciono depois um
//! writer implementando `core::fmt::Write`.

#![forbid(unsafe_code)]

use crate::arch::x86_64::serial;

/// Inicializa a serial. Idempotente; chamada uma vez em kmain.
pub fn init() {
    serial::init();
}

/// Escreve uma string ASCII na serial (traduzindo `\n` para `\r\n`).
pub fn write_str(s: &str) {
    serial::write_str(s);
}

/// Escreve um byte cru (usado por rotinas de hex/debug).
pub fn write_byte(b: u8) {
    serial::write_byte(b);
}

/// Escreve um u64 em hexadecimal com prefixo `0x`, largura 16.
pub fn write_hex64(v: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    write_byte(b'0');
    write_byte(b'x');
    for i in (0..16).rev() {
        let nibble = ((v >> (i * 4)) & 0xF) as usize;
        write_byte(HEX[nibble]);
    }
}
