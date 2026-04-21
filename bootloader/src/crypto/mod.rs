//! Primitivas criptográficas do bootloader. Implementadas internamente
//! para evitar dependências externas e reduzir a TCB. Todas são safe.

#![forbid(unsafe_code)]

pub mod sha256;
