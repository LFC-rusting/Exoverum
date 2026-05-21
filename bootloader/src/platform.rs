//! Camada de plataforma. Única fronteira onde `unsafe` é permitido no bootloader:
//! submódulos aqui encapsulam FFI UEFI (`uefi`) e acesso a portas de I/O (`serial`).
//! O resto do crate segue `#![forbid(unsafe_code)]`.

pub mod serial;
pub mod uefi;
