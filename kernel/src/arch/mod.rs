//! Camada arch. Somente x86_64 por enquanto (unico alvo do projeto).
//!
//! Modulo roteador. `forbid(unsafe_code)` nao pode ser aplicado aqui porque
//! `forbid` propaga para submodulos (regra do compilador) e os submodulos
//! hardware-especificos precisam de `unsafe` legitimo. Cada submodulo
//! declara seu proprio policy.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
