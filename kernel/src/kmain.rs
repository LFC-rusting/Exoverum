//! Sequencia de inicializacao do kernel.
//!
//! Fase 1 da roadmap: inicializa GDT, TSS, IDT e serial. Ainda nao usa
//! `BootInfo` alem de verificar que nao e nulo; paginacao e memoria virao
//! nas proximas fases.

#![forbid(unsafe_code)]

use bootinfo::BootInfo;

use crate::arch::x86_64::{cpu, gdt, idt};
use crate::log;

/// Entry point chamado pelo binario (`src/main.rs`).
pub fn start(bootinfo: *const BootInfo) -> ! {
    log::init();
    log::write_str("[kernel] hello\n");

    if bootinfo.is_null() {
        log::write_str("[kernel] bootinfo nulo\n");
        cpu::halt_forever();
    }

    gdt::init();
    log::write_str("[kernel] gdt+tss ok\n");

    idt::init();
    log::write_str("[kernel] idt ok\n");

    log::write_str("[kernel] fase 1 completa; halt\n");
    cpu::halt_forever();
}
