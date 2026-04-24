//! Sequencia de inicializacao do kernel.
//!
//! Fase 1: GDT, TSS, IDT, serial.
//! Fase 2: alocador de frames fisicos (mm::frame).

#![deny(unsafe_op_in_unsafe_fn)]

use bootinfo::BootInfo;

use crate::arch::x86_64::{cpu, gdt, idt};
use crate::log;
use crate::mm;

/// Entry point chamado pelo binario (`src/main.rs`).
///
/// # Safety
///
/// - `bootinfo` deve apontar para `BootInfo` valido preenchido pelo
///   bootloader em memoria LoaderData preservada apos `ExitBootServices`,
///   ou ser `null` (tratado explicitamente sem deref).
/// - Invocada uma unica vez por boot; chamadas subsequentes violam a
///   invariante de acesso sequencial ao alocador global.
/// - Kernel roda em identity mapping UEFI ate `mm::init` completar; essa
///   regiao deve cobrir o ponteiro recebido.
///
/// Violar qualquer item acima leva a UB (deref invalido ou corrupcao do
/// alocador). Por isso a funcao e `unsafe fn` apesar da deref ser a unica
/// op unsafe visivel no corpo.
pub unsafe fn start(bootinfo: *const BootInfo) -> ! {
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

    // SAFETY: bootinfo nao-nulo (checado acima); bootloader garante que o
    // ponteiro aponta para BootInfo valido em memoria LoaderData preservada.
    // Acesso apenas de leitura nesta funcao.
    let bi: &BootInfo = unsafe { &*bootinfo };

    // Diagnostico: loga valores crus da MemoryMap para confirmar que o
    // bootloader preencheu corretamente antes de parsear.
    log::write_str("[kernel] mm.ptr=0x");
    log_u64_hex(bi.memory_map.ptr);
    log::write_str(" len=");
    log_usize(bi.memory_map.len as usize);
    log::write_str(" desc_size=");
    log_usize(bi.memory_map.desc_size as usize);
    log::write_str("\n");

    match mm::init(bi) {
        Ok(()) => {
            log_frame_stats();
            demo_alloc_free();
        }
        Err(mm::FrameError::InvalidDescriptorSize) => {
            log::write_str("[kernel] mm::init err: desc_size invalido\n");
            cpu::halt_forever();
        }
        Err(mm::FrameError::InvalidMemoryMap) => {
            log::write_str("[kernel] mm::init err: memory map invalida\n");
            cpu::halt_forever();
        }
    }

    // Fase 3a: montar PML4 com W^X e trocar CR3.
    // SAFETY: `mm::init` completou com sucesso; `bi` continua vivo.
    match unsafe { mm::init_paging(bi) } {
        Ok(pml4) => {
            log::write_str("[kernel] paging ativo; cr3=0x");
            log_u64_hex(pml4);
            log::write_str("\n");
        }
        Err(mm::PagingError::OutOfFrames) => {
            log::write_str("[kernel] paging err: sem frames\n");
            cpu::halt_forever();
        }
        Err(mm::PagingError::InternalConflict) => {
            log::write_str("[kernel] paging err: colisao interna\n");
            cpu::halt_forever();
        }
    }

    // Fase 3b: heap bump allocator ativo. Demo: aloca 128 B, escreve, le.
    demo_heap();

    log::write_str("[kernel] fase 3 completa; halt\n");
    cpu::halt_forever();
}

/// Demonstra alloc de heap + write/read para validar que o range virtual
/// esta mapeado RW no novo PML4.
fn demo_heap() {
    match mm::KERNEL_HEAP.alloc_bytes(128, 16) {
        Ok(addr) => {
            log::write_str("[kernel] heap alloc @ 0x");
            log_u64_hex(addr as u64);
            log::write_str("; livres=");
            log_usize(mm::KERNEL_HEAP.free_bytes());
            log::write_str("\n");
            // SAFETY: heap alloc retorna endereco em [heap_base, heap_base+1MiB)
            // mapeado RW+NX no PML4 ativo; escrita de 1 byte dentro do bloco
            // solicitado (128 B) e valida.
            unsafe {
                let p = addr as *mut u8;
                p.write_volatile(0x42);
                let v = p.read_volatile();
                if v == 0x42 {
                    log::write_str("[kernel] heap read/write ok\n");
                } else {
                    log::write_str("[kernel] heap read/write INCOERENTE\n");
                }
            }
        }
        Err(mm::HeapError::NotInitialized) => {
            log::write_str("[kernel] heap err: nao inicializado\n");
        }
        Err(mm::HeapError::OutOfMemory) => {
            log::write_str("[kernel] heap err: OOM\n");
        }
        Err(mm::HeapError::BadAlignment) => {
            log::write_str("[kernel] heap err: alinhamento invalido\n");
        }
    }
}

/// Imprime "[kernel] frames livres: N de T" no log serial.
fn log_frame_stats() {
    log::write_str("[kernel] frames livres: ");
    log_usize(mm::free_count());
    log::write_str(" de ");
    log_usize(mm::total_frames());
    log::write_str("\n");
}

/// Demonstra alloc/free: tira um frame, imprime endereco, devolve.
fn demo_alloc_free() {
    match mm::alloc_frame() {
        Some(frame) => {
            log::write_str("[kernel] alloc frame @ 0x");
            log_u64_hex(frame.addr());
            log::write_str("\n");
            mm::free_frame(frame);
            log::write_str("[kernel] frame devolvido; livres: ");
            log_usize(mm::free_count());
            log::write_str("\n");
        }
        None => log::write_str("[kernel] sem frames livres!\n"),
    }
}

/// Loga um `usize` em decimal. Buffer estatico de 20 digitos e suficiente
/// para u64 (max 20 chars). Evita dependencia de `core::fmt`.
fn log_usize(mut n: usize) {
    if n == 0 {
        log::write_str("0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    // Reverter in-place para ordem correta.
    let s = &mut buf[..i];
    s.reverse();
    // `s` contem somente digitos ASCII, entao str::from_utf8 e seguro.
    if let Ok(text) = core::str::from_utf8(s) {
        log::write_str(text);
    }
}

/// Loga `u64` em hexadecimal sem prefixo. 16 digitos, zero-padded.
fn log_u64_hex(n: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [b'0'; 16];
    for i in 0..16 {
        let nibble = ((n >> ((15 - i) * 4)) & 0xf) as usize;
        buf[i] = HEX[nibble];
    }
    if let Ok(text) = core::str::from_utf8(&buf) {
        log::write_str(text);
    }
}
