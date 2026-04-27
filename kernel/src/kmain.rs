//! Sequencia de inicializacao do kernel.
//!
//! Fase 1: GDT, TSS, IDT, serial.
//! Fase 2: alocador de frames fisicos (mm::frame).

#![deny(unsafe_op_in_unsafe_fn)]

use bootinfo::BootInfo;

use core::sync::atomic::{AtomicU8, Ordering};

use crate::arch::x86_64::{apic, cpu, gdt, idt};
use crate::cap::{CapObject, CapRights, CapTable};
use crate::event::{self, EventHandle};
use crate::log;
use crate::mm;
use crate::thread::{self, ThreadHandle};

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
    //
    // IMPORTANTE: apos esta chamada, `bi` (derivado de `bootinfo` que aponta
    // para memoria UEFI em baixo-half) torna-se inalcancavel. Nenhum acesso
    // a `bi` ou `bootinfo` apos este ponto.
    //
    // SAFETY: `mm::init` completou; dados do bootinfo ja foram consumidos.
    match unsafe { mm::init_paging() } {
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

    // Fase 3d: prova que physmap esta ativo e que map_kernel_page consegue
    // materializar novas paginas POS-init_paging (pre-requisito da Fase 5).
    demo_physmap();

    // Fase 4: capabilities flat-table com CDT. Demo: mint raiz, deriva
    // subregioes, revoga e confirma que todos os descendentes sumiram.
    demo_caps();

    // Fase 5b: LAPIC timer one-shot + IRQ 0x40 -> handler stub. Prova
    // mecanismo: ticks chegam, handler loga, EOI funciona, rearm OK.
    // Sem preempcao com troca de contexto (essa entra na Fase 7 junto
    // com TSS IST + swapgs / syscalls).
    demo_timer();

    // Fase 6a: eventos single-bit idempotentes. Spawn duas threads que
    // exercitam (i) signal sticky consumido por wait posterior e
    // (ii) wait que parkeia + signal que acorda + yield_to que ressuscita.
    // Tambem exercita spawn+yield_to da Fase 5a (4 trocas de contexto).
    // Funcao divergente: A halta ao final.
    demo_events();
}

/// Inicializa LAPIC, habilita IRQ 0x40, espera 3 ticks e desliga
/// interrupcoes antes de retornar (proximas fases ainda assumem IF=0).
fn demo_timer() {
    // SAFETY: pos-init_paging; idt ja contem timer_handler_entry; chamada
    // unica por boot.
    if let Err(_) = unsafe { apic::init() } {
        log::write_str("[kernel] apic init falhou\n");
        return;
    }
    log::write_str("[kernel] apic ok; armando timer\n");
    // SAFETY: apic::init bem-sucedido garante MMIO mapeado.
    unsafe { apic::arm_oneshot(idt::timer_reload()); }
    cpu::sti();
    // Espera busy-wait por 3 ticks (handler incrementa TIMER_TICKS).
    while idt::TIMER_TICKS.load(Ordering::Relaxed) < 3 {
        cpu::hlt();
    }
    cpu::cli();
    log::write_str("[kernel] timer demo done; 3 ticks observados\n");
}

// Statics compartilhados entre as threads de `demo_events`. `u8::MAX`
// e sentinela invalido; sobrescritos por `demo_events` apos `spawn`/
// `event::create`. Entry-points leem aqui para descobrir peer e eventos.
static EV_THREAD_A: AtomicU8 = AtomicU8::new(u8::MAX);
static EV_THREAD_B: AtomicU8 = AtomicU8::new(u8::MAX);
static E1: AtomicU8 = AtomicU8::new(u8::MAX);
static E2: AtomicU8 = AtomicU8::new(u8::MAX);

extern "sysv64" fn ev_a_entry() -> ! {
    // SAFETY: este corpo executa apos `demo_events` ter (a) populado
    // EV_THREAD_B + E1 + E2 e (b) cedido para A. Os handles
    // reconstruidos por `from_raw` apontam para slots vivos que nao
    // sao destruidos nesta fase. `wait`/`signal`/`yield_to` cumprem
    // seus requisitos individuais (post-init, single-core, handle
    // valido, fallback != self).
    unsafe {
        let b = ThreadHandle::from_raw(EV_THREAD_B.load(Ordering::Relaxed));
        let e1 = EventHandle::from_raw(E1.load(Ordering::Relaxed));
        let e2 = EventHandle::from_raw(E2.load(Ordering::Relaxed));

        // 1) Cede a B para que ele faca signal(e1) sem waiter (sticky).
        log::write_str("[kernel] ev_a yield_to B (setup sticky)\n");
        let _ = thread::yield_to(b);

        // 2) e1 deve estar Signaled; wait consome imediato sem parkear.
        log::write_str("[kernel] ev_a wait(e1) (sticky deve consumir)\n");
        let _ = event::wait(e1, b);
        log::write_str("[kernel] ev_a consumiu e1 sticky\n");

        // 3) Agora wait(e2) com e2 Clear: parkea, cede a B.
        log::write_str("[kernel] ev_a wait(e2) (deve parkear)\n");
        let _ = event::wait(e2, b);
        // 5) Voltamos aqui depois que B signalar e2 e ceder a CPU.
        log::write_str("[kernel] ev_a acordou de wait(e2)\n");
    }
    log::write_str("[kernel] events demo done\n");
    cpu::halt_forever();
}

extern "sysv64" fn ev_b_entry() -> ! {
    // SAFETY: simetrica a `ev_a_entry`.
    unsafe {
        let a = ThreadHandle::from_raw(EV_THREAD_A.load(Ordering::Relaxed));
        let e1 = EventHandle::from_raw(E1.load(Ordering::Relaxed));
        let e2 = EventHandle::from_raw(E2.load(Ordering::Relaxed));

        // signal(e1) sem waiter -> sticky.
        log::write_str("[kernel] ev_b signal(e1) (sticky)\n");
        let _ = event::signal(e1);
        let _ = thread::yield_to(a);

        // 4) signal(e2) com A parkeada -> consome bit + acorda A (Ready).
        log::write_str("[kernel] ev_b signal(e2) (acorda A)\n");
        let _ = event::signal(e2);
        // A esta Ready; cede explicitamente para que ela retorne de wait.
        let _ = thread::yield_to(a);
    }
    // A halta ao final; este caminho fica como defensiva.
    cpu::halt_forever();
}

/// Cria 2 eventos + 2 threads e exercita: (i) signal antes de wait
/// (sticky); (ii) wait antes de signal (park-then-wake). Prova tambem
/// spawn + yield_to com 4 trocas de contexto.
fn demo_events() -> ! {
    // SAFETY: pos-init_paging + thread/event globals em estado Empty;
    // `create`/`spawn` sao idempotentes do ponto-de-vista do contrato
    // (single-core, slots disponiveis nesta fase).
    let (e1, e2) = unsafe {
        match (event::create(), event::create()) {
            (Ok(a), Ok(b)) => (a, b),
            _ => {
                log::write_str("[kernel] event::create falhou\n");
                cpu::halt_forever();
            }
        }
    };
    let (a, b) = unsafe {
        match (thread::spawn(ev_a_entry), thread::spawn(ev_b_entry)) {
            (Ok(x), Ok(y)) => (x, y),
            _ => {
                log::write_str("[kernel] spawn ev_a/ev_b falhou\n");
                cpu::halt_forever();
            }
        }
    };
    EV_THREAD_A.store(a.raw(), Ordering::Relaxed);
    EV_THREAD_B.store(b.raw(), Ordering::Relaxed);
    E1.store(e1.raw(), Ordering::Relaxed);
    E2.store(e2.raw(), Ordering::Relaxed);
    log::write_str("[kernel] events demo: yield_to ev_a\n");
    // SAFETY: a foi devolvido por spawn; thread Ready.
    unsafe {
        let _ = thread::yield_to(a);
    }
    // ev_a halta ao final; nao retornamos aqui.
    cpu::halt_forever();
}

/// Demonstra o pipeline de capabilities: insert_root -> retype -> copy ->
/// revoke. Serve como smoke test em boot real (complementando os 14 testes
/// host em cap::tests).
fn demo_caps() {
    let mut table = CapTable::new();
    let root = CapObject::Untyped {
        base: 0x10_0000,
        size: 0x10_0000,
        free_index: 0,
    };
    if table.insert_root(0, root, CapRights::ALL).is_err() {
        log::write_str("[kernel] cap err: insert_root\n");
        return;
    }
    // Duas subregioes derivadas + uma copia atenuada do primeiro child.
    // retype_untyped(src, dst, size): kernel escolhe base via watermark.
    // Impossivel derivar dois filhos sobrepostos (bug critico de seguranca
    // da API antiga com `new_base` livre).
    if table.retype_untyped(0, 1, 0x4_0000).is_err()
        || table.retype_untyped(0, 2, 0x4_0000).is_err()
        || table.copy(1, 3, CapRights::READ).is_err()
    {
        log::write_str("[kernel] cap err: derivacao\n");
        return;
    }
    log::write_str("[kernel] cap root + 3 descendentes criados\n");

    // Revoke global: apaga TODOS os descendentes da raiz.
    if table.revoke(0).is_err() {
        log::write_str("[kernel] cap err: revoke\n");
        return;
    }
    // Raiz sobrevive; slots 1..3 ficam vazios.
    use crate::cap::CapError;
    let root_ok = table.lookup(0).is_ok();
    let descendentes_limpos = [1u16, 2, 3]
        .iter()
        .all(|&s| table.lookup(s) == Err(CapError::SlotEmpty));
    if root_ok && descendentes_limpos {
        log::write_str("[kernel] revoke global ok; raiz intacta\n");
    } else {
        log::write_str("[kernel] revoke global INCOERENTE\n");
    }
}

/// Demonstra que `mm::map_kernel_page` consegue mapear uma nova pagina
/// POS-`init_paging` (identity ja sumiu) e que o physmap entrega a mesma
/// memoria via virtual alternativo. Pre-requisito de correcao para a Fase 5.
///
/// VA escolhida: `0xFFFF_FFFF_C000_0000` (PML4=511, PDPT=511; nao colide
/// com kernel em PDPT=510 nem com heap).
fn demo_physmap() {
    const DEMO_VA: u64 = 0xFFFF_FFFF_C000_0000;
    const PATTERN: u8 = 0xA5;

    let frame = match mm::alloc_frame() {
        Some(f) => f,
        None => {
            log::write_str("[kernel] physmap err: sem frames\n");
            return;
        }
    };
    // SAFETY: pos-init_paging, map_kernel_page e a API correta. VA e
    // phys alinhados a 4 KiB (frame.addr() vem de PhysFrame alinhado;
    // DEMO_VA termina em zeros).
    let r = unsafe { mm::map_kernel_page(DEMO_VA, frame.addr(), mm::Perm::Rw) };
    if r.is_err() {
        log::write_str("[kernel] physmap err: map_kernel_page\n");
        return;
    }
    // SAFETY: a pagina acabou de ser mapeada RW+NX na VA DEMO_VA; escrita
    // de um byte e valida. Leitura via physmap le o MESMO frame fisico por
    // outro VA (provando que ambos os mapeamentos apontam para a mesma RAM).
    unsafe {
        let p_via_map = DEMO_VA as *mut u8;
        p_via_map.write_volatile(PATTERN);
        let p_via_physmap = mm::phys_to_virt(frame.addr());
        let v = p_via_physmap.read_volatile();
        if v == PATTERN {
            log::write_str("[kernel] physmap ok: map+physmap view coerentes\n");
        } else {
            log::write_str("[kernel] physmap INCOERENTE\n");
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
