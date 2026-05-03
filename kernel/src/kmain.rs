//! Sequencia de inicializacao do kernel.
//!
//! Fase 1: GDT, TSS, IDT, serial.
//! Fase 2: alocador de frames fisicos (mm::frame).

#![deny(unsafe_op_in_unsafe_fn)]

use bootinfo::BootInfo;

use crate::arch::x86_64::{cpu, gdt, idt, userland};
use crate::cap::{CapObject, CapRights, CapTable};
use crate::domain;
use crate::log;
use crate::mm::{self, Perm};

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
        log::write_str("[kernel] null bootinfo\n");
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
            log::write_str("[kernel] mm::init err: invalid desc_size\n");
            cpu::halt_forever();
        }
        Err(mm::FrameError::InvalidMemoryMap) => {
            log::write_str("[kernel] mm::init err: invalid memory map\n");
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
            log::write_str("[kernel] paging active; cr3=0x");
            log_u64_hex(pml4);
            log::write_str("\n");
        }
        Err(mm::PagingError::OutOfFrames) => {
            log::write_str("[kernel] paging err: out of frames\n");
            cpu::halt_forever();
        }
        Err(mm::PagingError::InternalConflict) => {
            log::write_str("[kernel] paging err: internal collision\n");
            cpu::halt_forever();
        }
    }

    // Fase 3d: prova que physmap esta ativo e que map_kernel_page consegue
    // materializar novas paginas POS-init_paging (pre-requisito da Fase 5).
    demo_physmap();

    // Fase 4: capabilities flat-table com CDT. Demo: mint raiz, deriva
    // subregioes, revoga e confirma que todos os descendentes sumiram.
    demo_caps();

    // Smoke test ring 3 multi-dominio: dominios com CR3+CSpace
    // proprios, cap_grant entre dominios, PCT (domain_call/reply),
    // visible cross-CSpace revocation sincrona.
    demo_userland();
}

/// Smoke test: dois dominios em ring 3 exercitam o caminho completo
/// do exokernel.
///
///   - **A** (cliente): faz `domain_call(B)`, espera o reply, sai.
///   - **B** (servidor): recebe PCT, devolve 0x42 via `domain_reply`.
///
/// Sequencia:
///   1. setup A, B; A recebe `Domain{B}` (autoriza PCT) e da
///      `cap_grant` de um Frame para B (slot 5).
///   2. Kernel chama `revoke_granted(A, 0)`: a cap doada e removida
///      do CSpace de B. B descobre de modo sincrono se invocar o
///      slot 5 (lookup retorna SlotEmpty).
///   3. `enter A`. A faz `domain_call(B)`.
///   4. B executa, da `domain_reply(0x42)`.
///   5. A continua, `mov rax,1; int 0x80` sai e o kernel halta.
///
/// Cobre: ring-3 isolation, audited paging, INT-0x80 syscall, PCT
/// sync (call+reply), cap_grant, visible cross-CSpace revocation
/// sincrona sem upcall imposto pelo kernel.
///
/// Funcao divergente.
fn demo_userland() -> ! {
    const PAYLOAD_VA: u64 = 0x0000_0000_4000_0000;
    const STACK_VA: u64 = 0x0000_0000_5000_0000;

    log::write_str("[kernel] demo_userland: setup\n");

    let dh_a = match unsafe { domain::create() } {
        Ok(h) => h,
        Err(_) => fail("demo_userland: domain::create A falhou"),
    };
    let dh_b = match unsafe { domain::create() } {
        Ok(h) => h,
        Err(_) => fail("demo_userland: domain::create B falhou"),
    };

    setup_domain(dh_b, userland::payload_b_bytes(), None, PAYLOAD_VA, STACK_VA);

    let patch_off = userland::payload_a_target_imm_offset();
    setup_domain(
        dh_a,
        userland::payload_a_bytes(),
        Some((patch_off, dh_b.raw() as u32)),
        PAYLOAD_VA,
        STACK_VA,
    );

    if domain::insert_root(
        dh_a,
        2,
        CapObject::Domain { handle: dh_b.raw() },
        CapRights::ALL,
    )
    .is_err()
    {
        fail("demo_userland: insert Domain{B} cap em A falhou");
    }

    if domain::cap_grant(dh_a, 0, dh_b, 5, CapRights::READ).is_err() {
        fail("demo_userland: cap_grant A->B falhou");
    }
    log::write_str("[kernel] cap_grant A->B ok\n");

    // Visible cross-CSpace revocation sincrona: cap sumiu do CSpace
    // de B. Exokernel puro: sem upcall imposto.
    match domain::revoke_granted(dh_a, 0) {
        Ok(n) if n >= 1 => {
            log::write_str("[kernel] revoke_granted A.slot0 ok\n");
        }
        _ => fail("demo_userland: revoke_granted falhou"),
    }

    userland::install();

    log::write_str("[kernel] demo_userland: enter A\n");
    let user_rsp = STACK_VA + 0x1000;
    // SAFETY: dh_a valido; payload e stack mapeados; RSP0 ok; IDT pronta.
    let _ = unsafe { domain::enter(dh_a, PAYLOAD_VA, user_rsp) };
    cpu::halt_forever();
}

/// Setup completo de um dominio: aloca payload+stack, copia bytes
/// (com patch opcional), insere caps Frame R/RW, mapeia user-RX/RW,
/// programa entry_rip/entry_rsp.
fn setup_domain(
    dh: domain::DomainHandle,
    bytes: &[u8],
    patch: Option<(usize, u32)>,
    payload_va: u64,
    stack_va: u64,
) {
    if bytes.len() > 4096 {
        fail("setup_domain: payload > 4 KiB");
    }
    let pf = mm::alloc_frame().unwrap_or_else(|| fail("setup_domain: sem frame payload"));
    let sf = mm::alloc_frame().unwrap_or_else(|| fail("setup_domain: sem frame stack"));

    // Copia bytes via physmap (loop manual: target sem SSE).
    // SAFETY: physmap ativo; pf recem-alocado; bytes em higher-half kernel.
    unsafe {
        let dst = mm::phys_to_virt(pf.addr());
        let src = bytes.as_ptr();
        let mut i = 0usize;
        while i < bytes.len() {
            dst.add(i).write(src.add(i).read());
            i += 1;
        }
        if let Some((off, val)) = patch {
            let bs = val.to_le_bytes();
            let mut j = 0usize;
            while j < 4 {
                dst.add(off + j).write(bs[j]);
                j += 1;
            }
        }
    }

    let read = CapRights::READ;
    let rw = CapRights(CapRights::READ.0 | CapRights::WRITE.0);
    if domain::insert_root(dh, 0, CapObject::Frame { phys: pf.addr() }, read).is_err()
        || domain::insert_root(dh, 1, CapObject::Frame { phys: sf.addr() }, rw).is_err()
    {
        fail("setup_domain: insert caps falhou");
    }
    // SAFETY: pos-init_paging; va lower-half; perm user.
    let r1 = unsafe { domain::map(dh, payload_va, 0, Perm::UserRx) };
    let r2 = unsafe { domain::map(dh, stack_va, 1, Perm::UserRw) };
    if r1.is_err() || r2.is_err() {
        fail("setup_domain: domain::map falhou");
    }
    if domain::set_entry(dh, payload_va, stack_va + 0x1000).is_err() {
        fail("setup_domain: set_entry falhou");
    }
}

fn fail(msg: &str) -> ! {
    log::write_str("[kernel] ");
    log::write_str(msg);
    log::write_str("\n");
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
    };
    if table.insert_root(0, root, CapRights::ALL).is_err() {
        log::write_str("[kernel] cap err: insert_root failed\n");
        return;
    }
    // Duas subregioes derivadas + uma copia atenuada do primeiro child.
    // retype_untyped(src, dst, offset, size): LibOS escolhe offset
    // dentro do parent. Kernel valida bounds e non-overlap entre
    // irmaos (expose allocation: Engler 1995).
    if table.retype_untyped(0, 1, 0x0_0000, 0x4_0000).is_err()
        || table.retype_untyped(0, 2, 0x4_0000, 0x4_0000).is_err()
        || table.copy(1, 3, CapRights::READ).is_err()
    {
        log::write_str("[kernel] cap err: derivation failed\n");
        return;
    }
    log::write_str("[kernel] cap root + 3 descendants created\n");

    // Revoke global: apaga TODOS os descendentes da raiz.
    if table.revoke(0).is_err() {
        log::write_str("[kernel] cap err: revoke failed\n");
        return;
    }
    // Raiz sobrevive; slots 1..3 ficam vazios.
    use crate::cap::CapError;
    let root_ok = table.lookup(0).is_ok();
    let descendentes_limpos = [1u16, 2, 3]
        .iter()
        .all(|&s| table.lookup(s) == Err(CapError::SlotEmpty));
    if root_ok && descendentes_limpos {
        log::write_str("[kernel] global revoke ok; root intact\n");
    } else {
        log::write_str("[kernel] global revoke INCOHERENT\n");
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
            log::write_str("[kernel] physmap err: out of frames\n");
            return;
        }
    };
    // SAFETY: pos-init_paging, map_kernel_page e a API correta. VA e
    // phys alinhados a 4 KiB (frame.addr() vem de PhysFrame alinhado;
    // DEMO_VA termina em zeros).
    let r = unsafe { mm::map_kernel_page(DEMO_VA, frame.addr(), mm::Perm::Rw) };
    if r.is_err() {
        log::write_str("[kernel] physmap err: map_kernel_page failed\n");
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
            log::write_str("[kernel] physmap ok: map+physmap views coherent\n");
        } else {
            log::write_str("[kernel] physmap INCOHERENT\n");
        }
    }
}

/// Imprime "[kernel] free frames: N of T" no log serial.
fn log_frame_stats() {
    log::write_str("[kernel] free frames: ");
    log_usize(mm::free_count());
    log::write_str(" of ");
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
            log::write_str("[kernel] frame freed; free: ");
            log_usize(mm::free_count());
            log::write_str("\n");
        }
        None => log::write_str("[kernel] no free frames!\n"),
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
