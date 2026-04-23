//! GDT + TSS para long mode x86_64.
//!
//! Layout da GDT (selectors entre parenteses; ordem preservada para
//! compatibilidade com SYSCALL/SYSRET em fases futuras):
//!   0 (0x00) null
//!   1 (0x08) kernel code  DPL=0  L=1
//!   2 (0x10) kernel data  DPL=0
//!   3 (0x18) user data    DPL=3
//!   4 (0x20) user code    DPL=3  L=1
//!   5-6 (0x28) TSS descriptor de 16 bytes
//!
//! TSS guarda stacks de IRQ/excecao. Por ora so IST1 (double fault) recebe
//! uma stack dedicada; RSP0 e demais slots ficam em zero ate termos
//! userland (fase 7).
//!
//! Invariante: `init` e chamado uma unica vez em kmain, antes de qualquer
//! outra thread ou interrupcao. Por isso o acesso a `GDT`/`TSS` via
//! `static mut` e seguro (nenhum reader concorrente).

use core::arch::asm;
use core::mem::size_of;

const GDT_LEN: usize = 7;

// Valores canonicos (OSDev SDM 3A 3.4.5). Cada constante e um descriptor
// de 8 bytes ja codificado: limite 0xFFFFF, base 0, L=1 quando aplicavel.
const GDT_NULL: u64 = 0;
const GDT_KERNEL_CODE: u64 = 0x00AF_9A00_0000_FFFF;
const GDT_KERNEL_DATA: u64 = 0x00CF_9200_0000_FFFF;
const GDT_USER_DATA: u64 = 0x00CF_F200_0000_FFFF;
const GDT_USER_CODE: u64 = 0x00AF_FA00_0000_FFFF;

/// Selectors expostos para uso por IDT e futuros handlers.
pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
pub const TSS_SELECTOR: u16 = 0x28;

static mut GDT: [u64; GDT_LEN] = [
    GDT_NULL,
    GDT_KERNEL_CODE,
    GDT_KERNEL_DATA,
    GDT_USER_DATA,
    GDT_USER_CODE,
    0, // TSS low  (preenchido em init)
    0, // TSS high (preenchido em init)
];

#[repr(C, packed)]
struct Tss {
    reserved0: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    reserved1: u64,
    ist1: u64,
    ist2: u64,
    ist3: u64,
    ist4: u64,
    ist5: u64,
    ist6: u64,
    ist7: u64,
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

const TSS_SIZE: u16 = size_of::<Tss>() as u16;

static mut TSS: Tss = Tss {
    reserved0: 0,
    rsp0: 0,
    rsp1: 0,
    rsp2: 0,
    reserved1: 0,
    ist1: 0,
    ist2: 0,
    ist3: 0,
    ist4: 0,
    ist5: 0,
    ist6: 0,
    ist7: 0,
    reserved2: 0,
    reserved3: 0,
    iomap_base: TSS_SIZE,
};

// Stack dedicada ao handler de double fault (apontada via IST1).
const IST_STACK_SIZE: usize = 16 * 1024;
static mut DF_STACK: [u8; IST_STACK_SIZE] = [0; IST_STACK_SIZE];

#[repr(C, packed)]
struct GdtPtr {
    limit: u16,
    base: u64,
}

/// Inicializa GDT+TSS e carrega no core atual.
///
/// Apos esta chamada:
///   - CS = KERNEL_CS (0x08)
///   - SS/DS/ES/FS/GS = KERNEL_DS (0x10)
///   - TR = TSS_SELECTOR (0x28)
pub fn init() {
    // Calculo enderecos das statics; `addr_of(_mut)!` evita formar refs a
    // statics mutaveis e satisfaz o lint `static_mut_refs`.
    let tss_base = core::ptr::addr_of!(TSS) as u64;
    let df_stack_top =
        (core::ptr::addr_of!(DF_STACK) as u64) + IST_STACK_SIZE as u64;

    // SAFETY: `init` roda uma unica vez; nenhum reader concorrente de TSS
    // porque ainda nao carregamos a GDT nova. Escrita via ponteiro bruto
    // evita criar referencia mutavel a static.
    unsafe {
        let tss_ptr = core::ptr::addr_of_mut!(TSS);
        (*tss_ptr).ist1 = df_stack_top;
    }

    // Codifico o descriptor de TSS (16 bytes). Intel SDM 3A 7.2.3.
    // - access = 0x89: P=1, DPL=0, S=0, Type=0b1001 (Available 64-bit TSS)
    // - flags  = 0x0: G=0, L=0, D/B=0, AVL=0 (limite em bytes)
    let limit = (TSS_SIZE - 1) as u64;
    let base = tss_base;
    let desc_low: u64 = (limit & 0xFFFF)
        | ((base & 0x00FF_FFFF) << 16)
        | (0x89u64 << 40)
        | (((limit >> 16) & 0xF) << 48)
        | (((base >> 24) & 0xFF) << 56);
    let desc_high: u64 = base >> 32;

    // SAFETY: GDT ainda nao carregada; unica escrita concorrente e feita
    // por esta funcao chamada uma vez.
    unsafe {
        let gdt_ptr = core::ptr::addr_of_mut!(GDT) as *mut u64;
        gdt_ptr.add(5).write(desc_low);
        gdt_ptr.add(6).write(desc_high);
    }

    let gdt_base = core::ptr::addr_of!(GDT) as u64;
    let gdt_ptr = GdtPtr {
        limit: (size_of::<[u64; GDT_LEN]>() - 1) as u16,
        base: gdt_base,
    };

    // SAFETY: sequencia padrao Intel SDM 3A 3.4.5: `lgdt` carrega a nova
    // GDT; far return recarrega CS; movs recarregam demais selectores.
    // `ltr` carrega TSS. Todas as instrucoes sao privilegiadas mas validas
    // em ring0. Entradas da GDT ja estao escritas acima.
    unsafe {
        asm!(
            "lgdt [{ptr}]",
            "push {cs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov ds, {ds:x}",
            "mov es, {ds:x}",
            "mov fs, {ds:x}",
            "mov gs, {ds:x}",
            "mov ss, {ds:x}",
            ptr = in(reg) &gdt_ptr,
            cs = const KERNEL_CS as u64,
            ds = in(reg) KERNEL_DS,
            tmp = lateout(reg) _,
            options(preserves_flags),
        );

        asm!(
            "ltr {sel:x}",
            sel = in(reg) TSS_SELECTOR,
            options(nomem, nostack, preserves_flags),
        );
    }
}
