//! GDT + TSS para long mode x86_64.
//!
//! Layout da GDT (selectors entre parenteses; ordem fixada por SYSRET:
//! ele exige user-data em STAR_HIGH+8 e user-code em STAR_HIGH+16, com
//! STAR_HIGH = 0x10 implicando user-data 0x18 e user-code 0x20):
//!   0 (0x00) null
//!   1 (0x08) kernel code  DPL=0  L=1
//!   2 (0x10) kernel data  DPL=0
//!   3 (0x18) user data    DPL=3
//!   4 (0x20) user code    DPL=3  L=1
//!   5-6 (0x28) TSS descriptor de 16 bytes
//!
//! TSS guarda stacks de IRQ/excecao. Por ora so IST1 (double fault) recebe
//! uma stack dedicada; RSP0 sera preenchido em 7a.2 (entrada de SYSCALL
//! precisa de stack de kernel quando viermos de ring 3).
//!
//! User segments (`USER_CS` e `USER_DS`) ja sao expostos com RPL=3
//! embutido. Eles sao consumidos por `iretq` (entrada inicial em ring 3,
//! 7a.3) e por SYSRET (retorno rapido, 7a.2).
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
/// User code segment com RPL=3 ja embutido; consumido por `iretq`/SYSRET.
pub const USER_CS: u16 = 0x20 | 3;
/// User data/stack segment com RPL=3 ja embutido.
pub const USER_DS: u16 = 0x18 | 3;
pub const TSS_SELECTOR: u16 = 0x28;

// Const-asserts: protejo o layout dos descriptors contra regressao.
// Cada acesso isola um campo no descriptor de 8 bytes (Intel SDM 3A 3.4.5):
//   bit 47    = P (present)
//   bits 45-46= DPL
//   bit 44    = S (1 = code/data, 0 = system)
//   bit 53    = L (long mode, so para code)
//
// Se algum bit for trocado por engano, o build quebra com mensagem clara
// em vez de gerar um GP fault em runtime.
const _: () = {
    // Kernel code: P=1, DPL=0, S=1, L=1
    assert!((GDT_KERNEL_CODE >> 47) & 1 == 1, "kernel code: P");
    assert!((GDT_KERNEL_CODE >> 45) & 0b11 == 0, "kernel code: DPL");
    assert!((GDT_KERNEL_CODE >> 44) & 1 == 1, "kernel code: S");
    assert!((GDT_KERNEL_CODE >> 53) & 1 == 1, "kernel code: L");
    // Kernel data: P=1, DPL=0, S=1
    assert!((GDT_KERNEL_DATA >> 47) & 1 == 1, "kernel data: P");
    assert!((GDT_KERNEL_DATA >> 45) & 0b11 == 0, "kernel data: DPL");
    assert!((GDT_KERNEL_DATA >> 44) & 1 == 1, "kernel data: S");
    // User code: P=1, DPL=3, S=1, L=1
    assert!((GDT_USER_CODE >> 47) & 1 == 1, "user code: P");
    assert!((GDT_USER_CODE >> 45) & 0b11 == 0b11, "user code: DPL");
    assert!((GDT_USER_CODE >> 44) & 1 == 1, "user code: S");
    assert!((GDT_USER_CODE >> 53) & 1 == 1, "user code: L");
    // User data: P=1, DPL=3, S=1
    assert!((GDT_USER_DATA >> 47) & 1 == 1, "user data: P");
    assert!((GDT_USER_DATA >> 45) & 0b11 == 0b11, "user data: DPL");
    assert!((GDT_USER_DATA >> 44) & 1 == 1, "user data: S");
    // SYSRET impoe user-data = STAR_HIGH+8 e user-code = STAR_HIGH+16.
    // Se trocarmos a ordem da GDT, este assert falha antes do boot.
    assert!(USER_CS as u64 - 3 == (USER_DS as u64 - 3) + 8, "SYSRET layout");
};

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

/// Define o RSP0 do TSS — a stack que a CPU carrega ao receber uma
/// interrupcao/syscall vinda de ring 3. Sem isso, INT 0x80 a partir
/// de userland causa #DF (CPU tenta empilhar o frame de excecao numa
/// stack DPL=3 invalida).
///
/// Idempotente; pode ser chamado a qualquer momento, mas tipicamente
/// uma vez antes de entrar em ring 3 pela primeira vez.
pub fn set_rsp0(rsp0: u64) {
    // SAFETY: kernel single-core; escrita exclusiva em TSS pos-init.
    // TR ja foi carregado por `init`; CPU le RSP0 do TSS apontado por
    // TR a cada transicao de privilegio.
    unsafe {
        let tss = core::ptr::addr_of_mut!(TSS);
        (*tss).rsp0 = rsp0;
    }
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
