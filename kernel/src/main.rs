//! Binario do kernel Exoverum.
//!
//! Apenas o entry `kernel_start`; toda a logica vive na biblioteca `kernel`
//! (src/lib.rs). Isso permite testar modulos safe no host sem precisar do
//! entry bare-metal.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

// Entry point so existe em builds bare-metal (target_os = "none"). Em builds
// de host (cargo test, rust-analyzer default) o arquivo fica vazio para nao
// referenciar `kernel::kmain`, que esta gated fora. Evita falsos erros de
// analise estatica e mantem `cargo check` limpo nos dois targets.
#[cfg(target_os = "none")]
mod entry {
    use bootinfo::BootInfo;

    // Stack embutida no .bss do kernel via linker.ld. Necessaria porque o
    // bootloader deixa RSP apontando para a stack UEFI, que nao sera mais
    // mapeada apos a troca de CR3 para o PML4 do kernel.
    extern "C" {
        static __kernel_stack_top: u8;
    }

    /// Entry chamado pelo bootloader.
    ///
    /// **ABI `sysv64` explicita**: o bootloader roda em target UEFI
    /// (`extern "C"` == Windows x64, args em RCX/RDX/...), mas o kernel
    /// roda em bare-metal (`extern "C"` == SysV, args em RDI/RSI/...). Sem
    /// fixar a convencao, o ponteiro de `bootinfo` chega em registrador
    /// errado e o kernel dereferencia lixo.
    ///
    /// **Troca de stack**: antes de chamar `kmain::start`, pula para
    /// `__kernel_stack_top` via inline asm. Fase 3 substitui o PML4 UEFI
    /// por um novo que mapeia apenas `.text/.rodata/.data/.bss`; a stack
    /// original (UEFI) nao estaria mapeada.
    ///
    /// # Safety
    ///
    /// Funcao `unsafe` porque seu uso indevido **causa UB diretamente**
    /// (regra `unsafe-rust §9`):
    /// - `bootinfo` deve apontar para `BootInfo` valido em LoaderData
    ///   sobrevivente a ExitBootServices, com `MemoryMap.ptr/len/desc_size`
    ///   coerentes. Ponteiro nulo e tratado em `kmain::start`; outros
    ///   valores invalidos resultam em deref de lixo.
    /// - Invocada uma unica vez por boot. Reentrar = corrompe `static mut`
    ///   do alocador global.
    /// - Caller deve garantir CR3 com identity map UEFI ainda vigente
    ///   (kernel ainda nao trocou para seu proprio PML4).
    #[no_mangle]
    pub unsafe extern "sysv64" fn kernel_start(bootinfo: *const BootInfo) -> ! {
        // SAFETY:
        // - `__kernel_stack_top` definido pelo linker (`linker.ld`), 16 KiB-
        //   alinhado, em `.bss` (mapeado pelo identity UEFI e pelo PML4 do
        //   kernel construido em `mm::init_paging`).
        // - `call` empurra return address satisfazendo a invariante SysV
        //   `RSP % 16 == 8` na entrada de `kmain::start`.
        // - `bootinfo` fica em `rdi` (primeiro arg sysv64) atravessando
        //   asm + chamada; `options(noreturn)` indica que nao retornamos.
        // - `kmain::start` e `unsafe fn`; chamada satisfaz o contrato
        //   propagando o `bootinfo` recebido (ja documentado acima).
        unsafe {
            core::arch::asm!(
                // `lea` RIP-relative carrega o ENDERECO do simbolo no
                // registrador. `mov rsp, {top}` seria interpretado como
                // load de memoria em [top] (Intel syntax do asm! Rust).
                "lea rsp, [rip + {top}]",
                "call {f}",
                "ud2",
                top = sym __kernel_stack_top,
                f = sym kernel::kmain::start,
                in("rdi") bootinfo,
                options(noreturn),
            );
        }
    }
}
