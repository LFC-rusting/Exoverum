//! Binario do kernel Exoverum.
//!
//! Apenas o entry `kernel_start`; toda a logica vive na biblioteca `kernel`
//! (src/lib.rs). Isso permite testar modulos safe no host sem precisar do
//! entry bare-metal.

#![no_std]
#![no_main]

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
    #[no_mangle]
    pub extern "sysv64" fn kernel_start(bootinfo: *const BootInfo) -> ! {
        // SAFETY:
        // - `__kernel_stack_top` e definido pelo linker, 16 KiB-alinhado,
        //   dentro de .bss (mapeado tanto pelo identity UEFI quanto pelo
        //   PML4 do kernel).
        // - `call` empurra um endereco de retorno para satisfazer a
        //   invariante ABI de `RSP % 16 == 8` na entrada de `kmain::start`.
        // - `bootinfo` fica em `rdi` (sysv64, primeiro arg) entre o asm e
        //   a chamada; `options(noreturn)` desabilita epilogo.
        // - Esta e a unica invocacao de `kmain::start` por boot.
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
