/*
 * Linker script do kernel Exoverum (higher-half).
 *
 * VMA: 0xFFFFFFFF80200000 (kernel roda no topo do espaco de enderecamento,
 * deixando o low-half inteiro para LibOS/userland). LMA: 0x200000 (endereco
 * fisico onde o bootloader copia os PT_LOAD). A relacao `virt = phys +
 * KERNEL_VMA_OFFSET` com offset 0xFFFFFFFF80000000 eh fixa e replicada no
 * kernel (mm/mod.rs) como `KERNEL_VMA_OFFSET`.
 *
 * Secoes separadas por 4 KiB para permitir W^X por secao. Stack de 64 KiB
 * embutida em .bss: o entry stub (main.rs) troca RSP para `__kernel_stack_top`
 * antes da primeira chamada de funcao, para sobreviver ao drop do identity
 * mapping durante `mm::init_paging`.
 */

ENTRY(kernel_start)
OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)

KERNEL_LMA = 0x200000;
KERNEL_VMA = 0xFFFFFFFF80200000;
KERNEL_STACK_SIZE = 0x10000;

SECTIONS {
    . = KERNEL_VMA;

    __kernel_image_start = .;

    .text : AT(ADDR(.text) - KERNEL_VMA + KERNEL_LMA) ALIGN(0x1000) {
        __text_start = .;
        *(.text.boot)
        *(.text .text.*)
        . = ALIGN(0x1000);
        __text_end = .;
    }

    .rodata : AT(ADDR(.rodata) - KERNEL_VMA + KERNEL_LMA) ALIGN(0x1000) {
        __rodata_start = .;
        *(.rodata .rodata.*)
        . = ALIGN(0x1000);
        __rodata_end = .;
    }

    .data : AT(ADDR(.data) - KERNEL_VMA + KERNEL_LMA) ALIGN(0x1000) {
        __data_start = .;
        *(.data .data.*)
        . = ALIGN(0x1000);
        __data_end = .;
    }

    .bss : AT(ADDR(.bss) - KERNEL_VMA + KERNEL_LMA) ALIGN(0x1000) {
        __bss_start = .;
        *(COMMON)
        *(.bss .bss.*)

        /* Stack inicial do kernel; usado pelo entry stub em main.rs. */
        . = ALIGN(16);
        __kernel_stack_bottom = .;
        . += KERNEL_STACK_SIZE;
        __kernel_stack_top = .;

        . = ALIGN(0x1000);
        __bss_end = .;
    }

    __kernel_image_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame.*)
        *(.debug_frame .debug_frame.*)
    }
}
