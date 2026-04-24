/*
 * Linker script do kernel Exoverum.
 *
 * Layout minimo: kernel identity-mapped em 2 MiB (0x200000), area baixa ja
 * reservada pelo bootloader via AllocatePages. Uma unica secao de carga
 * contendo text/rodata/data/bss, alinhadas a 4 KiB para facilitar paginacao
 * futura. Uma stack inicial de 64 KiB e embutida em .bss para que o kernel
 * tenha RSP valido assim que salta no entry.
 *
 * ENTRY aponta para kernel_start (definido em src/main.rs). O bootloader
 * le o e_entry do ELF apos copiar as secoes PT_LOAD para seus p_paddr.
 */

ENTRY(kernel_start)
OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)

KERNEL_BASE = 0x200000;
KERNEL_STACK_SIZE = 0x10000;

SECTIONS {
    . = KERNEL_BASE;

    __kernel_image_start = .;

    .text : ALIGN(0x1000) {
        __text_start = .;
        *(.text.boot)
        *(.text .text.*)
        . = ALIGN(0x1000);
        __text_end = .;
    }

    .rodata : ALIGN(0x1000) {
        __rodata_start = .;
        *(.rodata .rodata.*)
        . = ALIGN(0x1000);
        __rodata_end = .;
    }

    .data : ALIGN(0x1000) {
        __data_start = .;
        *(.data .data.*)
        . = ALIGN(0x1000);
        __data_end = .;
    }

    .bss : ALIGN(0x1000) {
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
