# Exoverum — orquestracao top-level.
#
# Filosofia: Cargo manda nos crates Rust; Make orquestra o que esta fora
# disso (montagem da imagem FAT32 da ESP, QEMU, limpeza). Cada alvo faz
# uma coisa e so uma coisa (suckless/KISS).
#
# Alvos principais:
#   make            -> build + imagem ($(DISK_IMG))
#   make run        -> sobe QEMU com a imagem
#   make run-debug  -> QEMU parado em -S -s (gdb na 1234)
#   make test       -> testes host dos crates safe
#   make clean      -> remove artefatos
#
# Variaveis ajustaveis (via env ou `make VAR=...`):
#   PROFILE    = dev | release (default: release)
#   OVMF_CODE  = caminho para OVMF_CODE.fd
#   OVMF_VARS  = caminho para OVMF_VARS.fd (copiado para escrita)
#   QEMU       = binario do QEMU a usar

# --- Configuracao ---
PROFILE          ?= release
TARGET_DIR       ?= target
QEMU             ?= qemu-system-x86_64

# Caminhos tipicos: Arch (edk2-ovmf), Debian/Ubuntu (ovmf), Fedora (edk2-ovmf).
# Se nenhum existir, o usuario deve definir OVMF_CODE/OVMF_VARS manualmente.
OVMF_CODE ?= $(firstword $(wildcard \
    /usr/share/edk2/x64/OVMF_CODE.4m.fd \
    /usr/share/edk2-ovmf/x64/OVMF_CODE.fd \
    /usr/share/OVMF/OVMF_CODE.fd \
    /usr/share/ovmf/x64/OVMF_CODE.fd))
OVMF_VARS ?= $(firstword $(wildcard \
    /usr/share/edk2/x64/OVMF_VARS.4m.fd \
    /usr/share/edk2-ovmf/x64/OVMF_VARS.fd \
    /usr/share/OVMF/OVMF_VARS.fd \
    /usr/share/ovmf/x64/OVMF_VARS.fd))

ifeq ($(PROFILE),release)
    CARGO_FLAGS := --release
    KERNEL_BUILD_DIR     := $(TARGET_DIR)/x86_64-unknown-none/release
    BOOTLOADER_BUILD_DIR := $(TARGET_DIR)/x86_64-unknown-uefi/release
else
    CARGO_FLAGS :=
    KERNEL_BUILD_DIR     := $(TARGET_DIR)/x86_64-unknown-none/debug
    BOOTLOADER_BUILD_DIR := $(TARGET_DIR)/x86_64-unknown-uefi/debug
endif

KERNEL_ELF     := $(KERNEL_BUILD_DIR)/kernel
BOOTLOADER_EFI := $(BOOTLOADER_BUILD_DIR)/bootloader.efi
ESP_DIR        := $(TARGET_DIR)/esp
DISK_IMG       := $(TARGET_DIR)/exoverum.img
OVMF_VARS_RW   := $(TARGET_DIR)/OVMF_VARS.fd

# --- Targets ---
.PHONY: all kernel bootloader esp image run run-debug test clean help

all: image

help:
	@echo "Alvos disponiveis:"
	@echo "  make              -> build completo + imagem bootavel"
	@echo "  make kernel       -> so kernel.elf"
	@echo "  make bootloader   -> so bootloader.efi"
	@echo "  make image        -> monta disk.img com ESP + binarios"
	@echo "  make run          -> executa no QEMU"
	@echo "  make run-debug    -> QEMU parado em gdb (porta 1234)"
	@echo "  make test         -> cargo test-host"
	@echo "  make clean        -> remove artefatos"

kernel:
	cargo build $(CARGO_FLAGS) -p kernel --target x86_64-unknown-none

bootloader:
	cargo build $(CARGO_FLAGS) -p bootloader

# ESP: arvore de arquivos que sera copiada para dentro do FAT32. Usamos o
# nome canonico `BOOTX64.EFI` em `/EFI/BOOT/` para o firmware encontrar
# sem precisar de NVRAM/boot-entry.
$(ESP_DIR): kernel bootloader
	mkdir -p $(ESP_DIR)/EFI/BOOT
	cp $(BOOTLOADER_EFI) $(ESP_DIR)/EFI/BOOT/BOOTX64.EFI
	cp $(KERNEL_ELF)     $(ESP_DIR)/EFI/BOOT/kernel.elf
	@touch $(ESP_DIR)

esp: $(ESP_DIR)

# Imagem FAT32 de 64 MiB. Poderiamos usar partition table GPT para ficar
# mais fiel a UEFI, mas QEMU+OVMF aceita uma particao raw. Futuramente
# dividimos em ESP + root se precisarmos.
$(DISK_IMG): $(ESP_DIR)
	dd if=/dev/zero of=$(DISK_IMG) bs=1M count=64 status=none
	mkfs.fat -F 32 -n EXOVERUM $(DISK_IMG) > /dev/null
	mcopy -i $(DISK_IMG) -s $(ESP_DIR)/EFI ::/

image: $(DISK_IMG)

# Copia OVMF_VARS para um arquivo escrivel (OVMF_VARS original e readonly).
$(OVMF_VARS_RW): | $(TARGET_DIR)
	@if [ -z "$(OVMF_VARS)" ]; then \
	    echo "erro: OVMF_VARS nao encontrado. Instale edk2-ovmf ou defina OVMF_VARS=..."; \
	    exit 1; \
	fi
	cp $(OVMF_VARS) $(OVMF_VARS_RW)

$(TARGET_DIR):
	mkdir -p $(TARGET_DIR)

# Flags QEMU:
#   -machine q35       : chipset moderno (UEFI precisa)
#   -m 256M            : RAM inicial
#   -serial stdio      : nossa saida de log do bootloader/kernel
#   -display none      : headless
#   -no-reboot         : se o kernel fizer triple fault, ver erro em vez de loop
#   -d int,cpu_reset   : (run-debug) loga excecoes do CPU
QEMU_FLAGS := \
    -machine q35 -m 256M \
    -drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
    -drive if=pflash,format=raw,file=$(OVMF_VARS_RW) \
    -drive format=raw,file=$(DISK_IMG) \
    -serial stdio -display none -no-reboot

run: image $(OVMF_VARS_RW)
	@if [ -z "$(OVMF_CODE)" ]; then \
	    echo "erro: OVMF_CODE nao encontrado. Instale edk2-ovmf ou defina OVMF_CODE=..."; \
	    exit 1; \
	fi
	$(QEMU) $(QEMU_FLAGS)

run-debug: image $(OVMF_VARS_RW)
	$(QEMU) $(QEMU_FLAGS) -d int,cpu_reset -s -S

test:
	cargo test-host

clean:
	cargo clean
	rm -rf $(ESP_DIR) $(DISK_IMG) $(OVMF_VARS_RW)
