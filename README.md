# Exoverum

Exokernel written in Rust for x86_64. Uncompromising focus on security, a
minimal TCB, and a capability model inspired by seL4 / EROS / KeyKOS. The goal
is an academic OS offering isolated LibOSes on top of an extremely lean core,
prioritizing `#![forbid(unsafe_code)]` whenever possible and documenting every
exception.

## Status

- **Overall code budget (hard cap)**: keep overall Rust code at **<= 6k Rust LoC**.
- **Current kernel size (approx.)**: ~1.6k Rust LoC.
- **Current bootloader size (approx.)**: ~1.1k Rust LoC.
- **Phase 1 — boot & traps**: UEFI bootloader (ELF load, identity PT, memory
  map capture, ExitBootServices), kernel entry, GDT+TSS, IDT, serial logging.
- **Phase 2 — physical memory**: bitmap frame allocator parsing the UEFI
  memory map, with unconditional reservation of the first 1 MiB.
- **Phase 3a — paging**: kernel builds its own 4 KiB PML4, enforces W^X
  per section (`.text` RX, `.rodata` RO, `.data/.bss` RW+NX), enables NX via
  EFER, switches CR3. Kernel stack relocated to `.bss` via `lea` inline asm
  before any function call to survive the CR3 swap.
- **Phase 3b — heap**: 1 MiB bump allocator mapped RW+NX right after the
  kernel image. No `alloc` crate yet; safe API `KERNEL_HEAP.alloc_bytes`.
- **Phase 3c — higher-half**: kernel linked at `0xFFFF_FFFF_8020_0000`; the
  bootloader augments the active UEFI PML4 with a higher-half mapping (PML4[511]
  chain, 4 KiB pages, CR0.WP toggled for the in-place update) then jumps to
  the higher-half entry. The kernel then builds its own PML4 with **no**
  identity (higher-half + heap only) and switches CR3, permanently dropping
  the low-memory aliasing.
- **Phase 4 — capabilities (mechanism)**: flat-table CSpace (v1) with a
  Capability Derivation Tree (CDT) for **global revoke**. Kernel objects
  are referenced by `CapSlot` indexes; per-cap rights attenuation;
  `insert_root`/`copy`/`delete`/`revoke`/`retype_untyped`/`lookup`. Only
  `Untyped` object today; `Tcb`, `Frame`, `Endpoint`, `Notification` slot
  in as new `CapObject` variants in later phases without ABI change. The
  flat-table representation can later be swapped for a seL4-style graph
  (CNodes pointing to CNodes) while keeping every public operation intact.
  **Revoke is recursive over the CDT**: revoking any capability atomically
  invalidates every derivation descending from it — no access can outlive
  its root, across processes. Host-verified (14 focused tests) and smoke-
  tested at boot in the `demo_caps` flow.
- **Phase 5 — threads & minimal preemption** (next): `Tcb` kernel object,
  timer interrupt (APIC/HPET), context save/restore, and a **basic run
  queue** with **upcalls** to the LibOS when a quantum ends or a TCB blocks.
  The kernel provides only the *mechanism* (timer, switch, queue); policy
  (priority, fairness, real-time, cooperative) lives entirely in the LibOS.
  LibOSes drive the next-TCB decision via `yield_to(cap_tcb)` or by
  answering a quantum-end upcall.
- **Phase 6 — IPC** (pending): `Endpoint` (synchronous rendezvous) and
  `Notification` (asynchronous, bitmask signalling), with `send/recv/
  call/reply`. Messages carry typed caps (transfer via CDT link) so rights
  and revoke semantics are preserved across IPC.
- **Phase 7 — isolation & LibOS runtime** (pending): user-mode isolation,
  syscall/capability boundary, and initial LibOS execution model.
- **Phase 8 — hardening & verification** (pending): security hardening,
  adversarial testing, and cross-VM/bare-metal validation.

## Layout

```text
.cargo/config.toml      Targets (UEFI, bare-metal) + rustflags
Cargo.toml              Workspace + hardened release profile
Makefile                build / image / run / run-debug / test / clean
crates/bootinfo/        ABI crate (repr(C), forbid(unsafe_code))
bootloader/             UEFI PE binary
  src/main.rs           efi_main shim
  src/lib.rs            logic (panic handler, BootInfo assembly)
  src/elf.rs            ELF64 parser + validation (W^X, PT_LOAD)
  src/platform/uefi.rs  all UEFI FFI / unsafe (PML4 augment, CR0.WP toggle)
  src/platform/serial.rs  16550 UART driver
  src/crypto/sha256.rs  SHA-256 (pure safe Rust)
kernel/                 Bare-metal ELF binary
  src/main.rs           kernel_start (extern "sysv64") shim
  src/lib.rs            library (host-testable)
  src/kmain.rs          phased init
  src/log.rs, panic.rs  logging + panic
  src/arch/x86_64/      cpu / gdt / idt / serial (unsafe isolated)
  src/mm/               frame, paging, heap (+ unsafe boundary in mod.rs)
  src/cap.rs            capabilities flat-table + CDT + global revoke
  linker.ld             kernel layout (VMA 0xFFFFFFFF80200000, LMA 0x200000)
```

## Requirements

- `rustup` + component `rust-src` (for `-Zbuild-std`)
- `qemu-system-x86_64`, `edk2-ovmf` (x64), `mtools`, `dosfstools`, GNU `make`

## Build & run

```sh
make           # build bootloader + kernel + compose ESP image
make run       # boot in QEMU (serial -> stdout)
make run-debug # same, with -d int,cpu_reset -s -S (gdb on :1234)
make test      # host unit tests (frame allocator, ELF parser, ...)
make clean
```

On `make run` the expected serial trace is:

```text
[boot] efi_entry
[boot] carregando kernel.elf
[boot] validando ELF
[boot] copiando PT_LOAD para enderecos fisicos
[boot] ExitBootServices
[boot] salto para o kernel
[kernel] hello
[kernel] gdt+tss ok
[kernel] idt ok
[kernel] mm.ptr=0x... len=... desc_size=48
[kernel] frames livres: N de M
[kernel] alloc frame @ 0x00000000001XXXXX   <-- always >= 1 MiB
[kernel] frame devolvido; livres: N
[kernel] paging ativo; cr3=0x...           <-- higher-half-only PML4
[kernel] heap alloc @ 0xFFFFFFFF802XXXXX   <-- higher-half VMA
[kernel] heap read/write ok
[kernel] cap root + 3 descendentes criados
[kernel] revoke global ok; raiz intacta
[kernel] fase 4 completa; halt
```

## Security rules (binding)

- No external crates. Every dependency enlarges the TCB.
- `unsafe` minimal, isolated in dedicated modules, each block documented with
  a `SAFETY:` comment stating the invariant. High-level modules declare
  `#![forbid(unsafe_code)]`.
- ABI boundary types use `#[repr(C)]` (see `crates/bootinfo`).
- Hardened release profile: `opt-level="z"`, `lto="fat"`, `codegen-units=1`,
  `panic="abort"`, `strip=symbols`, `overflow-checks=true`.

## License

[The Unlicense](https://unlicense.org/).
