# Exoverum

Exokernel written in Rust for x86_64. Uncompromising focus on security, a
minimal TCB, and a capability model inspired by seL4 / EROS / KeyKOS. The
kernel exports **mechanism, not policy** (Engler, Kaashoek, O'Toole 1995):
physical resources and protection primitives only; every abstraction —
allocators, schedulers, IPC protocols, filesystems — lives in user-space
LibOSes. The goal is an academic OS offering isolated LibOSes on top of an
extremely lean core, prioritizing `#![forbid(unsafe_code)]` whenever possible
and documenting every exception.

**Reference sources**: Engler-1995 (MIT Aegis / ExOS) for exokernel philosophy
and the *protection vs. management* split; seL4 / EROS / KeyKOS for the
capability model and CDT-based revoke.

## Status

Hard code budget: total Rust source stays at **≤ 5k LoC**. Current footprint
is roughly 3.3k LoC (kernel ~2.1k, bootloader ~1.1k, shared ABI crate ~80).

Phases below are the roadmap from boot to a usable LibOS. Each phase only
delivers *mechanism*: schedulers, IPC protocols, filesystems and any other
abstraction live in user-space LibOSes (Engler-1995 §3 — *protection vs.
management*).

- **Phase 1 — boot & traps** (done). UEFI bootloader loads and validates the
  kernel image, captures the firmware memory map, leaves boot services and
  jumps to the kernel entry. The kernel installs its own descriptor and
  interrupt tables and brings serial logging up.

- **Phase 2 — physical memory** (done). Bitmap frame allocator built from
  the firmware memory map, with the first 1 MiB unconditionally reserved.

- **Phase 3 — paging** (done). The kernel builds its own higher-half page
  tables with **W^X enforced per section**, drops the firmware identity
  map, and exposes a direct-map view of physical RAM so any frame can be
  inspected or mutated later in the boot. **No kernel heap** by design
  (Engler-1995 §3.1: exokernels export primitive resources; LibOSes build
  dynamic memory). Kernel internals use only statically-sized state and
  capability-mediated retype over frames.

- **Phase 4 — capabilities** (done). A **flat capability table** with a
  Capability Derivation Tree for **global revoke**: revoking any
  capability atomically invalidates every derivation descending from it,
  across every process. Per-cap rights attenuation, retype from
  `Untyped`, copy and delete are all in place.

  > The flat table is a deliberate v1. It can evolve to a CSpace graph
  > (CNodes pointing to CNodes, seL4-style) later **without changing any
  > public operation**, but that evolution is optional and may never
  > happen — we'll switch only if a concrete need arises.

- **Phase 5a — Thread Control Blocks & cooperative yield** (done). The
  Thread Control Block (the *kernel object*, not to be confused with TCB
  = Trusted Computing Base) is a statically-sized kernel object with a
  guarded per-thread stack: a stack overflow becomes a fault, never silent
  corruption. A single primitive — cooperative `yield_to` — performs the
  context switch.

  **No run queue, no scheduling policy in the kernel.** Round-robin,
  priority, EDF, lottery, gang scheduling, all of it lives in the LibOS.
  Different LibOSes can run incompatible policies side-by-side.

- **Phase 5b — periodic timer & IRQ stub** (done; full preemption
  deferred). The local APIC is up and a one-shot timer is wired to a
  dedicated interrupt vector. The current handler is a stub: it logs and
  rearms.

  The full *upcall* path — handing the remaining quantum to a
  LibOS-registered entry point — lands together with user-mode in
  Phase 7, reusing the same machinery as syscalls (separate stack,
  saving the full register state, the privilege-boundary dance). When
  that arrives, failing to respond within a fixed deadline triggers
  fail-stop (security > liveness).

- **Phase 6 — Protected Control Transfer** (pending). The kernel does
  not define IPC abstractions. Per Engler-1995 it provides only the
  minimum mechanism for protected cross-domain control transfer;
  LibOSes build RPC, message passing, shared memory, sockets and
  condvars on top. Three primitives are reserved:

  - **Protected control transfer**: atomic switch of protection domain
    (address space + capability space), jumping to a previously
    registered entry on a pre-allocated stack. Optionally donates the
    remaining quantum, enabling sub-microsecond cross-domain calls
    without going through the scheduler.
  - **Single-bit idempotent events**: signal/wait with **no payload,
    no queue, no priority**. LibOSes layer notifications, semaphores
    and condvars on top.
  - **Mediated capability transfer between domains**, preserving the
    derivation tree and rights attenuation; the existing global revoke
    already cuts the whole sub-tree.

  The kernel guarantees only capability validation, domain isolation
  and correct context switch. Message formats, buffering, synchronization
  models and RPC protocols are out of scope by design.

- **Phase 7 — user-mode & first LibOS** (pending). Ring-3 isolation, a
  syscall surface over the existing capability primitives, the pieces
  deferred from Phases 5b/6 (preemption with full context switch, the
  protected control transfer primitives), and a first LibOS executing
  on top.

- **Phase 8 — hardening & verification** (pending). Security hardening,
  adversarial testing, cross-VM and bare-metal validation.

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
  src/mm/               frame, paging (+ unsafe boundary in mod.rs)
  src/cap.rs            capabilities flat-table + CDT + global revoke
  src/thread.rs         Thread Control Blocks + spawn + yield_to (Phase 5a)
  src/arch/x86_64/context.rs  switch_context (#[unsafe(naked)] + SysV)
  src/arch/x86_64/apic.rs     LAPIC init + timer one-shot + EOI (Phase 5b)
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
[kernel] physmap ok: map+physmap view coerentes
[kernel] cap root + 3 descendentes criados
[kernel] revoke global ok; raiz intacta
[kernel] apic ok; armando timer
[kernel] timer tick                         <-- LAPIC IRQ 0x40
[kernel] timer tick
[kernel] timer tick
[kernel] timer demo done; 3 ticks observados
[kernel] threads spawned; yield_to A
[kernel] thread A1                          <-- 6 cooperative
[kernel] thread B1                          <-- context switches
[kernel] thread A2
[kernel] thread B2
[kernel] thread A3
[kernel] thread B3; threads done
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
