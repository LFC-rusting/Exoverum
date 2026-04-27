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

## Non-negotiable principles

- **The kernel never depends on a specific LibOS.** Removing every LibOS
  (and the in-kernel demos) still leaves a kernel that boots to halt.
- **Multiple LibOSes coexist.** No LibOS is privileged or assumed by the
  kernel. Anything that would only make sense given one specific LibOS
  belongs in that LibOS, not in the kernel.
- **No POSIX / Unix in the kernel.** No file descriptors, no `signal(2)`
  semantics, no `pthread_*`, no `mmap`, no `fork`/`exec`. POSIX or Unix
  applications, if needed at all, are emulated by a LibOS.
- **Mechanism, not policy.** Schedulers, IPC protocols, filesystems,
  page-replacement strategies, name spaces — all in user-space.
- **Hardware exposed, not abstracted.** Physical names (frame numbers,
  IRQ vectors, MSRs) flow through the public API; the kernel guards
  resources via capabilities, it does not virtualize them.

## Status

Hard code budget: total Rust source stays at **≤ 5k LoC**. Current footprint
is roughly 3.7k LoC (kernel ~2.6k, bootloader ~1.1k, shared ABI crate ~80).

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

- **Phase 6 — Cooperative scaffolding** (removed in Phase 7b). The
  cooperative thread + single-bit event primitives that exercised
  `Ready` ↔ `Waiting` transitions before user-mode existed have been
  removed from the kernel. They are subsumed by ring-3 domains plus
  PCT/upcalls (Aegis-style, Engler-1995 §4).

- **Phase 7 — exokernel proper** (done). **Kernel mechanisms only.**
  Phase 7 does **not** create a LibOS, an OS personality, a runtime, or
  any user-space library. It only adds the kernel primitives that make
  user-space domains *possible*. Validation uses a minimal in-tree
  ring-3 payload (two domains, a few instructions each) as an
  integration smoke test, not as a LibOS. Real LibOSes, if ever built,
  live outside the kernel in their own directories and are
  substitutable; the kernel never assumes any of them.

  - **7a — Domains & exposed paging** (done). Ring-3 isolation,
    multiple address spaces, multiple capability spaces, page-table
    format owned by each domain (kernel only audits each PTE against
    the owning capabilities, enforces W^X/NX, and loads CR3). User GDT
    segments with const-asserts, INT 0x80 syscall path with DPL=3 gate
    and dedicated kernel stack, `Domain` object with own CR3 and own
    `CapTable`, `Frame`/`Domain` capability variants, `domain::map`
    auditing capability rights against W^X bits before writing PTEs.

  - **7b — Upcalls, control transfer & cross-domain capabilities** (done).
    A complete `UserContext` (15 GPRs + iret frame) is saved on the
    syscall stack and exposed as `*mut UserContext` to the kernel
    dispatcher; the dispatcher rewrites it in-place to switch domain
    or to deliver an upcall, and the trampoline's `iretq` carries
    whatever ring-3 state the kernel committed.

    Delivered:

    - **PCT sync** — `domain_call(target_dh)` (syscall 2) saves the
      caller's `UserContext`, validates a `CapObject::Domain { handle:
      target }` in the caller's CSpace, switches CR3 and resumes the
      callee at its programmed entry; `domain_reply(value)` (syscall
      3) restores the caller with `RAX = value`.
    - **Upcall framework** — `Domain` exposes `upcall_entry`/
      `upcall_stack`. Whenever the timer (or any future fault/repossession
      vector) interrupts ring 3, the kernel saves `pre_upcall_ctx` and
      rewrites the iret frame to dispatch into the domain's handler;
      the handler returns via `upcall_return` (syscall 4). The timer
      handler differentiates `CPL=0` (kernel: log + EOI + rearm) from
      `CPL=3` (domain: deliver upcall) using the saved `cs & 3` bit.
    - **`cap_grant`** — transfers a capability between distinct CSpaces
      with monotonic rights attenuation. The granted cap lands as a
      root in the destination CSpace; the type and the `phys`/`handle`
      payload travel unchanged.
    - **Scaffolding removed** — `thread.rs` and `event.rs` are gone
      from the kernel. Whoever runs in ring 3 implements its own
      threads and synchronization on top of PCT and upcalls.

    Async PCT and visible cross-CSpace revocation are deferred to
    Phase 8 (hardening): a global CDT spanning CSpaces is the natural
    home for both, and they share the repossession-upcall machinery.

  The kernel guarantees only capability validation, domain isolation
  and correct context switch. Message formats, buffering, scheduling
  policy, file systems, processes, IPC protocols, POSIX or any other
  high-level abstraction are out of scope by design and live entirely
  in user-space code (whether structured as a LibOS or not).

- **Phase 8 — hardening & verification** (pending). Security hardening,
  adversarial testing, abort protocol for uncooperative ring-3 domains,
  cross-VM and bare-metal validation. **At the end of Phase 8 the
  exokernel is complete, with no LibOS required.**

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
  src/cap.rs            capabilities flat-table + CDT + global revoke (local)
  src/domain.rs         Domain (CR3 + CSpace + entry/upcall/saved_ctx) + PCT + cap_grant
  src/arch/x86_64/apic.rs      LAPIC init + timer one-shot + EOI (Phase 5b)
  src/arch/x86_64/userland.rs  ring-3 entry/exit + UserContext save/restore +
                               syscall dispatch (5 calls) + timer upcall trampoline
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
[kernel] demo_userland: setup
[kernel] cap_grant A->B ok                                   <-- cross-CSpace transfer
[kernel] demo_userland: enter A                              <-- iretq into ring 3 (A)
[kernel] pct_call ok                                         <-- A.domain_call(B)
[kernel] pct_reply ok                                        <-- B.domain_reply(0x42)
[kernel] ring 3 exit; halting                                <-- A resumes, exits
```

The demo exercises every Phase 7 mechanism: ring-3 isolation
(domains A and B with distinct CR3s and CSpaces), audited paging
(`domain::map` rejects `UserRw` over a `CapRights::READ` cap),
`cap_grant` (A grants `Frame` to B), PCT sync (`domain_call` /
`domain_reply` with `RAX=0x42` carried back to A), and the timer
handler differentiating ring-0 ticks from ring-3 ticks. The
upcall framework (`UserContext` save/restore, `pre_upcall_ctx`,
`syscall=4 upcall_return`) is wired end-to-end and exercised by
the ring-0 timer path; ring-3 timer upcall is a no-op until a
domain calls `set_upcall(...)`. Phase 8 will land a domain that
actually subscribes to upcalls.

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
