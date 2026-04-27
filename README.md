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

Hard code budget: total Rust source stays at **≤ 4.5k LoC**. Current footprint
is roughly 4.0k LoC (kernel ~2.9k, bootloader ~1.1k, shared ABI crate ~80).
Host test suite: **49 tests passing**.

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

  The kernel guarantees only capability validation, domain isolation
  and correct context switch. Message formats, buffering, scheduling
  policy, file systems, processes, IPC protocols, POSIX or any other
  high-level abstraction are out of scope by design and live entirely
  in user-space code (whether structured as a LibOS or not).

- **Phase 8 — hardening & verification** (done). Closes the exokernel
  loop with the security primitives that finish the Engler-1995 model.

  - **Visible cross-CSpace revocation.** A small parallel table
    (`domain::GRANTS`, capacity 32) records every `cap_grant`. The
    new operation `domain::revoke_granted(src_dh, src_slot)` walks
    the table, removes each derived destination capability, and
    marks the affected domain with a `pending_upcall =
    Repossession`. This is the in-kernel half of seL4-style visible
    revocation — LibOSes find out *promptly* that they have lost a
    capability, never silently or out of band.
  - **Repossession upcall (proactive).** When a domain holding a
    `pending_upcall` is next given the CPU — either via
    `domain_call` or by a timer tick — the kernel jumps to its
    `upcall_entry` with `RDI = UpcallReason` *before* the normal
    entry runs. The handler returns through `upcall_return` (syscall
    4) and execution resumes where it would have gone otherwise.
  - **Abort protocol.** Every CPU exception now goes through a
    `fault_dispatch` that splits on `cs & 3`. CPL=0 means the kernel
    faulted: log + halt, security over liveness. CPL=3 means the
    active domain faulted: `domain::abort_current(Fault)` marks it
    `aborted = true`, clears `CURRENT`, and halts (a future
    scheduler will pick another LibOS instead of halting). Two naked
    trampolines (`fault_no_err_entry`, `fault_with_err_entry`) handle
    the with/without-error-code split; vectors `#DF`, `#TS`, `#NP`,
    `#SS`, `#GP`, `#PF`, `#AC`, `#CP` are routed to the with-errcode
    path.
  - **Tech debt cleanup.** `CapObject::Thread` and `CapObject::Event`
    — dead since Phase 7b removed the scaffolding — are gone from
    `cap.rs`. The capability enum now has only the three live
    variants: `Untyped`, `Frame`, `Domain`.
  - **Adversarial host tests.** 10 new tests in `cap::tests` cover
    `copy` from empty/aliased slots, double `revoke`, out-of-range
    `delete`, `Frame`/`Domain` round-trips, and `CapRights::contains`
    algebraic properties. Total: **49 host tests, all passing**.

  **Out of scope, deferred to LibOS work** (not the kernel): async
  PCT (one-way `domain_send`), preemptive scheduling policy, deadline
  enforcement on repossession (kernel currently relies on the
  domain's own cooperative response). These are *policy* in the
  Engler-1995 sense and cannot live in an exokernel; whoever needs
  them implements them in ring 3.

  **At the end of Phase 8 the exokernel is complete.** No LibOS is
  required for the kernel to boot, validate every Phase 7 + Phase 8
  mechanism, and halt cleanly.

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
  src/cap.rs            capabilities flat-table + CDT + local revoke + 26 host tests
  src/domain.rs         Domain (CR3 + CSpace + upcall/saved_ctx + aborted/pending) +
                        PCT + cap_grant + GRANTS + revoke_granted + abort_current
  src/arch/x86_64/apic.rs      LAPIC init + timer one-shot + EOI (Phase 5b)
  src/arch/x86_64/idt.rs       IDT + fault_dispatch (Phase 8: CPL split + abort)
  src/arch/x86_64/userland.rs  ring-3 entry/exit + UserContext save/restore +
                               syscall dispatch (5 calls) + timer upcall trampoline +
                               upcall handler payload
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
[kernel] cap_grant A->B ok                                   <-- cross-CSpace transfer (7b)
[kernel] revoke_granted A.slot0 ok                           <-- visible revocation (8)
[kernel] demo_userland: enter A                              <-- iretq into ring 3 (A)
[kernel] pct_call -> upcall (repossession)                   <-- repossession upcall (8)
[kernel] pct_reply ok                                        <-- B.domain_reply after handler
[kernel] ring 3 exit; halting                                <-- A resumes, exits
```

The demo exercises every kernel mechanism added in Phases 7+8:
ring-3 isolation (domains A and B with distinct CR3s and
CSpaces), audited paging (`domain::map` rejects `UserRw` over a
`CapRights::READ` cap), INT-0x80 syscall path with
save/restore of a full `UserContext`, `cap_grant` (A grants
`Frame` to B and the kernel records the grant), `revoke_granted`
(kernel revokes the grant and arms a `pending_upcall =
Repossession` on B), and the **proactive upcall delivery**: when
A finally calls `domain_call(B)`, the kernel notices B's pending
upcall and dispatches B's `upcall_entry` (with `RDI = 2`)
*before* its normal entry. The handler invokes `upcall_return`,
which restores the pre-upcall context and runs B's normal entry,
which in turn replies `0x42` to A via `domain_reply`. A resumes,
exits, and the kernel halts. Every privilege boundary, every
capability check and every state machine touched by the protocol
is covered by this single ~25-line demo.

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
