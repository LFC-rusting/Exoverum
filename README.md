# Exoverum

Exokernel written in Rust for x86_64 UEFI. Uncompromising focus on security, a
minimal Trusted Computer Base (TCB), and a capability model inspired by seL4, EROS, and KeyKOS.
The kernel exports **mechanism, not policy** (Engler, Kaashoek, O'Toole 1995):
physical resources and protection primitives only; every abstraction —
allocators, schedulers, IPC protocols, filesystems — lives in user-space
LibOSes.

The goal is to develop an academic **exokernel** that serves as a well-documented reference
for building such systems from scratch. While **monolithic** and **microkernel**
architectures are supported by numerous modern, open-source implementations with extensive
educational material, there is a clear lack of contemporary, fully open, and pedagogically
structured **exokernel** projects. This gap significantly limits the practical study, reproducibility,
and dissemination of **exokernel** design principles.

**Reference sources**: Engler-1995 (MIT Aegis / ExOS) for exokernel philosophy
and the *protection vs. management* split; seL4, EROS, and KeyKOS for the
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
- **Mechanism only, not policy.** Schedulers, IPC protocols, filesystems,
  page-replacement strategies, name spaces — all in user-space.
- **Hardware exposed, not abstracted.** Physical names (frame numbers,
  IRQ vectors, MSRs) flow through the public API; the kernel guards
  resources via capabilities, it does not virtualize them.

## Architectural conformance

Exoverum is audited against the canonical exokernel literature:

- **Engler, Kaashoek, O'Toole 1995** — *Exokernel: An Operating System
  Architecture for Application-Level Resource Management* (SOSP’95).
- **Kaashoek et al. 1997** — *Application Performance and Flexibility
  on Exokernel Systems* (SOSP’97).

Kaashoek–1997 §3.1 distills five principles. The table below shows how
the kernel implements each one.

| # | Principle | Status | Where |
|---|-----------|--------|-------|
| 1 | **Separate protection and management** | strict | the kernel only audits (W^X in `domain::map`, CDT in `revoke`, rights in `cap_grant`); no allocator, scheduler, file-system or IPC protocol lives in kernel space |
| 2 | **Expose allocation** | strict | `retype_untyped(src, dst, offset, size)` — the LibOS chooses *both* the offset inside the parent and the size; the kernel only checks bounds and sibling non-overlap. No watermark, no kernel policy on placement |
| 3 | **Expose names** | strict | capabilities carry physical addresses (`Frame{phys}`, `Untyped{base, size}`) and dense numeric handles (`Domain{handle}`); no virtual translations |
| 4 | **Expose revocation** | strict | `revoke` (local CDT) and `revoke_granted` (cross-CSpace) atomically remove every derived capability. Affected domains discover the loss *synchronously* on their next invocation of the now-empty slot (`lookup` returns `SlotEmpty`). No upcall is imposed by the kernel — detection and response are LibOS policy |
| 5 | **Expose information** | strict | events delivered via `Notification` (u64 signalword, `poll_notify` reads+clears); LAPIC timer fires route to a LibOS-chosen Notification bit. LibOS learns of elapsed time, revoked grants and any other event by polling; no kernel-imposed upcall |

Kaashoek–1997 §3.3 (*protected sharing*) is covered by `cap_grant` plus
the monotonic rights attenuation invariant. Mutual-trust sharing
works today; UDFs, wakeup predicates and software regions are
*policy* and live in the LibOS.

## Status

The exokernel is **architecturally complete**. All eight phases of
the roadmap are merged. Hard code budget: total Rust source stays
at **≤ 4.5k Lines of Code**. Current footprint is:

| Artifact | LoC |
|---|---|
| Bootloader | 1228 LoC |
| Kernel | 3185 LoC |
| Crates (bootinfo) | 58 LoC |
| **Total** | **4471 LoC** |

Of this footprint, the following lines exist only as scaffolding —
removing them yields a kernel that still boots to halt:

| Non-essential | LoC |
|---|---|
| Host tests (cap=567, frame=304, paging=193, sha256=165, bootinfo=58, elf=183, notification=100, timer=119) | 1689 |
| Demo userland (`kernel/src/arch/x86_64/userland.rs`) | 235 |
| Demo functions in `kmain.rs` (demo_userland, setup_domain, fail, demo_caps, demo_physmap, log_frame_stats, demo_alloc_free) | 179 |
| Bare-metal visual feedback (`kernel/src/fb.rs`) | 167 |
| **Total non-essential** | **2270** |

Host test suite:
**77 tests, all passing** (63 kernel + 10 bootloader + 4 bootinfo).

Phases below summarize what each milestone delivered. Every phase
delivers only *mechanism*; schedulers, IPC protocols, file systems
and any other abstraction live in user-space LibOSes (Engler–1995
§3 — *protection vs. management*).

- **Phase 1 — boot & traps.** UEFI bootloader loads and validates the
  kernel image, captures the firmware memory map, leaves boot services and
  jumps to the kernel entry. The kernel installs its own descriptor and
  interrupt tables and brings serial logging up.

- **Phase 2 — physical memory.** Bitmap frame allocator built from
  the firmware memory map, with the first 1 MiB unconditionally reserved.

  > **On "expose allocation" compliance.** The bitmap lives *inside*
  > the kernel but is only ever touched by kernel bootstrap code
  > (paging setup, framebuffer MMIO map, demos). No syscall exposes
  > `alloc_frame` to ring 3. LibOSes acquire memory exclusively through
  > `retype_untyped(src, dst, offset, size)` where the LibOS chooses
  > both offset and size; the kernel only audits bounds and sibling
  > non-overlap. This satisfies Kaashoek-1997 §3.1 principle #2:
  > allocation *policy* is exposed (LibOS-chosen), internal ownership
  > tracking (the bitmap) is implementation detail.

- **Phase 3 — paging.** The kernel builds its own higher-half page
  tables with **W^X enforced per section**, drops the firmware identity
  map, and exposes a direct-map view of physical RAM so any frame can be
  inspected or mutated later in the boot. **No kernel heap** by design
  (Engler-1995 §3.1: exokernels export primitive resources; LibOSes build
  dynamic memory). Kernel internals use only statically-sized state and
  capability-mediated retype over frames.

- **Phase 4 — capabilities.** A **flat capability table** with a
  Capability Derivation Tree for **global revoke**: revoking any
  capability atomically invalidates every derivation descending from it,
  across every process. Per-cap rights attenuation, retype from
  `Untyped`, copy and delete are all in place. Five variants:

  - `Untyped { base, size }` — raw physical region, retype-source.
  - `Frame { phys }` — 4 KiB page, mappable via `domain::map`.
  - `Domain { handle }` — ring-3 domain handle, authorizes `domain_call`.
  - `Notification { handle }` — seL4-style u64 signalword
    (`signal`=`fetch_or` requires WRITE, `poll`=`swap(0)` requires READ).
    Minimal async event mechanism; policy (poll vs block vs IPC-wrap)
    stays in LibOS.
  - `Timer` — singleton capability to arm LAPIC one-shot; delivers via
    a caller-provided `Notification` bit (see Phase 5b).

  > The flat table is a deliberate v1, not technical debt. It can evolve
  > to a CSpace graph (CNodes pointing to CNodes, seL4-style) later
  > **without changing any public operation**, but that evolution is
  > optional and may never happen — current CSpaces are 256 fixed slots
  > per domain with no sharing/dedup pressure. KISS until a concrete
  > need arises.

- **Phase 5a — Thread Control Blocks & cooperative yield.** The
  Thread Control Block (the *kernel object*, not to be confused with TCB
  = Trusted Computing Base) is a statically-sized kernel object with a
  guarded per-thread stack: a stack overflow becomes a fault, never silent
  corruption. A single primitive — cooperative `yield_to` — performs the
  context switch.

  **No run queue, no scheduling policy in the kernel.** Round-robin,
  priority, EDF, lottery, gang scheduling, all of it lives in the LibOS.
  Different LibOSes can run incompatible policies side-by-side.

- **Phase 5b — Timer capability.** An earlier draft wired up the
  LAPIC as kernel policy (always-on preemptive tick) and was
  removed. The current implementation exposes the LAPIC one-shot
  timer as a **capability**, not kernel policy:

  - `CapObject::Timer` is a singleton cap. Whoever holds it (with
    `WRITE` rights) may arm the hardware one-shot via syscall
    `timer_arm_oneshot(timer_slot, ticks, notif_slot, bits)`.
  - At fire time, the kernel's IRQ handler (vector 0x40) runs
    `timer::fire`, which signals the caller-provided `Notification`
    with `bits` via `notification::signal`, then EOIs the LAPIC.
    The handler does **not** switch domains, does **not** deliver an
    upcall, and does **not** make any scheduling decision.
  - The notified LibOS discovers the event on its next
    `poll_notify` (syscall 5). **When** to poll, **whether** to yield,
    and **which** domain runs next are all LibOS policy.

  This matches Engler-1995 §3.3 (expose events) + Kaashoek-1997 §3.1
  principle #5 (expose information): the timer *mechanism* (Initial
  Count, EOI, IRQ routing) is in the kernel; the *policy* (how often,
  what to do) is in ring 3. `arch::x86_64::lapic` holds all LAPIC
  unsafe MMIO; `timer` is a tiny target-agnostic callback shim
  (`#![forbid(unsafe_code)]`, host-testable).

  **What this does not solve.** Exoverum still has no scheduler: a
  ring-3 loop that neither polls its notification nor voluntarily
  calls another domain will monopolize the CPU, because the kernel
  does not force-switch on timer IRQ. That's deliberate — force-
  switching requires picking a next domain, i.e. policy. A future
  scheduler LibOS can hold the Timer cap, arm a periodic tick, and
  implement preemption in user-space via `domain_call`.

- **Phase 6 — Cooperative scaffolding** (subsumed by Phase 7b). The
  cooperative thread + single-bit event primitives that exercised
  `Ready` ↔ `Waiting` transitions before user-mode existed have been
  removed from the kernel. They are subsumed by ring-3 domains plus
  synchronous PCT (Engler-1995 §4).

- **Phase 7 — exokernel proper.** **Kernel mechanisms only.**
  Phase 7 does **not** create a LibOS, an OS personality, a runtime, or
  any user-space library. It only adds the kernel primitives that make
  user-space domains *possible*. Validation uses a minimal in-tree
  ring-3 payload (two domains, a few instructions each) as an
  integration smoke test, not as a LibOS. Real LibOSes, if ever built,
  live outside the kernel in their own directories and are
  substitutable; the kernel never assumes any of them.

  - **7a — Domains & exposed paging.** Ring-3 isolation,
    multiple address spaces, multiple capability spaces, page-table
    format owned by each domain (kernel only audits each PTE against
    the owning capabilities, enforces W^X/NX, and loads CR3). User GDT
    segments with const-asserts, INT 0x80 syscall path with DPL=3 gate
    and dedicated kernel stack, `Domain` object with own CR3 and own
    `CapTable`, `Frame`/`Domain` capability variants, `domain::map`
    auditing capability rights against W^X bits before writing PTEs.

  - **7b — Control transfer & cross-domain capabilities.**
    A complete `UserContext` (15 GPRs + iret frame) is saved on the
    syscall stack and exposed as `*mut UserContext` to the kernel
    dispatcher; the dispatcher rewrites it in-place to switch domain,
    and the trampoline's `iretq` carries whatever ring-3 state the
    kernel committed.

    Delivered:

    - **PCT sync** — `domain_call(target_dh)` (syscall 2) saves the
      caller's `UserContext`, validates a `CapObject::Domain { handle:
      target }` in the caller's CSpace, switches CR3 and resumes the
      callee at its programmed entry; `domain_reply(value)` (syscall
      3) restores the caller with `RAX = value`.
    - **`cap_grant`** — transfers a capability between distinct CSpaces
      with monotonic rights attenuation. The granted cap lands as a
      root in the destination CSpace; the type and the `phys`/`handle`
      payload travel unchanged.
    - **Scaffolding removed** — `thread.rs` and `event.rs` are gone
      from the kernel. Whoever runs in ring 3 implements its own
      threads and synchronization on top of PCT.

    - **`notify` / `poll_notify`** — syscalls 4 and 5, validated by
      `CapObject::Notification` in the caller's CSpace. `notify`
      (`WRITE`) does `signalword |= bits` via `fetch_or`;
      `poll_notify` (`READ`) does `swap(0)`. This is the minimal
      async-event mechanism (seL4-style). Cross-domain signalling:
      domain A `cap_grant`s a Notification cap to domain B; A polls,
      B signals. Handle space is a small static pool
      (`notification::MAX_NOTIFICATIONS = 16`).
    - **`timer_arm_oneshot`** — syscall 6. Takes a `Timer` cap + a
      `Notification` cap + tick count + bit mask. Programs LAPIC
      Initial Count; on fire, the kernel signals the notification.
      Complete description in Phase 5b.

    **No kernel-imposed upcall mechanism.** Earlier drafts shipped an
    `upcall_entry`/`upcall_stack` pair per domain plus a fifth syscall
    (`upcall_return`) so the kernel could preempt a LibOS and deliver
    timer ticks or revocation notifications from ring 0. That was
    **removed**: *when and how* a LibOS should be notified is policy,
    not mechanism. Notifications are pull-based (poll) with an opt-in
    hardware-signal path (timer IRQ → kernel bit set → LibOS polls).
    The seven syscalls (0–6) expose only primitive mechanisms; every
    higher-level abstraction lives in ring 3.

  The kernel guarantees only capability validation, domain isolation
  and correct context switch. Message formats, buffering, scheduling
  policy, file systems, processes, IPC protocols, POSIX or any other
  high-level abstraction are out of scope by design and live entirely
  in user-space code (whether structured as a LibOS or not).

- **Phase 8 — hardening & verification.** Closes the exokernel
  loop with the security primitives that finish the Engler–1995 model.

  - **Visible cross-CSpace revocation (synchronous).** A small
    parallel table (`domain::GRANTS`, capacity 32) records every
    `cap_grant`. The operation `domain::revoke_granted(src_dh,
    src_slot)` walks the table and removes each derived destination
    capability from the recipient's CSpace. The recipient notices
    synchronously on its next invocation of the slot: `lookup`
    returns `SlotEmpty`, the owning syscall (e.g. `domain::map`)
    fails, and the LibOS can react however it wants. *Mechanism is
    "the cap is gone from your CSpace"*; the response is policy.
  - **Exposed allocation in retype.** `retype_untyped(src, dst,
    offset, size)` takes both the offset within the parent and the
    new child's size from the LibOS. The kernel validates that the
    new range lies inside the parent and does not overlap any
    existing sibling. There is no in-kernel watermark (Kaashoek–1997
    §3.1 principle #2, in its strict form).
  - **Abort protocol.** Every CPU exception goes through a
    `fault_dispatch` that splits on `cs & 3`. CPL=0 means the kernel
    faulted: log + halt, security over liveness. CPL=3 means the
    active domain faulted: `domain::abort_current()` marks it
    `aborted = true`, clears `CURRENT`, and halts (a future
    scheduler will pick another LibOS instead of halting). Two naked
    trampolines (`fault_no_err_entry`, `fault_with_err_entry`) handle
    the with/without-error-code split; vectors `#DF`, `#TS`, `#NP`,
    `#SS`, `#GP`, `#PF`, `#AC`, `#CP` are routed to the with-errcode
    path.
  - **Tech debt cleanup.** `CapObject::Thread` and `CapObject::Event`
    — dead since Phase 7b removed the scaffolding — are gone from
    `cap.rs`. The upcall machinery (`upcall_entry`/`upcall_stack` +
    `upcall_return` syscall) is gone. The capability enum now has
    five live variants: `Untyped`, `Frame`, `Domain`, `Notification`,
    `Timer` (the last two added by Phase 4/5b re-scoping described
    above, as mechanism-only capabilities).
  - **Adversarial host tests.** `cap::tests` covers `copy` from
    empty/aliased slots, double `revoke`, out-of-range `delete`,
    `Frame`/`Domain` round-trips, `CapRights::contains` algebraic
    properties, sibling-overlap rejection on retype, and offset
    overflow defense. `notification::tests` and `timer::tests` cover
    signal/poll reset semantics, idempotence and callback overwrite.
    Total: **77 host tests, all passing** (63 kernel + 10 bootloader
    + 4 bootinfo).

  **Out of scope, deferred to LibOS work** (not the kernel):
  preemptive scheduling *policy* (who runs next on timer fire),
  async PCT (one-way `domain_send`), periodic timers built on top of
  one-shot, fairness, priority, any IPC protocol richer than PCT,
  file systems, POSIX, names. These are *policy* in the Engler-1995
  sense and cannot live in an exokernel. Note: timer and
  notification *mechanisms* are delivered (Phase 5b + Phase 4
  extension); only the *policy* of how to react to them is deferred.

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
  src/lib.rs            library root + panic handler (host-testable modules)
  src/kmain.rs          phased init (demo_userland, demo_caps, demo_physmap)
  src/fb.rs             framebuffer renderer (bare-metal only)
  src/arch/x86_64/      cpu / gdt / idt / serial / lapic / userland
                        (unsafe isolated here; only asm/MMIO/MSR lives below)
  src/mm/               frame, paging (+ unsafe boundary in mod.rs)
  src/kobj/             kernel objects (host-testable, except domain)
    cap.rs              capabilities flat-table + CDT + local revoke + host tests
                        variants: Untyped, Frame, Domain, Notification, Timer
    notification.rs     seL4-style async signalling: u64 signalword pool,
                        signal/poll/create/destroy; atomic, host-testable
    timer.rs            Timer callback shim: arms LAPIC, delivers on fire
                        via notification::signal (safe Rust, host-testable)
    domain.rs           Domain (CR3 + CSpace + saved_ctx + aborted) +
                        PCT + cap_grant + GRANTS + synchronous revoke_granted
                        + abort_current + notify/poll_notify/arm_timer helpers
  linker.ld             kernel layout (VMA 0xFFFFFFFF80200000, LMA 0x200000)
```

## Toolchain

| Tool | Built with | Minimum |
|---|---|---|
| `rustc` | 1.93.1 (2026-02-11) | 1.85 |
| `cargo` | 1.93.1 (2025-12-15) | 1.85 |

The `1.85` minimum is dictated by `edition = "2024"`-style features
used in `naked_asm!` and `#[unsafe(naked)]`. Anything older fails to
compile. We recommend tracking stable: install with `rustup default
stable` and run `rustup update` regularly. No nightly is required.

`rustup` also needs to be able to fetch the targets:

```sh
rustup target add x86_64-unknown-uefi
rustup target add x86_64-unknown-none
```

## Requirements

- `rustup` (with `stable` channel)
- `qemu-system-x86_64` and `edk2-ovmf` for `make run`
- `mtools` and `dosfstools` for assembling the FAT32 ESP image
- GNU `make` (only used to orchestrate; the kernel itself is built
  by `cargo`)

## Build & run with Make

```sh
make            # build bootloader + kernel + compose the FAT32 .img
make run        # boot in QEMU (serial -> stdout)
make run-debug  # QEMU stopped on -S -s with -d int,cpu_reset (gdb on :1234)
make test       # 65 host unit tests (cap, paging, frame, ELF, SHA-256, ...)
make clean
```

Optional knobs: `IMG_MB=64`, `OVMF_CODE=/path/to/OVMF_CODE.fd`,
`PROFILE=dev` (for an unoptimized build).

## Build & run with Cargo only

Make is just a thin orchestration layer. Everything below works
without it:

```sh
# 1. Build the bootloader (UEFI PE) and the kernel (bare-metal ELF).
cargo build --release -p bootloader                        # workspace default target = x86_64-unknown-uefi
cargo build --release -p kernel --target x86_64-unknown-none

# Or use the bundled aliases (defined in .cargo/config.toml):
cargo build-bootloader-release
cargo build-kernel-release

# 2. Run the host tests (65 tests, no QEMU needed):
cargo test-host
```

The two binaries land at:

- `target/x86_64-unknown-uefi/release/bootloader.efi`
- `target/x86_64-unknown-none/release/kernel`

To turn them into a bootable image without `make`, copy them into a
FAT32 ESP layout and assemble (this is exactly what `make image`
does):

```sh
mkdir -p target/esp/EFI/BOOT
cp target/x86_64-unknown-uefi/release/bootloader.efi target/esp/EFI/BOOT/BOOTX64.EFI
cp target/x86_64-unknown-none/release/kernel        target/esp/EFI/BOOT/kernel.elf
dd if=/dev/zero of=target/exoverum.img bs=1M count=33 status=none
mkfs.fat -F 32 -n EXOVERUM target/exoverum.img
mcopy -i target/exoverum.img -s target/esp/EFI ::/
```

Then feed it to QEMU directly:

```sh
qemu-system-x86_64 \
    -machine q35 -m 256M -display none -serial stdio -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd \
    -drive if=pflash,format=raw,file=/path/to/writable/OVMF_VARS.fd \
    -drive format=raw,file=target/exoverum.img
```

## Expected serial trace

The `make run` (or the equivalent QEMU invocation above) produces:

```text
[boot] efi_entry
[boot] loading kernel.elf
[boot] validating ELF
[boot] copying PT_LOAD to physical addresses
[boot] ExitBootServices
[boot] jumping to kernel
[kernel] hello
[kernel] gdt+tss ok
[kernel] idt ok
[kernel] mm.ptr=0x... len=... desc_size=48
[kernel] free frames: N of M
[kernel] alloc frame @ 0x00000000001XXXXX   <-- always >= 1 MiB
[kernel] frame freed; free: N
[kernel] paging active; cr3=0x...           <-- higher-half PML4
[kernel] lapic ok                            <-- MMIO mapped, enabled, timer masked
[kernel] physmap ok: map+physmap views coherent
[kernel] cap root + 3 descendants created
[kernel] global revoke ok; root intact
[kernel] demo_userland: setup
[kernel] cap_grant A->B ok                                   <-- cross-CSpace transfer (7b)
[kernel] revoke_granted A.slot0 ok                           <-- synchronous revocation (8)
[kernel] demo_userland: enter A                              <-- iretq into ring 3 (A)
[kernel] pct_call ok                                         <-- A -> B (synchronous)
[kernel] pct_reply ok                                        <-- B.domain_reply(0x42)
[kernel] ring 3 exit; halting                                <-- A resumes, exits
```

## Build artifacts and image

After a clean release build the on-disk footprint is:

| Artifact | Path | Size |
|---|---|---|
| Bootloader | `target/x86_64-unknown-uefi/release/bootloader.efi` | ~5.5 KiB |
| Kernel ELF | `target/x86_64-unknown-none/release/kernel` | ~76 KiB |
| Disk image | `target/exoverum.img` (FAT32) | 33 MiB |

The two binaries together are about **82 KiB**; the disk image is
33 MiB only because UEFI requires a FAT32 ESP and `mkfs.fat` refuses
to format anything smaller. Override with `make IMG_MB=N` if you
need a bigger ESP for future LibOSes; the binaries don't grow.

## Portability across virtual machines and bare metal

`target/exoverum.img` is a raw, byte-for-byte UEFI-bootable disk.
It boots as-is on **QEMU/KVM** (and any other firmware that accepts
raw images). For other VM hypervisors, convert the same image:

```sh
# VirtualBox (.vdi or .vmdk)
VBoxManage convertfromraw target/exoverum.img target/exoverum.vdi --format VDI

# VMware Workstation/Player (.vmdk)
qemu-img convert -O vmdk target/exoverum.img target/exoverum.vmdk

# Hyper-V (.vhdx)
qemu-img convert -O vhdx target/exoverum.img target/exoverum.vhdx
```

For **bare metal**, write the image to a USB stick and boot the
machine in UEFI mode (Secure Boot off, since it is not signed):

```sh
sudo dd if=target/exoverum.img of=/dev/sdX bs=4M status=progress conv=fsync
```

In every case the firmware looks for `/EFI/BOOT/BOOTX64.EFI`,
which is exactly where the build places the bootloader. No
bootloader configuration, no GRUB, no NVRAM entry needed.

### Bare-metal visual feedback

On real hardware the serial port is rarely wired. To make the same
boot validation visible without a serial cable, the kernel renders
five fixed text lines directly to the UEFI GOP framebuffer
(`kernel/src/fb.rs`, 167 LoC, optional and removable):

```text
[OK] Bootloader.
[OK] Paging.
[OK] Caps.
[OK] Userland.
[OK] Halt.
```

Each line corresponds to a `fb::mark()` call at the same point as
the matching serial log. Five lines on screen confirms that the entire
pipeline (UEFI handoff → paging W^X → capabilities/CDT → ring 3 → syscall
exit → halt) executed end-to-end on the real CPU.

If the firmware does not expose a 32-bpp linear GOP framebuffer
the visual feedback is silently skipped; the kernel itself runs
identically and the serial trace remains the canonical proof.

## What the in-tree demo exercises

The kernel ships with a single ring-3 demo (`kmain::demo_userland`)
that drives every Phase 7 + Phase 8 mechanism through one trace:
ring-3 isolation (two domains with distinct CR3s and CSpaces),
audited paging (`domain::map` rejects `UserRw` over a
`CapRights::READ` cap), INT-0x80 syscall path with save/restore of a
full `UserContext`, `cap_grant` (A grants `Frame` to B and the kernel
records the grant), synchronous `revoke_granted` (the grant is
removed from B's CSpace — if B later invoked the slot, the syscall
would fail cleanly with `SlotEmpty`), and **synchronous PCT**: A
calls `domain_call(B)`, the kernel switches CR3 and resumes B at its
programmed entry; B replies `0x42` via `domain_reply`; A sees the
value in `RAX`, issues `exit`, and the kernel halts. Every privilege
boundary, every capability check and every state machine touched by
the protocol is covered by this demo — no kernel-imposed upcall, no
timer, no in-kernel policy.

## Security rules

- No external crates. Every dependency enlarges the TCB.
- Minimal lines of code. Every line of code is a potential vulnerability.
- `unsafe` minimal, isolated in dedicated modules, each block documented with
  a `SAFETY:` comment stating the invariant. High-level modules declare
  `#![forbid(unsafe_code)]`.
- ABI boundary types use `#[repr(C)]` (see `crates/bootinfo`).
- Linker: `--gc-sections` for the kernel (LLD) and `/OPT:REF /OPT:ICF`
  for the bootloader (LLD-link) to drop unreferenced code without
  weakening any check.
- No SSE in the kernel (`target-feature=-sse`) so interrupt handlers
  never need to save FP state.

## License

[The Unlicense](https://unlicense.org/)
