# Exoverum

Exoverum is an exokernel written in Rust for x86_64, with an uncompromising focus on security, a minimal TCB, and a capability model inspired by seL4/EROS/KeyKOS. The goal is to build an academic operating system that offers isolated LibOSes on top of an extremely lean core, prioritizing `#![forbid(unsafe_code)]` whenever possible and documenting every exception.

This repository currently contains only the UEFI bootloader foundation, the kernel skeleton, and the `BootInfo` crate. The pipeline has not yet been tested end to end; I am consolidating specifications and invariants before exposing public build flows.

License: [The Unlicense](https://unlicense.org/).
