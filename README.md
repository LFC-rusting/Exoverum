# Exoverum

Exoverum é um exokernel escrito em Rust para x86_64, com foco absoluto em segurança, TCB mínima e adoção de um modelo de capabilities inspirado em seL4/EROS/KeyKOS. O objetivo é construir um sistema operacional acadêmico (TCC) que oferece LibOSs isolados sobre um núcleo extremamente enxuto, priorizando `#![forbid(unsafe_code)]` sempre que possível e documentando qualquer exceção.

O repositório atual contém apenas a fundação do bootloader UEFI, o esqueleto do kernel e o crate de `BootInfo`. O pipeline ainda não foi testado de ponta a ponta: estamos consolidando especificações e invariantes antes de expor fluxos de build públicos. Contribuições são bem-vindas desde que respeitem as regras essenciais: nada de dependências externas desnecessárias, mantenha o código mínimo e explique impactos na superfície de confiança.

Licença: [The Unlicense](https://unlicense.org/).
