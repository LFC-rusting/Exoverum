//! Camada UEFI: FFI mínimo e fluxo de boot `efi_entry`.
//!
//! Todo o `unsafe` do bootloader está concentrado aqui e em `serial`. Cada bloco
//! `unsafe` carrega um comentário SAFETY. Sempre que possível delegamos parsing
//! e verificação para o núcleo safe (`crate::elf`, `crate::crypto`).

use bootinfo::MemoryMap;
use core::ffi::c_void;
use core::mem;
use core::ptr::NonNull;
use core::slice;

use crate::{
    build_bootinfo,
    elf::{kernel_entry_from_elf, kernel_phys_range_from_elf, parse_elf_header, parse_ph, PT_LOAD},
    platform::serial,
    process_kernel_image,
    BootError,
    KernelImage,
    PhysRange,
};

// -----------------------
// Tipos FFI UEFI
// -----------------------

pub type EfiHandle = *mut c_void;

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Status(pub usize);

impl Status {
    pub const SUCCESS: Status = Status(0);
}

const EFI_ERROR_BIT: usize = 1 << (usize::BITS as usize - 1);
const EFI_BUFFER_TOO_SMALL: Status = Status(EFI_ERROR_BIT | 5);

const PAGE_SIZE: u64 = 4096;
const PTE_PRESENT: u64 = 1;
const PTE_WRITABLE: u64 = 1 << 1;
/// Teto de cobertura da identity map: 4 page tables * 512 entradas * 4 KiB = 8 MiB.
/// Se o kernel+stack ultrapassarem isso, `build_identity_pagetables` retorna erro
/// em vez de escrever fora do buffer.
const MAX_PT_PAGES: usize = 4;

fn status_success(status: Status) -> bool {
    status.0 == Status::SUCCESS.0
}

fn status_is_buffer_too_small(status: Status) -> bool {
    status.0 == EFI_BUFFER_TOO_SMALL.0
}

fn align_down(val: u64, align: u64) -> u64 {
    val & !(align - 1)
}

/// `align_up` com saturação: protege contra overflow quando `val` é próximo de
/// `u64::MAX`, respeitando a regra de não depender de comportamento não verificado
/// (o profile release desliga overflow-checks).
fn align_up(val: u64, align: u64) -> u64 {
    align_down(val.saturating_add(align - 1), align)
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[repr(C)]
pub struct EfiTableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct EfiSystemTable {
    pub hdr: EfiTableHeader,
    pub firmware_vendor: *const u16,
    pub firmware_revision: u32,
    pub console_in_handle: usize,
    pub con_in: *const c_void,
    pub console_out_handle: usize,
    pub con_out: *const c_void,
    pub standard_error_handle: usize,
    pub std_err: *const c_void,
    pub runtime_services: *const EfiRuntimeServices,
    pub boot_services: *const EfiBootServices,
}

#[repr(C)]
pub struct EfiSimpleTextOutputProtocol {
    pub reset: usize,
    pub output_string: unsafe extern "efiapi" fn(this: *mut EfiSimpleTextOutputProtocol, string: *const u16) -> Status,
    pub test_string: usize,
    pub query_mode: usize,
    pub set_mode: usize,
    pub set_attribute: usize,
    pub clear_screen: usize,
    pub set_cursor_position: usize,
    pub enable_cursor: usize,
    pub mode: *mut c_void,
}

#[repr(C)]
pub struct EfiRuntimeServices {
    pub hdr: EfiTableHeader,
}

/// `EFI_BOOT_SERVICES` em ordem estrita da UEFI 2.9 (secao 4.4). Qualquer campo
/// nao utilizado fica como `usize` placeholder para preservar o layout binario
/// exato. Alterar esta ordem QUEBRA todas as chamadas indiretas.
#[repr(C)]
pub struct EfiBootServices {
    pub hdr: EfiTableHeader,
    // Task Priority Services
    pub raise_tpl: usize,
    pub restore_tpl: usize,
    // Memory Services
    pub allocate_pages: unsafe extern "efiapi" fn(
        allocate_type: u32,
        memory_type: u32,
        pages: usize,
        memory: *mut u64,
    ) -> Status,
    pub free_pages: usize,
    pub get_memory_map: unsafe extern "efiapi" fn(
        memory_map_size: *mut usize,
        memory_map: *mut EfiMemoryDescriptor,
        map_key: *mut usize,
        descriptor_size: *mut usize,
        descriptor_version: *mut u32,
    ) -> Status,
    pub allocate_pool: unsafe extern "efiapi" fn(pool_type: u32, size: usize, buf: *mut *mut c_void) -> Status,
    pub free_pool: unsafe extern "efiapi" fn(buf: *mut c_void) -> Status,
    // Event & Timer Services
    pub create_event: usize,
    pub set_timer: usize,
    pub wait_for_event: usize,
    pub signal_event: usize,
    pub close_event: usize,
    pub check_event: usize,
    // Protocol Handler Services
    pub install_protocol_interface: usize,
    pub reinstall_protocol_interface: usize,
    pub uninstall_protocol_interface: usize,
    pub handle_protocol: usize,
    pub reserved: usize,
    pub register_protocol_notify: usize,
    pub locate_handle: usize,
    pub locate_device_path: usize,
    pub install_configuration_table: usize,
    // Image Services
    pub load_image: usize,
    pub start_image: usize,
    pub exit: usize,
    pub unload_image: usize,
    pub exit_boot_services: unsafe extern "efiapi" fn(image_handle: EfiHandle, map_key: usize) -> Status,
    // Misc Services
    pub get_next_monotonic_count: usize,
    pub stall: usize,
    pub set_watchdog_timer: usize,
    // DriverSupport Services
    pub connect_controller: usize,
    pub disconnect_controller: usize,
    // Open and Close Protocol Services
    pub open_protocol: unsafe extern "efiapi" fn(
        handle: EfiHandle,
        protocol: *const Guid,
        interface: *mut *mut c_void,
        agent_handle: EfiHandle,
        controller_handle: EfiHandle,
        attributes: u32,
    ) -> Status,
    pub close_protocol: usize,
    pub open_protocol_information: usize,
    // Library Services
    pub protocols_per_handle: usize,
    pub locate_handle_buffer: usize,
    pub locate_protocol: usize,
    pub install_multiple_protocol_interfaces: usize,
    pub uninstall_multiple_protocol_interfaces: usize,
    // 32-bit CRC Services
    pub calculate_crc32: usize,
    // Misc Services
    pub copy_mem: usize,
    pub set_mem: usize,
    pub create_event_ex: usize,
}

#[repr(C)]
pub struct EfiMemoryDescriptor {
    pub typ: u32,
    pub pad: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

pub const EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL: u32 = 0x0000_0001;

pub const EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID: Guid = Guid {
    data1: 0x0964e5b22,
    data2: 0x6459,
    data3: 0x11d2,
    data4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

pub const EFI_LOADED_IMAGE_PROTOCOL_GUID: Guid = Guid {
    data1: 0x5b1b31a1,
    data2: 0x9562,
    data3: 0x11d2,
    data4: [0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

pub const EFI_FILE_INFO_GUID: Guid = Guid {
    data1: 0x09576e92,
    data2: 0x6d3f,
    data3: 0x11d2,
    data4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

pub const EFI_FILE_MODE_READ: u64 = 0x0000_0000_0000_0001;
pub const EFI_LOADER_CODE: u32 = 3;
pub const EFI_LOADER_DATA: u32 = 4;

// EFI_ALLOCATE_TYPE (UEFI 2.9 secao 7.2.1).
pub const EFI_ALLOCATE_ANY_PAGES: u32 = 0;
pub const EFI_ALLOCATE_MAX_ADDRESS: u32 = 1;
pub const EFI_ALLOCATE_ADDRESS: u32 = 2;

pub const KERNEL_PATH_UTF16: [u16; 21] = [
    0x005c, 0x0045, 0x0046, 0x0049, 0x005c, 0x0042, 0x004f, 0x004f, 0x0054, 0x005c,
    0x006b, 0x0065, 0x0072, 0x006e, 0x0065, 0x006c, 0x002e, 0x0065, 0x006c, 0x0066,
    0x0000,
];

const BOOT_MSG_OK: [u16; 15] = [
    0x005b, 0x004f, 0x004b, 0x005d, 0x0020, 0x0042, 0x006f, 0x006f, 0x0074, 0x006c, 0x006f,
    0x0061, 0x0064, 0x000d, 0x0000,
];

#[repr(C)]
pub struct EfiLoadedImageProtocol {
    pub revision: u32,
    pub parent_handle: EfiHandle,
    pub system_table: *const EfiSystemTable,
    pub device_handle: EfiHandle,
    pub file_path: *const c_void,
    pub reserved: *const c_void,
    pub load_options_size: u32,
    pub load_options: *const c_void,
    pub image_base: *const c_void,
    pub image_size: u64,
    pub image_code_type: u32,
    pub image_data_type: u32,
    pub unload: usize,
}

#[repr(C)]
pub struct EfiSimpleFileSystemProtocol {
    pub revision: u64,
    pub open_volume: unsafe extern "efiapi" fn(
        this: *mut EfiSimpleFileSystemProtocol,
        root: *mut *mut EfiFileProtocol,
    ) -> Status,
}

#[repr(C)]
pub struct EfiFileProtocol {
    pub revision: u64,
    pub open: unsafe extern "efiapi" fn(
        this: *mut EfiFileProtocol,
        new_handle: *mut *mut EfiFileProtocol,
        file_name: *const u16,
        open_mode: u64,
        attributes: u64,
    ) -> Status,
    pub close: unsafe extern "efiapi" fn(this: *mut EfiFileProtocol) -> Status,
    pub delete: usize,
    pub read: unsafe extern "efiapi" fn(this: *mut EfiFileProtocol, buffer_size: *mut usize, buffer: *mut c_void) -> Status,
    pub write: usize,
    pub get_position: usize,
    pub set_position: usize,
    pub get_info: unsafe extern "efiapi" fn(
        this: *mut EfiFileProtocol,
        information_type: *const Guid,
        buffer_size: *mut usize,
        buffer: *mut c_void,
    ) -> Status,
    pub set_info: usize,
    pub flush: usize,
}

#[repr(C)]
pub struct EfiFileInfo {
    pub size: u64,
    pub file_size: u64,
    pub physical_size: u64,
    pub create_time: [u16; 8],
    pub last_access_time: [u16; 8],
    pub modification_time: [u16; 8],
    pub attribute: u64,
    pub file_name: [u16; 1],
}

// -----------------------
// Helpers de alto nível
// -----------------------

pub fn get_memory_map_real(
    bs: NonNull<EfiBootServices>,
    buffer: *mut EfiMemoryDescriptor,
    buffer_len: usize,
) -> Result<(MemoryMap, usize, usize), BootError> {
    let mut map_size = buffer_len;
    let mut map_key: usize = 0;
    let mut desc_size: usize = 0;
    let mut desc_version: u32 = 0;

    // SAFETY: chamada UEFI GetMemoryMap com ponteiros válidos e buffer alocado
    // pelo chamador com `buffer_len` bytes via AllocatePool.
    let status = unsafe {
        (bs.as_ref().get_memory_map)(
            &mut map_size as *mut usize,
            buffer,
            &mut map_key as *mut usize,
            &mut desc_size as *mut usize,
            &mut desc_version as *mut u32,
        )
    };

    if !status_success(status) {
        return Err(BootError::MemoryMapUnavailable);
    }

    Ok((
        MemoryMap {
            ptr: buffer as u64,
            len: map_size as u64,
        },
        map_key,
        desc_size,
    ))
}

pub fn load_kernel_real(
    bs: NonNull<EfiBootServices>,
    image_handle: EfiHandle,
    path_utf16: &[u16],
) -> Result<&'static [u8], BootError> {
    let loaded = open_protocol::<EfiLoadedImageProtocol>(bs, image_handle, &EFI_LOADED_IMAGE_PROTOCOL_GUID, image_handle)?;
    // SAFETY: `loaded` veio de OpenProtocol com sucesso; campos do protocolo são válidos enquanto não fechado.
    let device = unsafe { loaded.as_ref().device_handle };
    let sfs = open_protocol::<EfiSimpleFileSystemProtocol>(bs, device, &EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID, image_handle)?;

    let mut root: *mut EfiFileProtocol = core::ptr::null_mut();
    // SAFETY: sfs válido; open_volume preenche `root` se retornar sucesso.
    let status = unsafe { (sfs.as_ref().open_volume)(sfs.as_ptr(), &mut root as *mut *mut EfiFileProtocol) };
    if !status_success(status) || root.is_null() {
        return Err(BootError::MissingKernel);
    }

    let mut file: *mut EfiFileProtocol = core::ptr::null_mut();
    // SAFETY: `root` válido e `path_utf16` é UTF-16 NUL-terminated conforme UEFI spec.
    let status = unsafe {
        ((*root).open)(
            root,
            &mut file as *mut *mut EfiFileProtocol,
            path_utf16.as_ptr(),
            EFI_FILE_MODE_READ,
            0,
        )
    };
    if !status_success(status) || file.is_null() {
        // SAFETY: `root` ainda válido; fechamento é a chamada de limpeza padrão.
        unsafe {
            let _ = ((*root).close)(root);
        }
        return Err(BootError::MissingKernel);
    }

    // Descobrir tamanho via GetInfo (primeira chamada intencionalmente falha com BUFFER_TOO_SMALL).
    let mut info_size: usize = 0;
    // SAFETY: `file` válido; buffer nulo é permitido para consulta de tamanho.
    let status = unsafe { ((*file).get_info)(file, &EFI_FILE_INFO_GUID, &mut info_size as *mut usize, core::ptr::null_mut()) };
    if !status_is_buffer_too_small(status) || info_size < mem::size_of::<EfiFileInfo>() {
        // SAFETY: handles ainda válidos; close é sempre seguro para limpar.
        unsafe {
            let _ = ((*file).close)(file);
            let _ = ((*root).close)(root);
        }
        return Err(BootError::MissingKernel);
    }

    let info_buf = allocate_pool(bs, info_size)?;
    // SAFETY: `info_buf` alocado via AllocatePool com `info_size` bytes.
    let status = unsafe { ((*file).get_info)(file, &EFI_FILE_INFO_GUID, &mut info_size as *mut usize, info_buf.as_ptr()) };
    if !status_success(status) {
        // SAFETY: handles válidos; free_pool aceita ponteiro devolvido por AllocatePool.
        unsafe {
            let _ = (bs.as_ref().free_pool)(info_buf.as_ptr());
            let _ = ((*file).close)(file);
            let _ = ((*root).close)(root);
        }
        return Err(BootError::MissingKernel);
    }

    // SAFETY: GetInfo retornou sucesso preenchendo `info_buf` como EfiFileInfo.
    let info = unsafe { &*(info_buf.as_ptr() as *const EfiFileInfo) };
    let file_size = info.file_size as usize;
    let kernel_buf = allocate_pool(bs, file_size)?;

    let mut read_size = file_size;
    // SAFETY: `kernel_buf` tem `file_size` bytes; UEFI Read ajusta `read_size`.
    let status = unsafe { ((*file).read)(file, &mut read_size as *mut usize, kernel_buf.as_ptr()) };
    if !status_success(status) || read_size != file_size {
        // SAFETY: limpeza padrão de todos os handles e buffers alocados.
        unsafe {
            let _ = (bs.as_ref().free_pool)(kernel_buf.as_ptr());
            let _ = (bs.as_ref().free_pool)(info_buf.as_ptr());
            let _ = ((*file).close)(file);
            let _ = ((*root).close)(root);
        }
        return Err(BootError::MissingKernel);
    }

    // SAFETY: limpeza de handles/info_buf; `kernel_buf` permanece válido até ExitBootServices.
    unsafe {
        let _ = (bs.as_ref().free_pool)(info_buf.as_ptr());
        let _ = ((*file).close)(file);
        let _ = ((*root).close)(root);
    }

    // SAFETY: `kernel_buf` aponta para `file_size` bytes alocados por AllocatePool,
    // estáveis até ExitBootServices. Trata-se efetivamente de slice 'static nesse intervalo.
    let slice = unsafe { slice::from_raw_parts(kernel_buf.as_ptr() as *const u8, file_size) };
    Ok(slice)
}

fn allocate_pool(bs: NonNull<EfiBootServices>, size: usize) -> Result<NonNull<c_void>, BootError> {
    let mut buf: *mut c_void = core::ptr::null_mut();
    // SAFETY: AllocatePool preenche `buf` com ponteiro válido em caso de sucesso.
    let status = unsafe { (bs.as_ref().allocate_pool)(EFI_LOADER_DATA, size, &mut buf as *mut *mut c_void) };
    if !status_success(status) || buf.is_null() {
        return Err(BootError::MissingKernel);
    }
    NonNull::new(buf).ok_or(BootError::MissingKernel)
}

/// Aloca `pages` paginas de 4 KiB em endereco fisico fixo `addr`. Usado para
/// mapear cada segmento PT_LOAD do kernel em seu `p_paddr` antes de pular.
///
/// Retorna erro se o firmware nao puder conceder o endereco exato (p. ex.
/// regiao reservada).
fn allocate_pages_at(
    bs: NonNull<EfiBootServices>,
    addr: u64,
    pages: usize,
    mem_type: u32,
) -> Result<(), BootError> {
    let mut target = addr;
    // SAFETY: AllocatePages(AllocateAddress) tenta alocar `pages` em
    // `target`; em sucesso preserva o endereco. Em falha retorna status
    // != SUCCESS e a regiao fica intocada.
    let status = unsafe {
        (bs.as_ref().allocate_pages)(
            EFI_ALLOCATE_ADDRESS,
            mem_type,
            pages,
            &mut target as *mut u64,
        )
    };
    if !status_success(status) || target != addr {
        return Err(BootError::MissingKernel);
    }
    Ok(())
}

/// Carrega o kernel ELF em memoria fisica: para cada PT_LOAD aloca paginas em
/// `p_paddr`, copia `filesz` bytes e zera o resto (`memsz - filesz`).
///
/// Assume que o ELF ja foi validado por `validate_kernel_elf`. Em falha nao
/// desfaz alocacoes parciais (firmware as reclama apos ExitBootServices se
/// houver; aqui tratamos como erro fatal e damos `bail`).
pub fn load_elf_segments_real(
    bs: NonNull<EfiBootServices>,
    elf: &[u8],
) -> Result<u64, BootError> {
    let hdr = parse_elf_header(elf)?;

    // Aloca um unico bloco cobrindo toda a faixa fisica do kernel. Mais
    // simples que alocar por segmento (evita overlaps de pagina entre
    // segmentos) e garante uma unica chamada AllocatePages.
    let range = kernel_phys_range_from_elf(elf)?;
    let start = align_down(range.start, PAGE_SIZE);
    let end = align_up(range.end, PAGE_SIZE);
    let total_bytes = end
        .checked_sub(start)
        .ok_or(BootError::InvalidElf)?;
    let pages = (total_bytes / PAGE_SIZE) as usize;

    allocate_pages_at(bs, start, pages, EFI_LOADER_CODE)?;

    // SAFETY: regiao recem-alocada; sem outros leitores/escritores.
    // Zero antes de copiar para que `.bss` (memsz > filesz) fique zerada
    // sem precisar de logica adicional por segmento.
    unsafe {
        core::ptr::write_bytes(
            start as *mut u8,
            0,
            total_bytes as usize,
        );
    }

    // Copia cada PT_LOAD para seu `p_paddr`.
    for i in 0..hdr.phnum {
        let ph = parse_ph(elf, hdr.phoff, hdr.phentsize, i)?;
        if ph.p_type != PT_LOAD {
            continue;
        }
        let off = ph.offset as usize;
        let sz = ph.filesz as usize;
        let end_off = off.checked_add(sz).ok_or(BootError::InvalidElf)?;
        if end_off > elf.len() {
            return Err(BootError::InvalidElf);
        }
        // SAFETY: `src` valido dentro de `elf`. Destino alocado acima e
        // pertence a regiao do kernel; sem sobreposicao com `src` (pool
        // UEFI vs. memoria recem-alocada para o kernel).
        unsafe {
            core::ptr::copy_nonoverlapping(
                elf.as_ptr().add(off),
                ph.paddr as *mut u8,
                sz,
            );
        }
    }

    Ok(hdr.entry)
}

fn open_protocol<T>(
    bs: NonNull<EfiBootServices>,
    handle: EfiHandle,
    guid: &Guid,
    agent: EfiHandle,
) -> Result<NonNull<T>, BootError> {
    let mut iface: *mut c_void = core::ptr::null_mut();
    // SAFETY: OpenProtocol exige ponteiros válidos; GUID e handle vêm do chamador.
    let status = unsafe {
        (bs.as_ref().open_protocol)(
            handle,
            guid as *const Guid,
            &mut iface as *mut *mut c_void,
            agent,
            core::ptr::null_mut(),
            EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL,
        )
    };
    if !status_success(status) || iface.is_null() {
        return Err(BootError::MissingKernel);
    }
    NonNull::new(iface as *mut T).ok_or(BootError::MissingKernel)
}

fn zero_page(bs: NonNull<EfiBootServices>) -> Result<NonNull<u64>, BootError> {
    let page = allocate_pool(bs, PAGE_SIZE as usize)?;
    // SAFETY: `page` aponta para área de pelo menos PAGE_SIZE bytes alocada via AllocatePool.
    unsafe { core::ptr::write_bytes(page.as_ptr(), 0, PAGE_SIZE as usize) };
    NonNull::new(page.as_ptr() as *mut u64).ok_or(BootError::PageTableUnavailable)
}

/// Monta page tables 4 KiB identity mapping cobrindo `kernel_phys` ∪ `stack_phys`.
/// Retorna o endereço físico do PML4. Falha se o intervalo exceder `MAX_PT_PAGES * 2 MiB`.
fn build_identity_pagetables(
    bs: NonNull<EfiBootServices>,
    kernel_phys: PhysRange,
    stack_phys: PhysRange,
) -> Result<u64, BootError> {
    let map_start = if kernel_phys.start < stack_phys.start { kernel_phys.start } else { stack_phys.start };
    let map_end = if kernel_phys.end > stack_phys.end { kernel_phys.end } else { stack_phys.end };
    let map_start = align_down(map_start, PAGE_SIZE);
    let map_end = align_up(map_end, PAGE_SIZE);

    let max_bytes = (MAX_PT_PAGES as u64) * 512 * PAGE_SIZE;
    if map_end.saturating_sub(map_start) > max_bytes {
        return Err(BootError::PageTableUnavailable);
    }

    let pml4 = zero_page(bs)?;
    let pdpt = zero_page(bs)?;
    let pd = zero_page(bs)?;

    let pml4_phys = pml4.as_ptr() as u64;
    let pdpt_phys = pdpt.as_ptr() as u64;
    let pd_phys = pd.as_ptr() as u64;

    // SAFETY: páginas alocadas e zeradas; escrevo somente as primeiras entradas com flags P|W.
    unsafe {
        *pml4.as_ptr() = pdpt_phys | PTE_PRESENT | PTE_WRITABLE;
        *pdpt.as_ptr() = pd_phys | PTE_PRESENT | PTE_WRITABLE;
    }

    let mut pt_pages: [Option<NonNull<u64>>; MAX_PT_PAGES] = [None; MAX_PT_PAGES];

    let mut addr = map_start;
    while addr < map_end {
        let pd_index = ((addr >> 21) & 0x1ff) as usize;
        if pd_index >= pt_pages.len() {
            return Err(BootError::PageTableUnavailable);
        }
        let pt = match pt_pages[pd_index] {
            Some(p) => p,
            None => {
                let p = zero_page(bs)?;
                let pt_phys = p.as_ptr() as u64;
                // SAFETY: PD alocado, `pd_index` < MAX_PT_PAGES < 512.
                unsafe {
                    *pd.as_ptr().add(pd_index) = pt_phys | PTE_PRESENT | PTE_WRITABLE;
                }
                pt_pages[pd_index] = Some(p);
                p
            }
        };
        let pt_index = ((addr >> 12) & 0x1ff) as usize;
        // SAFETY: PT existe e `pt_index` < 512; mapeamento identidade (paddr = vaddr = addr).
        unsafe {
            *pt.as_ptr().add(pt_index) = addr | PTE_PRESENT | PTE_WRITABLE;
        }
        addr = addr.saturating_add(PAGE_SIZE);
    }

    Ok(pml4_phys)
}

/// Aborta o boot logando a causa pelo serial e entrando em loop. Usada para
/// substituir `expect`/`unwrap` no caminho crítico: o firmware já saiu ou vai
/// falhar ao retornar, então a única informação útil é a mensagem no serial.
fn bail(msg: &str) -> ! {
    serial::write_str(msg);
    loop {}
}

/// Entry point UEFI interno, chamado pelo binário.
///
/// Responsabilidades:
/// 1. iniciar serial para diagnóstico;
/// 2. validar `system_table` e `boot_services`;
/// 3. carregar `kernel.elf` da ESP, validar ELF e (opcionalmente) hash;
/// 4. alocar stack, construir identity page tables 4 KiB sobre kernel+stack;
/// 5. obter memory map, chamar ExitBootServices, saltar para o entry do kernel.
pub extern "efiapi" fn efi_entry(image: EfiHandle, system_table: *mut EfiSystemTable) -> ! {
    serial::init();
    serial::write_str("[boot] efi_entry\n");

    if system_table.is_null() {
        bail("[boot] erro: system_table nulo\n");
    }
    // SAFETY: verificado não-nulo acima; o firmware garante ponteiro válido.
    let st = unsafe { &*system_table };
    let bs = match NonNull::new(st.boot_services as *mut EfiBootServices) {
        Some(b) => b,
        None => bail("[boot] erro: boot_services nulo\n"),
    };

    serial::write_str("[boot] carregando kernel.elf\n");
    let kernel = match load_kernel_real(bs, image, &KERNEL_PATH_UTF16) {
        Ok(k) => k,
        Err(_) => bail("[boot] erro: kernel.elf nao encontrado\n"),
    };

    serial::write_str("[boot] validando ELF\n");
    let img = KernelImage { elf: kernel, expected_sha256: None };
    if process_kernel_image(&img).is_err() {
        bail("[boot] erro: ELF invalido ou hash invalido\n");
    }

    let kernel_phys = match kernel_phys_range_from_elf(kernel) {
        Ok(r) => r,
        Err(_) => bail("[boot] erro: faixa fisica do kernel invalida\n"),
    };

    // Copia os segmentos PT_LOAD para seus enderecos fisicos reais via
    // AllocatePages(AllocateAddress). Necessario porque `load_kernel_real`
    // deposita o ELF em pool arbitraria; o kernel precisa estar em `p_paddr`.
    serial::write_str("[boot] copiando PT_LOAD para enderecos fisicos\n");
    let _kernel_entry = match load_elf_segments_real(bs, kernel) {
        Ok(e) => e,
        Err(_) => bail("[boot] erro: falha ao carregar PT_LOAD em paddr\n"),
    };

    const STACK_SIZE: usize = 16 * 1024;
    let stack_buf = match allocate_pool(bs, STACK_SIZE) {
        Ok(b) => b,
        Err(_) => bail("[boot] erro: falha ao alocar stack\n"),
    };
    let stack_start = stack_buf.as_ptr() as u64;
    let stack_end = stack_start.saturating_add(STACK_SIZE as u64);
    let stack_phys = PhysRange { start: stack_start, end: stack_end };

    if crate::mapping::assert_non_overlapping(&[kernel_phys, stack_phys]).is_err() {
        bail("[boot] erro: layout kernel/stack sobreposto\n");
    }

    // Preparo buffer para o memory map. Duas chamadas: a primeira obtém tamanho.
    let mut map_key: usize = 0;
    let mut desc_size: usize = 0;
    let (map_buf, map_buf_len) = {
        let mut map_size: usize = 0;
        // SAFETY: GetMemoryMap aceita buffer nulo desde que `map_size = 0`; retorna BUFFER_TOO_SMALL.
        let status = unsafe {
            (bs.as_ref().get_memory_map)(
                &mut map_size as *mut usize,
                core::ptr::null_mut(),
                &mut map_key as *mut usize,
                &mut desc_size as *mut usize,
                core::ptr::null_mut(),
            )
        };
        if !status_is_buffer_too_small(status) {
            bail("[boot] erro: GetMemoryMap nao pediu buffer\n");
        }
        let extra = desc_size.saturating_mul(2);
        let total = map_size.saturating_add(extra);
        match allocate_pool(bs, total) {
            Ok(b) => (b, total),
            Err(_) => bail("[boot] erro: falha ao alocar memory map\n"),
        }
    };

    let (mem_map, map_key, _desc_size) = match get_memory_map_real(
        bs,
        map_buf.as_ptr() as *mut EfiMemoryDescriptor,
        map_buf_len,
    ) {
        Ok(t) => t,
        Err(_) => bail("[boot] erro: GetMemoryMap falhou\n"),
    };

    let page_table_root = match build_identity_pagetables(bs, kernel_phys, stack_phys) {
        Ok(r) => r,
        Err(_) => bail("[boot] erro: falha ao montar page tables 4K\n"),
    };

    let bootinfo = build_bootinfo(mem_map, None, None, None, page_table_root, kernel_phys);

    if !st.con_out.is_null() {
        let con_out = st.con_out as *mut EfiSimpleTextOutputProtocol;
        // SAFETY: con_out vem do firmware; OutputString aceita UTF-16 NUL-terminated.
        let _ = unsafe { ((*con_out).output_string)(con_out, BOOT_MSG_OK.as_ptr()) };
    }

    serial::write_str("[boot] ExitBootServices\n");
    // SAFETY: chamada UEFI terminal; `map_key` foi obtido na última GetMemoryMap.
    let status = unsafe { (bs.as_ref().exit_boot_services)(image, map_key) };
    if !status_success(status) {
        bail("[boot] erro: ExitBootServices falhou\n");
    }
    serial::write_str("[boot] salto para o kernel\n");

    let entry = match kernel_entry_from_elf(kernel) {
        Ok(e) => e as usize,
        Err(_) => bail("[boot] erro: entry invalido\n"),
    };
    // SAFETY: `entry` veio do ELF já validado (W^X, dentro de LOAD executável).
    let entry_fn: extern "C" fn(*const bootinfo::BootInfo) -> ! = unsafe { mem::transmute(entry) };
    entry_fn(&bootinfo as *const bootinfo::BootInfo)
}

