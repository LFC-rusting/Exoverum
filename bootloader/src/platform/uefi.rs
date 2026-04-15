use bootinfo::{FramebufferInfo, MemoryMap};
use core::ffi::c_void;
use core::mem;
use core::ptr::NonNull;
use core::slice;

use crate::{
    build_bootinfo,
    kernel_entry_from_elf,
    kernel_phys_range_from_elf,
    process_kernel_image,
    mapping::build_identity_map,
    BootError,
    KernelImage,
    Platform,
    PlatformInfo,
    PhysRange,
};

/// Estrutura placeholder para integrar dados coletados da UEFI sem alocação.
/// A coleta real (SimpleFileSystem, GetMemoryMap, GOP, RSDP/SMBIOS, CR3) deve preencher estes campos antes de chamar `boot_flow`.
pub struct UefiPlatform<'a> {
    pub kernel_elf: &'a [u8],
    pub expected_sha256: Option<[u8; 32]>,
    pub memory_map: Option<MemoryMap>,
    pub framebuffer: Option<FramebufferInfo>,
    pub rsdp: Option<u64>,
    pub smbios: Option<u64>,
    pub page_table_root: Option<u64>,
}

impl<'a> UefiPlatform<'a> {
    pub fn new(kernel_elf: &'a [u8]) -> Self {
        Self {
            kernel_elf,
            expected_sha256: None,
            memory_map: None,
            framebuffer: None,
            rsdp: None,
            smbios: None,
            page_table_root: None,
        }
    }

    pub fn with_hash(mut self, hash: [u8; 32]) -> Self {
        self.expected_sha256 = Some(hash);
        self
    }

    pub fn kernel_image(&self) -> KernelImage<'a> {
        KernelImage {
            elf: self.kernel_elf,
            expected_sha256: self.expected_sha256,
        }
    }
}

impl<'a> Platform for UefiPlatform<'a> {
    fn memory_map(&self) -> Option<MemoryMap> {
        self.memory_map
    }
    fn framebuffer(&self) -> Option<FramebufferInfo> {
        self.framebuffer
    }
    fn rsdp(&self) -> Option<u64> {
        self.rsdp
    }
    fn smbios(&self) -> Option<u64> {
        self.smbios
    }
    fn page_table_root(&self) -> Option<u64> {
        self.page_table_root
    }
}

/// Coleta dados já preenchidos na estrutura (placeholder seguro).
/// Em integração real, os campos devem ser populados com resultados das chamadas UEFI antes de invocar esta função.
pub fn collect(platform: &UefiPlatform<'_>, kernel_phys_range: PhysRange) -> Result<PlatformInfo, BootError> {
    let memory_map = platform.memory_map().ok_or(BootError::MemoryMapUnavailable)?;
    let page_table_root = platform.page_table_root().ok_or(BootError::PageTableUnavailable)?;
    Ok(PlatformInfo {
        memory_map,
        framebuffer: platform.framebuffer(),
        rsdp: platform.rsdp(),
        smbios: platform.smbios(),
        page_table_root,
        kernel_phys_range,
    })
}

/// Lê CR3 diretamente (somente x86_64).
#[cfg(target_arch = "x86_64")]
pub fn get_cr3() -> Option<u64> {
    // SAFETY: instrução `mov` em cr3 é leitura; sem efeitos colaterais. Usar apenas em contexto privilegiado.
    let val: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) val);
    }
    Some(val)
}

#[cfg(not(target_arch = "x86_64"))]
pub fn get_cr3() -> Option<u64> {
    None
}

// -----------------------
// FFI e scaffolding UEFI
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
const MAX_PT_PAGES: usize = 4; // cobre até ~8 MiB (4 PTs * 512 * 4KiB)

fn status_success(status: Status) -> bool {
    status.0 == Status::SUCCESS.0
}

fn status_is_buffer_too_small(status: Status) -> bool {
    status.0 == EFI_BUFFER_TOO_SMALL.0
}

fn align_down(val: u64, align: u64) -> u64 {
    val & !(align - 1)
}

fn align_up(val: u64, align: u64) -> u64 {
    align_down(val + align - 1, align)
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

#[repr(C)]
pub struct EfiBootServices {
    pub hdr: EfiTableHeader,
    pub allocate_pool: unsafe extern "efiapi" fn(pool_type: u32, size: usize, buf: *mut *mut c_void) -> Status,
    pub free_pool: unsafe extern "efiapi" fn(buf: *mut c_void) -> Status,
    pub get_memory_map: unsafe extern "efiapi" fn(
        memory_map_size: *mut usize,
        memory_map: *mut EfiMemoryDescriptor,
        map_key: *mut usize,
        descriptor_size: *mut usize,
        descriptor_version: *mut u32,
    ) -> Status,
    pub allocate_pages: usize,
    pub free_pages: usize,
    pub get_next_monotonic_count: usize,
    pub stall: usize,
    pub set_watchdog_timer: usize,
    pub connect_controller: usize,
    pub disconnect_controller: usize,
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
    pub protocols_per_handle: usize,
    pub locate_handle_buffer: usize,
    pub locate_protocol: unsafe extern "efiapi" fn(
        protocol: *const Guid,
        registration: *const c_void,
        interface: *mut *mut c_void,
    ) -> Status,
    pub install_multiple_protocol_interfaces: usize,
    pub uninstall_multiple_protocol_interfaces: usize,
    pub calculate_crc32: usize,
    pub copy_mem: usize,
    pub set_mem: usize,
    pub create_event_ex: usize,
    pub exit_boot_services: unsafe extern "efiapi" fn(image_handle: EfiHandle, map_key: usize) -> Status,
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
pub const EFI_FILE_READ_ONLY: u64 = 0x0000_0000_0000_0001;
pub const EFI_LOADER_DATA: u32 = 4;

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

pub fn get_memory_map_real(
    bs: NonNull<EfiBootServices>,
    buffer: *mut EfiMemoryDescriptor,
    buffer_len: usize,
) -> Result<(MemoryMap, usize, usize), BootError> {
    let mut map_size = buffer_len;
    let mut map_key: usize = 0;
    let mut desc_size: usize = 0;
    let mut desc_version: u32 = 0;

    // SAFETY: chamadas UEFI exigem ponteiros válidos e buffer disponível.
    // O chamador garante `buffer` com `buffer_len` bytes alocados via AllocatePool.
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
    let device = unsafe { loaded.as_ref().device_handle };
    let sfs = open_protocol::<EfiSimpleFileSystemProtocol>(bs, device, &EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID, image_handle)?;

    let mut root: *mut EfiFileProtocol = core::ptr::null_mut();
    // SAFETY: ponteiros UEFI válidos; open_volume preenche root.
    let status = unsafe { (sfs.as_ref().open_volume)(sfs.as_ptr(), &mut root as *mut *mut EfiFileProtocol) };
    if !status_success(status) || root.is_null() {
        return Err(BootError::MissingKernel);
    }

    let mut file: *mut EfiFileProtocol = core::ptr::null_mut();
    // SAFETY: root é válido e file_name é UTF-16 NUL-terminated.
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
        unsafe {
            let _ = ((*root).close)(root);
        }
        return Err(BootError::MissingKernel);
    }

    // Descobrir tamanho via GetInfo.
    let mut info_size: usize = 0;
    let status = unsafe { ((*file).get_info)(file, &EFI_FILE_INFO_GUID, &mut info_size as *mut usize, core::ptr::null_mut()) };
    if !status_is_buffer_too_small(status) || info_size < mem::size_of::<EfiFileInfo>() {
        unsafe {
            let _ = ((*file).close)(file);
            let _ = ((*root).close)(root);
        }
        return Err(BootError::MissingKernel);
    }

    let info_buf = allocate_pool(bs, info_size)?;
    let status = unsafe { ((*file).get_info)(file, &EFI_FILE_INFO_GUID, &mut info_size as *mut usize, info_buf.as_ptr()) };
    if !status_success(status) {
        unsafe {
            let _ = (bs.as_ref().free_pool)(info_buf.as_ptr());
            let _ = ((*file).close)(file);
            let _ = ((*root).close)(root);
        }
        return Err(BootError::MissingKernel);
    }

    let info = unsafe { &*(info_buf.as_ptr() as *const EfiFileInfo) };
    let file_size = info.file_size as usize;
    let kernel_buf = allocate_pool(bs, file_size)?;

    let mut read_size = file_size;
    let status = unsafe { ((*file).read)(file, &mut read_size as *mut usize, kernel_buf.as_ptr()) };
    if !status_success(status) || read_size != file_size {
        unsafe {
            let _ = (bs.as_ref().free_pool)(kernel_buf.as_ptr());
            let _ = (bs.as_ref().free_pool)(info_buf.as_ptr());
            let _ = ((*file).close)(file);
            let _ = ((*root).close)(root);
        }
        return Err(BootError::MissingKernel);
    }

    unsafe {
        let _ = (bs.as_ref().free_pool)(info_buf.as_ptr());
        let _ = ((*file).close)(file);
        let _ = ((*root).close)(root);
    }

    // SAFETY: buffer alocado via AllocatePool é estável até o kernel assumir; retornamos slice estática.
    let slice = unsafe { slice::from_raw_parts(kernel_buf.as_ptr() as *const u8, file_size) };
    Ok(slice)
}

fn allocate_pool(bs: NonNull<EfiBootServices>, size: usize) -> Result<NonNull<c_void>, BootError> {
    let mut buf: *mut c_void = core::ptr::null_mut();
    // SAFETY: chamada UEFI allocate_pool, escreve ponteiro válido em buf se sucesso.
    let status = unsafe { (bs.as_ref().allocate_pool)(EFI_LOADER_DATA, size, &mut buf as *mut *mut c_void) };
    if !status_success(status) || buf.is_null() {
        return Err(BootError::MissingKernel);
    }
    Ok(NonNull::new(buf).unwrap())
}

fn open_protocol<T>(
    bs: NonNull<EfiBootServices>,
    handle: EfiHandle,
    guid: &Guid,
    agent: EfiHandle,
) -> Result<NonNull<T>, BootError> {
    let mut iface: *mut c_void = core::ptr::null_mut();
    // SAFETY: open_protocol exige ponteiros válidos e GUID correto.
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
    Ok(unsafe { NonNull::new_unchecked(iface as *mut T) })
}

fn zero_page(bs: NonNull<EfiBootServices>) -> Result<NonNull<u64>, BootError> {
    let page = allocate_pool(bs, PAGE_SIZE as usize)?;
    // SAFETY: page aponta para área alocada de pelo menos 4096 bytes.
    unsafe { core::ptr::write_bytes(page.as_ptr(), 0, PAGE_SIZE as usize) };
    Ok(unsafe { NonNull::new_unchecked(page.as_ptr() as *mut u64) })
}

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

    // SAFETY: páginas alocadas e alinhadas; escrevemos entradas com flags mínimos (P|W).
    unsafe {
        *pml4.as_ptr() = pdpt_phys | PTE_PRESENT | PTE_WRITABLE;
        *pdpt.as_ptr() = pd_phys | PTE_PRESENT | PTE_WRITABLE;
    }

    let mut pt_pages: [Option<NonNull<u64>>; MAX_PT_PAGES] = [None, None, None, None];

    let mut addr = map_start;
    while addr < map_end {
        let pd_index = ((addr >> 21) & 0x1ff) as usize;
        if pd_index >= pt_pages.len() {
            return Err(BootError::PageTableUnavailable);
        }
        if pt_pages[pd_index].is_none() {
            let pt = zero_page(bs)?;
            let pt_phys = pt.as_ptr() as u64;
            // SAFETY: PD está alocado; pd_index dentro do limite MAX_PT_PAGES (<512).
            unsafe {
                *pd.as_ptr().add(pd_index) = pt_phys | PTE_PRESENT | PTE_WRITABLE;
            }
            pt_pages[pd_index] = Some(pt);
        }
        let pt = pt_pages[pd_index].unwrap();
        let pt_index = ((addr >> 12) & 0x1ff) as usize;
        // SAFETY: PT existe e pt_index < 512; mapeamento identidade (paddr = vaddr = addr).
        unsafe {
            *pt.as_ptr().add(pt_index) = addr | PTE_PRESENT | PTE_WRITABLE;
        }
        addr = addr.saturating_add(PAGE_SIZE);
    }

    Ok(pml4_phys)
}

/// Entry point UEFI.
#[no_mangle]
pub extern "efiapi" fn efi_main(image: EfiHandle, system_table: *mut EfiSystemTable) -> ! {
    if system_table.is_null() {
        loop {}
    }
    // SAFETY: já validamos que system_table não é nulo.
    let st = unsafe { &*system_table };
    let bs = NonNull::new(st.boot_services as *mut EfiBootServices).expect("boot_services nulo");

    // 1) Carregar kernel.elf manualmente.
    let kernel = load_kernel_real(bs, image, &KERNEL_PATH_UTF16).expect("kernel.elf não encontrado");

    // 2) Validar ELF e hash (se houver hash embutido).
    let img = KernelImage { elf: kernel, expected_sha256: None };
    process_kernel_image(&img).expect("ELF inválido ou hash inválido");

    // 3) Calcular faixa física do kernel.
    let kernel_phys = kernel_phys_range_from_elf(kernel).expect("faixa física inválida");

    // 3.1) Stack físico real para identity map mínima.
    const STACK_SIZE: usize = 16 * 1024;
    let stack_buf = allocate_pool(bs, STACK_SIZE).expect("falha ao alocar stack");
    let stack_start = stack_buf.as_ptr() as u64;
    let stack_end = stack_start.saturating_add(STACK_SIZE as u64);
    let stack_phys = PhysRange {
        start: stack_start,
        end: stack_end,
    };

    let _identity_map = build_identity_map(kernel_phys, stack_phys, None)
        .expect("identity map inválido");

    // 4) Preparar memory map imediatamente antes do ExitBootServices.
    let mut map_key: usize = 0;
    let mut desc_size: usize = 0;
    let (map_buf, map_buf_len) = loop {
        // primeira chamada para obter tamanho.
        let mut map_size: usize = 0;
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
            break (None, 0usize);
        }
        // reserva com margem de 2 descritores.
        let extra = desc_size.saturating_mul(2);
        let total = map_size.saturating_add(extra);
        let buf = allocate_pool(bs, total).ok();
        break (buf, total);
    };

    let map_buf = map_buf.expect("falha ao alocar memory map");
    let (mem_map, map_key, _desc_size) = get_memory_map_real(
        bs,
        map_buf.as_ptr() as *mut EfiMemoryDescriptor,
        map_buf_len,
    )
    .expect("GetMemoryMap falhou");

    // 5) BootInfo minimalista (page_table_root = 0 por enquanto).
    let page_table_root = build_identity_pagetables(bs, kernel_phys, stack_phys)
        .expect("falha ao montar page tables 4K");

    let bootinfo = build_bootinfo(mem_map, None, None, None, page_table_root, kernel_phys);

    // 6) ExitBootServices imediatamente após GetMemoryMap.
    let status = unsafe { (bs.as_ref().exit_boot_services)(image, map_key) };
    if !status_success(status) {
        loop {}
    }

    // 6.1) Sinalização mínima na saída de texto (se disponível) antes do salto.
    if !st.con_out.is_null() {
        let con_out = st.con_out as *mut EfiSimpleTextOutputProtocol;
        // SAFETY: con_out vem do firmware; OutputString aceita UTF-16 NUL-terminated.
        let _ = unsafe { ((*con_out).output_string)(con_out, BOOT_MSG_OK.as_ptr()) };
    }

    // 7) Salto para o kernel entry.
    let entry = kernel_entry_from_elf(kernel).expect("entry inválido") as usize;
    // SAFETY: entry vem do ELF validado e aponta para código do kernel.
    let entry_fn: extern "C" fn(*const bootinfo::BootInfo) -> ! = unsafe { mem::transmute(entry) };
    entry_fn(&bootinfo as *const bootinfo::BootInfo)
}
