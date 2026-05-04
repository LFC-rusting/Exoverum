//! Framebuffer minimo: rotulos textuais `[OK] <fase>.` em fonte 8x8
//! embutida, escala 2x. Prova visual de progresso em bare metal.
//!
//! Fluxo: `init_from_bootinfo` (antes de paging) guarda info crua;
//! `remap_after_paging` mapeia MMIO, limpa tela e imprime cabecalho;
//! `mark(n)`/`mark_halt(n)` imprimem uma linha fixa por fase. Sem
//! console, sem scroll, sem alocacao. `unsafe` confinado a MMIO.

use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use bootinfo::BootInfo;

static FB_BASE: AtomicPtr<u32> = AtomicPtr::new(core::ptr::null_mut());
static FB_PHYS_LO: AtomicU32 = AtomicU32::new(0);
static FB_PHYS_HI: AtomicU32 = AtomicU32::new(0);
static FB_PITCH: AtomicU32 = AtomicU32::new(0);
static FB_WIDTH: AtomicU32 = AtomicU32::new(0);
static FB_HEIGHT: AtomicU32 = AtomicU32::new(0);

/// VA higher-half reservada (PML4=511, PDPT=504, livre no mapa kernel).
const FB_VA: u64 = 0xFFFF_FFFF_E000_0000;

/// Escala: cada bit da fonte vira um bloco SCALE x SCALE de pixels.
const SCALE: u32 = 2;
const GLYPH_W: u32 = 8 * SCALE;
const GLYPH_H: u32 = 8 * SCALE;
/// Altura total de linha (glyph + gap).
const LINE_H: u32 = GLYPH_H + 4;
const FG: u32 = 0x00FF_FFFF;
const BG: u32 = 0x0000_0000;

const LABELS: [&str; 3] = ["[OK] Paging.", "[OK] Caps.", "[OK] Userland."];
const HEADER: &str = "[OK] Bootloader.";

pub fn init_from_bootinfo(bi: &BootInfo) {
    let Some(fi) = bi.framebuffer else { return };
    FB_PHYS_LO.store(fi.base as u32, Ordering::Relaxed);
    FB_PHYS_HI.store((fi.base >> 32) as u32, Ordering::Relaxed);
    FB_PITCH.store(fi.pitch, Ordering::Relaxed);
    FB_WIDTH.store(fi.width, Ordering::Relaxed);
    FB_HEIGHT.store(fi.height, Ordering::Relaxed);
}

/// Mapeia o framebuffer em `FB_VA` (`Perm::Mmio`) e imprime o cabecalho.
/// Cada `draw_line` apaga apenas a propria faixa antes de pintar — barato
/// mesmo em hardware com MMIO uncacheable (vs varrer a tela inteira).
///
/// # Safety
/// Pos-`mm::init_paging`; chamada unica por boot.
#[cfg(target_os = "none")]
pub unsafe fn remap_after_paging() -> Result<(), crate::mm::PagingError> {
    let phys = (FB_PHYS_HI.load(Ordering::Relaxed) as u64) << 32
        | FB_PHYS_LO.load(Ordering::Relaxed) as u64;
    if phys == 0 {
        return Ok(());
    }
    let bytes = (FB_PITCH.load(Ordering::Relaxed) as u64)
        .saturating_mul(FB_HEIGHT.load(Ordering::Relaxed) as u64);
    const PAGE: u64 = 4096;
    let mut i = 0u64;
    while i < bytes.div_ceil(PAGE) {
        // SAFETY: pos-init_paging; enderecos 4K-alinhados (UEFI GOP devolve
        // base page-aligned); Mmio = RW+NX+UC (proibido em user por assert).
        unsafe {
            crate::mm::map_kernel_page(FB_VA + i * PAGE, phys + i * PAGE, crate::mm::Perm::Mmio)?;
        }
        i += 1;
    }
    FB_BASE.store(FB_VA as *mut u32, Ordering::Relaxed);
    draw_line(0, HEADER, None);
    Ok(())
}

/// Imprime rotulo da fase `stage` (0..3) na linha `stage+1`.
pub fn mark(stage: u32) {
    if let Some(s) = LABELS.get(stage as usize) {
        draw_line(stage + 1, s, None);
    }
}

/// Imprime `[OK] Halt.` na linha final.
#[cfg(target_os = "none")]
pub fn mark_halt() {
    draw_line(LABELS.len() as u32 + 1, "[OK] Halt.", None);
}

fn draw_line(line: u32, s: &str, suffix: Option<&[u8]>) {
    let base = FB_BASE.load(Ordering::Relaxed);
    if base.is_null() {
        return;
    }
    let width = FB_WIDTH.load(Ordering::Relaxed);
    let height = FB_HEIGHT.load(Ordering::Relaxed);
    let y0 = line * LINE_H;
    if y0 + GLYPH_H > height {
        return;
    }
    // Limpa a altura inteira da linha (LINE_H), incluindo gap entre
    // linhas. Remove residuos do console UEFI entre uma linha e outra.
    let pitch = FB_PITCH.load(Ordering::Relaxed) as usize;
    let mut yy = y0;
    let y_end = core::cmp::min(y0 + LINE_H, height);
    while yy < y_end {
        // SAFETY: yy < height (checado acima); pitch e base validos.
        unsafe {
            let row = base.cast::<u8>().add(yy as usize * pitch).cast::<u32>();
            let mut x = 0u32;
            while x < width {
                row.add(x as usize).write_volatile(BG);
                x += 1;
            }
        }
        yy += 1;
    }
    let mut x = 0u32;
    for &b in s.as_bytes() {
        if x + GLYPH_W > width {
            return;
        }
        draw_glyph(x, y0, glyph(b));
        x += GLYPH_W;
    }
    if let Some(bytes) = suffix {
        for &d in bytes {
            if x + GLYPH_W > width {
                return;
            }
            draw_glyph(x, y0, glyph(d));
            x += GLYPH_W;
        }
    }
}

fn draw_glyph(x0: u32, y0: u32, g: &[u8; 8]) {
    let base = FB_BASE.load(Ordering::Relaxed);
    let pitch = FB_PITCH.load(Ordering::Relaxed) as usize;
    let mut row = 0u32;
    while row < 8 {
        let bits = g[row as usize];
        let mut col = 0u32;
        while col < 8 {
            let on = (bits >> (7 - col)) & 1 != 0;
            let color = if on { FG } else { BG };
            // Expande bit em bloco SCALE x SCALE.
            let mut dy = 0u32;
            while dy < SCALE {
                let mut dx = 0u32;
                while dx < SCALE {
                    // SAFETY: base cobre pitch*height mapeado Mmio. y e x
                    // dentro de bounds checados em draw_line. Pitch (e
                    // logo endereco) multiplo de 4.
                    unsafe {
                        let px = base
                            .cast::<u8>()
                            .add(((y0 + row * SCALE + dy) as usize) * pitch)
                            .cast::<u32>()
                            .add((x0 + col * SCALE + dx) as usize);
                        px.write_volatile(color);
                    }
                    dx += 1;
                }
                dy += 1;
            }
            col += 1;
        }
        row += 1;
    }
}

// Fonte 8x8, bit 7 = pixel esquerdo, byte 0 = topo. So os chars usados.
fn glyph(c: u8) -> &'static [u8; 8] {
    match c {
        b' ' => &[0; 8],
        b'.' => &[0, 0, 0, 0, 0, 0, 0x18, 0x18],
        b'[' => &[0x38, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x38],
        b']' => &[0x70, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x70],
        b'O' => &[0x3C, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x3C],
        b'K' => &[0x42, 0x44, 0x48, 0x70, 0x48, 0x44, 0x42, 0x00],
        b'B' => &[0x7C, 0x42, 0x42, 0x7C, 0x42, 0x42, 0x7C, 0x00],
        b'P' => &[0x7C, 0x42, 0x42, 0x7C, 0x40, 0x40, 0x40, 0x00],
        b'C' => &[0x3C, 0x42, 0x40, 0x40, 0x40, 0x42, 0x3C, 0x00],
        b'U' => &[0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x3C, 0x00],
        b'H' => &[0x42, 0x42, 0x42, 0x7E, 0x42, 0x42, 0x42, 0x00],
        b'a' => &[0x00, 0x00, 0x3C, 0x02, 0x3E, 0x42, 0x3E, 0x00],
        b'd' => &[0x02, 0x02, 0x02, 0x3E, 0x42, 0x42, 0x42, 0x3E],
        b'e' => &[0x00, 0x00, 0x3C, 0x42, 0x7E, 0x40, 0x42, 0x3C],
        b'g' => &[0x00, 0x3E, 0x42, 0x42, 0x3E, 0x02, 0x02, 0x3C],
        b'i' => &[0x10, 0x00, 0x30, 0x10, 0x10, 0x10, 0x38, 0x00],
        b'l' => &[0x30, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x38],
        b'n' => &[0x00, 0x00, 0x5C, 0x62, 0x42, 0x42, 0x42, 0x42],
        b'o' => &[0x00, 0x00, 0x3C, 0x42, 0x42, 0x42, 0x42, 0x3C],
        b'p' => &[0x00, 0x00, 0x7C, 0x42, 0x42, 0x7C, 0x40, 0x40],
        b'r' => &[0x00, 0x00, 0x5C, 0x62, 0x40, 0x40, 0x40, 0x40],
        b's' => &[0x00, 0x00, 0x3C, 0x40, 0x3C, 0x02, 0x3C, 0x00],
        b't' => &[0x20, 0x20, 0x78, 0x20, 0x20, 0x20, 0x20, 0x1C],
        b'0' => &[0x3C, 0x42, 0x46, 0x4A, 0x52, 0x62, 0x42, 0x3C],
        b'1' => &[0x10, 0x30, 0x10, 0x10, 0x10, 0x10, 0x10, 0x38],
        b'2' => &[0x3C, 0x42, 0x02, 0x0C, 0x10, 0x20, 0x40, 0x7E],
        b'3' => &[0x3C, 0x42, 0x02, 0x1C, 0x02, 0x02, 0x42, 0x3C],
        b'4' => &[0x08, 0x18, 0x28, 0x48, 0x7E, 0x08, 0x08, 0x08],
        b'5' => &[0x7E, 0x40, 0x40, 0x7C, 0x02, 0x02, 0x42, 0x3C],
        b'6' => &[0x1C, 0x20, 0x40, 0x7C, 0x42, 0x42, 0x42, 0x3C],
        b'7' => &[0x7E, 0x02, 0x04, 0x08, 0x10, 0x20, 0x20, 0x20],
        b'8' => &[0x3C, 0x42, 0x42, 0x3C, 0x42, 0x42, 0x42, 0x3C],
        b'9' => &[0x3C, 0x42, 0x42, 0x3E, 0x02, 0x02, 0x04, 0x38],
        _ => &[0; 8],
    }
}
