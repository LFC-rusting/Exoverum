use bootinfo::PhysRange;

use crate::BootError;

/// Representa um mapeamento identity mínimo necessário para handoff.
pub struct IdentityMap {
    pub kernel_phys: PhysRange,
    pub stack_phys: PhysRange,
    pub framebuffer_phys: Option<PhysRange>,
}

/// Valida se ranges não se sobrepõem (útil para sanity-check do layout).
pub fn assert_non_overlapping(ranges: &[PhysRange]) -> Result<(), BootError> {
    for (i, a) in ranges.iter().enumerate() {
        for (j, b) in ranges.iter().enumerate() {
            if i == j {
                continue;
            }
            if overlaps(a, b) {
                return Err(BootError::InvalidElfOverlap);
            }
        }
    }
    Ok(())
}

fn overlaps(a: &PhysRange, b: &PhysRange) -> bool {
    !(a.end <= b.start || b.end <= a.start)
}

/// Constrói IdentityMap validando sobreposição.
pub fn build_identity_map(
    kernel_phys: PhysRange,
    stack_phys: PhysRange,
    framebuffer_phys: Option<PhysRange>,
) -> Result<IdentityMap, BootError> {
    let mut buf: [Option<PhysRange>; 3] = [None, None, None];
    buf[0] = Some(kernel_phys);
    buf[1] = Some(stack_phys);
    if let Some(fb) = framebuffer_phys {
        buf[2] = Some(fb);
    }
    let mut collected = [kernel_phys; 3];
    let mut count = 0usize;
    for item in buf.iter().flatten() {
        collected[count] = *item;
        count += 1;
    }
    assert_non_overlapping(&collected[..count])?;
    Ok(IdentityMap {
        kernel_phys,
        stack_phys,
        framebuffer_phys,
    })
}
