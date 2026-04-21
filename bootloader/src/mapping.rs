//! Utilitários de layout físico. Atualmente só verifica sobreposição de ranges.
//! Mantido separado do montador real de page tables (em `platform::uefi`) porque
//! é lógica pura, safe, e testável sem UEFI.

#![forbid(unsafe_code)]

use bootinfo::PhysRange;

use crate::BootError;

/// Falha se quaisquer dois ranges da lista se sobrepõem. O(n^2) sem alocação;
/// `n` é sempre pequeno (kernel, stack, framebuffer).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sem_sobreposicao() {
        let r = [
            PhysRange { start: 0, end: 100 },
            PhysRange { start: 200, end: 300 },
        ];
        assert!(assert_non_overlapping(&r).is_ok());
    }

    #[test]
    fn com_sobreposicao() {
        let r = [
            PhysRange { start: 0, end: 150 },
            PhysRange { start: 100, end: 200 },
        ];
        assert!(assert_non_overlapping(&r).is_err());
    }

    #[test]
    fn adjacente_nao_sobrepoe() {
        let r = [
            PhysRange { start: 0, end: 100 },
            PhysRange { start: 100, end: 200 },
        ];
        assert!(assert_non_overlapping(&r).is_ok());
    }
}
